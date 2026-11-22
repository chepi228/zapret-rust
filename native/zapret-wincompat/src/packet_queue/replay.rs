//! Replay the deferred FIFO through the engine's packet and send callbacks.
use super::{Packet, Positions, Queue, RawSend, pop_owned, rawpacket_queue_count};
use crate::conntrack::replay_tcp_sequence;
use crate::logging::LogSink;
use crate::packet_policy::{VERDICT_DROP, VERDICT_MASK, VERDICT_MODIFY, VERDICT_PASS};
use std::{ffi::c_char, mem::MaybeUninit, ptr};

const RECONSTRUCT_CAPACITY: usize = 65_536;

type Process = unsafe extern "C-unwind" fn(
    u32,
    u32,
    usize,
    u32,
    *const c_char,
    *const c_char,
    *const Positions,
    *const u8,
    usize,
    *mut u8,
    *mut usize,
) -> u8;

#[repr(C)]
struct ReplayOps {
    process: Process,
    send: RawSend,
    debug: LogSink,
    error: LogSink,
}

// The engine keeps the queue alive on this thread throughout the call. The
// callbacks use a popped packet only until they return. Process initializes
// the modified prefix when it returns a Modify verdict with a valid length.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_replay_queue(queue: *mut Queue, ops: &ReplayOps) -> bool {
    let count = unsafe { rawpacket_queue_count(queue) };
    let mut modified = MaybeUninit::<[u8; RECONSTRUCT_CAPACITY]>::uninit();
    let modified = modified.as_mut_ptr().cast::<u8>();
    let mut index = 0u32;
    let mut offset = 0usize;
    let mut anchor = None;
    let mut success = true;

    while let Some(mut packet) = unsafe { pop_owned(queue) } {
        // Each pop transfers ownership. No queue borrow crosses the callbacks.
        let sequence = if packet.positions_present {
            unsafe {
                replay_tcp_sequence(ptr::from_ref(&packet.positions).cast(), packet.server_side)
            }
        } else {
            None
        };
        if let Some(sequence) = sequence {
            // A missing snapshot at the start of the queue leaves a byte
            // offset. Use the first known sequence as the anchor at that offset.
            let (first, base) = *anchor.get_or_insert((sequence, offset));
            offset = base.saturating_add(sequence.wrapping_sub(first) as usize);
        }

        let original = packet.packet;
        let original_length = packet.length;
        let payload_length = packet.payload_length;
        let pointer = ptr::from_mut(packet.as_mut());
        let number = index.wrapping_add(1);
        let mut length = RECONSTRUCT_CAPACITY;
        unsafe {
            (ops.debug)(
                c"REPLAYING delayed packet #%u offset %zu\n".as_ptr(),
                number,
                offset,
            );
            // The old adapter observed the processing arguments after logging.
            let positions = if (*pointer).positions_present {
                ptr::addr_of!((*pointer).positions)
            } else {
                ptr::null()
            };
            let verdict = (ops.process)(
                index,
                count,
                offset,
                (*pointer).original_mark,
                ptr::addr_of!((*pointer).interface_in).cast(),
                ptr::addr_of!((*pointer).interface_out).cast(),
                positions,
                (*pointer).packet,
                (*pointer).length,
                modified,
                &mut length,
            );
            // &= keeps draining the queue when a previous send has failed.
            match verdict & VERDICT_MASK {
                VERDICT_PASS => {
                    (ops.debug)(c"SENDING delayed packet #%u unmodified\n".as_ptr(), number);
                    success &= Packet::send(pointer, original, original_length, ops.send);
                }
                VERDICT_MODIFY if length <= RECONSTRUCT_CAPACITY => {
                    (ops.debug)(c"SENDING delayed packet #%u modified\n".as_ptr(), number);
                    success &= Packet::send(pointer, modified, length, ops.send);
                }
                VERDICT_MODIFY => {
                    (ops.error)(
                        c"delayed packet #%u has invalid modified length %zu\n".as_ptr(),
                        number,
                        length,
                    );
                    success = false;
                }
                VERDICT_DROP => {
                    (ops.debug)(c"DROPPING delayed packet #%u\n".as_ptr(), number);
                }
                _ => {}
            }
        }
        if sequence.is_none() {
            offset = offset.saturating_add(payload_length);
        }
        index = index.wrapping_add(1);
    }
    success
}
