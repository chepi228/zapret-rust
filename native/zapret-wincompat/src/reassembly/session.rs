//! Client reassembly lifecycle and deferred packet release.
use super::{Reassembly, feed};
use crate::{
    conntrack::{Positions, reassembly_client_sequence, reassembly_tcp_window},
    packet_queue::{Queue, RawSend, rawpacket_queue, rawpacket_queue_count, send_originals},
};
use std::ffi::{c_char, c_void};

#[cfg(windows)]
use crate::native_logging_entry::LogSink;

const TCP: u8 = 6;
const UNKNOWN_PAYLOAD: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy)]
enum Event {
    WindowTooSmall,
    Capacity,
    InitialFragment,
    AllocationFailed,
    Started,
    Appended,
    FragmentRejected,
    Cancelled,
    Finished,
    SendingDelayed,
    QueueFailed,
    Queued,
}

#[cfg(windows)]
#[unsafe(no_mangle)]
extern "C" fn zapret_reassembly_report(
    event: u32,
    first: usize,
    second: usize,
    third: usize,
    debug: LogSink,
    error: LogSink,
) {
    if event > Event::Queued as u32 {
        return;
    }
    // All discriminants from zero through Queued belong to Event.
    let event = unsafe { std::mem::transmute::<u32, Event>(event) };
    unsafe {
        match event {
            Event::WindowTooSmall => debug(
                c"reasm cancelled because server window size %zu is smaller than expected reasm size %zu\n".as_ptr(),
                first, second,
            ),
            Event::Capacity => debug(c"unexpected large payload for reassemble: size=%zu\n".as_ptr(), first),
            Event::InitialFragment => debug(c"reassemble initial fragment rejected: size=%zu payload=%zu\n".as_ptr(), first, second),
            Event::AllocationFailed => debug(c"reassemble init failed. out of memory\n".as_ptr()),
            Event::Started => debug(c"starting reassemble. now we have %zu/%zu\n".as_ptr(), first, second),
            Event::Appended => debug(c"reassemble : feeding data payload size=%zu. now we have %zu/%zu\n".as_ptr(), first, second, third),
            Event::FragmentRejected => debug(c"reassemble session failed\n".as_ptr()),
            Event::Cancelled => debug(c"reassemble session cancelled\n".as_ptr()),
            Event::Finished => debug(c"reassemble session finished\n".as_ptr()),
            Event::SendingDelayed => debug(c"SENDING %zu delayed packets\n".as_ptr(), first),
            Event::QueueFailed => error(c"rawpacket_queue failed !\n".as_ptr()),
            Event::Queued => debug(c"DELAY desync until reasm is complete (#%zu)\n".as_ptr(), first),
        };
    }
}

#[repr(C)]
pub(crate) struct Session {
    buffer: *mut Reassembly,
    kind: *mut u32,
    positions: *const c_void,
    delayed: *mut Queue,
}

#[repr(C)]
pub(crate) struct Ops {
    send: RawSend,
    replay: unsafe extern "C-unwind" fn(*mut Queue) -> bool,
    report: extern "C" fn(u32, usize, usize, usize),
}

#[repr(C)]
pub(crate) struct DeferredPacket {
    pub(crate) destination: *const c_void,
    pub(crate) interface_in: *const c_char,
    pub(crate) interface_out: *const c_char,
    pub(crate) data: *const u8,
    pub(crate) length: usize,
    pub(crate) payload_length: usize,
    pub(crate) original_mark: u32,
    pub(crate) mark: u32,
}

impl Session {
    // These offsets are asserted against the C connection definition before
    // the packet preparation adapter can be linked.
    pub(crate) unsafe fn for_track(track: *mut c_void) -> Option<Self> {
        if track.is_null() {
            return None;
        }
        Some(unsafe {
            Self {
                buffer: track.byte_add(232).cast(),
                kind: track.byte_add(228).cast(),
                positions: track.byte_add(24),
                delayed: track.byte_add(264).cast(),
            }
        })
    }

    pub(crate) fn positions(&self) -> *const Positions {
        self.positions.cast()
    }

    pub(crate) unsafe fn kind(&self) -> u32 {
        unsafe { self.kind.read() }
    }

    pub(crate) unsafe fn active(&self) -> bool {
        unsafe { (*self.buffer).size != 0 }
    }

    pub(crate) unsafe fn full(&self) -> bool {
        unsafe { self.active() && (*self.buffer).size == (*self.buffer).present }
    }

    pub(crate) unsafe fn payload(&self) -> (*const u8, usize) {
        unsafe { ((*self.buffer).packet, (*self.buffer).present) }
    }

    unsafe fn reset(&self) -> bool {
        let buffer = unsafe { &mut *self.buffer };
        let active = buffer.size != 0;
        buffer.clear();
        unsafe { self.kind.write(UNKNOWN_PAYLOAD) };
        active
    }

    unsafe fn release(&self, ops: &Ops) {
        let count = unsafe { rawpacket_queue_count(self.delayed) };
        if count != 0 {
            (ops.report)(Event::SendingDelayed as u32, count as usize, 0, 0);
            unsafe { send_originals(self.delayed, ops.send) };
        }
    }

    unsafe fn stop(&self, ops: &Ops, reason: Event) {
        if unsafe { self.reset() } {
            (ops.report)(reason as u32, 0, 0, 0);
        }
        unsafe { self.release(ops) };
    }
}

// The C adapter owns the connection for each call. Input fragments come from
// the incoming packet or decrypted scratch, disjoint from the session buffer.
// Callbacks run with no outstanding mutable borrow of the buffer or queue.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_reassembly_start(
    session: &Session,
    ops: &Ops,
    protocol: u8,
    kind: u32,
    size: usize,
    maximum: usize,
    payload: *const u8,
    length: usize,
) -> bool {
    let sequence = if protocol == TCP {
        let window = unsafe { reassembly_tcp_window(session.positions) };
        if let Some(window) = window.filter(|&window| (window as usize) < size) {
            (ops.report)(Event::WindowTooSmall as u32, window as usize, size, 0);
            return false;
        }
        unsafe { reassembly_client_sequence(session.positions) }
    } else {
        0
    };

    unsafe { session.reset() };
    let result = {
        let buffer = unsafe { &mut *session.buffer };
        if size > maximum {
            Err(Event::Capacity)
        } else if size == 0 || length > size || (length != 0 && payload.is_null()) {
            Err(Event::InitialFragment)
        } else if !buffer.initialize(size, sequence) {
            Err(Event::AllocationFailed)
        } else if feed(buffer, sequence, payload, length) {
            Ok(buffer.present)
        } else {
            buffer.clear();
            Err(Event::InitialFragment)
        }
    };
    match result {
        Ok(present) => {
            unsafe { session.kind.write(kind) };
            (ops.report)(Event::Started as u32, present, size, 0);
            true
        }
        Err(reason) => {
            (ops.report)(reason as u32, size, length, 0);
            unsafe { session.release(ops) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_reassembly_append(
    session: &Session,
    ops: &Ops,
    protocol: u8,
    payload: *const u8,
    length: usize,
) -> bool {
    let (success, present, size) = {
        let buffer = unsafe { &mut *session.buffer };
        if buffer.size == 0 {
            return false;
        }
        let sequence = if protocol == TCP {
            unsafe { reassembly_client_sequence(session.positions) }
        } else {
            buffer.present as u32
        };
        let success = (protocol == TCP || buffer.has_space(length))
            && (length == 0 || !payload.is_null())
            && feed(buffer, sequence, payload, length);
        (success, buffer.present, buffer.size)
    };
    if success {
        (ops.report)(Event::Appended as u32, length, present, size);
    } else {
        unsafe { session.stop(ops, Event::FragmentRejected) };
    }
    success
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C-unwind" fn zapret_reassembly_cancel(session: &Session, ops: &Ops) {
    unsafe { session.stop(ops, Event::Cancelled) };
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C-unwind" fn zapret_reassembly_defer(
    session: &Session,
    ops: &Ops,
    packet: &DeferredPacket,
    complete: bool,
) -> bool {
    let queued = unsafe {
        rawpacket_queue(
            session.delayed,
            packet.destination,
            packet.original_mark,
            packet.mark,
            packet.interface_in,
            packet.interface_out,
            packet.data.cast(),
            packet.length,
            packet.payload_length,
            session.positions,
            false,
        )
    };
    if queued.is_null() {
        (ops.report)(Event::QueueFailed as u32, 0, 0, 0);
        unsafe { session.stop(ops, Event::Cancelled) };
        return false;
    }

    let count = unsafe { rawpacket_queue_count(session.delayed) };
    (ops.report)(Event::Queued as u32, count as usize, 0, 0);
    if complete {
        // Replay reads the assembled bytes. Clear them after it returns.
        unsafe { (ops.replay)(session.delayed) };
        unsafe { session.stop(ops, Event::Finished) };
    }
    true
}
