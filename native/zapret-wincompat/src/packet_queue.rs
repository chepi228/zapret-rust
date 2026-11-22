//! Owns the copies of packets and connection positions used for deferred replay.
use crate::allocate::try_allocate;
use std::{
    collections::VecDeque,
    ffi::{c_char, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr::{self, NonNull},
};

mod replay;

const ADDRESS_SIZE: usize = 128;
const INTERFACE_SIZE: usize = 44;
const POSITIONS_SIZE: usize = 160;

#[repr(C, align(8))]
struct Address([MaybeUninit<u8>; ADDRESS_SIZE]);

#[repr(C, align(8))]
struct Positions([MaybeUninit<u8>; POSITIONS_SIZE]);

// The fields before storage are the C-visible packet. The extra Vec owns the
// bytes and stays private. Moving a queue entry moves only its pointer.
#[repr(C)]
pub(super) struct Packet {
    destination: Address,
    interface_in: [c_char; INTERFACE_SIZE],
    interface_out: [c_char; INTERFACE_SIZE],
    original_mark: u32,
    mark: u32,
    length: usize,
    payload_length: usize,
    packet: *mut u8,
    positions: Positions,
    positions_present: bool,
    server_side: bool,
    // C owns the full public prefix, including its tail padding.
    #[cfg(target_pointer_width = "32")]
    _prefix_padding: [u8; 6],
    storage: Vec<u8>,
}

#[derive(Default)]
struct Entries(VecDeque<NonNull<Packet>>);

impl Drop for Entries {
    fn drop(&mut self) {
        for packet in self.0.drain(..) {
            drop(unsafe { Box::from_raw(packet.as_ptr()) });
        }
    }
}

#[repr(C)]
pub(super) struct Queue {
    entries: *mut Entries,
    maximum: u32,
}

// A zeroed queue can be destroyed, including during partial conntrack
// initialization. Init is only called on fresh or cleared storage.
#[unsafe(no_mangle)]
unsafe extern "C" fn rawpacket_queue_init(queue: *mut Queue, maximum: u32) {
    unsafe {
        queue.write(Queue {
            entries: ptr::null_mut(),
            maximum,
        })
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawpacket_queue_destroy(queue: *mut Queue) {
    let entries = unsafe { ptr::replace(&mut (*queue).entries, ptr::null_mut()) };
    if !entries.is_null() {
        drop(unsafe { Box::from_raw(entries) });
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rawpacket_queue_count(queue: *const Queue) -> u32 {
    unsafe { (*queue).entries.as_ref() }.map_or(0, |entries| entries.0.len() as u32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawpacket_queue_empty(queue: *const Queue) -> bool {
    unsafe { rawpacket_queue_count(queue) == 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawpacket_dequeue(queue: *mut Queue) -> *mut Packet {
    let Some(entries) = (unsafe { (*queue).entries.as_mut() }) else {
        return ptr::null_mut();
    };
    // Keep the empty container until connection cleanup so another deferred
    // burst can reuse its allocation. Packet ownership still leaves the queue.
    entries
        .0
        .pop_front()
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawpacket_free(packet: *mut Packet) {
    if !packet.is_null() {
        drop(unsafe { Box::from_raw(packet) });
    }
}

/// Transfer ownership of the oldest packet without holding a queue borrow.
unsafe fn pop_owned(queue: *mut Queue) -> Option<Box<Packet>> {
    let packet = NonNull::new(unsafe { rawpacket_dequeue(queue) })?;
    Some(unsafe { Box::from_raw(packet.as_ptr()) })
}

pub(super) type RawSend =
    unsafe extern "C" fn(*const c_void, u32, *const c_char, *const c_void, usize) -> bool;

impl Packet {
    unsafe fn send(packet: *const Self, data: *const u8, length: usize, send: RawSend) -> bool {
        unsafe {
            send(
                ptr::addr_of!((*packet).destination).cast(),
                (*packet).mark,
                ptr::addr_of!((*packet).interface_out).cast(),
                data.cast(),
                length,
            )
        }
    }
}

pub(super) unsafe fn send_originals(queue: *mut Queue, send: RawSend) {
    while let Some(mut packet) = unsafe { pop_owned(queue) } {
        // A send failure must not abandon the remaining queue.
        let data = packet.packet;
        let length = packet.length;
        unsafe { Packet::send(ptr::from_mut(packet.as_mut()), data, length, send) };
    }
}

unsafe fn interface_name(name: *const c_char) -> [c_char; INTERFACE_SIZE] {
    let mut result = [0; INTERFACE_SIZE];
    if !name.is_null() {
        for (index, output) in result[..INTERFACE_SIZE - 1].iter_mut().enumerate() {
            let byte = unsafe { *name.add(index) };
            if byte == 0 {
                break;
            }
            *output = byte;
        }
    }
    result
}

// These pointers belong to a single engine thread. The caller supplies the C
// address and (optional) connection positions for the asserted Windows ABI.
// Copy them as MaybeUninit bytes because C struct padding can be uninitialized.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rawpacket_queue(
    queue: *mut Queue,
    destination: *const c_void,
    original_mark: u32,
    mark: u32,
    interface_in: *const c_char,
    interface_out: *const c_char,
    data: *const c_void,
    length: usize,
    payload_length: usize,
    positions: *const c_void,
    server_side: bool,
) -> *mut Packet {
    let queue = unsafe { &mut *queue };
    let mut fresh = Entries::default();
    let entries = unsafe { queue.entries.as_mut() }.unwrap_or(&mut fresh);
    if (queue.maximum != 0 && entries.0.len() >= queue.maximum as usize)
        || entries.0.try_reserve(1).is_err()
    {
        return ptr::null_mut();
    }
    let mut storage = Vec::new();
    // Keep a real allocated pointer even for an empty packet, as in C.
    if storage.try_reserve_exact(length.max(1)).is_err() {
        return ptr::null_mut();
    }
    if length != 0 {
        unsafe {
            ptr::copy_nonoverlapping(data.cast::<u8>(), storage.as_mut_ptr(), length);
            storage.set_len(length);
        }
    }
    let packet = Packet {
        destination: unsafe { destination.cast::<Address>().read() },
        interface_in: unsafe { interface_name(interface_in) },
        interface_out: unsafe { interface_name(interface_out) },
        original_mark,
        mark,
        length,
        payload_length,
        packet: storage.as_mut_ptr(),
        positions: if positions.is_null() {
            Positions([MaybeUninit::new(0); POSITIONS_SIZE])
        } else {
            unsafe { positions.cast::<Positions>().read() }
        },
        positions_present: !positions.is_null(),
        server_side,
        #[cfg(target_pointer_width = "32")]
        _prefix_padding: [0; 6],
        storage,
    };
    let Some(packet) = try_allocate(packet) else {
        return ptr::null_mut();
    };
    entries.0.push_back(packet);
    if queue.entries.is_null() {
        let Some(entries) = try_allocate(fresh) else {
            return ptr::null_mut();
        };
        queue.entries = entries.as_ptr();
    }
    packet.as_ptr()
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(offset_of!(Queue, maximum) == pointer);
    assert!(offset_of!(Packet, destination) == 0);
    assert!(offset_of!(Packet, interface_in) == 128);
    assert!(offset_of!(Packet, interface_out) == 172);
    assert!(offset_of!(Packet, original_mark) == 216);
    assert!(offset_of!(Packet, mark) == 220);
    assert!(offset_of!(Packet, length) == 224);
    assert!(offset_of!(Packet, packet) == 224 + 2 * pointer);
    assert!(offset_of!(Packet, positions) == 232 + 2 * pointer);
    assert!(offset_of!(Packet, positions_present) == 392 + 2 * pointer);
    assert!(offset_of!(Packet, server_side) == 393 + 2 * pointer);
    assert!(offset_of!(Packet, storage) == 400 + 2 * pointer);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emptied_queue_reuses_storage_and_releases_only_its_remaining_packets() {
        let mut queue = Queue {
            entries: ptr::null_mut(),
            maximum: 1,
        };
        let address = Address([MaybeUninit::new(0); ADDRESS_SIZE]);
        let enqueue = |queue: &mut Queue| unsafe {
            rawpacket_queue(
                queue,
                ptr::from_ref(&address).cast(),
                0,
                0,
                ptr::null(),
                ptr::null(),
                b"packet".as_ptr().cast(),
                6,
                0,
                ptr::null(),
                false,
            )
        };
        let first = enqueue(&mut queue);
        assert!(!first.is_null());
        let entries = queue.entries;
        let capacity = unsafe { (*entries).0.capacity() };
        unsafe {
            assert_eq!(rawpacket_dequeue(&mut queue), first);
            assert!(rawpacket_queue_empty(&queue));
        }
        assert_eq!(queue.entries, entries);
        assert_eq!(unsafe { (*entries).0.capacity() }, capacity);
        assert!(!enqueue(&mut queue).is_null());
        assert_eq!(queue.entries, entries);
        assert!(enqueue(&mut queue).is_null());
        unsafe {
            rawpacket_queue_destroy(&mut queue);
            assert_eq!((*first).storage, b"packet");
            rawpacket_free(first);
            assert!(rawpacket_queue_empty(&queue));
        }
        assert!(queue.entries.is_null());
    }
}
