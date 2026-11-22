//! Bounded engine diagnostics; formatting and variadic arguments remain in C.
use std::{
    cell::Cell,
    ffi::{c_char, c_int},
    ptr, slice,
    sync::Mutex,
};

// The native sink owns va_list, errno and FILE handling.
pub(super) type LogSink = unsafe extern "C" fn(*const c_char, ...) -> c_int;

const CAPACITY: usize = 4096;
pub(super) type Writer = unsafe extern "C" fn(i32, *const c_char);
struct Buffer {
    bytes: [u8; CAPACITY],
    used: usize,
}
static BUFFER: Mutex<Buffer> = Mutex::new(Buffer {
    bytes: [0; CAPACITY],
    used: 0,
});
thread_local! { static DEPTH: Cell<u8> = const { Cell::new(0) }; }
struct Depth;
impl Drop for Depth {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_log_buffer(
    message: *const c_char,
    length: usize,
    priority: i32,
    writer: Writer,
) -> bool {
    if length == 0 {
        return true;
    }
    if message.is_null() {
        return false;
    }
    let depth = DEPTH.with(|depth| {
        let previous = depth.get();
        if previous >= 2 {
            None
        } else {
            depth.set(previous + 1);
            Some(previous)
        }
    });
    let Some(depth) = depth else {
        return false;
    };
    let _depth = Depth;
    if depth != 0 {
        // An error reported by a writer must not wait for its own mutex. Emit
        // one complete nested message, and bound deeper callback recursion.
        let mut bytes = [0u8; CAPACITY];
        let mut size = length.min(CAPACITY - 2);
        unsafe { ptr::copy_nonoverlapping(message.cast::<u8>(), bytes.as_mut_ptr(), size) };
        if bytes[size - 1] != b'\n' {
            bytes[size] = b'\n';
            size += 1;
        }
        bytes[size] = 0;
        unsafe { writer(priority, bytes.as_ptr().cast()) };
        return true;
    }
    let mut buffer = BUFFER.lock().unwrap_or_else(|error| error.into_inner());
    let count = length.min(CAPACITY - 2 - buffer.used);
    let start = buffer.used;
    unsafe {
        ptr::copy_nonoverlapping(
            message.cast::<u8>(),
            buffer.bytes.as_mut_ptr().add(start),
            count,
        )
    };
    buffer.used += count;
    let mut size = buffer.used;
    let full = size == CAPACITY - 2;
    if full {
        buffer.bytes[size] = b'\n';
        size += 1;
    }
    buffer.bytes[size] = 0;
    if full || buffer.bytes[size - 1] == b'\n' {
        buffer.used = 0;
        // Serialize file/event writes as well as accumulation. Nested callbacks
        // use the independent path above instead of touching this buffer.
        unsafe { writer(priority, buffer.bytes.as_ptr().cast()) };
    }
    true
}

type HexWriter = unsafe extern "C" fn(*const c_char);
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_log_hex(
    data: *const u8,
    length: usize,
    limit: usize,
    writer: HexWriter,
) -> bool {
    let size = length.min(limit);
    if size == 0 {
        return true;
    }
    if data.is_null() {
        return false;
    }
    let cut = size != length;
    let Some(capacity) = size
        .checked_mul(4)
        .and_then(|value| value.checked_add(if cut { 11 } else { 3 }))
    else {
        return false;
    };
    let mut output = Vec::new();
    if output.try_reserve_exact(capacity).is_err() {
        return false;
    }
    let bytes = unsafe { slice::from_raw_parts(data, size) };
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        output.extend_from_slice(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize], b' ']);
    }
    if cut {
        output.extend_from_slice(b"... ");
    }
    output.extend_from_slice(b": ");
    for &byte in bytes {
        output.push(if (0x20..=0x7f).contains(&byte) {
            byte
        } else {
            b'.'
        });
    }
    if cut {
        output.extend_from_slice(b" ...");
    }
    output.push(0);
    unsafe { writer(output.as_ptr().cast()) };
    true
}
