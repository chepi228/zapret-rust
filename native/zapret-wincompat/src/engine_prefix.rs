//! Startup order, default blobs and capture activation for the native engine.
use crate::{
    logging::LogSink,
    text_buffer::{TextBuffer, decimal},
};
use std::ffi::{CStr, c_char, c_void};

const BLOB_MAXIMUM: usize = 16 * 1024;
const TLS_RESERVE: usize = 128;
const CAPTURE_CAPACITY: usize = 65536;
const DEFAULT_QUIC: [u8; 620] = {
    let mut packet = [0; 620];
    packet[0] = 0x40;
    packet
};

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_version(
    output: *mut c_char,
    capacity: usize,
    pinned: bool,
    version: *const c_char,
    revision: *const c_char,
    lua_compat: u32,
    print: LogSink,
) {
    if let Some(mut buffer) = unsafe { TextBuffer::new(output, capacity) } {
        buffer.bytes(if pinned {
            b"github version "
        } else {
            b"self-built version "
        });
        buffer.bytes(unsafe { CStr::from_ptr(version) }.to_bytes());
        buffer.bytes(if pinned { b" (" } else { b" " });
        buffer.bytes(unsafe { CStr::from_ptr(revision) }.to_bytes());
        buffer.bytes(if pinned {
            b") lua_compat_ver "
        } else {
            b" lua_compat_ver "
        });
        buffer.bytes(decimal(lua_compat, &mut [0; 10]));
    }
    unsafe { print(c"%s\n\n".as_ptr(), output) };
}

type PublishBlob =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void, usize, usize) -> *mut c_void;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_default_blobs(
    collection: *mut c_void,
    tls: *const u8,
    tls_length: usize,
    http_slot: *const *const c_char,
    publish: PublishBlob,
) -> bool {
    let add = |name: &CStr, data: *const c_void, length: usize, reserve| {
        !unsafe { publish(collection, name.as_ptr(), data, length, reserve) }.is_null()
    };
    if !add(c"fake_default_tls", tls.cast(), tls_length, TLS_RESERVE) {
        return false;
    }
    // The TLS publication can change the borrowed HTTP source.
    let http = unsafe { http_slot.read() };
    let http_length = unsafe { CStr::from_ptr(http) }.to_bytes().len();
    add(c"fake_default_http", http.cast(), http_length, 0)
        && add(
            c"fake_default_quic",
            DEFAULT_QUIC.as_ptr().cast(),
            DEFAULT_QUIC.len(),
            0,
        )
}

#[repr(C)]
pub(super) struct BlobLimits {
    pub(super) maximum: usize,
    pub(super) reserve: usize,
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_engine_blob_limits(index: i32) -> BlobLimits {
    if index == 17 {
        BlobLimits {
            maximum: BLOB_MAXIMUM,
            reserve: TLS_RESERVE,
        }
    } else {
        BlobLimits {
            maximum: 0,
            reserve: 0,
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_capture_capacity() -> usize {
    CAPTURE_CAPACITY
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_engine_parse_failure(dry_run: bool) -> u32 {
    if dry_run { 1 } else { 2 }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_prefix_next(
    previous: u32,
    available: bool,
    argc: i32,
    first: u8,
    error: LogSink,
) -> u32 {
    match previous {
        0 => 1,
        1 if available => 2,
        1 => 3,
        3 => 4,
        4 => 5,
        5 if argc < 2 => 6,
        5 | 6 => 7,
        7..=13 => previous + 1,
        14 if argc >= 2 => 15,
        15 if matches!(first, b'@' | b'$') => 16,
        14..=16 => 17,
        17 if available => 18,
        18 if available => 20,
        17 | 18 => {
            unsafe { error(c"out of memory\n".as_ptr()) };
            19
        }
        _ => 0,
    }
}

#[repr(C)]
struct ActivateOps {
    open: unsafe extern "C" fn(*const c_char) -> bool,
    sandbox: unsafe extern "C" fn() -> bool,
    console: LogSink,
    error: LogSink,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_activate_native(
    filter: *const c_char,
    intercept: *const bool,
    win32_error: *const u32,
    error: *mut u32,
    ops: &ActivateOps,
) -> bool {
    unsafe {
        if !(ops.open)(filter) {
            error.write(win32_error.read());
            return false;
        }
        // The driver callback can change capture mode before the message.
        let ready = if intercept.read() {
            c"windivert initialized. capture is started.\n"
        } else {
            c"windivert initialized\n"
        };
        (ops.console)(ready.as_ptr());
        if !(ops.sandbox)() {
            error.write(win32_error.read());
            (ops.error)(c"Cannot init Windows sandbox\n".as_ptr());
            return false;
        }
    }
    true
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_activate_next(previous: u32, succeeded: bool) -> u32 {
    match previous {
        0 => 1,
        1 | 2 if succeeded => 4,
        1 => 2,
        2 => 3,
        4 => 5,
        _ => 0,
    }
}
