//! Bind the read-only NLM report to the engine's UCRT stdout.
#![no_std]

use core::ffi::{c_uint, c_void};

type Write = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> bool;

unsafe extern "C" {
    static mut w_win32_error: u32;
    fn __acrt_iob_func(descriptor: c_uint) -> *mut c_void;
    fn fwrite(buffer: *const c_void, size: usize, count: usize, stream: *mut c_void) -> usize;
    fn zapret_network_environment_list(
        all: bool,
        stream: *mut c_void,
        write: Write,
        error: *mut u32,
    ) -> bool;
}

unsafe extern "C" fn write_stream(stream: *mut c_void, bytes: *const u8, count: usize) -> bool {
    unsafe { fwrite(bytes.cast(), 1, count, stream) == count }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn nlm_list(all: bool) -> bool {
    unsafe {
        zapret_network_environment_list(
            all,
            __acrt_iob_func(1),
            write_stream,
            &raw mut w_win32_error,
        )
    }
}
