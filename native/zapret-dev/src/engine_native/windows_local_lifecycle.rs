//! Windows command-line cleanup and termination.
#![no_std]

use core::ffi::{c_char, c_int, c_void};

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

unsafe extern "C" {
    static mut params: c_void;

    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn zapret_profile_report_status(status: u32, name: *const c_char, error: Log) -> bool;
    fn zapret_crt_close_std_and_exit(code: c_int) -> !;
    fn exithelp() -> !;
}

unsafe extern "C-unwind" {
    // Cleanup can run LuaJIT code using the pinned Win64 SEH ABI.
    fn cleanup_params(params: *mut c_void);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn exit_clean(code: c_int) -> ! {
    unsafe {
        cleanup_params(&raw mut params);
        zapret_crt_close_std_and_exit(code)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn exithelp_clean() -> ! {
    unsafe {
        cleanup_params(&raw mut params);
        exithelp()
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_profile_exit(status: u32, name: *const c_char) {
    if unsafe { zapret_profile_report_status(status, name, DLOG_ERR) } {
        unsafe { exit_clean(1) };
    }
}
