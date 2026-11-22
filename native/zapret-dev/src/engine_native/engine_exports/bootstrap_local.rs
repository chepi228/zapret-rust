//! Bind the bootstrap's local state, diagnostics and console banner.
use super::{
    DLOG_ERR, Log,
    startup_params::PARAMS,
    state::{WIN32_ERROR, params_address},
};
use core::ffi::{c_char, c_int};

const VERSION_CAPACITY: usize = 128;

unsafe extern "C" {
    fn writepid(filename: *const c_char) -> bool;
    fn wf_getenv(name: *const c_char) -> *mut c_char;
    fn __mingw_printf(format: *const c_char, ...) -> c_int;
    fn zapret_engine_version(
        output: *mut c_char,
        capacity: usize,
        pinned: bool,
        version: *const c_char,
        revision: *const c_char,
        lua_compat: u32,
        print: Log,
    );
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_boot_pid() -> bool {
    // engine_bootstrap_local_abi.h checks the borrowed PID path slot.
    unsafe { writepid(params_address().add(PARAMS.pidfile).cast()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_boot_selftest() -> bool {
    unsafe {
        let value = wf_getenv(c"ZAPRET_RING_SELFTEST".as_ptr());
        !value.is_null() && value.read() == b'1' as c_char && value.add(1).read() == 0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_boot_error() -> u32 {
    unsafe { (&raw const WIN32_ERROR).read() }
}

#[unsafe(no_mangle)]
extern "C" fn native_boot_report(event: u32, error: u32) {
    unsafe {
        if event == 0 {
            DLOG_ERR(c"could not write pidfile".as_ptr());
        } else {
            DLOG_ERR(
                c"win_dark_init failed. win32 error %u (0x%08X)\n".as_ptr(),
                error,
                error,
            );
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_main_version(
    pinned: bool,
    version: *const c_char,
    revision: *const c_char,
    lua_compat: u32,
) {
    // engine_banner_abi.h verifies the output slot and supplies build metadata.
    unsafe {
        zapret_engine_version(
            params_address().add(PARAMS.version).cast(),
            VERSION_CAPACITY,
            pinned,
            version,
            revision,
            lua_compat,
            __mingw_printf,
        );
    }
}
