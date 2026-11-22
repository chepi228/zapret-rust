//! Native entry ordering; VM calls and driver buffers remain in C adapters.
pub(crate) mod ucrt;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER, ERROR_TOO_MANY_OPEN_FILES,
};
#[repr(C)]
struct Input {
    daemon: bool,
    pid: bool,
    intercept: bool,
}
#[repr(C)]
struct Ops {
    daemon: unsafe extern "C" fn(),
    pid: unsafe extern "C" fn() -> bool,
    selftest: unsafe extern "C" fn() -> bool,
    sandbox: unsafe extern "C" fn() -> bool,
    lua: unsafe extern "C-unwind" fn() -> bool,
    idle: unsafe extern "C-unwind" fn(),
    network: unsafe extern "C" fn() -> bool,
    error: unsafe extern "C" fn() -> u32,
    capture: unsafe extern "C-unwind" fn() -> i32,
    network_destroy: unsafe extern "C" fn(),
    lua_destroy: unsafe extern "C-unwind" fn(),
    raw_destroy: unsafe extern "C" fn(),
    report: unsafe extern "C" fn(u32, u32),
}
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_engine_bootstrap(input: *const Input, ops: *const Ops) -> i32 {
    if input.is_null() || ops.is_null() {
        return ERROR_INVALID_PARAMETER as i32;
    }
    let input = unsafe { &*input };
    let ops = unsafe { &*ops };
    if input.daemon {
        unsafe { (ops.daemon)() };
    }
    if input.pid && !unsafe { (ops.pid)() } {
        unsafe { (ops.report)(0, ERROR_TOO_MANY_OPEN_FILES) };
        return ERROR_TOO_MANY_OPEN_FILES as i32;
    }
    let selftest = unsafe { (ops.selftest)() };
    if !input.intercept && selftest {
        if !unsafe { (ops.sandbox)() } {
            return ERROR_ACCESS_DENIED as i32;
        }
        if !unsafe { (ops.lua)() } {
            return ERROR_INVALID_PARAMETER as i32;
        }
        unsafe { (ops.idle)() };
        return 0;
    }
    let result = if unsafe { (ops.network)() } {
        unsafe { (ops.capture)() }
    } else {
        let mut error = unsafe { (ops.error)() };
        if error == 0 {
            error = ERROR_GEN_FAILURE;
        }
        unsafe { (ops.report)(1, error) };
        error as i32
    };
    // Matches the existing cleanup order, including failed partial initialization.
    unsafe {
        (ops.network_destroy)();
        (ops.lua_destroy)();
        (ops.raw_destroy)();
    }
    result
}
const _: () = {
    assert!(size_of::<Input>() == 3);
    assert!(size_of::<Ops>() == 13 * size_of::<usize>());
    assert!(std::mem::offset_of!(Ops, report) == 12 * size_of::<usize>());
};
