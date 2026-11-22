//! Startup policy linked into the pinned Cygwin x64 engine.
#![no_std]

use core::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64", target_env = "gnu")))]
compile_error!("The Cygwin startup entries require the Windows x64 GNU target");

const CONTINUE_STARTUP: c_int = -1;
const ERROR_ACCESS_DENIED: c_int = 5;
const ERROR_INVALID_PARAMETER: c_int = 87;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

unsafe extern "C" {
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn getenv(name: *const c_char) -> *const c_char;
    fn win_sandbox() -> bool;
}

unsafe extern "C-unwind" {
    fn luaL_openlibs(state: *mut LuaState);
    fn rust_ring_register(state: *mut LuaState) -> c_int;
    fn lua_close(state: *mut LuaState);
    fn lua_init() -> bool;
    #[link_name = "NoInterceptLoop"]
    fn idle_loop();
}

#[unsafe(no_mangle)]
extern "C" fn zapret_cygwin_alloc_filter(capacity: usize) -> *mut c_void {
    // The upstream engine releases this buffer with its own Cygwin allocator.
    unsafe { calloc(1, capacity) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_cygwin_openlibs(slot: *mut *mut LuaState) -> bool {
    unsafe {
        let state = slot.read();
        luaL_openlibs(state);
        if rust_ring_register(state) != 0 {
            return true;
        }
        lua_close(state);
        slot.write(ptr::null_mut());
        false
    }
}

#[unsafe(no_mangle)]
extern "C-unwind" fn zapret_cygwin_selftest(intercept: bool) -> c_int {
    let setting = unsafe { getenv(c"ZAPRET_RING_SELFTEST".as_ptr()) };
    if intercept || setting.is_null() || unsafe { CStr::from_ptr(setting) } != c"1" {
        return CONTINUE_STARTUP;
    }
    if !unsafe { win_sandbox() } {
        return ERROR_ACCESS_DENIED;
    }
    if !unsafe { lua_init() } {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { idle_loop() };
    0
}
