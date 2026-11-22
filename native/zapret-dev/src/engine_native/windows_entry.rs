//! Engine-only entry object. The shared Rust library also links into C fixtures.
#![no_std]

mod engine_exports;

use core::{
    ffi::{c_char, c_int},
    sync::atomic::Ordering,
};
use engine_exports::QUIT;

type EngineMain = unsafe extern "C-unwind" fn(c_int, *mut *mut c_char) -> c_int;

unsafe extern "C-unwind" {
    fn zapret_engine_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn zapret_native_start(argc: c_int, wide_argv: *const *const u16, engine: EngineMain) -> c_int;
    fn zapret_native_service_dispatch(
        argc: c_int,
        argv: *mut *mut c_char,
        engine: EngineMain,
        quit: unsafe extern "C" fn(),
    ) -> bool;
}

unsafe extern "C" {
    fn zapret_lua_vm_request_quit();
}
/// # Safety
/// The Windows CRT supplies the UTF-16 argument vector.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn wmain(argc: c_int, argv: *const *const u16) -> c_int {
    unsafe { zapret_native_start(argc, argv, zapret_engine_main) }
}

unsafe extern "C" fn service_quit() {
    unsafe {
        QUIT.store(1, Ordering::Release);
        zapret_lua_vm_request_quit();
    }
}

/// # Safety
/// The engine supplies its live argument vector until service dispatch returns.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn service_run(argc: c_int, argv: *mut *mut c_char) -> bool {
    unsafe { zapret_native_service_dispatch(argc, argv, zapret_engine_main, service_quit) }
}
