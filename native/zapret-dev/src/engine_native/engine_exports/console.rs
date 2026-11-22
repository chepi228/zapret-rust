//! Connect Windows and CRT console callbacks to the engine's Rust shutdown path.
use super::{DLOG_ERR, Log};
use crate::{QUIT, zapret_lua_vm_request_quit};
use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem::MaybeUninit,
    sync::atomic::AtomicI32,
};

type Signal = unsafe extern "C" fn(c_int);
type Control = unsafe extern "system" fn(u32) -> c_int;

#[repr(C)]
struct Ops {
    console: unsafe extern "system" fn(Option<Control>, c_int) -> c_int,
    signal: unsafe extern "C" fn(c_int, Signal) -> usize,
}

#[repr(C)]
struct Message {
    text: *const c_char,
    length: usize,
}

unsafe extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<Control>, install: c_int) -> c_int;
}

unsafe extern "C" {
    // The CRT returns a handler or the integer SIG_ERR encoded as a pointer.
    fn signal(event: c_int, handler: Signal) -> usize;
    fn write(descriptor: c_int, bytes: *const c_void, count: c_uint) -> c_int;
    fn zapret_engine_console_register(quit: Signal, ops: *const Ops, error: Log) -> bool;
    fn zapret_console_claim_shutdown(
        quit: *const AtomicI32,
        event: c_int,
        output: *mut Message,
    ) -> bool;
}

unsafe extern "C" fn console_quit(event: c_int) {
    let mut message = MaybeUninit::uninit();
    unsafe {
        if zapret_console_claim_shutdown(&raw const QUIT, event, message.as_mut_ptr()) {
            let message = message.assume_init();
            write(1, message.text.cast(), message.length as c_uint);
            // Requests interruption. The Lua hook raises errors on the VM frame.
            zapret_lua_vm_request_quit();
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn catch_signals() {
    const OPS: Ops = Ops {
        console: SetConsoleCtrlHandler,
        signal,
    };
    unsafe { zapret_engine_console_register(console_quit, &OPS, DLOG_ERR) };
}
