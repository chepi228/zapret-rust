//! Bind the Windows main entry to the engine's existing startup policy.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, any(target_arch = "x86", target_arch = "x86_64"))))]
compile_error!("The bootstrap entry requires the Windows x86 or x64 ABI");

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

#[repr(C, align(8))]
struct Params {
    before_daemon: [MaybeUninit<u8>; PARAMS.daemon],
    daemon: bool,
    intercept: bool,
    before_pid: [MaybeUninit<u8>; PARAMS.pidfile - PARAMS.intercept - 1],
    first_pid_byte: c_char,
    remaining: [MaybeUninit<u8>; PARAMS.size - PARAMS.pidfile - 1],
}

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
    capture: unsafe extern "C-unwind" fn() -> c_int,
    network_destroy: unsafe extern "C" fn(),
    lua_destroy: unsafe extern "C-unwind" fn(),
    raw_destroy: unsafe extern "C" fn(),
    report: unsafe extern "C" fn(u32, u32),
}

const _: () = {
    assert!(size_of::<Params>() == PARAMS.size);
    assert!(offset_of!(Params, daemon) == PARAMS.daemon);
    assert!(offset_of!(Params, intercept) == PARAMS.intercept);
    assert!(offset_of!(Params, first_pid_byte) == PARAMS.pidfile);
    assert!(size_of::<Input>() == 3);
    let pointer = size_of::<usize>();
    assert!(size_of::<Ops>() == 13 * pointer);
    assert!(offset_of!(Ops, capture) == 8 * pointer);
    assert!(offset_of!(Ops, report) == 12 * pointer);
};

unsafe extern "C" {
    static mut params: Params;
    fn daemonize();
    fn native_boot_pid() -> bool;
    fn native_boot_selftest() -> bool;
    fn win_sandbox() -> bool;
    fn native_boot_network() -> bool;
    fn native_boot_error() -> u32;
    fn win_dark_deinit();
    fn rawsend_cleanup();
    fn native_boot_report(event: u32, error: u32);
}

unsafe extern "C-unwind" {
    fn zapret_engine_bootstrap(input: *const Input, ops: *const Ops) -> c_int;
    fn lua_init() -> bool;
    #[link_name = "NoInterceptLoop"]
    fn idle_loop();
    fn native_boot_capture() -> c_int;
    fn lua_shutdown();
}

static BOOT_OPS: Ops = Ops {
    daemon: daemonize,
    pid: native_boot_pid,
    selftest: native_boot_selftest,
    sandbox: win_sandbox,
    lua: lua_init,
    idle: idle_loop,
    network: native_boot_network,
    error: native_boot_error,
    capture: native_boot_capture,
    network_destroy: win_dark_deinit,
    lua_destroy: lua_shutdown,
    raw_destroy: rawsend_cleanup,
    report: native_boot_report,
};

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn win_main() -> c_int {
    unsafe {
        // These flags are fixed before daemon and environment callbacks. The
        // PID and capture callbacks still read their current native fields.
        let input = Input {
            daemon: (&raw const params.daemon).read(),
            pid: (&raw const params.first_pid_byte).read() != 0,
            intercept: (&raw const params.intercept).read(),
        };
        zapret_engine_bootstrap(&input, &BOOT_OPS)
    }
}
