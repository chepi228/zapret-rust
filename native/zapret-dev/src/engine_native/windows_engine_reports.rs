//! Bind the live Windows log sinks to the engine's read-only reporters.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
};

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Perror = unsafe extern "C" fn(*const c_char) -> c_int;

#[repr(C)]
struct ParamsPrefix {
    _before_debug: [MaybeUninit<u8>; PARAMS.debug],
    debug: bool,
}

#[repr(C)]
struct AutolistSinks {
    debug: Log,
    error: Log,
    append: Log,
    perror: Perror,
}

const _: () = {
    assert!(core::mem::offset_of!(ParamsPrefix, debug) == PARAMS.debug);
    assert!(size_of::<AutolistSinks>() == 4 * size_of::<usize>());
};

unsafe extern "C" {
    static mut params: ParamsPrefix;

    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn HOSTLIST_DEBUGLOG_APPEND(format: *const c_char, ...) -> c_int;
    fn DLOG_PERROR(text: *const c_char) -> c_int;
    fn wf_error(error: u32);

    fn zapret_capture_prepare_report(
        event: u32,
        size: usize,
        text: *const c_char,
        debug: Log,
        error: Log,
    );
    fn zapret_capture_prepare_status(
        status: u32,
        error: u32,
        save: *const c_char,
        log: Log,
        publish: unsafe extern "C" fn(u32),
    );
    fn zapret_capture_loop_report(
        event: u32,
        id: u32,
        length: usize,
        other: usize,
        debug: Log,
        error: Log,
        console: Log,
    );
    fn zapret_packet_cache_report(
        context: *const c_void,
        event: u32,
        item: *const c_void,
        debug_enabled: bool,
        debug: Log,
        error: Log,
    );
    fn zapret_reassembly_report(
        event: u32,
        first: usize,
        second: usize,
        third: usize,
        debug: Log,
        error: Log,
    );
    fn zapret_autolist_report(
        event: u32,
        context: *const c_void,
        a: u64,
        b: u64,
        d: u64,
        e: u64,
        sinks: &AutolistSinks,
    );
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_capture_prepare_report(event: u32, size: usize, text: *const c_char) {
    unsafe { zapret_capture_prepare_report(event, size, text, DLOG, DLOG_ERR) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_capture_prepare_status(status: u32, error: u32, save: *const c_char) {
    unsafe { zapret_capture_prepare_status(status, error, save, DLOG_ERR, wf_error) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn loop_report(event: u32, id: u32, length: usize, other: usize) {
    unsafe { zapret_capture_loop_report(event, id, length, other, DLOG, DLOG_ERR, DLOG_CONDUP) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn packet_cache_report(context: *mut c_void, event: u32, item: *const c_void) {
    unsafe { zapret_packet_cache_report(context, event, item, params.debug, DLOG, DLOG_ERR) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn reassembly_report(event: u32, first: usize, second: usize, third: usize) {
    unsafe { zapret_reassembly_report(event, first, second, third, DLOG, DLOG_ERR) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn autolist_report(
    event: u32,
    context: *const c_void,
    a: u64,
    b: u64,
    d: u64,
    e: u64,
) {
    const SINKS: AutolistSinks = AutolistSinks {
        debug: DLOG,
        error: DLOG_ERR,
        append: HOSTLIST_DEBUGLOG_APPEND,
        perror: DLOG_PERROR,
    };
    unsafe { zapret_autolist_report(event, context, a, b, d, e, &SINKS) };
}
