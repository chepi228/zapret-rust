//! Bind the MinGW variadic entries to the live Rust logger.
#![no_std]

use core::{
    ffi::{VaList, c_char, c_int, c_void},
    ptr,
};

#[cfg(not(all(
    windows,
    any(target_arch = "x86", target_arch = "x86_64"),
    target_env = "gnu"
)))]
compile_error!("The logging entries require the MinGW x86 or x64 variadic ABI");

mod windows_startup_params;
use windows_startup_params::PARAMS as LAYOUT;

const LOG_ERR: c_int = 3;
const LOG_DEBUG: c_int = 7;

type Writer = unsafe extern "C" fn(c_int, *const c_char);

#[repr(C, align(8))]
struct Params([u8; LAYOUT.size]);

#[repr(C)]
struct LogRoute {
    debug: *const bool,
    target: *const c_int,
    buffer: unsafe extern "C" fn(Writer, c_int, *const c_char, VaList<'_>),
    file: Writer,
    event: Writer,
}

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<VaList<'_>>() == pointer && align_of::<VaList<'_>>() == pointer);
    assert!(size_of::<LogRoute>() == 5 * pointer);
};

unsafe extern "C" {
    #[link_name = "params"]
    static mut PARAMS: Params;

    fn zapret_crt_log_buffered(
        writer: Writer,
        priority: c_int,
        format: *const c_char,
        args: VaList<'_>,
    );
    fn zapret_crt_log_line(path: *const c_char, line: *const c_char, io: *const c_void);
    fn zapret_crt_log_dispatch(
        format: *const c_char,
        priority: c_int,
        duplicate: bool,
        args: VaList<'_>,
        route: &LogRoute,
        io: *const c_void,
    ) -> c_int;
    fn zapret_crt_log_path(
        path: *const c_char,
        format: *const c_char,
        args: VaList<'_>,
        timestamp: bool,
        io: *const c_void,
    ) -> c_int;
    fn zapret_log_path_enabled(path: *const c_char) -> bool;
    fn zapret_system_syslog(priority: c_int, line: *const c_char);
}

const PARAMS_ADDRESS: *const u8 = (&raw const PARAMS).cast();
const ROUTE: LogRoute = LogRoute {
    debug: PARAMS_ADDRESS.wrapping_add(LAYOUT.debug).cast(),
    target: PARAMS_ADDRESS.wrapping_add(LAYOUT.debug_target).cast(),
    buffer: zapret_crt_log_buffered,
    file: file_writer,
    event: zapret_system_syslog,
};

unsafe extern "C" fn file_writer(_priority: c_int, line: *const c_char) {
    // The live path can change before the formatter emits each line.
    unsafe {
        zapret_crt_log_line(
            PARAMS_ADDRESS.wrapping_add(LAYOUT.debug_logfile).cast(),
            line,
            ptr::null(),
        )
    };
}

#[unsafe(export_name = "DLOG")]
unsafe extern "C" fn debug_log(format: *const c_char, args: ...) -> c_int {
    unsafe { zapret_crt_log_dispatch(format, LOG_DEBUG, false, args, &ROUTE, ptr::null()) }
}

#[unsafe(export_name = "DLOG_CONDUP")]
unsafe extern "C" fn duplicate_debug_log(format: *const c_char, args: ...) -> c_int {
    unsafe { zapret_crt_log_dispatch(format, LOG_DEBUG, true, args, &ROUTE, ptr::null()) }
}

#[unsafe(export_name = "DLOG_ERR")]
unsafe extern "C" fn error_log(format: *const c_char, args: ...) -> c_int {
    unsafe { zapret_crt_log_dispatch(format, LOG_ERR, true, args, &ROUTE, ptr::null()) }
}

#[unsafe(export_name = "HOSTLIST_DEBUGLOG_APPEND")]
unsafe extern "C" fn append_hostlist_log(format: *const c_char, args: ...) -> c_int {
    let path = PARAMS_ADDRESS.wrapping_add(LAYOUT.auto_hostlist_log).cast();
    unsafe {
        if !zapret_log_path_enabled(path) {
            return 0;
        }
        zapret_crt_log_path(path, format, args, true, ptr::null())
    }
}
