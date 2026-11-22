//! FILE and routing over the pinned MinGW UCRT logging ABI.
use super::zapret_log_console_error;
use crate::logging::{Writer, zapret_log_buffer};
use libc::FILE;
use std::{
    ffi::{c_char, c_int, c_uint},
    mem::MaybeUninit,
};

// Checked by native_logging_stdio_abi.h. The caller owns the variadic frame.
// MinGW passes this cursor by value on x86 and x64, so duplicate writes can reuse it.
type VaList = *mut c_char;
type Buffer = unsafe extern "C" fn(Writer, c_int, *const c_char, VaList);

unsafe extern "C" {
    fn __acrt_iob_func(index: c_uint) -> *mut FILE;
    fn __mingw_vfprintf(file: *mut FILE, format: *const c_char, args: VaList) -> c_int;
    fn __mingw_fprintf(file: *mut FILE, format: *const c_char, ...) -> c_int;
    fn __mingw_vsnprintf(
        output: *mut c_char,
        size: usize,
        format: *const c_char,
        args: VaList,
    ) -> c_int;
    fn wf_fopen(path: *const c_char, mode: *const c_char) -> *mut FILE;
    fn zapret_crt_fprint_localtime(file: *mut FILE) -> c_int;
}

#[repr(C)]
struct LogIo {
    stream: unsafe extern "C" fn(c_uint) -> *mut FILE,
    open: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut FILE,
    vprint: unsafe extern "C" fn(*mut FILE, *const c_char, VaList) -> c_int,
    print: unsafe extern "C" fn(*mut FILE, *const c_char, ...) -> c_int,
    timestamp: unsafe extern "C" fn(*mut FILE) -> c_int,
    close: unsafe extern "C" fn(*mut FILE) -> c_int,
}

const UCRT: LogIo = LogIo {
    stream: __acrt_iob_func,
    open: wf_fopen,
    vprint: __mingw_vfprintf,
    print: __mingw_fprintf,
    timestamp: zapret_crt_fprint_localtime,
    close: libc::fclose,
};

#[repr(C)]
struct LogRoute {
    debug: *const bool,
    target: *const c_int,
    buffer: Buffer,
    file: Writer,
    event: Writer,
}

unsafe fn print_console(format: *const c_char, priority: c_int, args: VaList, io: &LogIo) -> c_int {
    let stream = if zapret_log_console_error(priority) {
        2
    } else {
        1
    };
    unsafe { (io.vprint)((io.stream)(stream), format, args) }
}

unsafe fn write_path(
    io: &LogIo,
    path: *const c_char,
    write: impl FnOnce(*mut FILE) -> c_int,
) -> c_int {
    let file = unsafe { (io.open)(path, c"at".as_ptr()) };
    if file.is_null() {
        return -1;
    }
    let result = write(file);
    unsafe { (io.close)(file) };
    result
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_file(
    file: *mut FILE,
    format: *const c_char,
    args: VaList,
    io: *const LogIo,
) -> c_int {
    let io = unsafe { io.as_ref() }.unwrap_or(&UCRT);
    unsafe { (io.vprint)(file, format, args) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_console(
    format: *const c_char,
    priority: c_int,
    args: VaList,
    io: *const LogIo,
) -> c_int {
    unsafe { print_console(format, priority, args, io.as_ref().unwrap_or(&UCRT)) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_path(
    path: *const c_char,
    format: *const c_char,
    args: VaList,
    timestamp: bool,
    io: *const LogIo,
) -> c_int {
    let io = unsafe { io.as_ref() }.unwrap_or(&UCRT);
    unsafe {
        write_path(io, path, |file| {
            if timestamp {
                (io.timestamp)(file);
                (io.print)(file, c" : ".as_ptr());
            }
            let result = (io.vprint)(file, format, args);
            if timestamp {
                (io.print)(file, c"\n".as_ptr());
            }
            result
        })
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_line(
    path: *const c_char,
    line: *const c_char,
    io: *const LogIo,
) {
    let io = unsafe { io.as_ref() }.unwrap_or(&UCRT);
    unsafe { write_path(io, path, |file| (io.print)(file, c"%s".as_ptr(), line)) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_buffered(
    writer: Writer,
    priority: c_int,
    format: *const c_char,
    args: VaList,
) {
    let mut text = MaybeUninit::<[c_char; 4095]>::uninit();
    let output = text.as_mut_ptr().cast::<c_char>();
    unsafe {
        if __mingw_vsnprintf(output, 4095, format, args) > 0 {
            zapret_log_buffer(output, libc::strlen(output), priority, writer);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_log_dispatch(
    format: *const c_char,
    priority: c_int,
    duplicate: bool,
    args: VaList,
    route: &LogRoute,
    io: *const LogIo,
) -> c_int {
    let io = unsafe { io.as_ref() }.unwrap_or(&UCRT);
    unsafe {
        if duplicate && !(route.debug.read() && route.target.read() == 0) {
            print_console(format, priority, args, io);
        }
        // A console write can change logging configuration. Read it again.
        if !route.debug.read() {
            return 0;
        }
        let writer = match route.target.read() {
            0 => return print_console(format, priority, args, io),
            1 => route.file,
            2 => route.event,
            _ => return 0,
        };
        (route.buffer)(writer, priority, format, args);
    }
    1
}

const _: () = {
    let pointer = size_of::<*const c_char>();
    assert!(size_of::<VaList>() == pointer);
    assert!(size_of::<LogIo>() == 6 * pointer);
    assert!(size_of::<LogRoute>() == 5 * pointer);
};
