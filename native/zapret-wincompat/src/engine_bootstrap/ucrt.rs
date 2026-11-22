//! Standard streams and calendar conversion using the engine's UCRT.
use crate::native_logging_entry::zapret_log_timestamp;
use libc::{FILE, tm};
use std::{
    ffi::{c_char, c_int, c_uint},
    mem::MaybeUninit,
    ptr,
};
use windows_sys::{Win32::Foundation::ERROR_INVALID_HANDLE, w};

type SetMode = unsafe extern "C" fn(c_int, c_int) -> c_int;
type ReopenStream = unsafe extern "C" fn(c_int, *const u16, *const u16) -> *mut FILE;

// The engine's UCRT build uses 64-bit time_t on Win32 as well as Win64.
pub(crate) type Time = i64;

unsafe extern "C" {
    fn _setmode(descriptor: c_int, mode: c_int) -> c_int;
    fn __acrt_iob_func(index: c_uint) -> *mut FILE;
    fn _wfreopen(path: *const u16, mode: *const u16, stream: *mut FILE) -> *mut FILE;
    pub(crate) fn _errno() -> *mut c_int;
    fn _gmtime64_s(output: *mut tm, value: *const Time) -> c_int;
    fn _localtime64_s(output: *mut tm, value: *const Time) -> c_int;
    fn _time64(output: *mut Time) -> Time;
}

unsafe extern "C" fn reopen_standard_stream(
    descriptor: c_int,
    path: *const u16,
    mode: *const u16,
) -> *mut FILE {
    unsafe { _wfreopen(path, mode, __acrt_iob_func(descriptor as c_uint)) }
}

pub(crate) unsafe fn configure_standard_stream(
    descriptor: c_int,
    use_null: bool,
) -> Result<(), c_int> {
    unsafe { configure_stream(descriptor, use_null, _setmode, reopen_standard_stream) }
}

unsafe fn configure_stream(
    descriptor: c_int,
    use_null: bool,
    set_mode: SetMode,
    reopen: ReopenStream,
) -> Result<(), c_int> {
    let ok = if use_null {
        let mode = if descriptor == 0 { w!("rb") } else { w!("wb") };
        !unsafe { reopen(descriptor, w!("NUL"), mode) }.is_null()
    } else {
        unsafe { set_mode(descriptor, libc::O_BINARY) >= 0 }
    };
    if ok {
        Ok(())
    } else {
        Err(ERROR_INVALID_HANDLE as c_int)
    }
}

type CalendarConvert = unsafe extern "C" fn(*mut tm, *const Time) -> c_int;
unsafe fn calendar(value: *const Time, output: *mut tm, convert: CalendarConvert) -> *mut tm {
    if value.is_null() || output.is_null() {
        unsafe { _errno().write(libc::EINVAL) };
        return ptr::null_mut();
    }
    if unsafe { convert(output, value) } == 0 {
        output
    } else {
        ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_localtime_r(value: *const Time, output: *mut tm) -> *mut tm {
    unsafe { calendar(value, output, _localtime64_s) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_gmtime_r(value: *const Time, output: *mut tm) -> *mut tm {
    unsafe { calendar(value, output, _gmtime64_s) }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_crt_set_console_io_buffering() {
    for descriptor in [1, 2] {
        unsafe {
            libc::setvbuf(
                __acrt_iob_func(descriptor),
                ptr::null_mut(),
                libc::_IOLBF,
                0,
            )
        };
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_crt_close_std() {
    for descriptor in [1, 2] {
        unsafe { libc::fclose(__acrt_iob_func(descriptor)) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_crt_close_std_and_exit(code: c_int) -> ! {
    zapret_crt_close_std();
    unsafe { libc::exit(code) };
}

type TimestampWrite = unsafe extern "C" fn(*mut FILE, *const c_char) -> c_int;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_log_write_timestamp(
    file: *mut FILE,
    fields: *const i32,
    write: TimestampWrite,
    abort: unsafe extern "C" fn() -> !,
) -> c_int {
    let mut text = [0; 64];
    if !unsafe { zapret_log_timestamp(fields, text.as_mut_ptr(), text.len()) } {
        unsafe { abort() };
    }
    unsafe { write(file, text.as_ptr().cast()) }
}

unsafe extern "C" fn print_timestamp(file: *mut FILE, text: *const c_char) -> c_int {
    unsafe { libc::fprintf(file, c"%s".as_ptr(), text) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_fprint_localtime(file: *mut FILE) -> c_int {
    let now = unsafe { _time64(ptr::null_mut()) };
    let mut value = MaybeUninit::<tm>::uninit();
    if unsafe { zapret_localtime_r(&now, value.as_mut_ptr()) }.is_null() {
        return -1;
    }
    let value = unsafe { value.assume_init() };
    let fields = [
        value.tm_mday,
        value.tm_mon,
        value.tm_year,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
    ];
    unsafe { zapret_log_write_timestamp(file, fields.as_ptr(), print_timestamp, libc::abort) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        SetMode(c_int, c_int),
        Reopen(c_int, *const u16, *const u16),
    }

    thread_local! {
        static CALLS: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    unsafe extern "C" fn set_mode(descriptor: c_int, mode: c_int) -> c_int {
        CALLS.with_borrow_mut(|calls| calls.push(Call::SetMode(descriptor, mode)));
        if FAIL.get() { -1 } else { libc::O_TEXT }
    }

    unsafe extern "C" fn reopen(
        descriptor: c_int,
        path: *const u16,
        mode: *const u16,
    ) -> *mut FILE {
        CALLS.with_borrow_mut(|calls| calls.push(Call::Reopen(descriptor, path, mode)));
        if FAIL.get() {
            ptr::null_mut()
        } else {
            ptr::dangling_mut()
        }
    }

    #[test]
    fn standard_stream_modes_and_native_failures() {
        for descriptor in 0..3 {
            for failure in [false, true] {
                FAIL.set(failure);
                let expected = if failure {
                    Err(ERROR_INVALID_HANDLE as c_int)
                } else {
                    Ok(())
                };
                assert_eq!(
                    unsafe { configure_stream(descriptor, false, set_mode, reopen) },
                    expected
                );
                assert_eq!(CALLS.take(), [Call::SetMode(descriptor, libc::O_BINARY)]);
                assert_eq!(
                    unsafe { configure_stream(descriptor, true, set_mode, reopen) },
                    expected
                );
                let calls = CALLS.take();
                let [Call::Reopen(actual, path, mode)] = calls.as_slice() else {
                    panic!("The original stream was not reopened");
                };
                assert_eq!(*actual, descriptor);
                let expected_mode = if descriptor == 0 { "rb\0" } else { "wb\0" };
                for (pointer, text) in [(*path, "NUL\0"), (*mode, expected_mode)] {
                    assert!(!pointer.is_null());
                    for (index, unit) in text.encode_utf16().enumerate() {
                        assert_eq!(unsafe { pointer.add(index).read() }, unit);
                    }
                }
            }
        }
    }
}
