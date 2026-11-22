//! Report filter preparation events and preserve the native last-error update.
use crate::native_logging_entry::LogSink;
use std::ffi::c_char;

#[unsafe(no_mangle)]
extern "C" fn zapret_capture_prepare_report(
    event: u32,
    size: usize,
    text: *const c_char,
    debug: LogSink,
    error: LogSink,
) {
    unsafe {
        if event == 0 {
            debug(
                c"windivert filter size: %zu\nwindivert filter:\n%s\n".as_ptr(),
                size,
                text,
            );
        } else {
            error(c"windivert filter: raw filter saved to %s\n".as_ptr(), text);
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_capture_prepare_status(
    status: u32,
    code: u32,
    save: *const c_char,
    error: LogSink,
    set_error: unsafe extern "C" fn(u32),
) {
    unsafe {
        match status {
            0 | 8 => {}
            1 => {
                error(c"invalid capture preparation storage\n".as_ptr());
            }
            2 => {
                error(c"windivert filter : must specify port or/and partial raw filter\n".as_ptr());
            }
            3 => {
                error(c"windivert filter : could not make filter\n".as_ptr());
            }
            4 => {
                error(c"out of memory\n".as_ptr());
            }
            5 => {
                set_error(code);
                error(
                    c"windivert filter: could not save raw filter to %s\n".as_ptr(),
                    save,
                );
            }
            6 => {
                error(c"A copy of winws2 is already running with the same filter\n".as_ptr());
            }
            _ => {
                set_error(code);
                error(
                    c"could not create the argument mutex: Windows error %u\n".as_ptr(),
                    code,
                );
            }
        }
    }
}
