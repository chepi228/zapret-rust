//! Startup input entries. The caller handles the process exit on failure.
use super::*;
use crate::native_logging_entry::LogSink;

#[repr(C)]
struct Logs {
    debug: LogSink,
    error: LogSink,
}

unsafe fn report_error(
    code: u32,
    argument: *const c_char,
    input: &InputDetails,
    named: bool,
    logs: &Logs,
) {
    let error = logs.error;
    unsafe {
        match code {
            v if v == Error::Identifier as u32 => error(
                c"bad identifier '%.*s'\n".as_ptr(),
                input.name_length as i32,
                argument,
            ),
            v if v == Error::Allocation as u32 => error(c"out of memory\n".as_ptr()),
            v if v == Error::Duplicate as u32 => error(
                c"duplicate blob name '%.*s'\n".as_ptr(),
                input.name_length as i32,
                argument,
            ),
            v if v == Error::Offset as u32 => {
                (logs.debug)(c"offset read error: %s\n".as_ptr(), argument)
            }
            v if v == Error::Access as u32 && named => {
                error(c"cannot access file '%s'\n".as_ptr(), input.source)
            }
            v if v == Error::Access as u32 || v == Error::Read as u32 => {
                error(c"could not read '%s'\n".as_ptr(), input.source)
            }
            v if v == Error::BeyondEnd as u32 => error(
                c"offset %llu is beyond file size %llu\n".as_ptr(),
                input.offset,
                input.file_size,
            ),
            v if v == Error::Hex as u32 => {
                error(c"invalid hex string: %s\n".as_ptr(), input.source)
            }
            _ => error(c"blob size out of range\n".as_ptr()),
        };
    }
}

unsafe fn report_read(argument: *const c_char, size: usize, input: &InputDetails, debug: LogSink) {
    let text = argument.cast::<u8>();
    unsafe {
        if text.read() == b'0' && text.add(1).read() == b'x' {
            debug(c"read %zu bytes from hex string\n".as_ptr(), size);
        } else {
            debug(
                c"read %zu bytes from '%s'. offset=%llu\n".as_ptr(),
                size,
                input.source,
                input.offset,
            );
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_read_fixed(
    argument: *const c_char,
    buffer: *mut u8,
    size: &mut usize,
    logs: &Logs,
) -> bool {
    let mut input = InputDetails::new(argument);
    unsafe {
        let code = zapret_blob_load_argument(argument, buffer, size, &mut input);
        if code != 0 {
            report_error(code, argument, &input, false, logs);
            return false;
        }
        report_read(argument, *size, &input, logs.debug);
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_read_named(
    head: *mut *mut Blob,
    argument: *const c_char,
    max_hex: usize,
    reserve: usize,
    allocator: &Allocator,
    logs: &Logs,
) -> *mut Blob {
    let mut input = InputDetails::new(argument);
    let mut blob = ptr::null_mut();
    unsafe {
        let code = zapret_blob_load_named(
            head, argument, max_hex, reserve, allocator, &mut input, &mut blob,
        );
        if code != 0 {
            report_error(code, argument, &input, true, logs);
            return ptr::null_mut();
        }
        let source = argument.add(input.name_length);
        let source = if source.read() as u8 == b':' {
            source.add(1)
        } else {
            source
        };
        report_read(source, (*blob).size, &input, logs.debug);
    }
    blob
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_read_const(
    head: *mut *mut Blob,
    name: *const c_char,
    data: *const u8,
    size: usize,
    reserve: usize,
    allocator: &Allocator,
    logs: &Logs,
) -> *mut Blob {
    let mut blob = ptr::null_mut();
    unsafe {
        let code = zapret_blob_load_const(head, name, data, size, reserve, allocator, &mut blob);
        if code != 0 {
            let mut input = InputDetails::new(name);
            input.name_length = CStr::from_ptr(name).to_bytes().len();
            report_error(code, name, &input, true, logs);
            return ptr::null_mut();
        }
    }
    blob
}
