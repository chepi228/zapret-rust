//! Match the engine's long option table without rearranging the caller's argv.
use crate::filters::decimal64_prefix;
use crate::logging::LogSink;
use std::{
    ffi::{CStr, c_char, c_int},
    mem::MaybeUninit,
    ptr, slice,
};

#[cfg(windows)]
const STDERR: std::ffi::c_uint = 2;

// The native engine uses MinGW ANSI formatting over the current UCRT stream.
#[cfg(windows)]
unsafe extern "C" {
    fn __acrt_iob_func(index: std::ffi::c_uint) -> *mut libc::FILE;
    fn __mingw_fprintf(file: *mut libc::FILE, format: *const c_char, ...) -> c_int;
}

#[cfg(windows)]
pub(super) unsafe fn stderr_argument(
    sink: Option<LogSink>,
    format: &CStr,
    argument: *const c_char,
) -> c_int {
    let format = format.as_ptr();
    unsafe {
        match sink {
            Some(sink) => sink(format, argument),
            None => __mingw_fprintf(__acrt_iob_func(STDERR), format, argument),
        }
    }
}

#[cfg(windows)]
pub(super) type FileOpen =
    unsafe extern "C" fn(*const c_char, *const c_char) -> *mut std::ffi::c_void;
#[cfg(windows)]
pub(super) type FileClose = unsafe extern "C" fn(*mut std::ffi::c_void) -> c_int;
#[cfg(windows)]
pub(super) type Perror = unsafe extern "C" fn(*const c_char) -> c_int;

#[repr(C)]
pub(super) struct OptionSpec {
    name: *const c_char,
    argument: c_int,
    flag: *mut c_int,
    value: c_int,
}

#[repr(C)]
struct OptionRead {
    argument: *mut c_char,
    diagnostic: *const c_char,
    diagnostic_length: usize,
    index: c_int,
}

#[repr(u32)]
enum Status {
    End,
    Match,
    Unknown,
    Ambiguous,
    MissingArgument,
    UnexpectedArgument,
}

enum Name {
    Matched(usize),
    Unknown,
    Ambiguous,
}

fn find(name: &[u8], options: &[OptionSpec]) -> Name {
    let mut first: Option<usize> = None;
    let mut ambiguous = false;
    for (index, option) in options.iter().enumerate() {
        if option.name.is_null() {
            continue;
        }
        let candidate = unsafe { CStr::from_ptr(option.name) }.to_bytes();
        if candidate == name {
            return Name::Matched(index);
        }
        if candidate.starts_with(name) {
            if let Some(previous) = first {
                let other = &options[previous];
                ambiguous |= option.argument != other.argument
                    || option.flag != other.flag
                    || option.value != other.value;
            }
            first.get_or_insert(index);
        }
    }
    if ambiguous {
        Name::Ambiguous
    } else {
        first.map_or(Name::Unknown, Name::Matched)
    }
}

unsafe fn read_option(
    argc: c_int,
    argv: *const *mut c_char,
    options: *const OptionSpec,
    option_count: usize,
    cursor: &mut usize,
    stop_at_operand: bool,
    output: *mut OptionRead,
) -> Status {
    let count = usize::try_from(argc).unwrap_or(0);
    if *cursor >= count {
        return Status::End;
    }
    let args = unsafe { slice::from_raw_parts(argv, count) };
    let options = if option_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(options, option_count) }
    };
    while let Some(&raw) = args.get(*cursor) {
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
        *cursor += 1;
        if bytes == b"--" {
            *cursor = count;
            return Status::End;
        }
        if bytes.len() < 2 || bytes[0] != b'-' {
            if stop_at_operand {
                *cursor = count;
                return Status::End;
            }
            continue;
        }
        let leading = if bytes[1] == b'-' { 2 } else { 1 };
        let option = &bytes[leading..];
        let separator = option.iter().position(|&byte| byte == b'=');
        let name = &option[..separator.unwrap_or(option.len())];
        let mut result = OptionRead {
            argument: ptr::null_mut(),
            diagnostic: unsafe { raw.add(leading) },
            diagnostic_length: name.len(),
            index: 0,
        };
        let status = match find(name, options) {
            Name::Unknown => {
                result.diagnostic_length = option.len();
                Status::Unknown
            }
            Name::Ambiguous => Status::Ambiguous,
            Name::Matched(index) => {
                let argument_mode = options[index].argument;
                result.index = index as c_int;
                if let Some(separator) = separator {
                    if argument_mode == 0 {
                        Status::UnexpectedArgument
                    } else {
                        result.argument = unsafe { raw.add(leading + separator + 1) };
                        Status::Match
                    }
                } else if argument_mode == 1 {
                    if let Some(&value) = args.get(*cursor) {
                        result.argument = value;
                        *cursor += 1;
                        Status::Match
                    } else {
                        Status::MissingArgument
                    }
                } else {
                    Status::Match
                }
            }
        };
        unsafe { output.write(result) };
        return status;
    }
    Status::End
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_read(
    argc: c_int,
    argv: *const *mut c_char,
    options: *const OptionSpec,
    option_count: usize,
    cursor: &mut usize,
    stop_at_operand: bool,
    output: *mut OptionRead,
) -> u32 {
    (unsafe {
        read_option(
            argc,
            argv,
            options,
            option_count,
            cursor,
            stop_at_operand,
            output,
        )
    }) as u32
}

#[repr(C)]
pub(super) struct CursorOutput {
    pub(super) argument: *mut *mut c_char,
    pub(super) index: *mut c_int,
    pub(super) stderr: Option<LogSink>,
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_cli_next(
    argc: c_int,
    argv: *const *mut c_char,
    options: *const OptionSpec,
    option_count: usize,
    cursor: &mut usize,
    stop_at_operand: bool,
    output: &CursorOutput,
) -> c_int {
    let mut parsed = MaybeUninit::uninit();
    let status = unsafe {
        read_option(
            argc,
            argv,
            options,
            option_count,
            cursor,
            stop_at_operand,
            parsed.as_mut_ptr(),
        )
    };
    unsafe { output.argument.write(ptr::null_mut()) };
    let description = match status {
        Status::End => return -1,
        Status::Match => {
            let option = unsafe { parsed.assume_init() };
            unsafe {
                output.argument.write(option.argument);
                output.index.write(option.index);
            }
            return 0;
        }
        Status::Unknown => c"unknown option",
        Status::Ambiguous => c"ambiguous option",
        Status::MissingArgument => c"option requires an argument",
        Status::UnexpectedArgument => c"option doesn't take an argument",
    };
    let option = unsafe { parsed.assume_init() };
    let length = option.diagnostic_length.min(c_int::MAX as usize) as c_int;
    let format = c"%s: %s -- %.*s\n".as_ptr();
    unsafe {
        let program = argv.read();
        let description = description.as_ptr();
        if let Some(sink) = output.stderr {
            sink(format, program, description, length, option.diagnostic);
        } else {
            #[cfg(windows)]
            __mingw_fprintf(
                __acrt_iob_func(STDERR),
                format,
                program,
                description,
                length,
                option.diagnostic,
            );
        }
    }
    c_int::from(b'?')
}

#[repr(C)]
#[derive(Default)]
pub(super) struct NumericOption {
    pub(super) target: *mut std::ffi::c_void,
    pub(super) explicit: *mut bool,
    pub(super) lower: i64,
    pub(super) upper: i64,
    pub(super) scale: u32,
    pub(super) kind: u32,
    pub(super) disable: *mut bool,
}

type SetNumber = unsafe extern "C" fn(*const c_char, &NumericOption) -> bool;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_set_boolean(
    text: *const c_char,
    target: *mut bool,
    set_number: SetNumber,
) -> bool {
    let option = NumericOption {
        target: target.cast(),
        lower: i64::from(i32::MIN),
        upper: i64::from(i32::MAX),
        scale: 1,
        ..NumericOption::default()
    };
    unsafe { set_number(text, &option) }
}

fn signed_prefix(text: &[u8]) -> Option<i64> {
    let text = text.trim_ascii_start();
    let negative = text.starts_with(b"-");
    let value = if negative { &text[1..] } else { text };
    let (value, _) = decimal64_prefix(value)?;
    let value = i64::try_from(value).ok()?;
    Some(if negative { -value } else { value })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_set_number(text: *const c_char, option: &NumericOption) -> bool {
    let value = if text.is_null() {
        if option.kind != 0 {
            return false;
        }
        1
    } else {
        let Some(value) = signed_prefix(unsafe { CStr::from_ptr(text) }.to_bytes()) else {
            return false;
        };
        value
    };
    if !(option.lower..=option.upper).contains(&value) {
        return false;
    }
    let Some(value) = value.checked_mul(i64::from(option.scale)) else {
        return false;
    };
    unsafe {
        match option.kind {
            0 => option.target.cast::<bool>().write(value != 0),
            1 => {
                let Ok(value) = i32::try_from(value) else {
                    return false;
                };
                option.target.cast::<i32>().write(value);
            }
            2 => {
                let Ok(value) = u32::try_from(value) else {
                    return false;
                };
                option.target.cast::<u32>().write(value);
            }
            3 => option.target.cast::<u32>().write(value as u32),
            4 => {
                let Ok(value) = u64::try_from(value) else {
                    return false;
                };
                option.target.cast::<u64>().write(value);
            }
            _ => return false,
        }
        if !option.explicit.is_null() {
            option.explicit.write(true);
        }
        if !option.disable.is_null() {
            option.disable.write(false);
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_timeouts(
    text: *const c_char,
    syn: *mut u32,
    established: *mut u32,
    fin: *mut u32,
    udp: *mut u32,
) -> bool {
    let mut rest = unsafe { CStr::from_ptr(text) }.to_bytes();
    let mut values = [0, 0, 0, unsafe { udp.read() }];
    let mut parsed = 0;
    for slot in &mut values {
        let Some((value, tail)) = decimal64_prefix(rest) else {
            break;
        };
        let Ok(value) = u32::try_from(value) else {
            return false;
        };
        *slot = value;
        parsed += 1;
        let Some(next) = tail.strip_prefix(b":") else {
            break;
        };
        rest = next;
    }
    if parsed < 3 {
        return false;
    }
    unsafe {
        syn.write(values[0]);
        established.write(values[1]);
        fin.write(values[2]);
        udp.write(values[3]);
    }
    true
}
