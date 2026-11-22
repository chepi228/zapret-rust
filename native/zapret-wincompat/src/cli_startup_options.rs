//! Startup option decisions over C-owned fields and primitive platform bindings.
use crate::{
    cli::{FileClose, FileOpen, Perror, stderr_argument},
    logging::LogSink,
};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
};
use windows_sys::Win32::Foundation::{ERROR_GEN_FAILURE, GetLastError};

#[repr(C)]
struct Target {
    path: *mut c_char,
    capacity: usize,
    enabled: *mut bool,
    debug: *mut bool,
    log_target: *mut i32,
    scripts: *mut c_void,
}
#[repr(C)]
struct Ops {
    resolve: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> u32,
    touch: unsafe extern "C" fn(*const c_char, bool) -> u32,
    cwd: unsafe extern "C" fn(*const c_char) -> u32,
    environment: unsafe extern "C" fn(*const c_char) -> *const c_char,
    syslog: unsafe extern "C" fn(c_int, c_int),
    trace_directory: LogSink,
    append: unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
}
#[repr(C)]
#[derive(Default)]
struct Detail {
    error: u32,
    argument_offset: u32,
}
#[repr(u32)]
#[derive(Clone, Copy)]
enum Kind {
    Invalid = 1,
    Path,
    UnknownDirectory,
    ChangeDirectory,
    Touch,
    Allocation,
    Debug,
}
struct Failure {
    kind: Kind,
    error: u32,
    offset: u32,
}

fn last_error_or_failure() -> u32 {
    match unsafe { GetLastError() } {
        0 => ERROR_GEN_FAILURE,
        code => code,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_startup_touch(
    path: *const c_char,
    truncate: bool,
    open: FileOpen,
    close: FileClose,
) -> u32 {
    let mode = if truncate { c"wt" } else { c"a+t" };
    let file = unsafe { open(path, mode.as_ptr()) };
    if file.is_null() || unsafe { close(file) } != 0 {
        last_error_or_failure()
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_startup_cwd(
    path: *const c_char,
    chdir: unsafe extern "C" fn(*const c_char) -> c_int,
) -> u32 {
    if unsafe { chdir(path) } != 0 {
        last_error_or_failure()
    } else {
        0
    }
}

fn fail(kind: Kind, error: u32, offset: u32) -> Failure {
    Failure {
        kind,
        error,
        offset,
    }
}
fn storage(size: usize) -> Result<Vec<u8>, Failure> {
    if size == 0 || size > isize::MAX as usize {
        return Err(fail(Kind::Invalid, 87, 0));
    }
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| fail(Kind::Allocation, 8, 0))?;
    value.resize(size, 0);
    Ok(value)
}
unsafe fn owned(text: *const c_char) -> Result<Vec<u8>, Failure> {
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes_with_nul();
    let mut value = storage(bytes.len())?;
    value.copy_from_slice(bytes);
    Ok(value)
}
unsafe fn resolved(
    text: *const c_char,
    capacity: usize,
    offset: u32,
    ops: &Ops,
) -> Result<Vec<u8>, Failure> {
    if text.is_null() {
        return Err(fail(Kind::Path, 87, offset));
    }
    let mut value = storage(capacity)?;
    let error = unsafe { (ops.resolve)(text, value.as_mut_ptr().cast(), capacity) };
    if error != 0 {
        return Err(fail(Kind::Path, error, offset));
    }
    let length = value
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| fail(Kind::Path, 13, offset))?;
    if length == 0 {
        return Err(fail(Kind::Path, 13, offset));
    }
    value.truncate(length + 1);
    Ok(value)
}
fn path_target(target: &Target) -> Result<(), Failure> {
    if target.path.is_null() || target.capacity == 0 || target.capacity > isize::MAX as usize {
        return Err(fail(Kind::Invalid, 87, 0));
    }
    Ok(())
}
unsafe fn commit(target: &Target, value: &[u8]) {
    unsafe { ptr::copy_nonoverlapping(value.as_ptr().cast(), target.path, value.len()) };
}
unsafe fn apply(kind: u32, text: *const c_char, target: &Target, ops: &Ops) -> Result<(), Failure> {
    match kind {
        0 => {
            if target.debug.is_null()
                || target.log_target.is_null()
                || !target.log_target.is_aligned()
            {
                return Err(fail(Kind::Invalid, 87, 0));
            }
            if text.is_null() {
                unsafe {
                    target.debug.write(true);
                    target.log_target.write(0)
                };
                return Ok(());
            }
            let value = unsafe { CStr::from_ptr(text) }.to_bytes();
            if value.first() == Some(&b'@') {
                path_target(target)?;
                let path = unsafe { resolved(text.add(1), target.capacity, 1, ops) }?;
                let error = unsafe { (ops.touch)(path.as_ptr().cast(), true) };
                if error != 0 {
                    return Err(fail(Kind::Touch, error, 1));
                }
                unsafe {
                    commit(target, &path);
                    target.debug.write(true);
                    target.log_target.write(1)
                };
            } else if value == b"syslog" {
                unsafe {
                    target.debug.write(true);
                    target.log_target.write(2);
                    (ops.syslog)(1, 8) // LOG_PID and LOG_USER
                };
            } else if matches!(value.first(), Some(b'0' | b'1')) {
                // Retain the pinned UCRT atoi-prefix semantics for valid modes.
                let enabled = unsafe { libc::atoi(text) } != 0;
                unsafe {
                    target.debug.write(enabled);
                    target.log_target.write(0)
                };
            } else {
                return Err(fail(Kind::Debug, 87, 0));
            }
        }
        1 => {
            let text = if text.is_null() {
                unsafe { (ops.environment)(c"EXEDIR".as_ptr()) }
            } else {
                text
            };
            if text.is_null() {
                return Err(fail(Kind::UnknownDirectory, 3, 0));
            }
            let value = unsafe { owned(text) }?;
            unsafe {
                (ops.trace_directory)(
                    c"changing dir to '%s'\n".as_ptr(),
                    value.as_ptr().cast::<c_char>(),
                );
            }
            let error = unsafe { (ops.cwd)(value.as_ptr().cast()) };
            if error != 0 {
                return Err(fail(Kind::ChangeDirectory, error, 0));
            }
        }
        2 | 3 | 5 => {
            path_target(target)?;
            if kind == 3 && target.enabled.is_null() {
                return Err(fail(Kind::Invalid, 87, 0));
            }
            if kind == 3 && text.is_null() {
                unsafe {
                    target.path.write(0);
                    target.enabled.write(true)
                };
                return Ok(());
            }
            let value = unsafe { resolved(text, target.capacity, 0, ops) }?;
            if kind == 5 {
                let error = unsafe { (ops.touch)(value.as_ptr().cast(), false) };
                if error != 0 {
                    return Err(fail(Kind::Touch, error, 0));
                }
            }
            unsafe { commit(target, &value) };
            if kind == 3 {
                unsafe { target.enabled.write(true) };
            }
        }
        4 => {
            if target.scripts.is_null() || text.is_null() {
                return Err(fail(Kind::Invalid, 87, 0));
            }
            if unsafe { text.read() } == b'@' as c_char {
                let mut value = unsafe { resolved(text.add(1), 4096, 1, ops) }?;
                value
                    .try_reserve_exact(1)
                    .map_err(|_| fail(Kind::Allocation, 8, 0))?;
                value.insert(0, b'@');
                if !unsafe { (ops.append)(target.scripts, value.as_ptr().cast()) } {
                    return Err(fail(Kind::Allocation, 8, 0));
                }
            } else if !unsafe { (ops.append)(target.scripts, text) } {
                return Err(fail(Kind::Allocation, 8, 0));
            }
        }
        _ => return Err(fail(Kind::Invalid, 87, 0)),
    }
    Ok(())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_startup_option(
    kind: u32,
    text: *const c_char,
    target: *const Target,
    ops: *const Ops,
    detail: *mut Detail,
) -> u32 {
    if !detail.is_null() {
        unsafe { detail.write(Detail::default()) };
    }
    if target.is_null() || ops.is_null() {
        if !detail.is_null() {
            unsafe { (*detail).error = 87 };
        }
        return Kind::Invalid as u32;
    }
    match unsafe { apply(kind, text, &*target, &*ops) } {
        Ok(()) => 0,
        Err(failure) => {
            if !detail.is_null() {
                unsafe {
                    detail.write(Detail {
                        error: failure.error,
                        argument_offset: failure.offset,
                    })
                };
            }
            failure.kind as u32
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_startup_report(
    kind: u32,
    status: u32,
    text: *const c_char,
    argument_offset: u32,
    error: LogSink,
    stderr: Option<LogSink>,
    perror: Perror,
) -> c_int {
    if status == 0 {
        return 1;
    }
    let argument = if text.is_null() {
        c"".as_ptr()
    } else {
        unsafe { text.add(argument_offset as usize) }
    };
    unsafe {
        match status {
            code if code == Kind::Path as u32 => error(c"bad file '%s'\n".as_ptr(), argument),
            code if code == Kind::UnknownDirectory as u32 => {
                error(c"chdir: directory unknown\n".as_ptr())
            }
            code if code == Kind::ChangeDirectory as u32 => perror(c"chdir".as_ptr()),
            code if code == Kind::Touch as u32 => {
                let format = c"cannot create %s\n";
                if kind == 0 {
                    stderr_argument(stderr, format, argument)
                } else {
                    error(format.as_ptr(), argument)
                }
            }
            code if code == Kind::Allocation as u32 => error(c"out of memory\n".as_ptr()),
            code if code == Kind::Debug as u32 => {
                stderr_argument(stderr, c"invalid debug mode : %s\n", argument)
            }
            _ => error(c"invalid startup option storage\n".as_ptr()),
        };
    }
    -1
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Target>() == 48);
    assert!(size_of::<Ops>() == 56);
    assert!(size_of::<Detail>() == 8);
};
