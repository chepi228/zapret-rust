//! Prepare a bounded writable directory before publishing its environment path.
use crate::files::{buffer, path_input, utf8};
use std::{
    ffi::{CStr, c_char},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_DIRECTORY, ERROR_FILE_EXISTS, ERROR_FILENAME_EXCED_RANGE,
        ERROR_GEN_FAILURE, ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
        ERROR_NO_UNICODE_TRANSLATION, ERROR_NOT_ENOUGH_MEMORY, GetLastError, SetLastError,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    },
    System::Environment::{GetEnvironmentVariableW, SetEnvironmentVariableW},
};
#[repr(C)]
struct Ops {
    getenv: unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32,
    mkdir: unsafe extern "system" fn(*const u16, *const SECURITY_ATTRIBUTES) -> i32,
    attributes: unsafe extern "system" fn(*const u16) -> u32,
    label: unsafe extern "C" fn(*const u16) -> u32,
    environment: unsafe extern "system" fn(*const u16, *const u16) -> i32,
    error: unsafe extern "system" fn() -> u32,
}
unsafe extern "C" fn label(path: *const u16) -> u32 {
    unsafe { crate::security_label::label_directory(path) }
}
const NATIVE: Ops = Ops {
    getenv: GetEnvironmentVariableW,
    mkdir: CreateDirectoryW,
    attributes: GetFileAttributesW,
    label,
    environment: SetEnvironmentVariableW,
    error: GetLastError,
};
const APPDATA: &[u16] = &[65, 80, 80, 68, 65, 84, 65, 76, 79, 87, 0];
const WRITABLE: &[u16] = &[87, 82, 73, 84, 65, 66, 76, 69, 0];
const PATH_MAX: usize = 4096;
fn failure(ops: &Ops) -> u32 {
    match unsafe { (ops.error)() } {
        0 => ERROR_GEN_FAILURE,
        error => error,
    }
}
fn default_path(ops: &Ops) -> Result<Vec<u8>, u32> {
    unsafe { SetLastError(0) };
    let mut capacity = unsafe { (ops.getenv)(APPDATA.as_ptr(), ptr::null_mut(), 0) };
    if capacity == 0 {
        let error = unsafe { (ops.error)() };
        return Err(if error == 0 {
            ERROR_INVALID_DATA
        } else {
            error
        });
    }
    for _ in 0..3 {
        if capacity > 32768 {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        let mut wide = buffer::<u16>(capacity as usize)?;
        unsafe { SetLastError(0) };
        let length = unsafe { (ops.getenv)(APPDATA.as_ptr(), wide.as_mut_ptr(), capacity) };
        if length == 0 {
            let error = unsafe { (ops.error)() };
            return Err(if error == 0 {
                ERROR_INVALID_DATA
            } else {
                error
            });
        }
        if length >= capacity {
            capacity = length;
            continue;
        }
        let length = length as usize;
        if wide[length] != 0 || wide[..length].contains(&0) {
            return Err(ERROR_INVALID_DATA);
        }
        let mut path = unsafe { utf8(wide.as_ptr()) }?;
        const SUFFIX: &[u8] = b"/zapret2\0";
        if path.len() + SUFFIX.len() - 1 > PATH_MAX {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        path.try_reserve_exact(SUFFIX.len())
            .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
        path.pop();
        path.extend_from_slice(SUFFIX);
        return Ok(path);
    }
    Err(ERROR_MORE_DATA)
}
fn raw_path(configured: *const c_char, ops: &Ops) -> Result<Vec<u8>, u32> {
    if configured.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let configured = unsafe { CStr::from_ptr(configured) };
    if configured.is_empty() {
        return default_path(ops);
    }
    let bytes = configured.to_bytes_with_nul();
    if bytes.len() > PATH_MAX {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    let mut output = buffer(bytes.len())?;
    output.copy_from_slice(bytes);
    Ok(output)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_writable_prepare(configured: *const c_char, input: *const Ops) -> u32 {
    let ops = if input.is_null() {
        &NATIVE
    } else {
        unsafe { &*input }
    };
    let result = (|| {
        let raw = raw_path(configured, ops)?;
        let text = CStr::from_bytes_with_nul(&raw)
            .map_err(|_| ERROR_INVALID_DATA)?
            .to_str()
            .map_err(|_| ERROR_NO_UNICODE_TRANSLATION)?;
        let mut published = buffer::<u16>(raw.len())?;
        let mut units = 0;
        for unit in text.encode_utf16() {
            published[units] = unit;
            units += 1;
        }
        published.truncate(units + 1);
        let path = path_input(raw.as_ptr().cast())?;
        if unsafe { (ops.mkdir)(path.as_ptr(), ptr::null()) } == 0 {
            let error = failure(ops);
            if error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS {
                return Err(error);
            }
        }
        let attributes = unsafe { (ops.attributes)(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(failure(ops));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(ERROR_DIRECTORY);
        }
        let error = unsafe { (ops.label)(path.as_ptr()) };
        if error != 0 {
            return Err(error);
        }
        if unsafe { (ops.environment)(WRITABLE.as_ptr(), published.as_ptr()) } == 0 {
            return Err(failure(ops));
        }
        Ok::<(), u32>(())
    })();
    result.err().unwrap_or(0)
}
