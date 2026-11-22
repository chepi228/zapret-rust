//! Engine binary reads/writes and text list appends over owned native handles.
use crate::files::{open_file, path_input};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr, slice,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_READ_FAULT, ERROR_WRITE_FAULT,
        GetLastError,
    },
    Storage::FileSystem::ReadFile,
};

fn io_error(error: std::io::Error, fallback: u32) -> u32 {
    error.raw_os_error().map_or(fallback, |value| value as u32)
}
unsafe fn open(filename: *const c_char, flags: i32) -> Result<File, u32> {
    let path = path_input(filename)?;
    let handle = open_file(
        &path,
        flags | libc::O_NOINHERIT,
        libc::S_IREAD | libc::S_IWRITE,
    )?;
    // This handle is owned exclusively by this File, without a CRT descriptor.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_engine_load_file(
    filename: *const c_char,
    offset: i64,
    output: *mut c_void,
    capacity: *mut usize,
) -> u32 {
    if capacity.is_null() || offset < 0 {
        return ERROR_INVALID_PARAMETER;
    }
    let size = unsafe { capacity.read() };
    if size > isize::MAX as usize || size != 0 && output.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let result = (|| {
        let mut file = unsafe { open(filename, libc::O_RDONLY) }?;
        if offset != 0 {
            file.seek(SeekFrom::Start(offset as u64))
                .map_err(|error| io_error(error, ERROR_READ_FAULT))?;
        }
        let mut read = 0;
        unsafe { capacity.write(0) };
        while read < size {
            let requested = (size - read).min(16 * 1024 * 1024) as u32;
            let mut count = 0;
            // The engine may provide uninitialized malloc storage. ReadFile
            // initializes it without constructing a Rust byte slice first.
            if unsafe {
                ReadFile(
                    file.as_raw_handle().cast(),
                    output.cast::<u8>().add(read),
                    requested,
                    &mut count,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(unsafe { GetLastError() });
            }
            if count == 0 {
                break;
            }
            read += count as usize;
            unsafe { capacity.write(read) };
        }
        Ok(())
    })();
    result.map_or_else(|error| error, |()| 0)
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_engine_save_file(
    filename: *const c_char,
    data: *const u8,
    size: usize,
) -> u32 {
    if size > isize::MAX as usize || size != 0 && data.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let result = (|| {
        let mut file = unsafe { open(filename, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC) }?;
        let data = if size == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(data, size) }
        };
        file.write_all(data)
            .map_err(|error| io_error(error, ERROR_WRITE_FAULT))
    })();
    result.map_or_else(|error| error, |()| 0)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_append_line(
    filename: *const c_char,
    text: *const c_char,
) -> u32 {
    if text.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
    let newlines = bytes.iter().filter(|&&byte| byte == b'\n').count();
    let Some(size) = bytes
        .len()
        .checked_add(newlines)
        .and_then(|size| size.checked_add(2))
    else {
        return ERROR_NOT_ENOUGH_MEMORY;
    };
    let mut line = Vec::new();
    if line.try_reserve_exact(size).is_err() {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    for &byte in bytes {
        if byte == b'\n' {
            line.push(b'\r');
        }
        line.push(byte);
    }
    line.extend_from_slice(b"\r\n");
    let result = (|| {
        let mut file = unsafe { open(filename, libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND) }?;
        file.write_all(&line)
            .map_err(|error| io_error(error, ERROR_WRITE_FAULT))
    })();
    result.map_or_else(|error| error, |()| 0)
}
