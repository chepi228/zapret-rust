//! Engine file metadata, access probes, path resolution and EXEDIR setup.
use super::{
    FileHandle, WinResult, executable_directory, metadata, open_file, path_input, realpath, utf16,
    win32_ok,
};
use std::{
    ffi::{CStr, c_char, c_int},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_PARAMETER},
    System::Environment::SetEnvironmentVariableW,
};

#[repr(C)]
struct Stamp {
    seconds: i64,
    nanoseconds: i32,
    reserved: u32,
    size: i64,
}
impl Stamp {
    const EMPTY: Self = Self {
        seconds: 0,
        nanoseconds: 0,
        reserved: 0,
        size: 0,
    };
}
fn status(result: WinResult<()>) -> u32 {
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_file_size(filename: *const c_char, output: *mut i64) -> u32 {
    let result = (|| {
        let data = metadata(&path_input(filename)?)?;
        if !output.is_null() {
            unsafe { output.write(data.size) };
        }
        Ok(())
    })();
    status(result)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_file_stamp(filename: *const c_char, output: *mut Stamp) -> u32 {
    if output.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let result = (|| {
        let data = metadata(&path_input(filename)?)?;
        Ok(Stamp {
            seconds: data.seconds,
            nanoseconds: data.nanoseconds as i32,
            reserved: 0,
            size: data.size,
        })
    })();
    match result {
        Ok(stamp) => {
            unsafe { output.write(stamp) };
            0
        }
        Err(error) => {
            unsafe { output.write(Stamp::EMPTY) };
            error
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_file_probe(filename: *const c_char, flags: c_int) -> u32 {
    // An access probe must not create, truncate or delete its input file.
    if flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_TEMPORARY) != 0 {
        return ERROR_INVALID_PARAMETER;
    }
    status((|| {
        let _file = FileHandle(open_file(
            &path_input(filename)?,
            flags | libc::O_NOINHERIT,
            0,
        )?);
        Ok(())
    })())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_set_exedir() -> u32 {
    status((|| {
        let directory = executable_directory()?;
        let value = CStr::from_bytes_with_nul(&directory).map_err(|_| ERROR_INVALID_PARAMETER)?;
        let value = utf16(value)?;
        const NAME: &[u16] = &[69, 88, 69, 68, 73, 82, 0];
        win32_ok(unsafe { SetEnvironmentVariableW(NAME.as_ptr(), value.as_ptr()) })
    })())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_realpath(
    filename: *const c_char,
    output: *mut c_char,
    capacity: usize,
) -> u32 {
    if output.is_null() || capacity == 0 || capacity > isize::MAX as usize {
        return ERROR_INVALID_PARAMETER;
    }
    status((|| {
        let resolved = realpath(&path_input(filename)?, true)?;
        if resolved.len() > capacity {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        unsafe { ptr::copy_nonoverlapping(resolved.as_ptr().cast(), output, resolved.len()) };
        Ok(())
    })())
}
