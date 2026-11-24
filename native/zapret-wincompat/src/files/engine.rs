//! Engine file metadata, access probes, path resolution and EXEDIR setup.
use super::{
    FileHandle, WinResult, executable_directory, metadata, open_file, path_input, realpath,
    unix_file_time, utf16, win32_ok,
};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
    sync::OnceLock,
};
use windows_sys::Wdk::Storage::FileSystem::FILE_STAT_INFORMATION;
use windows_sys::Win32::{
    Foundation::{ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_PARAMETER},
    Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES},
    System::{
        Environment::SetEnvironmentVariableW,
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
    },
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

type QueryFileByName = unsafe extern "system" fn(*const u16, i32, *mut c_void, u32) -> i32;

fn file_stamp(path: &[u16]) -> WinResult<Stamp> {
    // Resolve once so older Windows versions can keep using the handle query.
    static QUERY: OnceLock<Option<QueryFileByName>> = OnceLock::new();
    let query = QUERY.get_or_init(|| unsafe {
        let kernel = GetModuleHandleW(windows_sys::w!("kernel32.dll"));
        if kernel.is_null() {
            return None;
        }
        let query = GetProcAddress(kernel, c"GetFileInformationByName".as_ptr().cast())?;
        Some(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            QueryFileByName,
        >(query))
    });
    if let Some(query) = query {
        const FILE_STAT_BY_NAME_INFO: i32 = 0;
        let mut info = FILE_STAT_INFORMATION::default();
        let ok = unsafe {
            query(
                path.as_ptr(),
                FILE_STAT_BY_NAME_INFO,
                (&raw mut info).cast(),
                size_of::<FILE_STAT_INFORMATION>() as u32,
            )
        };
        // Follow the original path for reparse points, restricted access and
        // filesystems that do not support this query. Never cache a list's stamp.
        if ok != 0
            && info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && info.EffectiveAccess & FILE_READ_ATTRIBUTES != 0
            && info.EndOfFile >= 0
        {
            let (seconds, nanos) = unix_file_time(info.LastWriteTime);
            return Ok(Stamp {
                seconds,
                nanoseconds: nanos as i32,
                reserved: 0,
                size: info.EndOfFile,
            });
        }
    }
    let data = metadata(path)?;
    Ok(Stamp {
        seconds: data.seconds,
        nanoseconds: data.nanoseconds as i32,
        reserved: 0,
        size: data.size,
    })
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
    let result = path_input(filename).and_then(|path| file_stamp(&path));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::windows::{ffi::OsStrExt, fs::symlink_file},
        path::Path,
    };

    fn check_stamp(path: &Path) {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let observed = file_stamp(&wide).map(|s| (s.size, s.seconds, s.nanoseconds));
        let expected = metadata(&wide).map(|s| (s.size, s.seconds, s.nanoseconds as i32));
        assert_eq!(observed, expected);
    }

    #[test]
    fn stamps_follow_edits_links_and_replacement_at_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("список.txt");
        fs::write(&list, b"one").unwrap();
        check_stamp(&list);
        let hard = dir.path().join("hard.txt");
        fs::hard_link(&list, &hard).unwrap();
        fs::write(&hard, b"changed through another name").unwrap();
        check_stamp(&list);
        let link = dir.path().join("symbolic.txt");
        match symlink_file(&list, &link) {
            Ok(()) => check_stamp(&link),
            Err(e) if e.raw_os_error() == Some(1314) => {}
            Err(e) => panic!("symlink: {e}"),
        }
        fs::remove_file(&list).unwrap();
        check_stamp(&list);
        check_stamp(&link);
        fs::write(&list, b"replacement").unwrap();
        check_stamp(&list);
        check_stamp(&hard);
    }
}
