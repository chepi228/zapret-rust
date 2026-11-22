//! Win32 operations used by the upstream engine and LuaJIT file adapter.
mod engine;
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    mem::{offset_of, size_of},
    ptr::{self, null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ARITHMETIC_OVERFLOW, ERROR_ENVVAR_NOT_FOUND, ERROR_FILE_NOT_FOUND,
        ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_DRIVE, ERROR_INVALID_FUNCTION,
        ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED,
        ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, SetLastError, WIN32_ERROR,
    },
    Globalization::{
        CP_UTF8, MB_ERR_INVALID_CHARS, MultiByteToWideChar, WC_ERR_INVALID_CHARS,
        WideCharToMultiByte,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW,
        DELETE, DeleteFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_RANDOM_ACCESS,
        FILE_FLAG_SEQUENTIAL_SCAN, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileRenameInfo, FileRenameInfoEx,
        GetFileAttributesW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        GetFullPathNameW, INVALID_FILE_ATTRIBUTES, OPEN_ALWAYS, OPEN_EXISTING, RemoveDirectoryW,
        SYNCHRONIZE, SetFileInformationByHandle, TRUNCATE_EXISTING, VOLUME_NAME_DOS,
    },
    System::{
        Environment::{GetCurrentDirectoryW, GetEnvironmentVariableW, SetEnvironmentVariableW},
        LibraryLoader::GetModuleFileNameW,
        WindowsProgramming::{
            FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
        },
    },
};

pub(crate) type WinResult<T> = Result<T, WIN32_ERROR>;
type CAlloc = unsafe extern "C" fn(usize) -> *mut c_void;

const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const MAX_WIN32_PATH: u32 = 32_760;
const BACKSLASH: u16 = b'\\' as u16;
const EXTENDED: &[u16] = &[BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];
const DEVICE: &[u16] = &[BACKSLASH, BACKSLASH, b'.' as u16, BACKSLASH];
const EXTENDED_UNC: &[u16] = &[
    BACKSLASH,
    BACKSLASH,
    b'?' as u16,
    BACKSLASH,
    b'U' as u16,
    b'N' as u16,
    b'C' as u16,
    BACKSLASH,
];
const CYGDRIVE: &[u16] = &[
    BACKSLASH,
    b'c' as u16,
    b'y' as u16,
    b'g' as u16,
    b'd' as u16,
    b'r' as u16,
    b'i' as u16,
    b'v' as u16,
    b'e' as u16,
    BACKSLASH,
];

pub(crate) fn last_error() -> WIN32_ERROR {
    // Call before another Win32 operation or dropping an owned handle.
    unsafe { GetLastError() }
}

pub(crate) fn win32_ok(ok: i32) -> WinResult<()> {
    if ok == 0 { Err(last_error()) } else { Ok(()) }
}

pub(crate) fn buffer<T: Copy + Default>(len: usize) -> WinResult<Vec<T>> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(len)
        .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    storage.resize(len, T::default());
    Ok(storage)
}

pub(crate) fn path_input(path: *const c_char) -> WinResult<Vec<u16>> {
    if path.is_null() {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    // The private C ABI passes NUL-terminated input for the duration of the call.
    let path = unsafe { CStr::from_ptr(path) };
    if path.is_empty() {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    let mut wide = utf16(path)?;
    for unit in &mut wide {
        if *unit == u16::from(b'/') {
            *unit = BACKSLASH;
        }
    }
    // Old local state may contain /cygdrive/<letter> paths.
    if let Some([drive, separator, ..]) = wide.strip_prefix(CYGDRIVE) {
        if ((u16::from(b'a')..=u16::from(b'z')).contains(drive)
            || (u16::from(b'A')..=u16::from(b'Z')).contains(drive))
            && (*separator == BACKSLASH || *separator == 0)
        {
            let drive = *drive;
            if *separator == 0 {
                wide.truncate(4);
                wide[2] = BACKSLASH;
                wide[3] = 0;
            } else {
                wide.copy_within(CYGDRIVE.len() + 1.., 2);
                wide.truncate(wide.len() - (CYGDRIVE.len() - 1));
            }
            wide[0] = drive;
            wide[1] = u16::from(b':');
        }
    }
    if wide.starts_with(EXTENDED) || wide.starts_with(DEVICE) {
        return Ok(wide);
    }

    // Win32 resolves drive-relative paths and per-drive current directories.
    let size = unsafe { GetFullPathNameW(wide.as_ptr(), 0, null_mut(), null_mut()) };
    if size == 0 {
        return Err(last_error());
    }
    if size > MAX_WIN32_PATH {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    let mut absolute = buffer::<u16>(size as usize + EXTENDED_UNC.len())?;
    let length = unsafe {
        GetFullPathNameW(
            wide.as_ptr(),
            size,
            absolute.as_mut_ptr().add(EXTENDED_UNC.len()),
            null_mut(),
        )
    };
    if length == 0 {
        return Err(last_error());
    }
    if length >= size {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    let start = EXTENDED_UNC.len();
    absolute.truncate(start + length as usize + 1);
    let full = &absolute[start..];
    let (prefix, skip) = if full.starts_with(EXTENDED) || full.starts_with(DEVICE) {
        (&[][..], 0)
    } else if full.starts_with(&[BACKSLASH, BACKSLASH]) {
        (EXTENDED_UNC, 2)
    } else {
        (EXTENDED, 0)
    };
    absolute[..prefix.len()].copy_from_slice(prefix);
    absolute.copy_within(start + skip.., prefix.len());
    absolute.truncate(prefix.len() + length as usize + 1 - skip);
    Ok(absolute)
}

fn utf16(text: &CStr) -> WinResult<Vec<u16>> {
    let input = text.as_ptr().cast();
    let size =
        unsafe { MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, null_mut(), 0) };
    if size == 0 {
        return Err(last_error());
    }
    let mut wide = buffer::<u16>(size as usize)?;
    let length = unsafe {
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            input,
            -1,
            wide.as_mut_ptr(),
            size,
        )
    };
    win32_ok(length)?;
    Ok(wide)
}

/// # Safety
/// A non-null text pointer must point to a NUL-terminated UTF-16 string.
pub(crate) unsafe fn utf8(text: *const u16) -> WinResult<Vec<u8>> {
    let size = unsafe {
        WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text,
            -1,
            null_mut(),
            0,
            null(),
            null_mut(),
        )
    };
    if size == 0 {
        return Err(last_error());
    }
    let mut bytes = buffer::<u8>(size as usize)?;
    let length = unsafe {
        WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text,
            -1,
            bytes.as_mut_ptr(),
            size,
            null(),
            null_mut(),
        )
    };
    win32_ok(length)?;
    Ok(bytes)
}

fn path_output(path: &[u16]) -> WinResult<Vec<u8>> {
    let unc = path.starts_with(EXTENDED_UNC);
    let path = if unc {
        &path[6..]
    } else {
        path.strip_prefix(EXTENDED).unwrap_or(path)
    };
    let mut bytes = unsafe { utf8(path.as_ptr()) }?;
    if unc {
        bytes[0] = b'/';
    }
    for byte in &mut bytes {
        if *byte == b'\\' {
            *byte = b'/';
        }
    }
    Ok(bytes)
}

struct FileHandle(HANDLE);

impl FileHandle {
    fn open(path: &[u16], access: u32, flags: u32) -> WinResult<Self> {
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                SHARE,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(last_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn information(&self) -> WinResult<BY_HANDLE_FILE_INFORMATION> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        win32_ok(unsafe { GetFileInformationByHandle(self.0, &mut info) })?;
        Ok(info)
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn final_path(path: &[u16]) -> WinResult<Vec<u8>> {
    let file = FileHandle::open(path, 0, FILE_FLAG_BACKUP_SEMANTICS)?;
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let size = unsafe { GetFinalPathNameByHandleW(file.0, null_mut(), 0, flags) };
    if size == 0 {
        return Err(last_error());
    }
    let mut resolved = buffer::<u16>(size as usize + 1)?;
    let length =
        unsafe { GetFinalPathNameByHandleW(file.0, resolved.as_mut_ptr(), size + 1, flags) };
    if length == 0 {
        return Err(last_error());
    }
    if length > size {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    path_output(&resolved)
}

fn realpath(path: &[u16], allow_missing_leaf: bool) -> WinResult<Vec<u8>> {
    match final_path(path) {
        Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_INVALID_DRIVE)
            if allow_missing_leaf => {}
        result => return result,
    }
    let base = path
        .iter()
        .rposition(|&unit| unit == BACKSLASH)
        .ok_or(ERROR_PATH_NOT_FOUND)?
        + 1;
    if path[base] == 0 {
        return Err(ERROR_PATH_NOT_FOUND);
    }
    let name = unsafe { utf8(path[base..].as_ptr()) }?;
    let mut parent = buffer::<u16>(base + 1)?;
    parent[..base].copy_from_slice(&path[..base]);
    let mut result = final_path(&parent)?;
    result.pop(); // append the leaf before the final NUL
    result
        .try_reserve_exact(name.len() + 1)
        .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    if !result.is_empty() && !result.ends_with(b"/") {
        result.push(b'/');
    }
    result.extend_from_slice(&name);
    Ok(result)
}

pub(crate) fn current_directory_wide() -> WinResult<Vec<u16>> {
    let size = unsafe { GetCurrentDirectoryW(0, null_mut()) };
    if size == 0 {
        return Err(last_error());
    }
    let mut wide = buffer::<u16>(size as usize)?;
    let length = unsafe { GetCurrentDirectoryW(size, wide.as_mut_ptr()) };
    if length == 0 {
        return Err(last_error());
    }
    if length >= size {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    Ok(wide)
}

pub(crate) fn executable_path_wide() -> WinResult<Vec<u16>> {
    let mut wide = buffer::<u16>(32_768)?;
    let size =
        unsafe { GetModuleFileNameW(null_mut(), wide.as_mut_ptr(), wide.len() as u32) } as usize;
    if size == 0 {
        return Err(last_error());
    }
    if size >= wide.len() {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    wide.truncate(size + 1);
    Ok(wide)
}

fn executable_directory() -> WinResult<Vec<u8>> {
    let mut wide = executable_path_wide()?;
    let base = wide
        .iter()
        .rposition(|&unit| unit == BACKSLASH)
        .ok_or(ERROR_PATH_NOT_FOUND)?;
    let root = base == 2 && wide[1] == u16::from(b':');
    wide[base + usize::from(root)] = 0;
    path_output(&wide)
}

fn environment_variable(name: &CStr) -> WinResult<Vec<u8>> {
    let name = utf16(name)?;
    // Empty and absent variables both return zero.
    unsafe { SetLastError(ERROR_SUCCESS) };
    let size = unsafe { GetEnvironmentVariableW(name.as_ptr(), null_mut(), 0) };
    if size == 0 {
        let error = last_error();
        if error != ERROR_SUCCESS {
            return Err(error);
        }
    }
    let mut value = buffer::<u16>(size as usize + 1)?;
    let length = unsafe { GetEnvironmentVariableW(name.as_ptr(), value.as_mut_ptr(), size + 1) };
    if length > size || (length == 0 && last_error() == ERROR_ENVVAR_NOT_FOUND) {
        return Err(ERROR_ENVVAR_NOT_FOUND);
    }
    unsafe { utf8(value.as_ptr()) }
}

pub(crate) fn open_file(path: &[u16], flags: c_int, mode: c_int) -> WinResult<HANDLE> {
    use libc::{
        _O_SHORT_LIVED, O_APPEND, O_CREAT, O_EXCL, O_NOINHERIT, O_RANDOM, O_RDWR, O_SEQUENTIAL,
        O_TEMPORARY, O_TRUNC, O_WRONLY, S_IWRITE,
    };

    let mut access = if flags & O_WRONLY != 0 {
        GENERIC_WRITE
    } else {
        GENERIC_READ
    };
    if flags & O_RDWR != 0 {
        access = GENERIC_READ | GENERIC_WRITE;
    }
    if flags & O_APPEND != 0 {
        access = FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        if flags & O_RDWR != 0 {
            access |= GENERIC_READ;
        }
    }
    let disposition = match (
        flags & O_CREAT != 0,
        flags & O_EXCL != 0,
        flags & O_TRUNC != 0,
    ) {
        (true, true, _) => CREATE_NEW,
        (true, false, true) => CREATE_ALWAYS,
        (true, false, false) => OPEN_ALWAYS,
        (false, _, true) => TRUNCATE_EXISTING,
        (false, _, false) => OPEN_EXISTING,
    };
    let mut attributes = if flags & O_CREAT != 0 && mode & S_IWRITE == 0 {
        FILE_ATTRIBUTE_READONLY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if flags & _O_SHORT_LIVED != 0 {
        attributes |= FILE_ATTRIBUTE_TEMPORARY;
    }
    if flags & O_SEQUENTIAL != 0 {
        attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
    }
    if flags & O_RANDOM != 0 {
        attributes |= FILE_FLAG_RANDOM_ACCESS;
    }
    if flags & O_TEMPORARY != 0 {
        attributes |= FILE_FLAG_DELETE_ON_CLOSE;
        access |= DELETE;
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: i32::from(flags & O_NOINHERIT == 0),
    };
    let file = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            SHARE,
            &security,
            disposition,
            attributes,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        // Ownership transfers to UCRT via _open_osfhandle.
        Ok(file)
    }
}

fn file_index(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    join_words(info.nFileIndexHigh, info.nFileIndexLow)
}

fn join_words(high: u32, low: u32) -> u64 {
    u64::from(high) << 32 | u64::from(low)
}

#[repr(C)]
#[derive(Default)]
pub(super) struct FileMetadata {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) size: i64,
    pub(super) seconds: i64,
    pub(super) nanoseconds: u32,
    pub(super) directory: u32,
}

fn metadata(path: &[u16]) -> WinResult<FileMetadata> {
    let file = FileHandle::open(path, FILE_READ_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS)?;
    let data = file.information()?;
    let size = i64::try_from(join_words(data.nFileSizeHigh, data.nFileSizeLow))
        .map_err(|_| ERROR_ARITHMETIC_OVERFLOW)?;
    let ticks = join_words(
        data.ftLastWriteTime.dwHighDateTime,
        data.ftLastWriteTime.dwLowDateTime,
    );
    let unix_ticks = (ticks as i64).wrapping_sub(116_444_736_000_000_000);
    Ok(FileMetadata {
        device: u64::from(data.dwVolumeSerialNumber),
        inode: file_index(&data),
        size,
        seconds: unix_ticks.div_euclid(10_000_000),
        nanoseconds: unix_ticks.rem_euclid(10_000_000) as u32 * 100,
        directory: u32::from(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0),
    })
}

fn rename(from: &[u16], to: &[u16]) -> WinResult<()> {
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    let source = FileHandle::open(from, DELETE, flags)?;
    if let Ok(destination) = FileHandle::open(to, 0, flags) {
        if let (Ok(from), Ok(to)) = (source.information(), destination.information()) {
            if from.dwVolumeSerialNumber == to.dwVolumeSerialNumber
                && file_index(&from) == file_index(&to)
            {
                return Ok(());
            }
        }
    }

    // FILE_RENAME_INFO has a trailing UTF-16 array. Lay out its buffer with the
    // official field offsets and enough alignment for the handle member.
    let offset = offset_of!(FILE_RENAME_INFO, FileName);
    let size = offset + size_of_val(to);
    let name_size = size_of_val(to) - size_of::<u16>();
    let mut storage = buffer::<usize>(
        size.max(size_of::<FILE_RENAME_INFO>())
            .div_ceil(size_of::<usize>()),
    )?;
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // Storage is zeroed and aligned, and "to" includes its final NUL.
    unsafe {
        ptr::addr_of_mut!((*info).Anonymous.Flags)
            .write(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS);
        ptr::addr_of_mut!((*info).FileNameLength).write(name_size as u32);
        ptr::copy_nonoverlapping(to.as_ptr(), info.cast::<u8>().add(offset).cast(), to.len());
    }
    let result = win32_ok(unsafe {
        SetFileInformationByHandle(source.0, FileRenameInfoEx, info.cast(), size as u32)
    });
    match result {
        Err(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION) => {
            unsafe { ptr::addr_of_mut!((*info).Anonymous.Flags).write(1) };
            win32_ok(unsafe {
                SetFileInformationByHandle(source.0, FileRenameInfo, info.cast(), size as u32)
            })
        }
        _ => result,
    }
}

fn copy_to_c<T: Copy>(data: WinResult<Vec<T>>, allocate: CAlloc, out: *mut *mut T) -> WIN32_ERROR {
    let data = match data {
        Ok(data) => data,
        Err(err) => return err,
    };
    // The facade supplies the same CRT allocator the caller will free with.
    unsafe {
        let target = allocate(size_of_val(data.as_slice())).cast::<T>();
        if target.is_null() {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
        out.write(target);
    }
    ERROR_SUCCESS
}

fn status(result: WinResult<()>) -> WIN32_ERROR {
    result.err().unwrap_or(ERROR_SUCCESS)
}

// Private file operations shared by the facade and its C reference fixture.
// Input strings are NUL-terminated. Output slots are valid and writable for
// their declared C type. Only success writes outputs.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_path(
    path: *const c_char,
    alloc: CAlloc,
    out: *mut *mut u16,
) -> u32 {
    copy_to_c(path_input(path), alloc, out)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_utf8(
    text: *const u16,
    alloc: CAlloc,
    out: *mut *mut u8,
) -> u32 {
    copy_to_c(unsafe { utf8(text) }, alloc, out)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_realpath(
    path: *const c_char,
    allow_missing_leaf: c_int,
    alloc: CAlloc,
    out: *mut *mut u8,
) -> u32 {
    copy_to_c(
        path_input(path).and_then(|wide| realpath(&wide, allow_missing_leaf != 0)),
        alloc,
        out,
    )
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_stat(path: *const c_char, out: *mut FileMetadata) -> u32 {
    match path_input(path).and_then(|wide| metadata(&wide)) {
        Ok(info) => {
            unsafe { out.write(info) };
            ERROR_SUCCESS
        }
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_exedir(alloc: CAlloc, out: *mut *mut u8) -> u32 {
    copy_to_c(executable_directory(), alloc, out)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_getenv(
    name: *const c_char,
    alloc: CAlloc,
    out: *mut *mut u8,
) -> u32 {
    if name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    copy_to_c(
        environment_variable(unsafe { CStr::from_ptr(name) }),
        alloc,
        out,
    )
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_setenv(name: *const c_char, value: *const c_char) -> u32 {
    let set = || {
        let name = utf16(unsafe { CStr::from_ptr(name) })?;
        let value = utf16(unsafe { CStr::from_ptr(value) })?;
        win32_ok(unsafe { SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) })
    };
    status(set())
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_open(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
    out: *mut HANDLE,
) -> u32 {
    match path_input(path).and_then(|wide| open_file(&wide, flags, mode)) {
        Ok(handle) => {
            unsafe { out.write(handle) };
            ERROR_SUCCESS
        }
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_getcwd(alloc: CAlloc, out: *mut *mut u8) -> u32 {
    copy_to_c(
        current_directory_wide().and_then(|wide| path_output(&wide)),
        alloc,
        out,
    )
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_mkdir(path: *const c_char) -> u32 {
    status(
        path_input(path)
            .and_then(|wide| win32_ok(unsafe { CreateDirectoryW(wide.as_ptr(), null()) })),
    )
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_unlink(path: *const c_char) -> u32 {
    status(path_input(path).and_then(|wide| win32_ok(unsafe { DeleteFileW(wide.as_ptr()) })))
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_remove(path: *const c_char) -> u32 {
    let remove = || {
        let wide = path_input(path)?;
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(last_error());
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            win32_ok(unsafe { RemoveDirectoryW(wide.as_ptr()) })
        } else {
            win32_ok(unsafe { DeleteFileW(wide.as_ptr()) })
        }
    };
    status(remove())
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_wf_rename(from: *const c_char, to: *const c_char) -> u32 {
    let rename_paths = || rename(&path_input(from)?, &path_input(to)?);
    status(rename_paths())
}
