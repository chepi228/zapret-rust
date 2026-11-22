//! Native entry points and Win32/UCRT bindings for the UTF-8 file facade.
use super::{Environment, FileIo, Flags, Metadata, error_class, zapret_file_facade};
use crate::{
    engine_bootstrap::ucrt::{_errno, Time},
    files,
};
use libc::FILE;
use std::{
    ffi::{c_char, c_int, c_long, c_void},
    mem::offset_of,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, SetLastError},
    System::Threading::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive, SRWLOCK, SRWLOCK_INIT},
};

unsafe extern "C" {
    fn strcasecmp(first: *const c_char, second: *const c_char) -> c_int;
    fn _wfdopen(descriptor: c_int, mode: *const u16) -> *mut FILE;
    fn _wchdir(path: *const u16) -> c_int;
}

const FLAGS: Flags = Flags {
    append: libc::O_APPEND,
    text: libc::O_TEXT,
    binary: libc::O_BINARY,
    noinherit: libc::O_NOINHERIT,
    rdwr: libc::O_RDWR,
    rdonly: libc::O_RDONLY,
    wronly: libc::O_WRONLY,
    create: libc::O_CREAT,
    truncate: libc::O_TRUNC,
    exclusive: libc::O_EXCL,
    directory: libc::S_IFDIR,
    regular: libc::S_IFREG,
};
const ERRNO: [c_int; 14] = [
    libc::EIO,
    libc::ENOENT,
    libc::EACCES,
    libc::EEXIST,
    libc::EXDEV,
    libc::ENOTDIR,
    libc::ENOTEMPTY,
    libc::ENOSPC,
    libc::ENOMEM,
    libc::ENAMETOOLONG,
    libc::EILSEQ,
    libc::EINVAL,
    libc::EOVERFLOW,
    libc::ERANGE,
];

// All accesses through the head pointer occur under the exclusive SRW lock.
static mut ENVIRONMENT: *mut Environment = ptr::null_mut();
static mut ENVIRONMENT_LOCK: SRWLOCK = SRWLOCK_INIT;

extern "C" fn lock_environment(acquire: bool) {
    let lock = &raw mut ENVIRONMENT_LOCK;
    unsafe {
        if acquire {
            AcquireSRWLockExclusive(lock);
        } else {
            ReleaseSRWLockExclusive(lock);
        }
    }
}

extern "C" fn read_errno() -> c_int {
    unsafe { _errno().read() }
}

extern "C" fn write_errno(error: c_int) {
    unsafe { _errno().write(error) };
}

extern "C" fn write_errno_class(category: u32) {
    write_errno(ERRNO[category as usize]);
}

#[repr(C)]
struct Timespec {
    tv_sec: Time,
    tv_nsec: c_long,
}

#[repr(C)]
struct FileInfo {
    device: u64,
    inode: u64,
    size: i64,
    mode: u32,
    modified: Timespec,
}

unsafe extern "C" fn publish_stat(output: *mut c_void, raw: *const Metadata, mode: u32) {
    let output = output.cast::<FileInfo>();
    // The C entry writes the fields individually and leaves padding intact.
    unsafe {
        let raw = &*raw;
        (&raw mut (*output).device).write(raw.device);
        (&raw mut (*output).inode).write(raw.inode);
        (&raw mut (*output).size).write(raw.size);
        (&raw mut (*output).mode).write(mode);
        (&raw mut (*output).modified.tv_sec).write(raw.seconds);
        (&raw mut (*output).modified.tv_nsec).write(raw.nanoseconds as c_long);
    }
}

const IO: FileIo = FileIo {
    allocate: libc::malloc,
    realpath: files::zapret_wf_realpath,
    stat: files::zapret_wf_stat,
    exedir: files::zapret_wf_exedir,
    getenv: files::zapret_wf_getenv,
    setenv: files::zapret_wf_setenv,
    open: files::zapret_wf_open,
    getcwd: files::zapret_wf_getcwd,
    path: files::zapret_wf_path,
    utf8: files::zapret_wf_utf8,
    allocate_zeroed: libc::calloc,
    duplicate: libc::strdup,
    release: libc::free,
    compare_names: strcasecmp,
    lock_environment,
    read_errno,
    write_errno,
    report_error: wf_error,
    descriptor: libc::open_osfhandle,
    close_handle: CloseHandle,
    fdopen: _wfdopen,
    close_descriptor: libc::close,
    publish_stat,
    write_errno_class,
    chdir: _wchdir,
};

unsafe fn facade(operation: u32, a: usize, b: usize, c: usize, d: usize) -> usize {
    unsafe { zapret_file_facade(operation, a, b, c, d, &FLAGS, &IO) }
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn wf_error(error: u32) {
    write_errno_class(error_class(error));
    unsafe { SetLastError(error) };
}

fn status(error: u32) -> c_int {
    unsafe { facade(0, error as usize, 0, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_path_utf16(path: *const c_char) -> *mut u16 {
    unsafe { facade(10, path as usize, 0, 0, 0) as *mut u16 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_wide_to_utf8(text: *const u16) -> *mut c_char {
    unsafe { facade(11, text as usize, 0, 0, 0) as *mut c_char }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_realpath(path: *const c_char, output: *mut c_char) -> *mut c_char {
    unsafe { facade(1, path as usize, output as usize, 0, 0) as *mut c_char }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_realpath_any(path: *const c_char, output: *mut c_char) -> bool {
    unsafe { facade(1, path as usize, output as usize, 1, 0) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_file_stat(path: *const c_char, output: *mut FileInfo) -> c_int {
    unsafe { facade(2, path as usize, output as usize, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_set_exedir() -> bool {
    unsafe { facade(3, (&raw mut ENVIRONMENT) as usize, 0, 0, 0) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_getenv(name: *const c_char) -> *mut c_char {
    unsafe { facade(4, name as usize, (&raw mut ENVIRONMENT) as usize, 0, 0) as *mut c_char }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    unsafe {
        facade(
            5,
            name as usize,
            value as usize,
            overwrite as usize,
            (&raw mut ENVIRONMENT) as usize,
        ) as c_int
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    let permissions = (libc::S_IREAD | libc::S_IWRITE) as usize;
    unsafe { facade(6, path as usize, mode as usize, permissions, 0) as *mut FILE }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_open_mode(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    unsafe { facade(7, path as usize, flags as usize, mode as usize, 0) as c_int }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_chdir(path: *const c_char) -> c_int {
    unsafe { facade(12, path as usize, 0, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_getcwd(output: *mut c_char, size: usize) -> *mut c_char {
    unsafe { facade(8, output as usize, size, 0, 0) as *mut c_char }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_mkdir(path: *const c_char, _mode: c_int) -> c_int {
    // Windows inherits the parent DACL. The engine sets its label separately.
    status(unsafe { files::zapret_wf_mkdir(path) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_unlink(path: *const c_char) -> c_int {
    status(unsafe { files::zapret_wf_unlink(path) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_remove(path: *const c_char) -> c_int {
    status(unsafe { files::zapret_wf_remove(path) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_rename(from: *const c_char, to: *const c_char) -> c_int {
    status(unsafe { files::zapret_wf_rename(from, to) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wf_state_result(error: u32) -> bool {
    unsafe { facade(9, error as usize, 0, 0, 0) != 0 }
}

const _: () = {
    assert!(size_of::<FileInfo>() == 48);
    assert!(offset_of!(FileInfo, modified) == 32);
    assert!(size_of::<Timespec>() == 16);
    assert!(offset_of!(Timespec, tv_nsec) == 8);
};
