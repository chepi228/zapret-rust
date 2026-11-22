//! Startup checks and registration around the shared list registry.
use super::{FileRegistry, HostPool, ListFile, zapret_list_files_at};
use crate::native_logging_entry::LogSink;
use std::{
    ffi::{c_char, c_void},
    ptr,
};

type Probe = unsafe extern "C" fn(*const c_char) -> bool;
type ProbeError = unsafe extern "C" fn(u32, *const ListFile);
type RegisterError = unsafe extern "C" fn(u32, *const c_char);
type Register = unsafe extern "C" fn(*mut c_void, u32, *const c_char) -> *mut ListFile;
type InsertHost = unsafe extern "C" fn(*mut *mut HostPool, *const c_char, usize, u32) -> bool;
type Perror = unsafe extern "C" fn(*const c_char) -> i32;

unsafe fn access_failure(
    label: &std::ffi::CStr,
    filename: *const c_char,
    kind: *const c_char,
    perror: Perror,
    error: LogSink,
) -> bool {
    unsafe {
        perror(label.as_ptr());
        error(
            c"cannot access %s file '%s'. in-memory content remains unchanged.\n".as_ptr(),
            kind,
            filename,
        );
    }
    false
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_stamp_checked(
    filename: *const c_char,
    stamp: *mut c_void,
    kind: *const c_char,
    read_stamp: unsafe extern "C" fn(*const c_char, *mut c_void) -> bool,
    perror: Perror,
    error: LogSink,
) -> bool {
    unsafe {
        read_stamp(filename, stamp)
            || access_failure(c"file_mod_signature", filename, kind, perror, error)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_read_checked(
    filename: *const c_char,
    kind: *const c_char,
    flags: i32,
    probe: unsafe extern "C" fn(*const c_char, i32) -> bool,
    perror: Perror,
    error: LogSink,
) -> bool {
    unsafe {
        probe(filename, flags) || access_failure(c"file_open_test", filename, kind, perror, error)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_startup_report(
    kind: u32,
    file: *const ListFile,
    perror: Perror,
    error: LogSink,
) {
    unsafe {
        perror(c"file_open_test".as_ptr());
        // The errno reporter can change the borrowed filename.
        error(zapret_list_startup_error(kind), (*file).filename);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_startup_probe(
    hosts: *const *mut FileRegistry,
    ips: *const *mut FileRegistry,
    probe: Probe,
    report: ProbeError,
) -> bool {
    for (kind, slot) in [(0, hosts), (1, ips)] {
        let mut index = 0;
        loop {
            // The probe can replace the registry before the next observation.
            let file = unsafe { zapret_list_files_at(slot.read(), index) };
            if file.is_null() {
                break;
            }
            let name = unsafe { (*file).filename };
            if !name.is_null() && !unsafe { probe(name) } {
                unsafe { report(kind, file) };
                return false;
            }
            index += 1;
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_register_checked(
    profile: *mut c_void,
    excluded: bool,
    kind: u32,
    name: *const c_char,
    size: Probe,
    report: RegisterError,
    register: Register,
) -> *mut ListFile {
    if kind > 1 {
        return ptr::null_mut();
    }
    if !name.is_null() && !unsafe { size(name) } {
        unsafe { report(kind, name) };
        return ptr::null_mut();
    }
    // Field projection follows the probe. A failed probe never touches the profile.
    unsafe { register(profile, kind * 2 + u32::from(excluded), name) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_host_nonempty(
    slot: *mut *mut HostPool,
    insert: InsertHost,
) -> bool {
    const SENTINEL: &std::ffi::CStr = c"@&()";
    !unsafe { slot.read() }.is_null()
        || unsafe { insert(slot, SENTINEL.as_ptr(), SENTINEL.to_bytes().len(), 0) }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_list_startup_error(kind: u32) -> *const c_char {
    match kind {
        0 => c"cannot access hostlist file '%s'\n".as_ptr(),
        1 => c"cannot access ipset file '%s'\n".as_ptr(),
        _ => ptr::null(),
    }
}
