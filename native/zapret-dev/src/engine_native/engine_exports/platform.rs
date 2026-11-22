//! Publish the engine's Windows status through the original C ABI.
use super::state::{WIN32_ERROR, params_address};
use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

unsafe extern "system" {
    fn SetLastError(error: u32);
}

unsafe extern "C" {
    fn logical_net_filter_present() -> bool;
    fn wf_error(error: u32);
    fn zapret_security_label_w(path: *const u16, rid: u32, flags: u32, ops: *const c_void) -> u32;
    fn zapret_security_label_file(
        path: *const c_char,
        rid: u32,
        flags: u32,
        ops: *const c_void,
    ) -> u32;
    fn zapret_security_label_object(
        handle: *mut c_void,
        kind: c_int,
        rid: u32,
        revision: u32,
        flags: u32,
        ops: *const c_void,
    ) -> u32;
    fn zapret_security_ensure(path: *const c_char, directory: bool, ops: *const c_void) -> u32;
    fn zapret_security_appdata(ops: *const c_void) -> u32;
    fn zapret_security_job(ops: *const c_void) -> u32;
    fn zapret_security_sandbox(
        network_filter: unsafe extern "C" fn() -> bool,
        native_error: *mut u32,
        ops: *const c_void,
    ) -> u32;
    fn zapret_security_adjust(
        token: *mut c_void,
        names: *const *const c_char,
        enable: bool,
        ops: *const c_void,
    ) -> u32;
    fn zapret_security_adjust_current(
        names: *const *const c_char,
        enable: bool,
        ops: *const c_void,
    ) -> u32;
    fn zapret_security_low(ops: *const c_void) -> u32;
    fn zapret_writable_prepare(path: *const c_char, ops: *const c_void) -> u32;
    fn zapret_route_source(
        version: u32,
        target: *const u8,
        output: *mut u8,
        ops: *const c_void,
    ) -> bool;
}

fn publish(error: u32) -> bool {
    unsafe {
        (&raw mut WIN32_ERROR).write(error);
        SetLastError(error);
    }
    error == 0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn SetMandatoryLabelFileW(path: *const u16, rid: u32, flags: u32) -> c_int {
    c_int::from(publish(unsafe {
        zapret_security_label_w(path, rid, flags, ptr::null())
    }))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn SetMandatoryLabelFile(path: *const c_char, rid: u32, flags: u32) -> c_int {
    c_int::from(publish(unsafe {
        zapret_security_label_file(path, rid, flags, ptr::null())
    }))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn SetMandatoryLabelObject(
    handle: *mut c_void,
    kind: c_int,
    rid: u32,
    revision: u32,
    flags: u32,
) -> c_int {
    c_int::from(publish(unsafe {
        zapret_security_label_object(handle, kind, rid, revision, flags, ptr::null())
    }))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ensure_file_access(path: *const c_char) -> bool {
    publish(unsafe { zapret_security_ensure(path, false, ptr::null()) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ensure_dir_access(path: *const c_char) -> bool {
    publish(unsafe { zapret_security_ensure(path, true, ptr::null()) })
}

#[unsafe(no_mangle)]
extern "C" fn prepare_low_appdata() -> bool {
    publish(unsafe { zapret_security_appdata(ptr::null()) })
}

#[unsafe(no_mangle)]
extern "C" fn JobSandbox() -> c_int {
    c_int::from(publish(unsafe { zapret_security_job(ptr::null()) }))
}

#[unsafe(no_mangle)]
extern "C" fn win_sandbox() -> bool {
    publish(unsafe {
        zapret_security_sandbox(logical_net_filter_present, ptr::null_mut(), ptr::null())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AdjustPrivileges(
    token: *mut c_void,
    names: *const *const c_char,
    enable: c_int,
) -> c_int {
    c_int::from(publish(unsafe {
        zapret_security_adjust(token, names, enable != 0, ptr::null())
    }))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AdjustPrivilegesForCurrentProcess(
    names: *const *const c_char,
    enable: c_int,
) -> c_int {
    c_int::from(publish(unsafe {
        zapret_security_adjust_current(names, enable != 0, ptr::null())
    }))
}

#[unsafe(no_mangle)]
extern "C" fn LowMandatoryLevel() -> c_int {
    c_int::from(publish(unsafe { zapret_security_low(ptr::null()) }))
}

#[unsafe(no_mangle)]
extern "C" fn make_writable_dir() -> bool {
    // windows_exports_abi.h pins the path in the live engine parameters.
    let path = unsafe {
        params_address()
            .add(super::startup_params::PARAMS.writable_dir)
            .cast()
    };
    let error = unsafe { zapret_writable_prepare(path, ptr::null()) };
    let success = publish(error);
    if !success {
        unsafe { wf_error(error) };
    }
    success
}

#[unsafe(no_mangle)]
unsafe extern "C" fn get_source_ip4(target: *const u8, output: *mut u8) -> bool {
    unsafe { zapret_route_source(4, target, output, ptr::null()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn get_source_ip6(target: *const u8, output: *mut u8) -> bool {
    unsafe { zapret_route_source(6, target, output, ptr::null()) }
}
