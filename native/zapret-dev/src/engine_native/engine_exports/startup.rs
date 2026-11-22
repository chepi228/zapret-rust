//! Bind the native parameter slots and host callouts to the shared startup policy.
use super::{DLOG, DLOG_ERR, Log, startup_params::PARAMS, state::params_address};
use core::{
    ffi::{c_char, c_void},
    ptr,
};

type ProfileHead = *mut *mut c_void;
type Check = unsafe extern "C" fn() -> bool;
type Summary = unsafe extern "C" fn();
type Report = unsafe extern "C" fn(u32, u32, *const c_char);
type Environment = unsafe extern "C" fn(*const c_char) -> *mut c_char;

#[repr(C)]
struct ValidationTarget {
    profiles: ProfileHead,
    templates: ProfileHead,
    debug_file: *const c_char,
    auto_log: *const c_char,
    profile_count: u32,
    template_count: u32,
    log_target: *const u32,
    writable: *const bool,
    server: *const bool,
}

#[repr(C)]
struct ValidationOps {
    add_default: Option<unsafe extern "C" fn(ProfileHead) -> bool>,
    writable: Option<Check>,
    label: Option<unsafe extern "C" fn(*const c_char) -> bool>,
    defaults: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    debug: Option<unsafe extern "C" fn(*const c_void, *const c_char)>,
    checks: [Option<Check>; 4],
    summary: Option<Summary>,
    report: Option<Report>,
    destroy_templates: Option<unsafe extern "C" fn(ProfileHead)>,
}

#[repr(C)]
struct ValidationLogs {
    debug: Log,
    console: Log,
    error: Log,
    environment: Environment,
}

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<ValidationTarget>() == 7 * pointer + 8);
    assert!(size_of::<ValidationOps>() == 12 * pointer);
    assert!(size_of::<ValidationLogs>() == 4 * pointer);
};

unsafe extern "C" {
    fn DLOG_CONDUP(format: *const c_char, ...) -> core::ffi::c_int;
    fn wf_getenv(name: *const c_char) -> *mut c_char;
    fn native_profile_add_default(head: ProfileHead) -> bool;
    fn make_writable_dir() -> bool;
    fn ensure_file_access(path: *const c_char) -> bool;
    fn filter_defaults(profile: *mut c_void) -> bool;
    fn LuaDesyncDebug(profile: *const c_void, entity: *const c_char);
    fn test_list_files() -> bool;
    fn lua_test_init_script_files() -> bool;
    fn LoadAllHostLists() -> bool;
    fn LoadAllIpsets() -> bool;
    fn HostlistsDebug();
    fn IpsetsDebug();
    fn BlobDebug();
    fn dp_list_destroy(head: ProfileHead);

    fn zapret_profile_startup_validate(target: &ValidationTarget, ops: &ValidationOps) -> u32;
    fn zapret_profile_startup_status(status: u32, error: Log) -> bool;
    fn zapret_profile_startup_report(
        event: u32,
        count: u32,
        path: *const c_char,
        logs: &ValidationLogs,
    );
    fn zapret_profile_startup_summary(hosts: Summary, ips: Summary, blobs: Summary, debug: Log);

    fn zapret_startup_icon(ops: *const c_void) -> u32;
    fn wf_error(error: u32);
    fn zapret_native_config_read(
        filename: *const c_char,
        words: *mut c_void,
        allocator: *const c_void,
        set_error: unsafe extern "C" fn(u32),
        report: Log,
    ) -> bool;
}

unsafe extern "C" fn validation_summary() {
    unsafe { zapret_profile_startup_summary(HostlistsDebug, IpsetsDebug, BlobDebug, DLOG) };
}

unsafe extern "C" fn validation_report(event: u32, count: u32, path: *const c_char) {
    const LOGS: ValidationLogs = ValidationLogs {
        debug: DLOG,
        console: DLOG_CONDUP,
        error: DLOG_ERR,
        environment: wf_getenv,
    };
    unsafe { zapret_profile_startup_report(event, count, path, &LOGS) };
}

const VALIDATION_OPS: ValidationOps = ValidationOps {
    add_default: Some(native_profile_add_default),
    writable: Some(make_writable_dir),
    label: Some(ensure_file_access),
    defaults: Some(filter_defaults),
    debug: Some(LuaDesyncDebug),
    checks: [
        Some(test_list_files),
        Some(lua_test_init_script_files),
        Some(LoadAllHostLists),
        Some(LoadAllIpsets),
    ],
    summary: Some(validation_summary),
    report: Some(validation_report),
    destroy_templates: Some(dp_list_destroy),
};

#[unsafe(no_mangle)]
unsafe extern "C" fn native_startup_validate(profile_count: u32, template_count: u32) -> bool {
    let params = params_address();
    // The policy reads the live fields after the host callbacks that precede them.
    let field = |offset| unsafe { params.add(offset) };
    let target = ValidationTarget {
        profiles: field(PARAMS.profile_head).cast(),
        templates: field(PARAMS.template_head).cast(),
        debug_file: field(PARAMS.debug_logfile).cast(),
        auto_log: field(PARAMS.auto_hostlist_log).cast(),
        profile_count,
        template_count,
        log_target: field(PARAMS.debug_target).cast(),
        writable: field(PARAMS.writable_enabled).cast(),
        server: field(PARAMS.server).cast(),
    };
    unsafe {
        zapret_profile_startup_status(
            zapret_profile_startup_validate(&target, &VALIDATION_OPS),
            DLOG_ERR,
        )
    }
}

#[unsafe(export_name = "WinSetIcon")]
extern "C" fn win_set_icon() {
    unsafe { zapret_startup_icon(ptr::null()) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_config_from_file(filename: *const c_char) -> bool {
    // wexp starts the pinned params record. The native caller handles failure
    // and process cleanup after this entry has returned.
    unsafe {
        zapret_native_config_read(
            filename,
            params_address().cast(),
            ptr::null(),
            wf_error,
            DLOG_ERR,
        )
    }
}
