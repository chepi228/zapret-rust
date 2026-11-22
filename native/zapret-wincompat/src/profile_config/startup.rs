//! Validate parsed native startup state before building capture and initializing the VM.
use super::*;
use crate::native_logging_entry::LogSink;

#[repr(C)]
struct Target {
    profiles: *mut *mut Entry,
    templates: *mut *mut Entry,
    debug_file: *const c_char,
    auto_log: *const c_char,
    profile_count: u32,
    template_count: u32,
    log_target: *const u32,
    writable: *const bool,
    server: *const bool,
}
#[repr(C)]
struct StartupOps {
    add_default: Option<unsafe extern "C" fn(*mut *mut Entry) -> bool>,
    writable: Option<unsafe extern "C" fn() -> bool>,
    label: Option<unsafe extern "C" fn(*const c_char) -> bool>,
    defaults: Option<unsafe extern "C" fn(*mut Profile) -> bool>,
    debug: Option<unsafe extern "C" fn(*const Profile, *const c_char)>,
    checks: [Option<unsafe extern "C" fn() -> bool>; 4],
    summary: Option<unsafe extern "C" fn()>,
    report: Option<unsafe extern "C" fn(u32, u32, *const c_char)>,
    destroy_templates: Option<unsafe extern "C" fn(*mut *mut Entry)>,
}
fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_add_default(head: *mut *mut Entry, ops: *const Ops) -> bool {
    if !valid(head) || !valid(ops) {
        return false;
    }
    let ops = unsafe { &*ops };
    // Neither the list nor the previous tail changes until both allocations succeed.
    let name = unsafe { (ops.duplicate)(c"no_action".as_ptr()) };
    if name.is_null() {
        return false;
    }
    let entry = unsafe { zapret_profile_add(head, ops) };
    if entry.is_null() {
        unsafe { (ops.release)(name.cast()) };
        return false;
    }
    unsafe { (*entry).profile.name = name };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_startup_validate(
    target: *const Target,
    ops: *const StartupOps,
) -> u32 {
    if !valid(target) || !valid(ops) {
        return 9;
    }
    let target = unsafe { &*target };
    let ops = unsafe { &*ops };
    if !valid(target.profiles)
        || !valid(target.templates)
        || target.debug_file.is_null()
        || target.auto_log.is_null()
        || !valid(target.log_target)
        || !valid(target.writable)
        || !valid(target.server)
    {
        return 9;
    }
    let (
        Some(add_default),
        Some(writable),
        Some(label),
        Some(defaults),
        Some(debug),
        Some(summary),
        Some(report),
        Some(destroy_templates),
    ) = (
        ops.add_default,
        ops.writable,
        ops.label,
        ops.defaults,
        ops.debug,
        ops.summary,
        ops.report,
        ops.destroy_templates,
    )
    else {
        return 9;
    };
    let [Some(lists), Some(scripts), Some(hosts), Some(ips)] = ops.checks else {
        return 9;
    };
    unsafe { report(0, 0, ptr::null()) };
    if !unsafe { add_default(target.profiles) } {
        return 1;
    }
    unsafe {
        report(1, target.profile_count, ptr::null());
        report(2, target.template_count, ptr::null())
    };
    if unsafe { target.writable.read() } {
        if !unsafe { writable() } {
            return 2;
        }
        unsafe { report(3, 0, ptr::null()) };
    }
    if unsafe { target.log_target.read() } == 1 && !unsafe { label(target.debug_file) } {
        unsafe { report(4, 0, target.debug_file) };
    }
    if unsafe { target.auto_log.read() } != 0 && !unsafe { label(target.auto_log) } {
        unsafe { report(5, 0, target.auto_log) };
    }
    let mut entry = unsafe { target.profiles.read() };
    while !entry.is_null() {
        let profile = unsafe { ptr::addr_of_mut!((*entry).profile) };
        if unsafe { target.server.read() && !(*profile).automatic.is_null() } {
            return 3;
        }
        let automatic = unsafe { (*profile).automatic };
        if !automatic.is_null() {
            // A registered ListFile's stable C prefix starts with its borrowed filename.
            let filename = unsafe { automatic.cast::<*const c_char>().read() };
            if filename.is_null() {
                return 9;
            }
            if !unsafe { label(filename) } {
                // The access callback precedes the diagnostic's second native read.
                let automatic = unsafe { (*profile).automatic };
                if automatic.is_null() {
                    return 9;
                }
                let filename = unsafe { automatic.cast::<*const c_char>().read() };
                unsafe { report(6, 0, filename) };
            }
        }
        if !unsafe { defaults(profile) } {
            return 4;
        }
        unsafe { debug(profile, c"profile".as_ptr()) };
        entry = unsafe { (*entry).next };
    }
    let mut entry = unsafe { target.templates.read() };
    while !entry.is_null() {
        unsafe { debug(ptr::addr_of!((*entry).profile), c"template".as_ptr()) };
        entry = unsafe { (*entry).next };
    }
    for (step, check) in [lists, scripts, hosts, ips].into_iter().enumerate() {
        if !unsafe { check() } {
            return 5 + step as u32;
        }
    }
    unsafe {
        summary();
        destroy_templates(target.templates)
    };
    0
}

#[repr(C)]
struct StartupLogs {
    debug: LogSink,
    console: LogSink,
    error: LogSink,
    environment: unsafe extern "C" fn(*const c_char) -> *const c_char,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_startup_report(
    event: u32,
    count: u32,
    path: *const c_char,
    logs: &StartupLogs,
) {
    unsafe {
        match event {
            0 => (logs.debug)(c"adding low-priority default empty desync profile\n".as_ptr()),
            1 => (logs.console)(
                c"we have %u user defined desync profile(s) and default low priority profile 0\n".as_ptr(),
                count,
            ),
            2 => (logs.console)(c"we have %u user defined desync template(s)\n".as_ptr(), count),
            3 => (logs.debug)(c"LUA writable dir : %s\n".as_ptr(), (logs.environment)(c"WRITABLE".as_ptr())),
            4 => (logs.error)(
                c"could not make '%s' accessible. log file may not be writable after privilege drop\n".as_ptr(),
                path,
            ),
            5 => (logs.error)(
                c"could not make '%s' accessible. auto hostlist debug log may not be writable after privilege drop\n".as_ptr(),
                path,
            ),
            _ => (logs.error)(
                c"could not make '%s' accessible. auto hostlist file may not be writable after privilege drop\n".as_ptr(),
                path,
            ),
        };
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_profile_startup_status(status: u32, error: LogSink) -> bool {
    let message = match status {
        0 => return true,
        1 => c"desync_profile_add: out of memory\n",
        2 => c"could not make writable dir for LUA\n",
        3 => c"autohostlists not supported in server mode\n",
        7 => c"hostlists load failed\n",
        8 => c"ipset load failed\n",
        9 => c"invalid startup validation storage\n",
        _ => return false,
    };
    unsafe {
        error(message.as_ptr());
    }
    false
}

#[unsafe(no_mangle)]
extern "C" fn zapret_profile_startup_summary(
    hosts: unsafe extern "C" fn(),
    ips: unsafe extern "C" fn(),
    blobs: unsafe extern "C" fn(),
    debug: LogSink,
) {
    unsafe {
        debug(c"\nlists summary:\n".as_ptr());
        hosts();
        ips();
        debug(c"\nblobs summary:\n".as_ptr());
        blobs();
        debug(c"\n".as_ptr());
    }
}
#[cfg(windows)]
const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<Target>() == 7 * pointer + 8);
    assert!(size_of::<StartupOps>() == 12 * pointer);
    assert!(size_of::<StartupLogs>() == 4 * pointer);
};
