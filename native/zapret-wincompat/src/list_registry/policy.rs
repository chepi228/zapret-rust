//! Bulk reload and include/exclude decisions without per-element C iterators.
use super::{Collection, FileRegistry, ListFile, zapret_list_collection_empty};
use crate::{
    host_pool::host_match_logged,
    ip_pool::zapret_ip_check,
    logging::LogSink,
    profile_config::{profile_display_name, profile_number},
};
use std::ffi::{c_char, c_void};

#[repr(C)]
struct HostOps {
    reload: unsafe extern "C" fn(*mut ListFile, *mut bool) -> bool,
    automatic: unsafe extern "C" fn(),
    log: Option<LogSink>,
}
#[repr(C)]
struct IpOps {
    reload: unsafe extern "C" fn(*mut ListFile) -> bool,
    log: Option<LogSink>,
    format_address: unsafe extern "C" fn(*const u8, usize, *mut c_char, usize) -> usize,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_report_profile(profile: *const c_void, ipset: bool, log: LogSink) {
    let format = if ipset {
        c"* ipset check for profile %u (%s)\n"
    } else {
        c"* hostlist check for profile %u (%s)\n"
    };
    unsafe {
        log(
            format.as_ptr(),
            profile_number(profile),
            profile_display_name(profile),
        )
    };
}

unsafe fn report_file(file: *const ListFile, exclude: bool, log: Option<LogSink>) {
    if let Some(log) = log {
        let filename = unsafe { (*file).filename };
        let name = if filename.is_null() {
            c"fixed".as_ptr()
        } else {
            filename
        };
        let relation = if exclude { c"exclude" } else { c"include" };
        unsafe { log(c"[%s] %s ".as_ptr(), name, relation.as_ptr()) };
    }
}

unsafe fn reload_hosts(collection: *const Collection, ops: &HostOps) -> bool {
    let Some(collection) = (unsafe { collection.as_ref() }) else {
        return true;
    };
    let mut changed = false;
    for file in &collection.0 {
        if !unsafe { (ops.reload)(file.as_ptr(), &mut changed) } {
            return false;
        }
    }
    if changed {
        unsafe { (ops.automatic)() };
    }
    true
}
unsafe fn reload_ips(collection: *const Collection, ops: &IpOps) -> bool {
    let Some(collection) = (unsafe { collection.as_ref() }) else {
        return true;
    };
    for file in &collection.0 {
        if !unsafe { (ops.reload)(file.as_ptr()) } {
            return false;
        }
    }
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostlists_load_all(
    registry: *const FileRegistry,
    ops: &HostOps,
) -> bool {
    let mut changed = false;
    let mut okay = true;
    if let Some(registry) = unsafe { registry.as_ref() } {
        for file in registry.0.iter().rev() {
            // Attempt every global file, preserving the existing error order.
            if !unsafe { (ops.reload)(file.as_ptr(), &mut changed) } {
                okay = false;
            }
        }
    }
    if okay && changed {
        unsafe { (ops.automatic)() };
    }
    okay
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipsets_load_all(registry: *const FileRegistry, ops: &IpOps) -> bool {
    let mut okay = true;
    if let Some(registry) = unsafe { registry.as_ref() } {
        for file in registry.0.iter().rev() {
            if !unsafe { (ops.reload)(file.as_ptr()) } {
                okay = false;
            }
        }
    }
    okay
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostlists_reload_pair(
    include: *const Collection,
    exclude: *const Collection,
    ops: &HostOps,
) -> bool {
    unsafe { reload_hosts(include, ops) && reload_hosts(exclude, ops) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipsets_reload_pair(
    include: *const Collection,
    exclude: *const Collection,
    ops: &IpOps,
) -> bool {
    unsafe { reload_ips(include, ops) && reload_ips(exclude, ops) }
}
unsafe fn host_matches(
    collection: *const Collection,
    exclude: bool,
    host: *const c_char,
    no_subdomains: bool,
    ops: &HostOps,
) -> bool {
    let Some(collection) = (unsafe { collection.as_ref() }) else {
        return false;
    };
    for file in &collection.0 {
        unsafe { report_file(file.as_ptr(), exclude, ops.log) };
        let pool = unsafe { *file.as_ref().hosts.get() };
        if !host.is_null() && unsafe { host_match_logged(pool, host, no_subdomains, ops.log) } {
            return true;
        }
    }
    false
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostlists_check(
    include: *const Collection,
    exclude: *const Collection,
    host: *const c_char,
    no_subdomains: bool,
    excluded: *mut bool,
    skip_reload: bool,
    ops: &HostOps,
) -> bool {
    if !excluded.is_null() {
        unsafe { excluded.write(false) };
    }
    if !skip_reload && !unsafe { zapret_hostlists_reload_pair(include, exclude, ops) } {
        return false;
    }
    if unsafe { host_matches(exclude, true, host, no_subdomains, ops) } {
        if !excluded.is_null() {
            unsafe { excluded.write(true) };
        }
        return false;
    }
    unsafe {
        zapret_list_collection_empty(include)
            || host_matches(include, false, host, no_subdomains, ops)
    }
}
unsafe fn ip_matches(file: *mut ListFile, ipv4: *const u8, ipv6: *const u8, ops: &IpOps) -> bool {
    let ips = unsafe { &*(*file).ips.get() };
    let result = if ipv4.is_null() == ipv6.is_null() {
        false
    } else if !ipv4.is_null() {
        (unsafe { zapret_ip_check(ips.ipv4, ipv4, 32) }) != 0
    } else {
        (unsafe { zapret_ip_check(ips.ipv6, ipv6, 128) }) != 0
    };
    if let Some(log) = ops.log {
        unsafe {
            if ipv4.is_null() == ipv6.is_null() {
                log(
                    c"ipset check error !!!!!!!! ipv4=%p ipv6=%p\n".as_ptr(),
                    ipv4.cast::<c_void>(),
                    ipv6.cast::<c_void>(),
                );
            } else {
                let (address, width) = if ipv4.is_null() {
                    (ipv6, 16)
                } else {
                    (ipv4, 4)
                };
                let mut text = [0; 65]; // INET6_ADDRSTRLEN
                (ops.format_address)(address, width, text.as_mut_ptr(), text.len());
                let status = if result { c"positive" } else { c"negative" };
                log(
                    c"ipset check for %s : %s\n".as_ptr(),
                    text.as_ptr(),
                    status.as_ptr(),
                );
            }
        }
    }
    result
}
unsafe fn collection_matches(
    collection: *const Collection,
    exclude: bool,
    ipv4: *const u8,
    ipv6: *const u8,
    reverse4: *const u8,
    reverse6: *const u8,
    ops: &IpOps,
) -> bool {
    let Some(collection) = (unsafe { collection.as_ref() }) else {
        return false;
    };
    for file in &collection.0 {
        unsafe { report_file(file.as_ptr(), exclude, ops.log) };
        if unsafe { ip_matches(file.as_ptr(), ipv4, ipv6, ops) } {
            return true;
        }
        if !reverse4.is_null() || !reverse6.is_null() {
            unsafe { report_file(file.as_ptr(), exclude, ops.log) };
            if unsafe { ip_matches(file.as_ptr(), reverse4, reverse6, ops) } {
                return true;
            }
        }
    }
    false
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipsets_check(
    include: *const Collection,
    exclude: *const Collection,
    ipv4: *const u8,
    ipv6: *const u8,
    reverse4: *const u8,
    reverse6: *const u8,
    ops: &IpOps,
) -> bool {
    let absent = |collection: *const Collection| {
        unsafe { collection.as_ref() }.is_none_or(|collection| collection.0.is_empty())
    };
    if absent(include) && absent(exclude) {
        return true;
    }
    if !unsafe { zapret_ipsets_reload_pair(include, exclude, ops) } {
        return false;
    }
    if unsafe { collection_matches(exclude, true, ipv4, ipv6, reverse4, reverse6, ops) } {
        return false;
    }
    unsafe {
        zapret_list_collection_empty(include)
            || collection_matches(include, false, ipv4, ipv6, reverse4, reverse6, ops)
    }
}
