//! Ordered profile selection over the native engine's stable profile records.
#[cfg(windows)]
mod diagnostics;

use crate::{
    filters::{IcmpFilter, IpProtocolFilter, PortFilter},
    profile_config::profile_hosts_empty,
    protocol::l7_proto_match,
};
use std::{
    ffi::{c_char, c_void},
    ptr,
};

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;

#[repr(C)]
struct FilterItem<T> {
    filter: T,
    next: *const Self,
}

// A missing filter list admits all values. Entries in a populated list are ORed.
unsafe fn matches_any<T>(mut item: *const FilterItem<T>, matches: impl Fn(&T) -> bool) -> bool {
    if item.is_null() {
        return true;
    }
    while let Some(current) = unsafe { item.as_ref() } {
        if matches(&current.filter) {
            return true;
        }
        item = current.next;
    }
    false
}

// View of the contiguous fields starting at desync_profile.filter_ipv4.
// profile_selection_windows.inc checks the C field offsets at compile time.
#[repr(C)]
struct ProfileFilters {
    ipv4: bool,
    ipv6: bool,
    tcp: *const FilterItem<PortFilter>,
    udp: *const FilterItem<PortFilter>,
    icmp: *const FilterItem<IcmpFilter>,
    ip_protocol: *const FilterItem<IpProtocolFilter>,
    l7: u64,
    ip_include: *const c_void,
    ip_exclude: *const c_void,
    host_include: *const c_void,
    host_exclude: *const c_void,
    auto_hostlist: *const c_void,
}

impl ProfileFilters {
    unsafe fn matches_headers(&self, query: &Query) -> bool {
        if (!query.ipv4.is_null() && !self.ipv4)
            || (!query.ipv6.is_null() && !self.ipv6)
            || !l7_proto_match(query.l7, self.l7)
        {
            return false;
        }
        unsafe {
            match query.protocol {
                TCP => matches_any(self.tcp, |filter| filter.matches(query.port)),
                UDP => matches_any(self.udp, |filter| filter.matches(query.port)),
                ICMP | ICMPV6 => matches_any(self.icmp, |filter| {
                    filter.matches(query.icmp_type, query.icmp_code)
                }),
                protocol => matches_any(self.ip_protocol, |filter| filter.matches(protocol)),
            }
        }
    }
}

#[repr(C)]
struct Query {
    ipv4: *const c_void,
    ipv6: *const c_void,
    reverse_ipv4: *const c_void,
    reverse_ipv6: *const c_void,
    hostname: *const c_char,
    check_done: *mut bool,
    check_result: *mut bool,
    excluded: *mut bool,
    l7: u32,
    port: u16,
    icmp_type: u8,
    icmp_code: u8,
    no_subdomains: bool,
    protocol: u8,
}

type Profile = *const c_void;
type CheckIps = unsafe extern "C" fn(
    Profile,
    *const c_void,
    *const c_void,
    *const c_void,
    *const c_void,
) -> bool;

#[repr(C)]
struct ListChecks {
    reload_hosts: unsafe extern "C" fn(Profile) -> bool,
    check_ips: CheckIps,
    check_host: unsafe extern "C" fn(Profile, *const c_char, bool, *mut bool, bool) -> bool,
}

unsafe fn write_optional(output: *mut bool, value: bool) {
    if !output.is_null() {
        unsafe { output.write(value) };
    }
}

unsafe fn matches_profile(
    profile: Profile,
    filter_offset: usize,
    query: &Query,
    checks: &ListChecks,
) -> bool {
    let filters = unsafe { &*profile.byte_add(filter_offset).cast::<ProfileFilters>() };
    if !unsafe { filters.matches_headers(query) } {
        return false;
    }
    // Reload may mutate the list contents. Copy flags before calling C.
    let automatic = !filters.auto_hostlist.is_null();
    let has_hosts = !filters.host_include.is_null() || !filters.host_exclude.is_null();
    let has_ips = !filters.ip_include.is_null() || !filters.ip_exclude.is_null();
    let has_hostname = !query.hostname.is_null();
    if has_hosts && !unsafe { (checks.reload_hosts)(profile) } {
        return false;
    }
    let hosts_empty = !has_hosts || unsafe { profile_hosts_empty(profile) };
    if !automatic && !has_hostname && !hosts_empty {
        return false;
    }
    if has_ips
        && !unsafe {
            (checks.check_ips)(
                profile,
                query.ipv4,
                query.ipv6,
                query.reverse_ipv4,
                query.reverse_ipv6,
            )
        }
    {
        return false;
    }
    if automatic && has_hostname || hosts_empty {
        return true;
    }
    if !has_hostname {
        return false;
    }
    unsafe {
        write_optional(query.check_done, true);
        let result = (checks.check_host)(
            profile,
            query.hostname,
            query.no_subdomains,
            query.excluded,
            true,
        );
        write_optional(query.check_result, result);
        result
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_find(
    mut node: *mut c_void,
    filter_offset: usize,
    next_offset: usize,
    query: &Query,
    checks: &ListChecks,
) -> *mut c_void {
    // The C caller keeps the list links and headers live for the search. List
    // callbacks may update the contents of pools without moving profile records.
    let _reload_scope = crate::list_registry::ReloadScope::enter();
    unsafe { write_optional(query.check_done, false) };
    while !node.is_null() {
        unsafe { write_optional(query.check_done, false) };
        if unsafe { matches_profile(node, filter_offset, query, checks) } {
            return node;
        }
        node = unsafe { node.byte_add(next_offset).cast::<*mut c_void>().read() };
    }
    ptr::null_mut()
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{offset_of, size_of};

    assert!(size_of::<PortFilter>() == 6);
    assert!(size_of::<IcmpFilter>() == 4);
    assert!(size_of::<IpProtocolFilter>() == 2);
    assert!(offset_of!(FilterItem<PortFilter>, next) == 8);
    assert!(offset_of!(FilterItem<IcmpFilter>, next) == 8);
    assert!(offset_of!(FilterItem<IpProtocolFilter>, next) == 8);
    assert!(offset_of!(ProfileFilters, tcp) == 8);
    assert!(offset_of!(ProfileFilters, l7) == 40);
    assert!(offset_of!(ProfileFilters, ip_include) == 48);
    assert!(offset_of!(ProfileFilters, host_include) == 64);
    assert!(offset_of!(ProfileFilters, auto_hostlist) == 80);
    assert!(offset_of!(Query, check_done) == 40);
    assert!(offset_of!(Query, l7) == 64);
    assert!(offset_of!(Query, protocol) == 73);
    assert!(size_of::<Query>() == 80);
};
