//! Diagnostic presenters read the engine's lists in native order and use its log sink.
use crate::{
    blob::Blob,
    collections::{Node, Pair},
    list_registry::{FileRegistry, ListFile, zapret_list_collection_at, zapret_list_files_at},
    logging::LogSink,
    lua_rules::Rule,
    packet_policy::Range,
    profile_config::{
        profile_auto_host_file, profile_display_name, profile_list_collection, profile_lua,
        profile_next, profile_number,
    },
};
use std::ffi::{c_char, c_void};

#[repr(C)]
struct ListSources {
    debug: *const bool,
    registry: *const *const FileRegistry,
    profiles: *const *const c_void,
    templates: *const *const c_void,
}

#[derive(Clone, Copy)]
enum Relation {
    Include,
    Exclude,
    Automatic,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_native_ip_fill(ipv4: *const c_void, ipv6: *const c_void) -> *const c_char {
    match (!ipv4.is_null(), !ipv6.is_null()) {
        (true, true) => c"ipv4+ipv6",
        (true, false) => c"ipv4",
        (false, true) => c"ipv6",
        (false, false) => c"empty",
    }
    .as_ptr()
}

unsafe fn list_tail(file: *const ListFile, ip: bool) -> *const c_char {
    if ip {
        let (ipv4, ipv6) = unsafe { ListFile::ip_pools(file) };
        zapret_native_ip_fill(ipv4, ipv6)
    } else if unsafe { (*file).hosts.get().read() }.is_null() {
        c" (empty)".as_ptr()
    } else {
        c"".as_ptr()
    }
}

unsafe fn log_profile_file(
    profile: *const c_void,
    entity: *const c_char,
    file: *const ListFile,
    relation: Relation,
    ip: bool,
    log: LogSink,
) {
    let filename = unsafe { (*file).filename };
    let named = !filename.is_null();
    let format = match (relation, ip, named) {
        (Relation::Include, false, true) => c"%s %u (%s) include hostlist %s%s\n",
        (Relation::Include, false, false) => c"%s %u (%s) include fixed hostlist%s\n",
        (Relation::Exclude, false, true) => c"%s %u (%s) exclude hostlist %s%s\n",
        (Relation::Exclude, false, false) => c"%s %u (%s) exclude fixed hostlist%s\n",
        (Relation::Automatic, _, _) => c"%s %u (%s) auto hostlist %s%s\n",
        (Relation::Include, true, true) => c"%s %u (%s) include ipset %s (%s)\n",
        (Relation::Include, true, false) => c"%s %u (%s) include fixed ipset (%s)\n",
        (Relation::Exclude, true, true) => c"%s %u (%s) exclude ipset %s (%s)\n",
        (Relation::Exclude, true, false) => c"%s %u (%s) exclude fixed ipset (%s)\n",
    };
    unsafe {
        let number = profile_number(profile);
        let name = profile_display_name(profile);
        let tail = list_tail(file, ip);
        if named || matches!(relation, Relation::Automatic) {
            log(format.as_ptr(), entity, number, name, filename, tail);
        } else {
            log(format.as_ptr(), entity, number, name, tail);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_list_profile_debug(
    profile: *const c_void,
    entity: *const c_char,
    ip: bool,
    log: LogSink,
) {
    for (exclude, relation) in [(false, Relation::Include), (true, Relation::Exclude)] {
        let mut index = 0usize;
        loop {
            // Read the collection again after each call into the native log sink.
            let file = unsafe {
                zapret_list_collection_at(profile_list_collection(profile, ip, exclude), index)
            };
            if file.is_null() {
                break;
            }
            if ip || exclude || file.cast_const() != unsafe { profile_auto_host_file(profile) } {
                unsafe { log_profile_file(profile, entity, file, relation, ip, log) };
            }
            index = index.wrapping_add(1);
        }
    }
    if !ip {
        let automatic = unsafe { profile_auto_host_file(profile) };
        if !automatic.is_null() {
            unsafe {
                log_profile_file(profile, entity, automatic, Relation::Automatic, false, log)
            };
        }
    }
}

unsafe fn log_global_file(file: *const ListFile, ip: bool, log: LogSink) {
    let filename = unsafe { (*file).filename };
    let tail = unsafe { list_tail(file, ip) };
    unsafe {
        match (ip, filename.is_null()) {
            (false, false) => log(c"hostlist file %s%s\n".as_ptr(), filename, tail),
            (false, true) => log(c"hostlist fixed%s\n".as_ptr(), tail),
            (true, false) => log(c"ipset file %s (%s)\n".as_ptr(), filename, tail),
            (true, true) => log(c"ipset fixed (%s)\n".as_ptr(), tail),
        }
    };
}

unsafe fn log_profiles(mut entry: *const c_void, entity: *const c_char, ip: bool, log: LogSink) {
    while !entry.is_null() {
        unsafe {
            // The C list entry begins with the profile.
            zapret_native_list_profile_debug(entry, entity, ip, log);
            entry = profile_next(entry);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_list_debug(sources: &ListSources, ip: bool, log: LogSink) {
    if !unsafe { sources.debug.read() } {
        return;
    }

    let mut index = 0usize;
    loop {
        let file = unsafe { zapret_list_files_at(sources.registry.read(), index) };
        if file.is_null() {
            break;
        }
        unsafe { log_global_file(file, ip, log) };
        index = index.wrapping_add(1);
    }

    unsafe {
        log_profiles(sources.profiles.read(), c"profile".as_ptr(), ip, log);
        log_profiles(sources.templates.read(), c"template".as_ptr(), ip, log);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_blob_debug(head: *const *const Blob, log: LogSink) {
    let mut blob = unsafe { head.read() };
    while !blob.is_null() {
        unsafe {
            log(
                c"blob '%s' : size=%zu alloc=%zu\n".as_ptr(),
                (*blob).name,
                (*blob).size,
                (*blob).capacity,
            );
            blob = (*blob).next;
        }
    }
}

unsafe fn log_rule_ranges(incoming: Range, outgoing: Range, log: LogSink) {
    let delimiter = |range: Range| i32::from(if range.upper_cutoff { b'<' } else { b'-' });
    unsafe {
        log(
            c" range_in=%c%u%c%c%u range_out=%c%u%c%c%u payload_type=".as_ptr(),
            i32::from(incoming.from.mode as i8),
            incoming.from.value,
            delimiter(incoming),
            i32::from(incoming.to.mode as i8),
            incoming.to.value,
            i32::from(outgoing.from.mode as i8),
            outgoing.from.value,
            delimiter(outgoing),
            i32::from(outgoing.to.mode as i8),
            outgoing.to.value,
        );
    }
}

type PayloadName = unsafe extern "C" fn(u32) -> *const c_char;
const PAYLOAD_COUNT: u32 = 31; // L7P_LAST in the engine headers.

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_lua_debug(
    profile: *const c_void,
    entity: *const c_char,
    debug: bool,
    payload_name: PayloadName,
    log: LogSink,
) {
    if !debug {
        return;
    }

    let mut rule = unsafe { profile_lua(profile).cast::<Rule>() };
    while !rule.is_null() {
        unsafe {
            log(
                c"%s %u (%s) lua %s(".as_ptr(),
                entity,
                profile_number(profile),
                profile_display_name(profile),
                (*rule).name,
            );

            let mut arg = (*rule).args.cast::<Node<Pair>>();
            let mut count = 0u32;
            while !arg.is_null() {
                if count != 0 {
                    log(c",".as_ptr());
                }
                let value = (*arg).value.second;
                let format = if value.is_null() {
                    c"%s=\"\""
                } else {
                    c"%s=\"%s\""
                };
                log(format.as_ptr(), (*arg).value.first, value);
                count = count.wrapping_add(1);
                arg = (*arg).next;
            }

            log_rule_ranges((*rule).incoming, (*rule).outgoing, log);
            if (*rule).payload_mask == 0 {
                log(c" all".as_ptr());
            } else {
                for index in 0..PAYLOAD_COUNT {
                    if (*rule).payload_mask & (1u64 << index) != 0 {
                        log(c" %s".as_ptr(), payload_name(index));
                    }
                }
            }
            log(c")\n".as_ptr());
            rule = (*rule).next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CStr, ptr};

    #[test]
    fn ip_labels_cover_both_pools() {
        let none = ptr::null();
        let pool = ptr::dangling();
        for (v4, v6, label) in [
            (none, none, c"empty"),
            (pool, none, c"ipv4"),
            (none, pool, c"ipv6"),
            (pool, pool, c"ipv4+ipv6"),
        ] {
            assert_eq!(
                unsafe { CStr::from_ptr(zapret_native_ip_fill(v4, v6)) },
                label
            );
        }
    }

    #[test]
    fn debug_off_skips_borrowed_native_data() {
        unsafe extern "C" fn unexpected_payload(_: u32) -> *const c_char {
            unreachable!()
        }
        unsafe {
            zapret_native_list_debug(
                &ListSources {
                    debug: &false,
                    registry: ptr::null(),
                    profiles: ptr::null(),
                    templates: ptr::null(),
                },
                false,
                libc::printf,
            );
            zapret_native_lua_debug(
                ptr::null(),
                ptr::null(),
                false,
                unexpected_payload,
                libc::printf,
            );
        }
    }
}
