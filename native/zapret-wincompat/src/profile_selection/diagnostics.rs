//! Profile search diagnostics preserve native string bytes and late name reads.
use super::{Profile, Query};
use crate::{
    address::zapret_address_ntopa46,
    logging::LogSink,
    packet::describe::zapret_packet_proto_name,
    profile_config::{
        profile_display_name, profile_has_automatic_hosts, profile_name, profile_number,
    },
    protocol::l7proto_str,
};
use std::ffi::{c_char, c_int};

fn text_or_empty(text: *const c_char) -> *const c_char {
    if text.is_null() { c"".as_ptr() } else { text }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_search_report(
    query: *const Query,
    ssid: *const c_char,
    mark: u32,
    enabled: bool,
    log: LogSink,
) {
    if !enabled {
        return;
    }
    // This is the Windows SDK's INET6_ADDRSTRLEN, including the trailing NUL.
    let mut local = [0; 65];
    let mut remote = [0; 65];
    unsafe {
        zapret_address_ntopa46(
            (*query).ipv4.cast(),
            (*query).ipv6.cast(),
            local.as_mut_ptr(),
            local.len(),
        );
        let paired = !(*query).reverse_ipv4.is_null() || !(*query).reverse_ipv6.is_null();
        if paired {
            zapret_address_ntopa46(
                (*query).reverse_ipv4.cast(),
                (*query).reverse_ipv6.cast(),
                remote.as_mut_ptr(),
                remote.len(),
            );
        }
        let protocol = zapret_packet_proto_name((*query).protocol);
        let payload_protocol = l7proto_str((*query).l7);
        let ssid = text_or_empty(ssid);
        let hostname = text_or_empty((*query).hostname);
        let port = c_int::from((*query).port);
        let kind = c_int::from((*query).icmp_type);
        let code = c_int::from((*query).icmp_code);
        if paired {
            log(c"desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostname='%s'\n".as_ptr(),
                protocol, local.as_ptr(), remote.as_ptr(), port, kind, code, payload_protocol, ssid, mark, hostname);
        } else {
            log(c"desync profile search for %s ip=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostname='%s'\n".as_ptr(),
                protocol, local.as_ptr(), port, kind, code, payload_protocol, ssid, mark, hostname);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_result_report(
    profile: Profile,
    query: *const Query,
    log: LogSink,
) {
    if profile.is_null() {
        unsafe { log(c"desync profile not found\n".as_ptr()) };
        return;
    }
    unsafe {
        if profile_has_automatic_hosts(profile) && !(*query).hostname.is_null() {
            log(
                c"autohostlist profile %u (%s) wins because hostname is known\n".as_ptr(),
                profile_number(profile),
                profile_name(profile),
            );
        }
        // The match line observes the current name and number after the first log.
        log(
            c"desync profile %u (%s) matches\n".as_ptr(),
            profile_number(profile),
            profile_display_name(profile),
        );
    }
}
