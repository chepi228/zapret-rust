//! Bind CLI profile options to the shared Rust text parsers and existing records.
use super::{
    DLOG_ERR, Log, lua_arguments::parse_lua_call, profile_layout as profile,
    startup_params::PARAMS, state::params_address,
};
use core::ffi::{c_char, c_int, c_void};

type Head = *mut *mut c_void;
type ParseList = unsafe extern "C" fn(*const c_char, Head) -> bool;
type ParseMask = unsafe extern "C" fn(*const c_char, *mut u64) -> bool;

#[repr(C)]
struct Profile {
    _prefix: [u8; 3 * profile::POINTER],
    ipv4: bool,
    ipv6: bool,
    tcp: *mut c_void,
    udp: *mut c_void,
    icmp: *mut c_void,
    ip_protocol: *mut c_void,
    protocols: u64,
    _collections: [u8; profile::LUA_CALLS - profile::FIRST_COLLECTION],
    lua_calls: *mut c_void,
    _explicit: [u8; 8],
    explicit_versions: bool,
    explicit_protocols: bool,
}

#[repr(C)]
struct PacketRange {
    _opaque: [u8; 0],
}

#[derive(Default)]
#[repr(C)]
struct FilterTarget {
    value: *mut c_void,
    explicit: *mut bool,
    extra: *mut bool,
    payload: *const u64,
    incoming: *const PacketRange,
    outgoing: *const PacketRange,
}

#[repr(C)]
struct FilterOps {
    versions: unsafe extern "C" fn(*const c_char, *mut bool, *mut bool) -> bool,
    ports: ParseList,
    icmp: ParseList,
    ip_protocol: ParseList,
    protocols: ParseMask,
    payloads: ParseMask,
    range: unsafe extern "C" fn(*const c_char, *mut PacketRange) -> bool,
    append: unsafe extern "C" fn(Head, *const c_char) -> *mut c_void,
}

const PROFILE_FILTER_CATEGORY: u32 = 3;

const _: () = {
    use core::mem::offset_of;
    let pointer = profile::POINTER;
    assert!(size_of::<Profile>() == profile::SIZE && align_of::<Profile>() == 8);
    assert!(
        offset_of!(Profile, ipv4) == 3 * pointer && offset_of!(Profile, ipv6) == 3 * pointer + 1
    );
    assert!(offset_of!(Profile, tcp) == 4 * pointer && offset_of!(Profile, udp) == 5 * pointer);
    assert!(
        offset_of!(Profile, icmp) == 6 * pointer && offset_of!(Profile, ip_protocol) == 7 * pointer
    );
    assert!(offset_of!(Profile, protocols) == profile::FIRST_COLLECTION - 8);
    assert!(offset_of!(Profile, lua_calls) == profile::LUA_CALLS);
    assert!(offset_of!(Profile, explicit_versions) == profile::FIRST_EXPLICIT + 8);
    assert!(offset_of!(Profile, explicit_protocols) == profile::FIRST_EXPLICIT + 9);
    assert!(size_of::<FilterTarget>() == 6 * pointer && size_of::<FilterOps>() == 8 * pointer);
};

unsafe extern "C" {
    fn zapret_native_cli_kind(index: c_int, category: u32) -> c_int;
    fn zapret_filter_ip_versions(text: *const c_char, ipv4: *mut bool, ipv6: *mut bool) -> bool;
    fn parse_pf_list(text: *const c_char, head: Head) -> bool;
    fn parse_icf_list(text: *const c_char, head: Head) -> bool;
    fn parse_ipp_list(text: *const c_char, head: Head) -> bool;
    fn zapret_parse_l7_list(text: *const c_char, value: *mut u64) -> bool;
    fn zapret_parse_payload_list(text: *const c_char, value: *mut u64) -> bool;
    fn zapret_packet_range_parse(text: *const c_char, range: *mut PacketRange) -> bool;
    fn zapret_cli_profile_filter(
        kind: u32,
        text: *const c_char,
        target: &FilterTarget,
        ops: &FilterOps,
    ) -> u32;
    fn zapret_cli_profile_filter_report(
        kind: u32,
        status: u32,
        text: *const c_char,
        error: Log,
    ) -> c_int;
}

unsafe extern "C" fn append_call(head: Head, text: *const c_char) -> *mut c_void {
    unsafe { parse_lua_call(text, head) }
}

const OPS: FilterOps = FilterOps {
    versions: zapret_filter_ip_versions,
    ports: parse_pf_list,
    icmp: parse_icf_list,
    ip_protocol: parse_ipp_list,
    protocols: zapret_parse_l7_list,
    payloads: zapret_parse_payload_list,
    range: zapret_packet_range_parse,
    append: append_call,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn engine_profile_filter(
    index: c_int,
    text: *const c_char,
    profile: *mut Profile,
    payload: *mut u64,
    incoming: *mut PacketRange,
    outgoing: *mut PacketRange,
) -> c_int {
    let kind = unsafe { zapret_native_cli_kind(index, PROFILE_FILTER_CATEGORY) };
    let mut target = FilterTarget::default();
    target.value = unsafe {
        match kind {
            0 => {
                target.extra = &raw mut (*profile).ipv6;
                target.explicit = &raw mut (*profile).explicit_versions;
                (&raw mut (*profile).ipv4).cast()
            }
            1 => (&raw mut (*profile).tcp).cast(),
            2 => (&raw mut (*profile).udp).cast(),
            3 => (&raw mut (*profile).icmp).cast(),
            4 => (&raw mut (*profile).ip_protocol).cast(),
            5 => {
                target.explicit = &raw mut (*profile).explicit_protocols;
                (&raw mut (*profile).protocols).cast()
            }
            6 => params_address().add(PARAMS.payload_disabled).cast(),
            7 => params_address().add(PARAMS.reassembly_disabled).cast(),
            8 => payload.cast(),
            9 => outgoing.cast(),
            10 => incoming.cast(),
            11 => {
                target.payload = payload;
                target.incoming = incoming;
                target.outgoing = outgoing;
                (&raw mut (*profile).lua_calls).cast()
            }
            _ => return 0,
        }
    };
    let kind = kind as u32;
    let status = unsafe { zapret_cli_profile_filter(kind, text, &target, &OPS) };
    unsafe { zapret_cli_profile_filter_report(kind, status, text, DLOG_ERR) }
}
