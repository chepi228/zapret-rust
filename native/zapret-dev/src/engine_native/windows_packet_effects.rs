//! Live cache, profile and automatic hostlist effects for packet playback.
use super::*;

#[derive(Default)]
#[repr(C)]
struct Check {
    done: bool,
    result: bool,
    excluded: bool,
}

#[repr(C)]
struct Query {
    ipv4: *const u8,
    ipv6: *const u8,
    source4: *const u8,
    source6: *const u8,
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

type CheckIp =
    unsafe extern "C" fn(*const Profile, *const u8, *const u8, *const u8, *const u8) -> bool;

#[repr(C)]
struct ProfileChecks {
    reload_hosts: unsafe extern "C" fn(*const Profile) -> bool,
    check_ips: CheckIp,
    check_host: HostCheck,
}

#[repr(C)]
struct HostSession {
    play: *mut Play,
    profile: *mut *mut Profile,
    connection: *mut *mut Profile,
    checks: *mut Check,
    host: *mut c_char,
    l7: u32,
    protocol: u8,
    have_host: bool,
}

#[repr(C)]
struct RediscoveryOps {
    normalize: unsafe extern "C" fn(*mut c_char) -> bool,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_void),
    cache: unsafe extern "C" fn(*const Play, *const c_char, bool) -> bool,
    find: unsafe extern "C" fn(*const Play, *const c_char, bool, *mut Check) -> *mut Profile,
    check_host: HostCheck,
    udp_failure: unsafe extern "C" fn(*const Play),
    log: Log,
    error: Log,
    format_endpoint: unsafe extern "C" fn(*const Address, *mut c_char, usize),
    debug_enabled: *const bool,
}

#[repr(C)]
struct CacheKey {
    ipv4: *const u8,
    ipv6: *const u8,
    interface: *const c_char,
}

#[repr(C)]
struct CacheOps {
    find: unsafe extern "C" fn(*const CacheKey) -> *mut c_void,
    touch: unsafe extern "C" fn(*const CacheKey) -> *mut c_void,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_void),
    report: unsafe extern "C" fn(*const CacheKey, u32, *const c_void),
}

#[repr(C)]
struct CacheSession {
    context: *const CacheKey,
    ops: *const CacheOps,
    enabled: bool,
    server: bool,
}

#[repr(C)]
struct DnsReport {
    log: Log,
    format_address: unsafe extern "C" fn(*const u8, usize, *mut c_char, usize) -> usize,
}

type SaveHost = unsafe extern "C" fn(*const u8, *const u8, *const c_char, bool) -> bool;

#[repr(C)]
struct AutolistContext {
    profile: *mut Profile,
    hostname: *const c_char,
    client_text: *const c_char,
    client: *const Address,
    interface: *const c_char,
    track: *mut Track,
    l7: u32,
    flags: u32,
    no_subdomains: bool,
}

#[repr(C)]
struct AutolistOps {
    find: unsafe extern "C" fn(*mut Profile, *const c_char) -> *mut c_void,
    add: unsafe extern "C" fn(*mut Profile, *const c_char, c_int) -> *mut c_void,
    remove: unsafe extern "C" fn(*mut Profile, *mut c_void),
    check_host: HostCheck,
    append: unsafe extern "C" fn(*const AutolistContext) -> bool,
    stamp: unsafe extern "C" fn(*const AutolistContext) -> bool,
    send: unsafe extern "C" fn(*const AutolistContext, *const u8, usize) -> bool,
    report: unsafe extern "C" fn(u32, *const AutolistContext, u64, u64, u64, u64),
}

#[derive(Default)]
#[repr(C)]
struct TrackInput {
    track: *mut Track,
    profile: *mut Profile,
    client: *const Address,
    interface: *const c_char,
    l7: u32,
}

#[repr(C)]
struct TrackOps {
    effects: *const AutolistOps,
    server: *const bool,
    debug: *const bool,
    append_path: *const c_char,
    format_client: unsafe extern "C" fn(*const Address, *mut c_char, usize),
}

const _: () = {
    assert!(size_of::<Query>() == 80 && offset_of!(Query, protocol) == 73);
    assert!(size_of::<ProfileChecks>() == 24 && size_of::<Check>() == 3);
    assert!(size_of::<HostSession>() == 48 && size_of::<RediscoveryOps>() == 88);
    assert!(
        size_of::<CacheKey>() == 24
            && size_of::<CacheOps>() == 40
            && size_of::<CacheSession>() == 24
    );
    assert!(size_of::<DnsReport>() == 16 && size_of::<AutolistContext>() == 64);
    assert!(
        size_of::<AutolistOps>() == 64
            && size_of::<TrackInput>() == 40
            && size_of::<TrackOps>() == 40
    );
};

unsafe extern "C" {
    fn HostlistsReloadCheckForProfile(profile: *const Profile) -> bool;
    fn IpsetCheck(
        profile: *const Profile,
        a4: *const u8,
        a6: *const u8,
        b4: *const u8,
        b6: *const u8,
    ) -> bool;
    fn zapret_profile_find(
        first: *mut Profile,
        filter_offset: usize,
        next_offset: usize,
        query: &Query,
        checks: &ProfileChecks,
    ) -> *mut Profile;
    fn zapret_profile_search_report(
        query: &Query,
        ssid: *const c_char,
        mark: u32,
        debug: bool,
        log: Log,
    );
    fn zapret_profile_result_report(profile: *const Profile, query: &Query, log: Log);
    fn zapret_profile_rediscover(session: &HostSession, ops: &RediscoveryOps) -> bool;
    #[link_name = "zapret_address_strip_host"]
    fn strip_host_to_ip(text: *mut c_char) -> bool;
    #[link_name = "zapret_address_ntop_port"]
    fn ntop46_port(address: *const Address, out: *mut c_char, capacity: usize);
    fn HostFailPoolPurgeRateLimited(head: *mut *mut c_void, last: *mut i64);
    fn HostFailPoolFind(head: *const c_void, hostname: *const c_char) -> *mut c_void;
    fn HostFailPoolAdd(
        head: *mut *mut c_void,
        hostname: *const c_char,
        timeout: c_int,
    ) -> *mut c_void;
    fn HostFailPoolDel(head: *mut *mut c_void, item: *mut c_void);
    fn append_to_list_file(file: *const c_char, host: *const c_char) -> bool;
    fn file_mod_signature(file: *const c_char, stamp: *mut c_void) -> bool;
    fn autolist_report(
        event: u32,
        ctx: *const AutolistContext,
        first: u64,
        second: u64,
        third: u64,
        fourth: u64,
    );
    fn zapret_autolist_track(
        input: &TrackInput,
        kind: u32,
        packet: *const Packet,
        positions: *const c_void,
        payload: u32,
        ops: &TrackOps,
    );
    fn ipcacheFind(
        cache: *mut c_void,
        a4: *const u8,
        a6: *const u8,
        interface: *const c_char,
    ) -> *mut c_void;
    fn ipcacheTouch(
        cache: *mut c_void,
        a4: *const u8,
        a6: *const u8,
        interface: *const c_char,
    ) -> *mut c_void;
    fn packet_cache_report(key: *const CacheKey, event: u32, item: *const c_void);
    fn zapret_cache_put_hostname(session: &CacheSession, host: *const c_char, is_ip: bool) -> bool;
    fn zapret_cache_get_hostname(
        session: &CacheSession,
        host: *mut c_char,
        capacity: usize,
        is_ip: *mut bool,
    ) -> bool;
    fn zapret_cache_ttl(session: &CacheSession, ttl: *mut u8, update: bool);
    fn zapret_lua_ntop(data: *const u8, length: usize, out: *mut c_char, capacity: usize) -> usize;
    fn zapret_feed_dns_response(
        data: *const u8,
        size: usize,
        enabled: bool,
        debug: bool,
        cache: SaveHost,
        report: &DnsReport,
    ) -> bool;
}

unsafe fn find(query: &Query, ssid: *const c_char, mark: u32) -> *mut Profile {
    const CHECKS: ProfileChecks = ProfileChecks {
        reload_hosts: HostlistsReloadCheckForProfile,
        check_ips: IpsetCheck,
        check_host: HostlistCheck,
    };
    unsafe {
        zapret_profile_search_report(query, ssid, mark, params.debug, DLOG);
        let profile = zapret_profile_find(params.profiles, 24, 184, query, &CHECKS);
        zapret_profile_result_report(profile, query, DLOG);
        profile
    }
}

unsafe extern "C" fn find_for_play(
    play: *const Play,
    hostname: *const c_char,
    is_ip: bool,
    check: *mut Check,
) -> *mut Profile {
    unsafe {
        let query = Query {
            ipv4: (*play).target4,
            ipv6: (*play).target6,
            source4: ptr::null(),
            source6: ptr::null(),
            hostname,
            check_done: if check.is_null() {
                ptr::null_mut()
            } else {
                &raw mut (*check).done
            },
            check_result: if check.is_null() {
                ptr::null_mut()
            } else {
                &raw mut (*check).result
            },
            excluded: if check.is_null() {
                ptr::null_mut()
            } else {
                &raw mut (*check).excluded
            },
            l7: (*play).l7,
            port: (*play).port,
            icmp_type: 0xff,
            icmp_code: 0xff,
            no_subdomains: is_ip,
            protocol: (*(*play).packet).protocol,
        };
        find(&query, (*play).ssid, (*play).mark)
    }
}

pub(super) unsafe extern "C" fn prolog_find(
    play: *const Play,
    host: *const c_char,
    is_ip: bool,
) -> *mut Profile {
    unsafe { find_for_play(play, host, is_ip, ptr::null_mut()) }
}

pub(super) unsafe extern "C" fn other_find(query: *const OtherQuery) -> *mut Profile {
    let query = unsafe { &*query };
    let options = Query {
        ipv4: query.destination.ipv4,
        ipv6: query.destination.ipv6,
        source4: query.source.ipv4,
        source6: query.source.ipv6,
        hostname: query.hostname,
        check_done: ptr::null_mut(),
        check_result: ptr::null_mut(),
        excluded: ptr::null_mut(),
        l7: UNKNOWN,
        port: 0,
        icmp_type: query.icmp_type,
        icmp_code: query.icmp_code,
        no_subdomains: query.hostname_is_ip,
        protocol: query.protocol,
    };
    unsafe { find(&options, query.ssid, query.mark) }
}

pub(super) unsafe extern "C" fn purge_failures(profile: *mut Profile) {
    unsafe {
        HostFailPoolPurgeRateLimited(
            &raw mut (*profile).fail_counters,
            &raw mut (*profile).last_purge,
        )
    };
}

unsafe extern "C" fn cache_find(key: *const CacheKey) -> *mut c_void {
    unsafe {
        ipcacheFind(
            (&raw mut params.cache).cast(),
            (*key).ipv4,
            (*key).ipv6,
            (*key).interface,
        )
    }
}

unsafe extern "C" fn cache_touch(key: *const CacheKey) -> *mut c_void {
    unsafe {
        ipcacheTouch(
            (&raw mut params.cache).cast(),
            (*key).ipv4,
            (*key).ipv6,
            (*key).interface,
        )
    }
}

unsafe fn cache_session(key: &CacheKey) -> CacheSession {
    const OPS: CacheOps = CacheOps {
        find: cache_find,
        touch: cache_touch,
        duplicate: strdup,
        release: free,
        report: packet_cache_report,
    };
    CacheSession {
        context: key,
        ops: &OPS,
        enabled: unsafe { params.cache_hostname },
        server: unsafe { params.server },
    }
}

unsafe extern "C" fn put_hostname(
    ipv4: *const u8,
    ipv6: *const u8,
    host: *const c_char,
    is_ip: bool,
) -> bool {
    let key = CacheKey {
        ipv4,
        ipv6,
        interface: ptr::null(),
    };
    unsafe { zapret_cache_put_hostname(&cache_session(&key), host, is_ip) }
}

pub(super) unsafe extern "C" fn other_hostname(
    address: RouteAddress,
    host: *mut c_char,
    is_ip: *mut bool,
) -> bool {
    let key = CacheKey {
        ipv4: address.ipv4,
        ipv6: address.ipv6,
        interface: ptr::null(),
    };
    unsafe { zapret_cache_get_hostname(&cache_session(&key), host, 256, is_ip) }
}

pub(super) unsafe extern "C" fn cached_hostname(play: *mut Play, is_ip: *mut bool) -> bool {
    unsafe {
        other_hostname(
            RouteAddress {
                ipv4: (*play).target4,
                ipv6: (*play).target6,
            },
            (&raw mut (*play).host).cast(),
            is_ip,
        )
    }
}

unsafe fn ttl(play: *const Play, interface: *const c_char, update: bool) {
    unsafe {
        let key = CacheKey {
            ipv4: (*play).target4,
            ipv6: (*play).target6,
            interface,
        };
        let track = (*play).track;
        let field = if track.is_null() {
            ptr::null_mut()
        } else {
            &raw mut (*track).incoming_ttl
        };
        zapret_cache_ttl(&cache_session(&key), field, update);
    }
}

pub(super) unsafe extern "C" fn update_ttl(play: *const Play, interface: *const c_char) {
    unsafe { ttl(play, interface, true) };
}

pub(super) unsafe extern "C" fn get_ttl(play: *const Play, interface: *const c_char) {
    unsafe { ttl(play, interface, false) };
}

pub(super) unsafe extern "C" fn dns_response(data: *const u8, size: usize) -> bool {
    const REPORT: DnsReport = DnsReport {
        log: DLOG,
        format_address: zapret_lua_ntop,
    };
    unsafe {
        zapret_feed_dns_response(
            data,
            size,
            params.cache_hostname,
            params.debug,
            put_hostname,
            &REPORT,
        )
    }
}

unsafe extern "C" fn rediscovery_cache(
    play: *const Play,
    host: *const c_char,
    is_ip: bool,
) -> bool {
    unsafe { put_hostname((*play).target4, (*play).target6, host, is_ip) }
}

pub(super) unsafe fn rediscover(play: *mut Play) -> bool {
    const OPS: RediscoveryOps = RediscoveryOps {
        normalize: strip_host_to_ip,
        duplicate: strdup,
        release: free,
        cache: rediscovery_cache,
        find: find_for_play,
        check_host: HostlistCheck,
        udp_failure,
        log: DLOG,
        error: DLOG_ERR,
        format_endpoint: ntop46_port,
        debug_enabled: unsafe { &raw const params.debug },
    };
    unsafe {
        let track = (*play).replay_track;
        let session = HostSession {
            play,
            profile: &raw mut (*play).profile,
            connection: if track.is_null() {
                ptr::null_mut()
            } else {
                &raw mut (*track).profile
            },
            checks: if track.is_null() {
                ptr::null_mut()
            } else {
                (&raw mut (*track).checks).cast()
            },
            host: (&raw mut (*play).host).cast(),
            l7: (*play).l7,
            protocol: (*(*play).packet).protocol,
            have_host: (*play).have_host,
        };
        zapret_profile_rediscover(&session, &OPS)
    }
}

unsafe extern "C" fn find_counter(profile: *mut Profile, host: *const c_char) -> *mut c_void {
    unsafe { HostFailPoolFind((*profile).fail_counters, host) }
}

unsafe extern "C" fn add_counter(
    profile: *mut Profile,
    host: *const c_char,
    timeout: c_int,
) -> *mut c_void {
    unsafe { HostFailPoolAdd(&raw mut (*profile).fail_counters, host, timeout) }
}

unsafe extern "C" fn remove_counter(profile: *mut Profile, entry: *mut c_void) {
    unsafe { HostFailPoolDel(&raw mut (*profile).fail_counters, entry) };
}

unsafe extern "C" fn append(context: *const AutolistContext) -> bool {
    unsafe { append_to_list_file((*(*(*context).profile).auto_file).name, (*context).hostname) }
}

unsafe extern "C" fn stamp(context: *const AutolistContext) -> bool {
    unsafe {
        let file = (*(*context).profile).auto_file;
        file_mod_signature((*file).name, (&raw mut (*file).stamp).cast())
    }
}

unsafe extern "C" fn auto_send(
    context: *const AutolistContext,
    data: *const u8,
    length: usize,
) -> bool {
    unsafe {
        rawsend(
            (*context).client,
            0,
            (*context).interface,
            data.cast(),
            length,
        )
    }
}

const TRACK_OPS: TrackOps = TrackOps {
    effects: &AutolistOps {
        find: find_counter,
        add: add_counter,
        remove: remove_counter,
        check_host: HostlistCheck,
        append,
        stamp,
        send: auto_send,
        report: autolist_report,
    },
    server: unsafe { &raw const params.server },
    debug: unsafe { &raw const params.debug },
    append_path: unsafe { (&raw const params.auto_log).cast() },
    format_client: ntop46_port,
};

pub(super) unsafe extern "C" fn reply(play: *mut Play) {
    unsafe {
        let input = TrackInput {
            track: (*play).track,
            profile: (*play).profile,
            client: &raw const (*play).destination,
            interface: ptr::null(),
            l7: (*play).l7,
        };
        zapret_autolist_track(
            &input,
            2,
            (*play).packet,
            ptr::null(),
            (*play).payload,
            &TRACK_OPS,
        );
    }
}

pub(super) unsafe extern "C" fn retransmit(play: *mut Play, interface: *const c_char) {
    unsafe {
        let input = TrackInput {
            track: (*play).track,
            client: &raw const (*play).source,
            interface,
            ..TrackInput::default()
        };
        zapret_autolist_track(&input, 0, (*play).packet, ptr::null(), 0, &TRACK_OPS);
    }
}

unsafe extern "C" fn udp_failure(play: *const Play) {
    unsafe {
        let input = TrackInput {
            track: (*play).replay_track,
            client: &raw const (*play).source,
            ..TrackInput::default()
        };
        zapret_autolist_track(&input, 1, ptr::null(), (*play).positions, 0, &TRACK_OPS);
    }
}
