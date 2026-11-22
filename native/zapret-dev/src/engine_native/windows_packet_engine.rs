//! Live Windows packet dispatch and playback around the shared Rust policies.
#![no_std]

mod windows_packet_effects;

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
    ptr,
};

const PASS: u8 = 0;
const DROP: u8 = 2;
const UNKNOWN: u32 = 1;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type HostCheck = unsafe extern "C" fn(*const Profile, *const c_char, bool, *mut bool, bool) -> bool;
type RawSend =
    unsafe extern "C" fn(*const Address, u32, *const c_char, *const c_void, usize) -> bool;
type Debug = unsafe extern "C" fn(bool, *const Packet);

#[repr(C)]
struct File {
    name: *const c_char,
    stamp: [MaybeUninit<u64>; 3],
}

#[repr(C)]
struct Profile {
    before_auto_file: [MaybeUninit<u8>; 104],
    auto_file: *mut File,
    before_fail_counters: [MaybeUninit<u8>; 32],
    fail_counters: *mut c_void,
    last_purge: i64,
}

#[repr(C)]
struct Track {
    checks: [bool; 3],
    before_positions: [MaybeUninit<u8>; 21],
    positions: [MaybeUninit<u8>; 160],
    profile: *mut Profile,
    before_ttl: [MaybeUninit<u8>; 3],
    incoming_ttl: u8,
    before_kind: [MaybeUninit<u8>; 32],
    reassembly_kind: u32,
    reassembly: [MaybeUninit<u8>; 32],
    delayed: [MaybeUninit<u8>; 16],
}

#[repr(C, align(8))]
struct Address([MaybeUninit<u8>; 128]);

#[repr(C, align(8))]
struct Packet {
    before_protocol: [MaybeUninit<u8>; 40],
    protocol: u8,
    before_tcp: [MaybeUninit<u8>; 7],
    tcp: *const u8,
    after_tcp: [MaybeUninit<u8>; 56],
}

#[repr(C)]
struct Play {
    packet: *const Packet,
    profile: *mut Profile,
    positions: *const c_void,
    track: *mut Track,
    replay_track: *mut Track,
    source: Address,
    destination: Address,
    target4: *const u8,
    target6: *const u8,
    port: u16,
    verdict: u8,
    host: [c_char; 256],
    l7: u32,
    payload: u32,
    ssid: *const c_char,
    mark: u32,
    reverse: bool,
    incoming: bool,
    have_host: bool,
}

#[repr(C)]
struct Params {
    before_debug: [MaybeUninit<u8>; 4252],
    debug: bool,
    before_mark: [MaybeUninit<u8>; 11],
    mark: u32,
    before_profiles: [MaybeUninit<u8>; 4],
    profiles: *mut Profile,
    before_auto_log: [MaybeUninit<u8>; 8528 - 4280],
    auto_log: [c_char; 4096],
    before_conntrack: [MaybeUninit<u8>; 40],
    conntrack: [MaybeUninit<u8>; 40],
    disabled: bool,
    server: bool,
    cache_hostname: bool,
    before_lifetime: MaybeUninit<u8>,
    lifetime: u32,
    cache: [MaybeUninit<u8>; 16],
    reassembly_disable: u64,
    payload_disable: u64,
}

#[repr(C)]
struct Reassembly {
    buffer: *mut c_void,
    kind: *mut u32,
    positions: *const c_void,
    delayed: *mut c_void,
}

#[repr(C)]
struct ReassemblyOps {
    send: RawSend,
    replay: unsafe extern "C-unwind" fn(*mut c_void) -> bool,
    report: unsafe extern "C" fn(u32, usize, usize, usize),
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Payload {
    data: *const u8,
    length: usize,
}

#[repr(C)]
struct Input {
    inbound: *const c_char,
    outbound: *const c_char,
    payload_disable: u64,
    reassembly_disable: u64,
    mark: u32,
    desync_mark: u32,
    replay: bool,
    debug: bool,
}

#[repr(C)]
struct PayloadOps {
    reassembly: *const ReassemblyOps,
    reply: unsafe extern "C" fn(*mut Play),
    retransmit: unsafe extern "C" fn(*mut Play, *const c_char),
    dns: unsafe extern "C" fn(*const u8, usize) -> bool,
    log: Log,
    tls_record: unsafe extern "C" fn(*const u8, usize),
    tls_handshake: unsafe extern "C" fn(*const u8, usize),
}

#[repr(C)]
struct PrologOps {
    cached_hostname: unsafe extern "C" fn(*mut Play, *mut bool) -> bool,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    find: unsafe extern "C" fn(*const Play, *const c_char, bool) -> *mut Profile,
    purge_failures: unsafe extern "C" fn(*mut Profile),
    update_ttl: unsafe extern "C" fn(*const Play, *const c_char),
    get_ttl: unsafe extern "C" fn(*const Play, *const c_char),
    log: Log,
    error: Log,
    format_address: unsafe extern "C" fn(*const u8, *const u8, *mut c_char, usize),
    debug_enabled: *const bool,
    server: *const bool,
}

#[repr(C)]
struct ReplayOps {
    process: unsafe extern "C-unwind" fn(
        u32,
        u32,
        usize,
        u32,
        *const c_char,
        *const c_char,
        *const c_void,
        *const u8,
        usize,
        *mut u8,
        *mut usize,
    ) -> u8,
    send: RawSend,
    debug: Log,
    error: Log,
}

struct Call {
    input: Input,
    piece: u32,
    pieces: u32,
    offset: usize,
    positions: *const c_void,
    modified: *mut u8,
    length: *mut usize,
}

#[derive(Default)]
#[repr(C)]
struct FinishFlow {
    phase: u32,
    verdict: u8,
}

#[derive(Default)]
#[repr(C)]
struct FinishFeedback {
    verdict: u8,
    found: bool,
    tcp: bool,
    incoming: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteAddress {
    ipv4: *const u8,
    ipv6: *const u8,
}

#[repr(C)]
struct OtherQuery {
    destination: RouteAddress,
    source: RouteAddress,
    hostname: *const c_char,
    ssid: *const c_char,
    mark: u32,
    protocol: u8,
    icmp_type: u8,
    icmp_code: u8,
    hostname_is_ip: bool,
}

#[repr(C)]
struct OtherPlay {
    profile: *mut Profile,
    track: *mut Track,
    target: RouteAddress,
    l7: u32,
    payload: u32,
    incoming: bool,
}

#[repr(C)]
struct OtherOps {
    search: unsafe extern "C" fn(*const Packet, *mut *mut Track, *mut bool) -> bool,
    cached_host: unsafe extern "C" fn(RouteAddress, *mut c_char, *mut bool) -> bool,
    find: unsafe extern "C" fn(*const OtherQuery) -> *mut Profile,
    ssid: Option<unsafe extern "C" fn(*const c_char) -> *const c_char>,
    log: Log,
    attached_debug: Option<Debug>,
}

const _: () = {
    assert!(offset_of!(File, stamp) == 8 && offset_of!(Profile, auto_file) == 104);
    assert!(offset_of!(Profile, fail_counters) == 144 && offset_of!(Profile, last_purge) == 152);
    assert!(size_of::<Track>() == 280 && offset_of!(Track, profile) == 184);
    assert!(offset_of!(Track, positions) == 24 && offset_of!(Track, incoming_ttl) == 195);
    assert!(offset_of!(Track, reassembly_kind) == 228 && offset_of!(Track, reassembly) == 232);
    assert!(offset_of!(Track, delayed) == 264 && size_of::<Packet>() == 112);
    assert!(offset_of!(Packet, protocol) == 40 && offset_of!(Packet, tcp) == 48);
    assert!(size_of::<Play>() == 600 && offset_of!(Play, source) == 40);
    assert!(offset_of!(Play, destination) == 168 && offset_of!(Play, target4) == 296);
    assert!(offset_of!(Play, verdict) == 314 && offset_of!(Play, host) == 315);
    assert!(offset_of!(Play, l7) == 572 && offset_of!(Play, payload) == 576);
    assert!(offset_of!(Play, reverse) == 596 && offset_of!(Play, incoming) == 597);
    assert!(offset_of!(Params, debug) == 4252 && offset_of!(Params, mark) == 4264);
    assert!(offset_of!(Params, profiles) == 4272 && offset_of!(Params, auto_log) == 8528);
    assert!(offset_of!(Params, conntrack) == 12664 && offset_of!(Params, disabled) == 12704);
    assert!(offset_of!(Params, server) == 12705 && offset_of!(Params, cache_hostname) == 12706);
    assert!(offset_of!(Params, cache) == 12712 && offset_of!(Params, reassembly_disable) == 12728);
    assert!(offset_of!(Params, payload_disable) == 12736 && offset_of!(Params, lifetime) == 12708);
    assert!(size_of::<ReplayOps>() == 32 && size_of::<PrologOps>() == 88);
    assert!(size_of::<Reassembly>() == 32 && size_of::<ReassemblyOps>() == 24);
    assert!(
        size_of::<Payload>() == 16 && size_of::<Input>() == 48 && size_of::<PayloadOps>() == 56
    );
    assert!(size_of::<FinishFlow>() == 8 && size_of::<FinishFeedback>() == 4);
    assert!(
        size_of::<OtherQuery>() == 56
            && size_of::<OtherPlay>() == 48
            && size_of::<OtherOps>() == 48
    );
};

unsafe extern "C" {
    static mut params: Params;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn strdup(text: *const c_char) -> *mut c_char;
    fn free(data: *mut c_void);
    fn rawsend(
        address: *const Address,
        mark: u32,
        interface: *const c_char,
        data: *const c_void,
        length: usize,
    ) -> bool;
    fn HostlistCheck(
        profile: *const Profile,
        name: *const c_char,
        no_subdomains: bool,
        excluded: *mut bool,
        reload: bool,
    ) -> bool;
    #[link_name = "zapret_address_ntopa46"]
    fn ntopa46(a4: *const u8, a6: *const u8, out: *mut c_char, length: usize);
    fn reassembly_report(event: u32, first: usize, second: usize, third: usize);
    fn packet_debug(replay: bool, packet: *const Packet);
    fn TLSDebug(data: *const u8, size: usize);
    fn TLSDebugHandshake(data: *const u8, size: usize);
    fn ipcachePurgeRateLimited(cache: *mut c_void, lifetime: i64);
    fn ConntrackPoolDoubleSearch(
        table: *mut c_void,
        packet: *const Packet,
        out: *mut *mut Track,
        reverse: *mut bool,
    ) -> bool;
    fn proto_dissect_l3l4(data: *const u8, size: usize, output: *mut Packet, partial: bool);
    fn zapret_packet_route(packet: *const Packet, replay: bool, log: Log, debug: Debug) -> u32;
    fn zapret_prepare_other_packet(
        packet: *const Packet,
        inbound: *const c_char,
        outbound: *const c_char,
        mark: u32,
        server: bool,
        ops: &OtherOps,
        play: *mut OtherPlay,
    ) -> bool;
    fn zapret_packet_repair_checksum(packet: *const Packet, verdict: u8, debug: Option<Log>);
    fn zapret_play_begin(
        play: *mut Play,
        packet: *const Packet,
        positions: *const c_void,
        replay: bool,
        flags: u32,
        mark: u32,
    ) -> u32;
    fn zapret_play_resume(
        play: *mut Play,
        inbound: *const c_char,
        outbound: *const c_char,
        replay: bool,
        found: bool,
        flags: u32,
        ops: &PrologOps,
    ) -> bool;
    fn zapret_play_finish_step(flow: &mut FinishFlow, feedback: &FinishFeedback) -> u32;
}

unsafe extern "C-unwind" {
    fn ConntrackPoolPurge(table: *mut c_void);
    fn ConntrackPoolFeed(
        table: *mut c_void,
        packet: *const Packet,
        out: *mut *mut Track,
        reverse: *mut bool,
    ) -> bool;
    fn zapret_prepare_tcp(
        play: *mut Play,
        input: &Input,
        ops: &PayloadOps,
        payload: *mut Payload,
    ) -> bool;
    fn zapret_prepare_udp(play: *mut Play, input: &Input, ops: &PayloadOps) -> bool;
    fn zapret_prepare_quic(
        play: *mut Play,
        input: &Input,
        ops: &PayloadOps,
        buffer: *mut u8,
        payload: *mut Payload,
    ) -> bool;
    fn zapret_replay_queue(queue: *mut c_void, ops: &ReplayOps) -> bool;
    fn zapret_reassembly_cancel(session: &Reassembly, ops: &ReassemblyOps);
    fn zapret_native_desync(
        profile: *mut Profile,
        mark: u32,
        inbound: *const c_char,
        outbound: *const c_char,
        incoming: bool,
        track: *mut Track,
        positions: *const c_void,
        payload: u32,
        protocol: u32,
        packet: *const Packet,
        target4: *const u8,
        target6: *const u8,
        port: u16,
        output: *mut u8,
        output_length: *mut usize,
        piece: u32,
        pieces: u32,
        offset: usize,
        reassembly: *const u8,
        reassembly_length: usize,
        decryption: *const u8,
        decryption_length: usize,
    ) -> u8;
}

const REASSEMBLY_OPS: ReassemblyOps = ReassemblyOps {
    send: rawsend,
    replay,
    report: reassembly_report,
};
const PAYLOAD_OPS: PayloadOps = PayloadOps {
    reassembly: &REASSEMBLY_OPS,
    reply: windows_packet_effects::reply,
    retransmit: windows_packet_effects::retransmit,
    dns: windows_packet_effects::dns_response,
    log: DLOG,
    tls_record: TLSDebug,
    tls_handshake: TLSDebugHandshake,
};

unsafe extern "C-unwind" fn replay(queue: *mut c_void) -> bool {
    const OPS: ReplayOps = ReplayOps {
        process: dispatch,
        send: rawsend,
        debug: DLOG,
        error: DLOG_ERR,
    };
    unsafe { zapret_replay_queue(queue, &OPS) }
}

unsafe fn cancel(track: *mut Track) {
    if !track.is_null() {
        let session = unsafe {
            Reassembly {
                buffer: (&raw mut (*track).reassembly).cast(),
                kind: &raw mut (*track).reassembly_kind,
                positions: (&raw const (*track).positions).cast(),
                delayed: (&raw mut (*track).delayed).cast(),
            }
        };
        unsafe { zapret_reassembly_cancel(&session, &REASSEMBLY_OPS) };
    }
}

unsafe fn begin(
    play: *mut Play,
    packet: *const Packet,
    inbound: *const c_char,
    outbound: *const c_char,
    mark: u32,
    positions: *const c_void,
    replay: bool,
) -> bool {
    use windows_packet_effects::*;
    const OPS: PrologOps = PrologOps {
        cached_hostname,
        duplicate: strdup,
        find: prolog_find,
        purge_failures,
        update_ttl,
        get_ttl,
        log: DLOG,
        error: DLOG_ERR,
        format_address: ntopa46,
        debug_enabled: unsafe { &raw const params.debug },
        server: unsafe { &raw const params.server },
    };
    unsafe {
        let flags = u32::from(params.server)
            | (u32::from(params.disabled) << 1)
            | (u32::from(params.debug) << 2);
        let table = (&raw mut params.conntrack).cast();
        let found = match zapret_play_begin(play, packet, positions, replay, flags, mark) {
            1 => ConntrackPoolDoubleSearch(
                table,
                packet,
                &raw mut (*play).replay_track,
                &raw mut (*play).reverse,
            ),
            2 => {
                ConntrackPoolPurge(table);
                ConntrackPoolFeed(
                    table,
                    packet,
                    &raw mut (*play).track,
                    &raw mut (*play).reverse,
                )
            }
            3 => false,
            _ => return false,
        };
        zapret_play_resume(play, inbound, outbound, replay, found, flags, &OPS)
    }
}

unsafe fn finish(play: *mut Play, call: &Call, tcp: Payload, decrypted: Payload) -> u8 {
    let mut flow = FinishFlow::default();
    let mut value = FinishFeedback::default();
    let input = &call.input;
    unsafe {
        loop {
            match zapret_play_finish_step(&mut flow, &value) {
                1 => value.found = windows_packet_effects::rediscover(play),
                2 => {
                    (*play).verdict = zapret_native_desync(
                        (*play).profile,
                        input.mark,
                        input.inbound,
                        input.outbound,
                        (*play).incoming,
                        (*play).replay_track,
                        call.positions,
                        (*play).payload,
                        (*play).l7,
                        (*play).packet,
                        (*play).target4,
                        (*play).target6,
                        (*play).port,
                        call.modified,
                        call.length,
                        call.piece,
                        call.pieces,
                        call.offset,
                        tcp.data,
                        tcp.length,
                        decrypted.data,
                        decrypted.length,
                    );
                }
                3 => cancel((*play).track),
                4 => {
                    value.verdict = (*play).verdict;
                    value.incoming = (*play).incoming;
                }
                5 => value.verdict = DROP,
                6 => return flow.verdict,
                8 => value.tcp = !(*(*play).packet).tcp.is_null(),
                _ => {
                    DLOG_ERR(c"invalid final packet play policy\n".as_ptr());
                    return PASS;
                }
            }
        }
    }
}

#[inline(never)]
unsafe fn play_quic(play: *mut Play, call: &Call) -> u8 {
    let mut buffer = MaybeUninit::<[u8; 16_384]>::uninit();
    let mut payload = Payload::default();
    unsafe {
        if zapret_prepare_quic(
            play,
            &call.input,
            &PAYLOAD_OPS,
            buffer.as_mut_ptr().cast(),
            &mut payload,
        ) {
            return DROP;
        }
        finish(play, call, Payload::default(), payload)
    }
}

unsafe fn play_transport(
    route: u32,
    packet: *const Packet,
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
    piece: u32,
    pieces: u32,
    offset: usize,
    positions: *const c_void,
    modified: *mut u8,
    length: *mut usize,
) -> u8 {
    let mut play = MaybeUninit::<Play>::uninit();
    let play = play.as_mut_ptr();
    let replay = pieces != 0;
    unsafe {
        if !begin(play, packet, inbound, outbound, mark, positions, replay) {
            return (*play).verdict;
        }
        let call = Call {
            input: Input {
                inbound,
                outbound,
                payload_disable: params.payload_disable,
                reassembly_disable: params.reassembly_disable,
                mark,
                desync_mark: params.mark,
                replay,
                debug: params.debug,
            },
            piece,
            pieces,
            offset,
            positions,
            modified,
            length,
        };
        let mut payload = Payload::default();
        if route == 1 {
            if zapret_prepare_tcp(play, &call.input, &PAYLOAD_OPS, &mut payload) {
                return DROP;
            }
        } else if zapret_prepare_udp(play, &call.input, &PAYLOAD_OPS) {
            return play_quic(play, &call);
        }
        finish(play, &call, payload, Payload::default())
    }
}

unsafe extern "C" fn other_search(
    packet: *const Packet,
    track: *mut *mut Track,
    reverse: *mut bool,
) -> bool {
    unsafe { ConntrackPoolDoubleSearch((&raw mut params.conntrack).cast(), packet, track, reverse) }
}

unsafe fn other(
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
    packet: *const Packet,
    modified: *mut u8,
    length: *mut usize,
) -> u8 {
    let ops = OtherOps {
        search: other_search,
        cached_host: windows_packet_effects::other_hostname,
        find: windows_packet_effects::other_find,
        ssid: None,
        log: DLOG,
        attached_debug: unsafe { params.debug }.then_some(packet_debug),
    };
    let mut play = MaybeUninit::<OtherPlay>::uninit();
    unsafe {
        if !zapret_prepare_other_packet(
            packet,
            inbound,
            outbound,
            mark,
            params.server,
            &ops,
            play.as_mut_ptr(),
        ) {
            return PASS;
        }
        let play = play.assume_init();
        zapret_native_desync(
            play.profile,
            mark,
            inbound,
            outbound,
            play.incoming,
            play.track,
            ptr::null(),
            play.payload,
            play.l7,
            packet,
            play.target.ipv4,
            play.target.ipv6,
            0,
            modified,
            length,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
        )
    }
}

unsafe extern "C-unwind" fn dispatch(
    piece: u32,
    pieces: u32,
    offset: usize,
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
    positions: *const c_void,
    data: *const u8,
    length: usize,
    modified: *mut u8,
    modified_length: *mut usize,
) -> u8 {
    let mut packet = MaybeUninit::<Packet>::uninit();
    unsafe {
        proto_dissect_l3l4(data, length, packet.as_mut_ptr(), false);
        let packet = packet.as_ptr();
        let route = zapret_packet_route(packet, pieces != 0, DLOG, packet_debug);
        let verdict = match route {
            0 => return PASS,
            1 | 2 => play_transport(
                route,
                packet,
                mark,
                inbound,
                outbound,
                piece,
                pieces,
                offset,
                positions,
                modified,
                modified_length,
            ),
            _ => other(mark, inbound, outbound, packet, modified, modified_length),
        };
        if route != 4 {
            zapret_packet_repair_checksum(packet, verdict, params.debug.then_some(DLOG));
        }
        verdict
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn dpi_desync_packet(
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
    data: *const u8,
    length: usize,
    modified: *mut u8,
    modified_length: *mut usize,
) -> u8 {
    unsafe {
        ipcachePurgeRateLimited((&raw mut params.cache).cast(), i64::from(params.lifetime));
        dispatch(
            0,
            0,
            0,
            mark,
            inbound,
            outbound,
            ptr::null(),
            data,
            length,
            modified,
            modified_length,
        )
    }
}
