//! IP and ICMP profile preparation and the Windows checksum policy.
use crate::{
    checksum::wire::{zapret_checksum_icmp, zapret_checksum_tcp, zapret_checksum_udp},
    logging::LogSink,
    packet::Packet,
    packet_policy::{VERDICT_MASK, VERDICT_PASS},
    play_prolog::{connection, incoming_interface},
    profile_config::{profile_display_name, profile_number},
};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

const L7_UNKNOWN: u32 = 1;
const PAYLOAD_IPV4: u32 = 4;
const PAYLOAD_IPV6: u32 = 5;
const PAYLOAD_ICMP: u32 = 6;
const VERDICT_NOCSUM: u8 = 8;

#[repr(u32)]
enum Route {
    Invalid,
    Tcp,
    Udp,
    Icmp,
    Ip,
}

type PacketDebug = unsafe extern "C" fn(bool, *const Packet);

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_route(
    packet: &Packet,
    replay: bool,
    log: LogSink,
    packet_debug: PacketDebug,
) -> u32 {
    let route = if !packet.valid_ip() {
        unsafe { log(c"invalid packet - neither ipv4 or ipv6\n".as_ptr()) };
        return Route::Invalid as u32;
    } else if !packet.tcp.is_null() {
        Route::Tcp
    } else if !packet.udp.is_null() {
        Route::Udp
    } else if !packet.icmp.is_null() {
        Route::Icmp
    } else {
        Route::Ip
    };
    unsafe { packet_debug(replay, packet) };
    route as u32
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Address {
    ipv4: *const u8,
    ipv6: *const u8,
}

impl Address {
    unsafe fn from_packet(packet: &Packet, source: bool) -> Self {
        let mut result = Self {
            ipv4: ptr::null(),
            ipv6: ptr::null(),
        };
        if packet.ipv4.is_null() {
            result.ipv6 = unsafe { packet.ipv6.add(if source { 8 } else { 24 }) };
        } else {
            result.ipv4 = unsafe { packet.ipv4.add(if source { 12 } else { 16 }) };
        }
        result
    }
}

#[repr(C)]
struct Query {
    destination: Address,
    source: Address,
    hostname: *const c_char,
    ssid: *const c_char,
    mark: u32,
    protocol: u8,
    icmp_type: u8,
    icmp_code: u8,
    hostname_is_ip: bool,
}

#[repr(C)]
struct Play {
    profile: *mut c_void,
    track: *mut c_void,
    target: Address,
    l7: u32,
    payload: u32,
    incoming: bool,
}

type Ssid = unsafe extern "C" fn(*const c_char) -> *const c_char;

#[repr(C)]
struct Ops {
    search: unsafe extern "C" fn(*const Packet, *mut *mut c_void, *mut bool) -> bool,
    cached_host: unsafe extern "C" fn(Address, *mut c_char, *mut bool) -> bool,
    find: unsafe extern "C" fn(&Query) -> *mut c_void,
    ssid: Option<Ssid>,
    log: LogSink,
    attached_debug: Option<PacketDebug>,
}

enum Event {
    InvalidAttached,
    Attached(*const Packet),
    TrackFound(bool),
    CachedProfile(*const c_void),
    TrackMissing,
    ProfileMissing,
}

impl Ops {
    unsafe fn report(&self, event: Event) {
        // Presence of the callback records the entry-time diagnostics setting.
        let Some(packet_debug) = self.attached_debug else {
            return;
        };
        let log = |message: &CStr| {
            unsafe { (self.log)(message.as_ptr()) };
        };
        unsafe {
            match event {
                Event::InvalidAttached => log(c"attached packet is invalid\n"),
                Event::Attached(packet) => {
                    log(c"attached packet\n");
                    packet_debug(false, packet);
                }
                Event::TrackFound(reverse) => {
                    (self.log)(
                        c"found conntrack entry. inverted reverse=%u\n".as_ptr(),
                        u32::from(reverse),
                    );
                }
                Event::CachedProfile(profile) => {
                    (self.log)(
                        c"using desync profile %u (%s) from conntrack entry\n".as_ptr(),
                        profile_number(profile),
                        profile_display_name(profile),
                    );
                }
                Event::TrackMissing => log(c"conntrack entry not found\n"),
                Event::ProfileMissing => log(c"matching desync profile not found\n"),
            };
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_prepare_other_packet(
    packet: &Packet,
    ifin: *const c_char,
    ifout: *const c_char,
    mark: u32,
    server: bool,
    ops: &Ops,
    output: *mut Play,
) -> bool {
    if !packet.valid_ip() {
        return false;
    }
    let no_icmp = packet.icmp.is_null();
    let (kind, code) = if no_icmp {
        (255, 255)
    } else {
        unsafe { (*packet.icmp, *packet.icmp.add(1)) }
    };
    let mut state = Play {
        profile: ptr::null_mut(),
        track: ptr::null_mut(),
        target: Address {
            ipv4: ptr::null(),
            ipv6: ptr::null(),
        },
        l7: L7_UNKNOWN,
        payload: if no_icmp { L7_UNKNOWN } else { PAYLOAD_ICMP },
        incoming: false,
    };

    let mut reverse = false;
    // The previous engine accepts this union of ICMPv4 and ICMPv6 error
    // types. An inner datagram can be a truncated header quote.
    if matches!(kind, 1..=5 | 11 | 12) && !packet.payload.is_null() {
        let attached = unsafe { Packet::dissect(packet.payload, packet.payload_length, true) };
        if !attached.valid_ip() {
            unsafe { ops.report(Event::InvalidAttached) };
        } else {
            state.payload = if attached.ipv4.is_null() {
                PAYLOAD_IPV6
            } else {
                PAYLOAD_IPV4
            };
            unsafe { ops.report(Event::Attached(&attached)) };
            if unsafe { (ops.search)(&attached, &mut state.track, &mut reverse) }
                && !state.track.is_null()
            {
                reverse = !reverse;
                unsafe { ops.report(Event::TrackFound(reverse)) };
                let entry = unsafe { connection(state.track) };
                if unsafe { (*entry).search_complete && !(*entry).profile.is_null() } {
                    state.profile = unsafe { (*entry).profile };
                    unsafe { ops.report(Event::CachedProfile(state.profile)) };
                }
                state.l7 = unsafe { (*entry).l7 };
            } else {
                state.track = ptr::null_mut();
                unsafe { ops.report(Event::TrackMissing) };
            }
        }
    }
    let tracked = !state.track.is_null();
    if !tracked {
        reverse = unsafe { incoming_interface(ifin, ifout) };
    }
    state.incoming = if tracked { reverse ^ server } else { reverse };

    let destination = unsafe { Address::from_packet(packet, false) };
    let source = unsafe { Address::from_packet(packet, true) };
    state.target = if state.incoming { source } else { destination };
    let mut ssid = ptr::null();
    if let Some(lookup) = ops.ssid {
        // Plain IP always checks ifin first. ICMP uses the inferred direction,
        // and can fall back to the other interface only without conntrack.
        let (first, second) = if no_icmp || reverse {
            (ifin, ifout)
        } else {
            (ifout, ifin)
        };
        ssid = unsafe { lookup(first) };
        let interface = if ssid.is_null() && !tracked {
            ssid = unsafe { lookup(second) };
            second
        } else {
            first
        };
        if !ssid.is_null() {
            unsafe { (ops.log)(c"found ssid for %s : %s\n".as_ptr(), interface, ssid) };
        }
    }
    if state.profile.is_null() {
        let mut host = [0; 256];
        let mut hostname = ptr::null();
        let mut is_ip = false;
        if tracked {
            let entry = unsafe { connection(state.track) };
            hostname = unsafe { (*entry).hostname };
            if !hostname.is_null() {
                is_ip = unsafe { (*entry).hostname_is_ip };
            }
        }
        if hostname.is_null()
            && (unsafe { (ops.cached_host)(destination, host.as_mut_ptr(), &mut is_ip) }
                || unsafe { (ops.cached_host)(source, host.as_mut_ptr(), &mut is_ip) })
        {
            hostname = host.as_ptr();
        }
        state.profile = unsafe {
            (ops.find)(&Query {
                destination,
                source,
                hostname,
                ssid,
                mark,
                protocol: packet.protocol,
                icmp_type: kind,
                icmp_code: code,
                hostname_is_ip: is_ip,
            })
        };
        if state.profile.is_null() {
            unsafe { ops.report(Event::ProfileMissing) };
            return false;
        }
    }
    unsafe { output.write(state) };
    true
}

// The Windows receive and replay paths pass writable packet storage. The log
// sink runs before the shared wire helper reads or changes those bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_repair_checksum(
    packet: &Packet,
    verdict: u8,
    debug: Option<LogSink>,
) {
    if verdict & (VERDICT_NOCSUM | VERDICT_MASK) != VERDICT_PASS || !packet.valid_ip() {
        return;
    }
    let log = |message: &CStr| {
        if let Some(debug) = debug {
            unsafe { debug(message.as_ptr()) };
        }
    };
    unsafe {
        if !packet.tcp.is_null() {
            log(c"fixing tcp checksum\n");
            zapret_checksum_tcp(
                packet.tcp.cast_mut(),
                packet.transport_length,
                packet.ipv4,
                packet.ipv6,
            );
        } else if !packet.udp.is_null() {
            log(c"fixing udp checksum\n");
            zapret_checksum_udp(
                packet.udp.cast_mut(),
                packet.transport_length,
                packet.ipv4,
                packet.ipv6,
            );
        } else if !packet.icmp.is_null() {
            log(c"fixing icmp checksum\n");
            zapret_checksum_icmp(packet.icmp.cast_mut(), packet.transport_length, packet.ipv6);
        }
    }
}
