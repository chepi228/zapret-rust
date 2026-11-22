//! Packet setup and cached-profile selection around C-owned Lua operations.
use crate::{
    logging::LogSink,
    packet::Packet,
    profile_config::{profile_display_name, profile_number},
    profile_rediscovery::Connection,
};
use std::{
    ffi::{c_char, c_void},
    ptr,
};

const SERVER: u32 = 1;
const TRACKING_DISABLED: u32 = 2;
const DEBUG: u32 = 4;
const UNKNOWN: u32 = 1;
const EMPTY_PAYLOAD: u32 = 2;
const TRACK_PROFILE_OFFSET: usize = 184;
const TRACK_POSITIONS_OFFSET: usize = 24;

#[repr(C, align(8))]
pub(super) struct SocketAddress([u8; 128]);

#[repr(C)]
pub(super) struct PlayState {
    pub(super) packet: *const Packet,
    profile: *mut c_void,
    pub(super) positions: *const c_void,
    pub(super) track: *mut c_void,
    pub(super) replay_track: *mut c_void,
    pub(super) source: SocketAddress,
    pub(super) destination: SocketAddress,
    search_ipv4: *const u8,
    search_ipv6: *const u8,
    search_port: u16,
    verdict: u8,
    pub(super) host: [c_char; 256],
    pub(super) l7: u32,
    pub(super) payload_kind: u32,
    ssid: *const c_char,
    mark: u32,
    pub(super) reverse: bool,
    pub(super) reverse_fixed: bool,
    pub(super) have_host: bool,
}

#[repr(C)]
struct Ops {
    cached_hostname: unsafe extern "C" fn(*mut PlayState, *mut bool) -> bool,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    find: unsafe extern "C" fn(*const PlayState, *const c_char, bool) -> *mut c_void,
    purge_failures: unsafe extern "C" fn(*mut c_void),
    update_ttl: unsafe extern "C" fn(*const PlayState, *const c_char),
    get_ttl: unsafe extern "C" fn(*const PlayState, *const c_char),
    log: LogSink,
    error: LogSink,
    format_address: unsafe extern "C" fn(*const u8, *const u8, *mut c_char, usize),
    debug_enabled: *const bool,
    server: *const bool,
}

pub(super) unsafe fn connection(track: *mut c_void) -> *mut Connection {
    unsafe { track.byte_add(TRACK_PROFILE_OFFSET).cast() }
}

pub(super) unsafe fn incoming_interface(
    interface_in: *const c_char,
    interface_out: *const c_char,
) -> bool {
    !interface_in.is_null()
        && unsafe { *interface_in } != 0
        && (interface_out.is_null() || unsafe { *interface_out } == 0)
}

unsafe fn endpoint(target: *mut SocketAddress, address: *const u8, port: *const u8, ipv6: bool) {
    let target = target.cast::<u8>();
    unsafe {
        target.cast::<u16>().write(if ipv6 { 23 } else { 2 });
        if port.is_null() {
            target.add(2).cast::<u16>().write(0);
        } else {
            ptr::copy_nonoverlapping(port, target.add(2), 2);
        }
        if ipv6 {
            target.add(4).cast::<u32>().write(0);
            ptr::copy_nonoverlapping(address, target.add(8), 16);
            target.add(24).cast::<u32>().write(0);
        } else {
            ptr::copy_nonoverlapping(address, target.add(4), 4);
        }
    }
}

unsafe fn setup_direction(state: *mut PlayState, server: bool) {
    let packet = unsafe { (*state).packet };
    let ipv6 = unsafe { !(*packet).ipv6.is_null() };
    let transport = if unsafe { (*packet).tcp.is_null() } {
        unsafe { (*packet).udp }
    } else {
        unsafe { (*packet).tcp }
    };
    let (source, destination) = if ipv6 {
        unsafe { ((*packet).ipv6.add(8), (*packet).ipv6.add(24)) }
    } else {
        unsafe { ((*packet).ipv4.add(12), (*packet).ipv4.add(16)) }
    };
    let destination_port = if transport.is_null() {
        transport
    } else {
        unsafe { transport.add(2) }
    };
    unsafe {
        endpoint(ptr::addr_of_mut!((*state).source), source, transport, ipv6);
        endpoint(
            ptr::addr_of_mut!((*state).destination),
            destination,
            destination_port,
            ipv6,
        );
    }
    let reverse = unsafe { (*state).reverse_fixed };
    let address = if reverse { source } else { destination };
    let port = if reverse ^ server {
        transport
    } else {
        destination_port
    };
    unsafe {
        (*state).search_ipv4 = if ipv6 { ptr::null() } else { address };
        (*state).search_ipv6 = if ipv6 { address } else { ptr::null() };
        (*state).search_port = if port.is_null() {
            0
        } else {
            u16::from_be_bytes([*port, *port.add(1)])
        };
    }
}

// Returns the requested C operation: 0 rejects, 1 searches, 2 purges/feeds,
// and 3 continues with connection tracking disabled. Lua runs after return.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_play_begin(
    state: *mut PlayState,
    packet: *const Packet,
    positions: *const c_void,
    replay: bool,
    flags: u32,
    mark: u32,
) -> u32 {
    unsafe { (*state).verdict = 0 };
    if unsafe { (*packet).ipv4.is_null() == (*packet).ipv6.is_null() } {
        return 0;
    }
    unsafe {
        (*state).packet = packet;
        (*state).positions = positions;
        (*state).profile = ptr::null_mut();
        (*state).track = ptr::null_mut();
        (*state).replay_track = ptr::null_mut();
        (*state).reverse = false;
        (*state).reverse_fixed = false;
        (*state).have_host = false;
        (*state).l7 = UNKNOWN;
        (*state).payload_kind = if (*packet).payload_length == 0 {
            EMPTY_PAYLOAD
        } else {
            UNKNOWN
        };
        (*state).ssid = ptr::null();
        (*state).mark = mark;
    }
    if replay {
        1
    } else if flags & TRACKING_DISABLED == 0 {
        2
    } else {
        3
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_play_resume(
    state: *mut PlayState,
    interface_in: *const c_char,
    interface_out: *const c_char,
    replay: bool,
    found: bool,
    flags: u32,
    ops: &Ops,
) -> bool {
    let server = flags & SERVER != 0;
    let debug = flags & DEBUG != 0;
    if replay {
        if !found || unsafe { (*state).reverse } {
            return false;
        }
    } else if found {
        unsafe {
            (*state).profile = (*connection((*state).track)).profile;
            (*state).replay_track = (*state).track;
        }
    }
    unsafe {
        (*state).reverse_fixed = if replay || !(*state).track.is_null() {
            (*state).reverse ^ server
        } else {
            (*state).reverse = incoming_interface(interface_in, interface_out);
            (*state).reverse
        };
        setup_direction(state, server);
        if debug && *ops.debug_enabled {
            let mut text = [0; 65]; // INET6_ADDRSTRLEN
            (ops.format_address)(
                (*state).search_ipv4,
                (*state).search_ipv6,
                text.as_mut_ptr(),
                text.len(),
            );
            let mode = if *ops.server { c"server" } else { c"client" };
            (ops.log)(
                c"%s mode desync profile/ipcache search target ip=%s port=%u\n".as_ptr(),
                mode.as_ptr(),
                text.as_ptr(),
                u32::from((*state).search_port),
            );
        }
    }
    let track = if replay {
        unsafe { (*state).replay_track }
    } else {
        unsafe { (*state).track }
    };
    let track_state = if track.is_null() {
        ptr::null_mut()
    } else {
        unsafe { connection(track) }
    };
    if !track_state.is_null() {
        unsafe {
            (*state).l7 = (*track_state).l7;
            if replay {
                (*state).profile = (*track_state).profile;
            }
        }
    }
    let profile = unsafe { (*state).profile };
    if !profile.is_null() {
        if debug {
            unsafe {
                (ops.log)(
                    c"using cached desync profile %u (%s)\n".as_ptr(),
                    profile_number(profile),
                    profile_display_name(profile),
                )
            };
        }
    } else if track_state.is_null() || unsafe { !(*track_state).search_complete } {
        let mut hostname = ptr::null();
        let mut is_ip = false;
        if !track_state.is_null() {
            unsafe {
                hostname = (*track_state).hostname;
                is_ip = (*track_state).hostname_is_ip;
                if !replay
                    && hostname.is_null()
                    && !(*state).reverse
                    && (ops.cached_hostname)(state, &mut is_ip)
                {
                    let duplicated = (ops.duplicate)(ptr::addr_of!((*state).host).cast());
                    if duplicated.is_null() {
                        (ops.error)(c"strdup(host): out of memory\n".as_ptr());
                        return false;
                    }
                    (*track_state).hostname = duplicated;
                    (*track_state).hostname_is_ip = is_ip;
                    hostname = duplicated;
                }
            }
        }
        let profile = unsafe { (ops.find)(state, hostname, is_ip) };
        unsafe {
            (*state).profile = profile;
            if !track_state.is_null() {
                (*track_state).profile = profile;
                (*track_state).search_complete = true;
            }
        }
    }
    if unsafe { (*state).profile.is_null() } {
        if debug {
            unsafe { (ops.log)(c"matching desync profile not found\n".as_ptr()) };
        }
        return false;
    }
    if !replay {
        unsafe { (ops.purge_failures)((*state).profile) };
        if unsafe { (*state).reverse_fixed } {
            if !track_state.is_null() && unsafe { (*track_state).incoming_ttl == 0 } {
                let packet = unsafe { (*state).packet };
                let ttl = if unsafe { (*packet).ipv4.is_null() } {
                    unsafe { *(*packet).ipv6.add(7) }
                } else {
                    unsafe { *(*packet).ipv4.add(8) }
                };
                unsafe {
                    (*track_state).incoming_ttl = ttl;
                    if debug {
                        (ops.log)(
                            c"incoming TTL %u\n".as_ptr(),
                            u32::from((*connection((*state).track)).incoming_ttl),
                        );
                    }
                }
            }
            unsafe { (ops.update_ttl)(state, interface_in) };
        } else {
            unsafe { (ops.get_ttl)(state, interface_out) };
        }
    }
    unsafe {
        if (*state).positions.is_null() && !(*state).replay_track.is_null() {
            (*state).positions = (*state).replay_track.byte_add(TRACK_POSITIONS_OFFSET);
        }
    }
    true
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{offset_of, size_of};

    assert!(size_of::<Packet>() == 112);
    assert!(offset_of!(Packet, ipv4) == 16);
    assert!(offset_of!(Packet, tcp) == 48);
    assert!(offset_of!(Packet, payload_length) == 96);
    assert!(size_of::<PlayState>() == 600);
    assert!(offset_of!(PlayState, source) == 40);
    assert!(offset_of!(PlayState, destination) == 168);
    assert!(offset_of!(PlayState, search_ipv4) == 296);
    assert!(offset_of!(PlayState, host) == 315);
    assert!(offset_of!(PlayState, l7) == 572);
    assert!(offset_of!(PlayState, ssid) == 584);
    assert!(offset_of!(PlayState, reverse) == 596);
    assert!(offset_of!(PlayState, reverse_fixed) == 597);
};
