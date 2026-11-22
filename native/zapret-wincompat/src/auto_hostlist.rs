//! Automatic hostlist failure decisions and bounded reset packet serialization.
#[cfg(windows)]
mod diagnostics;

use crate::{
    caches::{Failure, zapret_hostfail_increment},
    conntrack::{Position, Positions},
    host_pool::{PublishError, add_persisted},
    list_registry::ListFile,
    packet::Packet,
    packet_write::{fix_ipv4_checksum, transport_checksum},
    profile_rediscovery::Connection,
    protocol::HttpReplyLooksLikeDPIRedirect,
};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

const SERVER: u32 = 1;
const LOGGING: u32 = 2;
const TCP: u8 = 6;
const STOP: u8 = 255;
const HTTP_REPLY: u32 = 8;

// Offset of hostlist_auto in the C-owned desync_profile.
const CONFIG_OFFSET: usize = if cfg!(target_pointer_width = "64") {
    104
} else {
    56
};

#[repr(C)]
struct Config {
    automatic: *mut ListFile,
    fail_threshold: i32,
    fail_time: i32,
    retrans_threshold: i32,
    udp_in: i32,
    udp_out: i32,
    retrans_maxseq: u32,
    incoming_maxseq: u32,
    retrans_reset: bool,
}

#[repr(C)]
struct Context {
    profile: *mut c_void,
    hostname: *const c_char,
    client_text: *const c_char,
    client: *const c_void,
    interface: *const c_char,
    track: *mut c_void,
    l7: u32,
    flags: u32,
    no_subdomains: bool,
}

#[repr(C)]
struct Ops {
    find_counter: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut Failure,
    add_counter: unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> *mut Failure,
    remove_counter: unsafe extern "C" fn(*mut c_void, *mut Failure),
    check_host: unsafe extern "C" fn(*const c_void, *const c_char, bool, *mut bool, bool) -> bool,
    append: unsafe extern "C" fn(*const Context) -> bool,
    stamp: unsafe extern "C" fn(*const Context) -> bool,
    send: unsafe extern "C" fn(*const Context, *const u8, usize) -> bool,
    report: unsafe extern "C" fn(u32, *const Context, u64, u64, u64, u64),
}

#[repr(C)]
struct TrackInput {
    track: *mut c_void,
    profile: *mut c_void,
    client: *const c_void,
    interface: *const c_char,
    l7: u32,
}

#[repr(C)]
struct TrackOps {
    effects: *const Ops,
    server: *const bool,
    debug: *const bool,
    append_path: *const c_char,
    format_client: unsafe extern "C" fn(*const c_void, *mut c_char, usize),
}

enum TrackKind {
    Tcp,
    Udp,
    Incoming,
}

#[repr(u32)]
enum Event {
    ResetCounter,
    OutsideSequence,
    RetransThreshold,
    SendReset,
    RetransCounter,
    CounterAllocationFailed,
    FailureCounter,
    FailureThreshold,
    RecheckHost,
    AddHost,
    SkipHost,
    HostAllocationFailed,
    AppendFailed,
    StampFailed,
    RetransFailure,
    UdpSuccess,
    UdpFailure,
    IncomingReset,
    IncomingHttp,
    RedirectOther,
    RedirectLocal,
    IncomingLimit,
}

impl Context {
    unsafe fn report(&self, ops: &Ops, event: Event, values: [u64; 4]) {
        if self.flags & LOGGING != 0 {
            unsafe { self.error(ops, event, values) };
        }
    }

    unsafe fn error(&self, ops: &Ops, event: Event, values: [u64; 4]) {
        unsafe {
            (ops.report)(
                event as u32,
                self,
                values[0],
                values[1],
                values[2],
                values[3],
            )
        };
    }
}

unsafe fn config(profile: *mut c_void) -> *const Config {
    unsafe { profile.byte_add(CONFIG_OFFSET).cast() }
}

unsafe fn connection(track: *mut c_void) -> *mut Connection {
    unsafe { track.byte_add(184).cast() }
}

unsafe fn positions(track: *const c_void) -> *const Positions {
    unsafe { track.byte_add(24).cast() }
}

unsafe fn needs_client_text(
    input: &TrackInput,
    track: *const Connection,
    kind: &TrackKind,
) -> bool {
    match kind {
        TrackKind::Tcp => true,
        TrackKind::Udp => unsafe {
            !track.is_null()
                && !(*track).profile.is_null()
                && !(*track).hostname.is_null()
                && (*track).auto_check
                && !(*track).failure_finalized
                && (*config((*track).profile)).udp_out != 0
        },
        TrackKind::Incoming => unsafe {
            !track.is_null()
                && (*track).auto_check
                && !(*track).failure_finalized
                && (*config(input.profile)).incoming_maxseq != 0
                && (*positions(input.track)).server.sequence
                    != (*positions(input.track)).server.initial_sequence
        },
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_track(
    input: &TrackInput,
    kind: u32,
    packet: *const Packet,
    snapshot: *const Positions,
    payload_kind: u32,
    ops: &TrackOps,
) {
    let kind = match kind {
        0 => TrackKind::Tcp,
        1 => TrackKind::Udp,
        2 => TrackKind::Incoming,
        _ => return,
    };
    let track = if input.track.is_null() {
        ptr::null()
    } else {
        unsafe { connection(input.track) }.cast_const()
    };
    let mut client = [0; 48];
    if unsafe { ops.append_path.read() != 0 && !ops.server.read() }
        && unsafe { needs_client_text(input, track, &kind) }
        && unsafe { ops.append_path.read() != 0 }
    {
        unsafe { (ops.format_client)(input.client, client.as_mut_ptr(), client.len()) };
    }

    // The formatter can update these fields. Inactive tracking never needs a report view.
    if track.is_null()
        || unsafe { ops.server.read() || !(*track).auto_check || (*track).failure_finalized }
    {
        return;
    }
    let (hostname, no_subdomains) =
        unsafe { ((*track).hostname.cast_const(), (*track).hostname_is_ip) };
    let (profile, l7) = if matches!(kind, TrackKind::Incoming) {
        (input.profile, input.l7)
    } else {
        unsafe { ((*track).profile, (*track).l7) }
    };
    let context = Context {
        profile,
        hostname,
        client_text: client.as_ptr(),
        client: input.client,
        interface: input.interface,
        track: input.track,
        l7,
        flags: if unsafe { ops.debug.read() || ops.append_path.read() != 0 } {
            LOGGING
        } else {
            0
        },
        no_subdomains,
    };
    let effects = unsafe { &*ops.effects };
    unsafe {
        match kind {
            TrackKind::Tcp => zapret_autolist_tcp(&context, packet, effects),
            TrackKind::Udp => zapret_autolist_udp(&context, snapshot, effects),
            TrackKind::Incoming => {
                zapret_autolist_incoming(&context, packet, payload_kind, effects)
            }
        }
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_is_retransmission(position: *const Position) -> bool {
    unsafe {
        (*position)
            .previous_upper
            .wrapping_sub((*position).position)
            & 0x8000_0000
            == 0
    }
}

unsafe fn stop(track: *mut Connection) {
    if unsafe { (*track).auto_check } {
        unsafe { (*track).retransmissions = STOP };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_reset(context: &Context, ops: &Ops) {
    if context.hostname.is_null() {
        return;
    }
    let counter = unsafe { (ops.find_counter)(context.profile, context.hostname) };
    if !counter.is_null() {
        unsafe {
            (ops.remove_counter)(context.profile, counter);
            context.report(ops, Event::ResetCounter, [0; 4]);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_failed(context: &Context, ops: &Ops) {
    let settings = unsafe { config(context.profile) };
    let mut counter = unsafe { (ops.find_counter)(context.profile, context.hostname) };
    if counter.is_null() {
        counter =
            unsafe { (ops.add_counter)(context.profile, context.hostname, (*settings).fail_time) };
        if counter.is_null() {
            unsafe { context.error(ops, Event::CounterAllocationFailed, [0; 4]) };
            return;
        }
    }
    unsafe { zapret_hostfail_increment(counter) };
    let count = unsafe { (*counter).counter };
    let threshold = unsafe { (*settings).fail_threshold };
    unsafe {
        context.report(
            ops,
            Event::FailureCounter,
            [count as u64, threshold as u64, 0, 0],
        )
    };
    if count < threshold {
        return;
    }
    unsafe {
        context.report(ops, Event::FailureThreshold, [0; 4]);
        (ops.remove_counter)(context.profile, counter);
        context.report(ops, Event::RecheckHost, [0; 4]);
    }
    let mut excluded = false;
    if unsafe {
        (ops.check_host)(
            context.profile,
            context.hostname,
            context.no_subdomains,
            &mut excluded,
            false,
        )
    } || excluded
    {
        unsafe { context.report(ops, Event::SkipHost, [0; 4]) };
        return;
    }
    unsafe { context.report(ops, Event::AddHost, [0; 4]) };
    let file = unsafe { (*settings).automatic };
    let slot = unsafe { (*file).hosts.get() };
    let result = unsafe {
        add_persisted(slot, CStr::from_ptr(context.hostname), || {
            (ops.append)(context)
        })
    };
    match result {
        Err(PublishError::Allocation) => unsafe {
            context.error(ops, Event::HostAllocationFailed, [0; 4]);
        },
        Err(PublishError::Write) => unsafe {
            context.error(ops, Event::AppendFailed, [0; 4]);
        },
        Ok(()) => {
            if !unsafe { (ops.stamp)(context) } {
                unsafe { context.error(ops, Event::StampFailed, [0; 4]) };
            }
        }
    }
}

unsafe fn send_reset(packet: *const Packet, state: *const Positions, context: &Context, ops: &Ops) {
    let ipv6 = unsafe { (*packet).ipv4.is_null() };
    let header_len = if ipv6 { 40 } else { 20 };
    let mut frame = [0u8; 60];
    let header = if ipv6 {
        unsafe { (*packet).ipv6 }
    } else {
        unsafe { (*packet).ipv4 }
    };
    unsafe {
        ptr::copy_nonoverlapping(header, frame.as_mut_ptr(), header_len);
        ptr::copy_nonoverlapping((*packet).tcp, frame.as_mut_ptr().add(header_len), 20);
    }
    let (ip, tcp) = frame[..header_len + 20].split_at_mut(header_len);
    if ipv6 {
        let flow = unsafe { (*state).server.ipv6_flow };
        ip[..4].copy_from_slice(&if flow == 0 { 0x6000_0000 } else { flow }.to_be_bytes());
        ip[4..6].copy_from_slice(&20u16.to_be_bytes());
        ip[6] = TCP;
        for i in 0..16 {
            ip.swap(8 + i, 24 + i);
        }
    } else {
        ip[0] = (ip[0] & 0xf0) | 5;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[4..6].fill(0);
        for i in 0..4 {
            ip.swap(12 + i, 16 + i);
        }
        fix_ipv4_checksum(ip);
    }
    tcp.swap(0, 2);
    tcp.swap(1, 3);
    for i in 0..4 {
        tcp.swap(4 + i, 8 + i);
    }
    tcp[12] = (tcp[12] & 15) | 0x50;
    tcp[13] = 4;
    // The pinned reset builder assigns the stored window directly to the wire field.
    tcp[14..16].copy_from_slice(&unsafe { (*state).server.window }.to_ne_bytes());
    tcp[16..18].fill(0);
    let sum = transport_checksum(ip, tcp, 6, ipv6);
    tcp[16..18].copy_from_slice(&sum.to_le_bytes());
    unsafe {
        context.report(ops, Event::SendReset, [0; 4]);
        (ops.send)(context, frame.as_ptr(), header_len + 20);
    }
}

unsafe fn retransmission(
    track: *mut Connection,
    state: *const Positions,
    packet: *const Packet,
    context: &Context,
    ops: &Ops,
) -> bool {
    if !unsafe { (*track).auto_check }
        || unsafe { (*track).failure_finalized }
        || unsafe { (*track).retransmissions == STOP }
    {
        return false;
    }
    let settings = unsafe { config(context.profile) };
    if unsafe { (*packet).protocol == TCP && (*state).state != 0 } {
        let sequence = unsafe { (*state).client.sequence };
        let first = unsafe { (*state).client.initial_sequence };
        let maximum = unsafe { (*settings).retrans_maxseq };
        if sequence.wrapping_sub(first) > maximum {
            unsafe {
                (*track).failure_finalized = true;
                context.report(
                    ops,
                    Event::OutsideSequence,
                    [
                        sequence.into(),
                        first.into(),
                        first.wrapping_add(maximum).into(),
                        0,
                    ],
                );
                stop(track);
                zapret_autolist_reset(context, ops);
            }
            return false;
        }
        if !unsafe { zapret_is_retransmission(ptr::addr_of!((*state).client)) } {
            return false;
        }
    }
    let count = unsafe { (*track).retransmissions + 1 };
    unsafe { (*track).retransmissions = count };
    let threshold = unsafe { (*settings).retrans_threshold };
    if i32::from(count) < threshold {
        unsafe {
            context.report(
                ops,
                Event::RetransCounter,
                [count.into(), threshold as u64, 0, 0],
            )
        };
        return false;
    }
    unsafe {
        context.report(
            ops,
            Event::RetransThreshold,
            [count.into(), threshold as u64, 0, 0],
        );
        stop(track);
        (*track).failure_finalized = true;
        if !(*packet).tcp.is_null()
            && (*settings).retrans_reset
            && (!(*packet).ipv4.is_null() || !(*packet).ipv6.is_null())
        {
            send_reset(packet, state, context, ops);
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_tcp(context: &Context, packet: *const Packet, ops: &Ops) {
    if context.flags & SERVER != 0
        || context.track.is_null()
        || context.profile.is_null()
        || context.hostname.is_null()
    {
        return;
    }
    if unsafe {
        retransmission(
            connection(context.track),
            positions(context.track),
            packet,
            context,
            ops,
        )
    } {
        unsafe {
            context.report(ops, Event::RetransFailure, [0; 4]);
            zapret_autolist_failed(context, ops);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_udp(context: &Context, snapshot: *const Positions, ops: &Ops) {
    if context.flags & SERVER != 0
        || context.track.is_null()
        || context.profile.is_null()
        || context.hostname.is_null()
    {
        return;
    }
    let track = unsafe { connection(context.track) };
    let settings = unsafe { config(context.profile) };
    if unsafe { !(*track).auto_check || (*track).failure_finalized || (*settings).udp_out == 0 } {
        return;
    }
    let snapshot = if snapshot.is_null() {
        unsafe { positions(context.track) }
    } else {
        snapshot
    };
    let incoming = unsafe { (*snapshot).server.packets };
    let outgoing = unsafe { (*snapshot).client.packets };
    let max_in = unsafe { (*settings).udp_in };
    let max_out = unsafe { (*settings).udp_out };
    if incoming > max_in as u64 {
        unsafe {
            (*track).failure_finalized = true;
            context.report(ops, Event::UdpSuccess, [incoming, max_in as u64, 0, 0]);
            zapret_autolist_reset(context, ops);
        }
    } else if outgoing >= max_out as u64 {
        unsafe {
            (*track).failure_finalized = true;
            context.report(
                ops,
                Event::UdpFailure,
                [incoming, max_in as u64, outgoing, max_out as u64],
            );
            zapret_autolist_failed(context, ops);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_incoming(
    context: &Context,
    packet: *const Packet,
    payload_kind: u32,
    ops: &Ops,
) {
    if context.flags & SERVER != 0 || context.track.is_null() || context.profile.is_null() {
        return;
    }
    let track = unsafe { connection(context.track) };
    let settings = unsafe { config(context.profile) };
    let maximum = unsafe { (*settings).incoming_maxseq };
    if unsafe { !(*track).auto_check || (*track).failure_finalized } || maximum == 0 {
        return;
    }
    let state = unsafe { positions(context.track) };
    let sequence = unsafe { (*state).server.sequence };
    let initial = unsafe { (*state).server.initial_sequence };
    let relative = sequence.wrapping_sub(initial);
    if relative == 0 {
        return;
    }
    if sequence.wrapping_sub(initial.wrapping_add(1)) > maximum.wrapping_sub(1) {
        unsafe {
            context.report(
                ops,
                Event::IncomingLimit,
                [relative.into(), maximum.into(), 0, 0],
            );
            zapret_autolist_reset(context, ops);
            (*track).failure_finalized = true;
        }
        return;
    }
    let failed = if unsafe { *(*packet).tcp.add(13) & 4 != 0 } {
        unsafe { context.report(ops, Event::IncomingReset, [relative.into(), 0, 0, 0]) };
        true
    } else if unsafe { (*packet).payload_length != 0 } && payload_kind == HTTP_REPLY {
        unsafe { context.report(ops, Event::IncomingHttp, [relative.into(), 0, 0, 0]) };
        let redirected = unsafe {
            HttpReplyLooksLikeDPIRedirect(
                (*packet).payload,
                (*packet).payload_length,
                context.hostname,
            )
        };
        unsafe {
            context.report(
                ops,
                if redirected {
                    Event::RedirectOther
                } else {
                    Event::RedirectLocal
                },
                [relative.into(), 0, 0, 0],
            );
        }
        redirected
    } else {
        false
    };
    if failed {
        unsafe {
            zapret_autolist_failed(context, ops);
            (*track).failure_finalized = true;
        }
    }
}

const _: () = {
    use std::mem::{offset_of, size_of};
    let pointer = size_of::<usize>();
    assert!(offset_of!(Config, retrans_maxseq) == pointer + 20);
    assert!(offset_of!(Config, incoming_maxseq) == pointer + 24);
    assert!(offset_of!(Config, retrans_reset) == pointer + 28);
    assert!(size_of::<Context>() == if pointer == 8 { 64 } else { 36 });
    assert!(offset_of!(Context, l7) == 6 * pointer);
    assert!(size_of::<TrackInput>() == 5 * pointer && offset_of!(TrackInput, l7) == 4 * pointer);
    assert!(
        size_of::<TrackOps>() == 5 * pointer && offset_of!(TrackOps, format_client) == 4 * pointer
    );
};
