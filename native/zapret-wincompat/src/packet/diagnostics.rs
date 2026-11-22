//! Ordered packet diagnostics. Borrow each field at its original output boundary.
use super::{
    Packet,
    describe::{zapret_packet_describe, zapret_packet_name_text},
};
use crate::logging::LogSink;
use std::ffi::{CStr, c_char};

type Dump = unsafe extern "C" fn(*const u8, usize, usize);

unsafe fn header<const N: usize>(
    kind: u32,
    bytes: *const u8,
    protocol: u8,
    ipv6: bool,
) -> [c_char; N] {
    let mut buffer = [0; N];
    unsafe { zapret_packet_describe(kind, bytes, protocol, ipv6, buffer.as_mut_ptr(), N) };
    buffer
}

unsafe fn print_payload(packet: *const Packet, log: LogSink, dump: Dump) {
    // Either length or the borrowed payload can change during the preceding log.
    unsafe {
        dump((*packet).payload, (*packet).payload_length, 32);
        log(c"\n".as_ptr());
    }
}

unsafe fn transport<const N: usize>(
    packet: *const Packet,
    bytes: *const u8,
    kind: u32,
    format: &CStr,
    log: LogSink,
    dump: Dump,
) {
    let buffer = unsafe { header::<N>(kind, bytes, 0, false) };
    unsafe { log(c" %s\n".as_ptr(), buffer.as_ptr()) };
    let length = unsafe { (*packet).payload_length };
    if length != 0 {
        unsafe {
            log(format.as_ptr(), length);
            print_payload(packet, log, dump);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_debug_report(
    packet: *const Packet,
    replay: bool,
    enabled: bool,
    log: LogSink,
    dump: Dump,
) {
    if !enabled {
        return;
    }
    // Native logging can alter later borrowed observations. No Rust reference
    // into Packet is held across a callback.
    unsafe {
        if replay {
            log(c"REPLAY ".as_ptr());
        }
        let ipv4 = (*packet).ipv4;
        if !ipv4.is_null() {
            let buffer = header::<66>(0, ipv4, 0, false);
            log(c"IP4: %s".as_ptr(), buffer.as_ptr());
        } else {
            let ipv6 = (*packet).ipv6;
            if !ipv6.is_null() {
                let buffer = header::<128>(1, ipv6, (*packet).protocol, true);
                log(c"IP6: %s".as_ptr(), buffer.as_ptr());
            }
        }

        let tcp = (*packet).tcp;
        if !tcp.is_null() {
            transport::<80>(packet, tcp, 2, c"TCP: len=%zu : ", log, dump);
            return;
        }
        let udp = (*packet).udp;
        if !udp.is_null() {
            transport::<30>(packet, udp, 3, c"UDP: len=%zu : ", log, dump);
            return;
        }
        let icmp = (*packet).icmp;
        if !icmp.is_null() {
            let buffer = header::<72>(4, icmp, 0, !(*packet).ipv6.is_null());
            log(
                c" %s\nICMP: len=%zu : ".as_ptr(),
                buffer.as_ptr(),
                (*packet).payload_length,
            );
        } else if (*packet).payload_length == 0 {
            log(c"\n".as_ptr());
            return;
        } else {
            let mut protocol = [0; 16];
            zapret_packet_name_text(
                protocol.as_mut_ptr(),
                protocol.len(),
                (*packet).protocol,
                false,
                false,
            );
            if (*packet).fragmented {
                log(
                    c"\nIP FRAG off=%u PROTO %s: len=%zu : ".as_ptr(),
                    u32::from((*packet).fragment_offset),
                    protocol.as_ptr(),
                    (*packet).payload_length,
                );
            } else {
                log(
                    c"\nIP PROTO %s: len=%zu : ".as_ptr(),
                    protocol.as_ptr(),
                    (*packet).payload_length,
                );
            }
        }
        print_payload(packet, log, dump);
    }
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Packet>() == 14 * pointer);
    assert!(std::mem::offset_of!(Packet, payload_length) == 12 * pointer);
    assert!(std::mem::offset_of!(Packet, fragment_offset) == 13 * pointer + 2);
};
