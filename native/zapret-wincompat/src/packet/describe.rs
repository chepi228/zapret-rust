//! Packet diagnostics retain the native names, flags and truncation rules.
use crate::{address::zapret_lua_ntop, text_buffer::TextBuffer};
use std::{
    ffi::{CStr, c_char},
    fmt::Write,
    ptr,
};

fn protocol_name(protocol: u8) -> Option<&'static CStr> {
    Some(match protocol {
        6 => c"tcp",
        17 => c"udp",
        1 => c"icmp",
        58 => c"icmp6",
        2 => c"igmp",
        50 => c"esp",
        41 => c"6in4",
        4 => c"4in4",
        132 => c"sctp",
        _ => return None,
    })
}
fn icmp_name(ipv6: bool, kind: u8) -> Option<&'static CStr> {
    Some(if ipv6 {
        match kind {
            128 => c"echo_req6",
            129 => c"echo_reply6",
            1 => c"dest_unreach6",
            2 => c"packet_too_big",
            3 => c"time_exceeded6",
            4 => c"param_problem6",
            130 => c"mld_listener_query",
            131 => c"mld_listener_report",
            132 => c"mld_listener_reduction",
            133 => c"router_sol",
            134 => c"router_adv",
            135 => c"neigh_sol",
            136 => c"neigh_adv",
            137 => c"redirect6",
            _ => return None,
        }
    } else {
        match kind {
            0 => c"echo_reply",
            3 => c"dest_unreach",
            5 => c"redirect",
            8 => c"echo_req",
            11 => c"time_exceeded",
            12 => c"param_problem",
            13 => c"ts",
            14 => c"ts_reply",
            15 => c"info_req",
            16 => c"info_reply",
            _ => return None,
        }
    })
}
#[unsafe(no_mangle)]
pub(crate) extern "C" fn zapret_packet_proto_name(protocol: u8) -> *const c_char {
    protocol_name(protocol).map_or(ptr::null(), CStr::as_ptr)
}
#[unsafe(no_mangle)]
extern "C" fn zapret_packet_icmp_name(ipv6: bool, kind: u8) -> *const c_char {
    icmp_name(ipv6, kind).map_or(ptr::null(), CStr::as_ptr)
}
fn name(output: &mut TextBuffer, label: Option<&CStr>, number: u8) {
    if let Some(label) = label {
        let _ = output.write_str(label.to_str().unwrap_or(""));
    } else {
        let _ = write!(output, "{number}");
    }
}
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_packet_name_text(
    output: *mut c_char,
    capacity: usize,
    kind: u8,
    icmp: bool,
    ipv6: bool,
) {
    if let Some(mut output) = unsafe { TextBuffer::new(output, capacity) } {
        name(
            &mut output,
            if icmp {
                icmp_name(ipv6, kind)
            } else {
                protocol_name(kind)
            },
            kind,
        );
    }
}
fn address(output: &mut TextBuffer, input: *const u8, ipv6: bool) {
    let mut buffer = [0u8; 46];
    if unsafe {
        zapret_lua_ntop(
            input,
            if ipv6 { 16 } else { 4 },
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    } != 0
    {
        let text = unsafe { CStr::from_ptr(buffer.as_ptr().cast()) };
        let _ = output.write_str(text.to_str().unwrap_or(""));
    }
}
fn endpoints(output: &mut TextBuffer, source: *const u8, destination: *const u8, ipv6: bool) {
    address(output, source, ipv6);
    let _ = output.write_str(" => ");
    address(output, destination, ipv6);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_addresses_text(
    output: *mut c_char,
    capacity: usize,
    source: *const u8,
    destination: *const u8,
    ipv6: bool,
) {
    if source.is_null() || destination.is_null() {
        return;
    }
    if let Some(mut output) = unsafe { TextBuffer::new(output, capacity) } {
        endpoints(&mut output, source, destination, ipv6);
    }
}
unsafe fn word(input: *const u8, offset: usize) -> u16 {
    u16::from_be(unsafe { input.add(offset).cast::<u16>().read_unaligned() })
}
unsafe fn dword(input: *const u8, offset: usize) -> u32 {
    u32::from_be(unsafe { input.add(offset).cast::<u32>().read_unaligned() })
}
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_packet_describe(
    operation: u32,
    input: *const u8,
    protocol: u8,
    ipv6: bool,
    output: *mut c_char,
    capacity: usize,
) {
    let Some(mut output) = (unsafe { TextBuffer::new(output, capacity) }) else {
        return;
    };
    if input.is_null() {
        return;
    }
    match operation {
        0 | 1 => unsafe {
            let ipv6 = operation == 1;
            endpoints(
                &mut output,
                input.add(if ipv6 { 8 } else { 12 }),
                input.add(if ipv6 { 24 } else { 16 }),
                ipv6,
            );
            let _ = output.write_str(" proto=");
            let protocol = if ipv6 { protocol } else { input.add(9).read() };
            name(&mut output, protocol_name(protocol), protocol);
            let _ = write!(
                output,
                " ttl={}",
                input.add(if ipv6 { 7 } else { 8 }).read()
            );
        },
        2 => unsafe {
            let bits = input.add(13).read();
            let mut flags = [0u8; 6];
            let mut count = 0;
            for (bit, letter) in [
                (2, b'S'),
                (16, b'A'),
                (4, b'R'),
                (1, b'F'),
                (8, b'P'),
                (32, b'U'),
            ] {
                if bits & bit != 0 {
                    flags[count] = letter;
                    count += 1;
                }
            }
            let flags = std::str::from_utf8_unchecked(&flags[..count]);
            let _ = write!(
                output,
                "sport={} dport={} flags={} seq={} ack_seq={}",
                word(input, 0),
                word(input, 2),
                flags,
                dword(input, 4),
                dword(input, 8)
            );
        },
        3 => {
            let _ = write!(
                output,
                "sport={} dport={}",
                unsafe { word(input, 0) },
                unsafe { word(input, 2) }
            );
        }
        4 => unsafe {
            let kind = input.read();
            let _ = output.write_str("icmp_type=");
            name(&mut output, icmp_name(ipv6, kind), kind);
            let _ = write!(output, " icmp_code={}", input.add(1).read());
            // The pinned engine recognizes all four echo type numbers here,
            // independently of the family used for the displayed type name.
            if matches!(kind, 0 | 8 | 128 | 129) {
                let _ = write!(
                    output,
                    " id=0x{:04X} seq={}",
                    word(input, 4),
                    word(input, 6)
                );
            } else {
                let _ = write!(output, " data=0x{:08X}", dword(input, 4));
            }
        },
        _ => {}
    }
}

// Native display entries declared in the pinned darkmagic.h.
#[unsafe(no_mangle)]
extern "C" fn proto_name(protocol: u8) -> *const c_char {
    zapret_packet_proto_name(protocol)
}

#[unsafe(no_mangle)]
extern "C" fn icmp_type_name(ipv6: bool, kind: u8) -> *const c_char {
    zapret_packet_icmp_name(ipv6, kind)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_proto_name(output: *mut c_char, capacity: usize, protocol: u8) {
    unsafe { zapret_packet_name_text(output, capacity, protocol, false, false) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_icmp_type_name(
    output: *mut c_char,
    capacity: usize,
    ipv6: bool,
    kind: u8,
) {
    unsafe { zapret_packet_name_text(output, capacity, kind, true, ipv6) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_ip(output: *mut c_char, capacity: usize, header: *const u8) {
    unsafe { zapret_packet_describe(0, header, 0, false, output, capacity) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_srcdst_ip6(
    output: *mut c_char,
    capacity: usize,
    source: *const u8,
    destination: *const u8,
) {
    unsafe { zapret_packet_addresses_text(output, capacity, source, destination, true) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_ip6hdr(
    output: *mut c_char,
    capacity: usize,
    header: *const u8,
    protocol: u8,
) {
    unsafe { zapret_packet_describe(1, header, protocol, true, output, capacity) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_tcphdr(output: *mut c_char, capacity: usize, header: *const u8) {
    unsafe { zapret_packet_describe(2, header, 0, false, output, capacity) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_udphdr(output: *mut c_char, capacity: usize, header: *const u8) {
    unsafe { zapret_packet_describe(3, header, 0, false, output, capacity) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str_icmphdr(
    output: *mut c_char,
    capacity: usize,
    ipv6: bool,
    header: *const u8,
) {
    unsafe { zapret_packet_describe(4, header, 0, ipv6, output, capacity) };
}
