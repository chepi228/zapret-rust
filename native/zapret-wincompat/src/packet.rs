//! Packet layout compatibility with the pinned zapret2 engine.
//! The parser reports offsets into the input and owns no packet buffers.

#[cfg(windows)]
pub(super) mod describe;
#[cfg(windows)]
mod diagnostics;
#[cfg(windows)]
mod helpers;

use std::{ptr, slice};

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const ICMP_HEADER: usize = 8;

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTHENTICATION: u8 = 51;
const ICMPV6: u8 = 58;
const IPV6_NO_NEXT: u8 = 59;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const IPV6_MOBILITY: u8 = 135;
const IPV6_HOST_IDENTITY: u8 = 139;
const IPV6_SHIM6: u8 = 140;

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq)]
struct PacketLayout {
    packet_len: usize,
    ip_header_len: usize,
    transport_header_len: usize,
    fragment_offset: u16,
    version: u8,
    protocol: u8,
    fragmented: u8,
}

/// The C engine's dissected view. All pointers refer to the input buffer.
#[repr(C)]
pub(super) struct Packet {
    pub(super) data: *const u8,
    pub(super) length: usize,
    pub(super) ipv4: *const u8,
    pub(super) ipv6: *const u8,
    l3_length: usize,
    pub(super) protocol: u8,
    pub(super) tcp: *const u8,
    pub(super) udp: *const u8,
    pub(super) icmp: *const u8,
    l4_length: usize,
    pub(super) transport_length: usize,
    pub(super) payload: *const u8,
    pub(super) payload_length: usize,
    fragmented: bool,
    fragment_offset: u16,
}

impl Packet {
    pub(super) fn valid_ip(&self) -> bool {
        self.ipv4.is_null() != self.ipv6.is_null()
    }

    pub(super) unsafe fn dissect(data: *const u8, length: usize, allow_partial: bool) -> Self {
        let layout = packet_layout(unsafe { input(data, length) }, allow_partial);
        let mut result = Self {
            data,
            length: layout.packet_len,
            ipv4: ptr::null(),
            ipv6: ptr::null(),
            l3_length: layout.ip_header_len,
            protocol: layout.protocol,
            tcp: ptr::null(),
            udp: ptr::null(),
            icmp: ptr::null(),
            l4_length: layout.transport_header_len,
            transport_length: 0,
            payload: ptr::null(),
            payload_length: 0,
            fragmented: layout.fragmented != 0,
            fragment_offset: layout.fragment_offset,
        };
        if layout.version == 0 {
            return result;
        }
        if layout.version == 4 {
            result.ipv4 = data;
        } else {
            result.ipv6 = data;
        }
        let transport = unsafe { data.add(layout.ip_header_len) };
        if layout.transport_header_len != 0 {
            match layout.protocol {
                TCP => result.tcp = transport,
                UDP => result.udp = transport,
                ICMP | ICMPV6 => result.icmp = transport,
                _ => {}
            }
        }
        result.transport_length = layout.packet_len - layout.ip_header_len;
        result.payload_length = result.transport_length - layout.transport_header_len;
        result.payload = unsafe { transport.add(layout.transport_header_len) };
        result
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn proto_dissect_l3l4(
    data: *const u8,
    length: usize,
    output: *mut Packet,
    allow_partial: bool,
) {
    unsafe { output.write(Packet::dissect(data, length, allow_partial)) };
}

pub(super) fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let header = packet.first()?;
    if header >> 4 != 4 || packet.len() < IPV4_HEADER {
        return None;
    }
    let header_len = usize::from(header & 15) * 4;
    let packet_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    (header_len >= IPV4_HEADER && packet_len >= header_len && packet.len() >= header_len)
        .then_some(header_len)
}

pub(super) fn ipv6_header_present(packet: &[u8]) -> bool {
    packet.len() >= IPV6_HEADER && packet[0] >> 4 == 6
}

pub(super) fn tcp_header_len(data: &[u8]) -> Option<usize> {
    if data.len() < TCP_HEADER {
        return None;
    }
    let header_len = usize::from(data[12] >> 4) * 4;
    (header_len >= TCP_HEADER && data.len() >= header_len).then_some(header_len)
}

fn transport_header_len(data: &[u8], protocol: u8, allow_partial: bool) -> usize {
    match protocol {
        TCP => tcp_header_len(data).unwrap_or(0),
        UDP if data.len() >= UDP_HEADER => {
            let declared = usize::from(u16::from_be_bytes([data[4], data[5]]));
            if allow_partial || (UDP_HEADER..=data.len()).contains(&declared) {
                UDP_HEADER
            } else {
                0
            }
        }
        ICMP | ICMPV6 if data.len() >= ICMP_HEADER => ICMP_HEADER,
        _ => 0,
    }
}

struct Ipv6Extensions {
    end: usize,
    protocol: u8,
    fragment_offset: u16,
    fragmented: bool,
    found: Option<usize>,
}

pub(super) fn ipv6_extension_length(kind: u8, payload: &[u8]) -> Option<usize> {
    match kind {
        IPV6_HOP_BY_HOP
        | IPV6_ROUTING
        | IPV6_DESTINATION_OPTIONS
        | IPV6_MOBILITY
        | IPV6_HOST_IDENTITY
        | IPV6_SHIM6 => payload.get(1).map(|&length| 8 + usize::from(length) * 8),
        IPV6_AUTHENTICATION => payload.get(1).map(|&length| 8 + usize::from(length) * 4),
        IPV6_FRAGMENT => Some(8),
        _ => None,
    }
}

fn ipv6_extensions(mut payload: &[u8], first: u8, find: Option<u8>) -> Ipv6Extensions {
    let mut extensions = Ipv6Extensions {
        end: IPV6_HEADER,
        protocol: first,
        fragment_offset: 0,
        fragmented: false,
        found: None,
    };
    let mut next = first;
    while let Some(&following) = payload.first() {
        if find == Some(next) {
            extensions.found = Some(extensions.end);
            break;
        }
        let length = match next {
            IPV6_HOP_BY_HOP
            | IPV6_ROUTING
            | IPV6_DESTINATION_OPTIONS
            | IPV6_MOBILITY
            | IPV6_HOST_IDENTITY
            | IPV6_SHIM6
            | IPV6_AUTHENTICATION
            | IPV6_FRAGMENT => ipv6_extension_length(next, payload),
            IPV6_NO_NEXT => break,
            _ => {
                extensions.protocol = next;
                break;
            }
        };
        let Some(length) = length else {
            break;
        };
        let Some(rest) = payload.get(length..) else {
            break;
        };
        if next == IPV6_FRAGMENT {
            let field = u16::from_be_bytes([payload[2], payload[3]]);
            extensions.fragment_offset = field & 0xfff8;
            extensions.fragmented = field & 0xfff9 != 0;
        }
        extensions.end += length;
        if extensions.fragment_offset != 0 {
            break;
        }
        next = following;
        payload = rest;
    }
    extensions
}

fn packet_layout(packet: &[u8], allow_partial: bool) -> PacketLayout {
    let mut layout = PacketLayout {
        packet_len: packet.len(),
        ..PacketLayout::default()
    };
    if let Some(header_len) = ipv4_header_len(packet) {
        let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if !allow_partial && declared > packet.len() {
            return layout;
        }
        let flags = u16::from_be_bytes([packet[6], packet[7]]);
        layout.packet_len = declared.min(packet.len());
        layout.ip_header_len = header_len;
        layout.fragment_offset = (flags & 0x1fff) << 3;
        layout.version = 4;
        layout.protocol = packet[9];
        layout.fragmented = u8::from(flags & 0x3fff != 0);
    } else if ipv6_header_present(packet) {
        let declared = IPV6_HEADER + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        if !allow_partial && declared > packet.len() {
            return layout;
        }
        layout.packet_len = declared.min(packet.len());
        let extensions = ipv6_extensions(&packet[IPV6_HEADER..layout.packet_len], packet[6], None);
        layout.ip_header_len = extensions.end;
        layout.fragment_offset = extensions.fragment_offset;
        layout.version = 6;
        layout.protocol = extensions.protocol;
        layout.fragmented = u8::from(extensions.fragmented);
    }
    if layout.version != 0 && layout.fragmented == 0 {
        layout.transport_header_len = transport_header_len(
            &packet[layout.ip_header_len..layout.packet_len],
            layout.protocol,
            allow_partial,
        );
    }
    layout
}

/// # Safety
/// For nonzero lengths the pointer must cover the entire declared input.
unsafe fn input<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipv6_extension(data: *const u8, len: usize, protocol: u8) -> usize {
    let packet = unsafe { input(data, len) };
    ipv6_extension(packet, protocol).unwrap_or(0)
}

pub(super) fn ipv6_extension(packet: &[u8], protocol: u8) -> Option<usize> {
    if packet.len() < IPV6_HEADER {
        return None;
    }
    let declared = IPV6_HEADER + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    ipv6_extensions(
        &packet[IPV6_HEADER..declared.min(packet.len())],
        packet[6],
        Some(protocol),
    )
    .found
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipv4_header(data: *const u8, len: usize) -> usize {
    ipv4_header_len(unsafe { input(data, len) }).unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipv6_header(data: *const u8, len: usize) -> u8 {
    u8::from(ipv6_header_present(unsafe { input(data, len) }))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_tcp_header(data: *const u8, len: usize) -> usize {
    tcp_header_len(unsafe { input(data, len) }).unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_check_ipv4(data: *const u8, len: usize) -> bool {
    unsafe { zapret_ipv4_header(data, len) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_check_ipv6(data: *const u8, len: usize) -> bool {
    unsafe { zapret_ipv6_header(data, len) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_check_tcp(data: *const u8, len: usize) -> bool {
    unsafe { zapret_tcp_header(data, len) != 0 }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_packet_check_udp(_data: *const u8, len: usize) -> bool {
    len >= UDP_HEADER
}

#[unsafe(no_mangle)]
extern "C" fn zapret_packet_check_icmp(_data: *const u8, len: usize) -> bool {
    len >= ICMP_HEADER
}
