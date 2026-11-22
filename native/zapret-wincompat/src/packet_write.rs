//! Wire serialization for values decoded by the engine's Lua bindings.
#[cfg(windows)]
mod lua_fields;
#[cfg(windows)]
mod lua_list;
use crate::{
    checksum::{fold, internet_sum},
    packet::ipv6_extension,
};
use std::{mem, ptr, slice};

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_HEADER: usize = 20;
const MAX_OPTIONS: usize = 40;
const UDP_HEADER: usize = 8;
const ICMP_HEADER: usize = 8;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTH: u8 = 51;

#[repr(C)]
struct Ipv4Fields {
    source: [u8; 4],
    destination: [u8; 4],
    length: u16,
    identification: u16,
    fragment: u16,
    service: u8,
    hop_limit: u8,
    protocol: u8,
}

#[repr(C)]
struct Ipv6Fields {
    source: [u8; 16],
    destination: [u8; 16],
    flow: u32,
    payload_length: u16,
    next: u8,
    hop_limit: u8,
    has_payload_length: u8,
}

#[repr(C)]
struct TcpFields {
    sequence: u32,
    acknowledgement: u32,
    source: u16,
    destination: u16,
    window: u16,
    checksum: u16,
    urgent: u16,
    reserved: u8,
    flags: u8,
}

#[repr(C)]
struct UdpFields {
    source: u16,
    destination: u16,
    length: u16,
    checksum: u16,
}

#[repr(C)]
struct IcmpFields {
    data: u32,
    checksum: u16,
    kind: u8,
    code: u8,
}

const _: () = {
    assert!(mem::size_of::<Ipv4Fields>() == 18);
    assert!(mem::size_of::<Ipv6Fields>() == 44);
    assert!(mem::size_of::<TcpFields>() == 20);
    assert!(mem::size_of::<UdpFields>() == UDP_HEADER);
    assert!(mem::size_of::<IcmpFields>() == ICMP_HEADER);
};

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

pub(super) fn fix_ipv4_checksum(header: &mut [u8]) {
    put_u16(header, 10, 0);
    let checksum = !internet_sum(header);
    header[10..12].copy_from_slice(&checksum.to_le_bytes());
}

// The Lua adapter gives Rust only the prefix it is allowed to write. Initialize
// it before building a byte slice, since the caller's buffer can be uninitialized.
unsafe fn initialize<'a>(output: *mut u8, length: usize) -> &'a mut [u8] {
    unsafe {
        output.write_bytes(0, length);
        slice::from_raw_parts_mut(output, length)
    }
}

unsafe fn copy_input(output: &mut [u8], input: *const u8) {
    if !output.is_empty() {
        unsafe { ptr::copy_nonoverlapping(input, output.as_mut_ptr(), output.len()) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_ipv4(
    output: *mut u8,
    capacity: usize,
    fields: *const Ipv4Fields,
    options: *const u8,
    options_len: usize,
) -> usize {
    if options_len > MAX_OPTIONS {
        return 0;
    }
    let length = IPV4_HEADER + options_len.next_multiple_of(4);
    if length > capacity {
        return 0;
    }
    let fields = unsafe { &*fields };
    let header = unsafe { initialize(output, length) };
    header[0] = 0x40 | ((length / 4) as u8);
    header[1] = fields.service;
    put_u16(header, 2, fields.length);
    put_u16(header, 4, fields.identification);
    put_u16(header, 6, fields.fragment);
    header[8] = fields.hop_limit;
    header[9] = fields.protocol;
    header[12..16].copy_from_slice(&fields.source);
    header[16..20].copy_from_slice(&fields.destination);
    unsafe { copy_input(&mut header[IPV4_HEADER..IPV4_HEADER + options_len], options) };
    fix_ipv4_checksum(header);
    length
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_ipv6(output: *mut u8, fields: *const Ipv6Fields) {
    let fields = unsafe { &*fields };
    let header = unsafe { initialize(output, IPV6_HEADER) };
    header[..4].copy_from_slice(&fields.flow.to_be_bytes());
    put_u16(header, 4, fields.payload_length);
    header[6] = fields.next;
    header[7] = fields.hop_limit;
    header[8..24].copy_from_slice(&fields.source);
    header[24..40].copy_from_slice(&fields.destination);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_ipv6_extension(
    output: *mut u8,
    capacity: usize,
    kind: u8,
    next: u8,
    data: *const u8,
    data_len: usize,
) -> usize {
    let (limit, word, bias) = if kind == IPV6_AUTH {
        (1024, 4, 2)
    } else {
        (2048, 8, 1)
    };
    if !(6..limit).contains(&data_len) {
        return 0;
    }
    let length = data_len + 2;
    if length > capacity || length % word != 0 {
        return 0;
    }
    let output = unsafe { initialize(output, length) };
    output[0] = next;
    output[1] = ((length / word) - bias) as u8;
    unsafe { copy_input(&mut output[2..], data) };
    length
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_finish_ipv6(
    output: *mut u8,
    length: usize,
    fields: *const Ipv6Fields,
    last_next_offset: usize,
    protocol: u8,
    preserve_next: bool,
) {
    let fields = unsafe { &*fields };
    // Every extension and the base header have already been initialized.
    let header = unsafe { slice::from_raw_parts_mut(output, length) };
    if !preserve_next {
        header[last_next_offset] = protocol;
    }
    if fields.has_payload_length == 0 {
        put_u16(header, 4, (length - IPV6_HEADER) as u16);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_tcp_option(
    output: *mut u8,
    capacity: usize,
    kind: u8,
    data: *const u8,
    data_len: usize,
) -> usize {
    if kind <= 1 {
        if capacity == 0 {
            return 0;
        }
        unsafe { output.write(kind) };
        return 1;
    }
    let Some(length) = data_len.checked_add(2) else {
        return 0;
    };
    if length > capacity.min(MAX_OPTIONS) {
        return 0;
    }
    let option = unsafe { initialize(output, length) };
    option[0] = kind;
    option[1] = length as u8;
    unsafe { copy_input(&mut option[2..], data) };
    length
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_tcp(
    output: *mut u8,
    capacity: usize,
    fields: *const TcpFields,
    options_len: usize,
) -> usize {
    if options_len > MAX_OPTIONS {
        return 0;
    }
    let length = TCP_HEADER + options_len.next_multiple_of(4);
    if length > capacity {
        return 0;
    }
    let fields = unsafe { &*fields };
    let header = unsafe { initialize(output, TCP_HEADER) };
    put_u16(header, 0, fields.source);
    put_u16(header, 2, fields.destination);
    header[4..8].copy_from_slice(&fields.sequence.to_be_bytes());
    header[8..12].copy_from_slice(&fields.acknowledgement.to_be_bytes());
    header[12] = (((length / 4) as u8) << 4) | (fields.reserved & 15);
    header[13] = fields.flags;
    put_u16(header, 14, fields.window);
    put_u16(header, 16, fields.checksum);
    put_u16(header, 18, fields.urgent);
    let unpadded = TCP_HEADER + options_len;
    unsafe { output.add(unpadded).write_bytes(0, length - unpadded) };
    length
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_udp(output: *mut u8, fields: *const UdpFields) {
    let fields = unsafe { &*fields };
    let header = unsafe { initialize(output, UDP_HEADER) };
    put_u16(header, 0, fields.source);
    put_u16(header, 2, fields.destination);
    put_u16(header, 4, fields.length);
    put_u16(header, 6, fields.checksum);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_write_icmp(output: *mut u8, fields: *const IcmpFields) {
    let fields = unsafe { &*fields };
    let header = unsafe { initialize(output, ICMP_HEADER) };
    header[0] = fields.kind;
    header[1] = fields.code;
    put_u16(header, 2, fields.checksum);
    header[4..8].copy_from_slice(&fields.data.to_be_bytes());
}

// The Lua adapter provides the offsets of the headers it wrote. Fields declared
// in those headers still use the pinned engine's 16-bit length arithmetic.
#[repr(C)]
struct Finish {
    ip_length: usize,
    version: u8,
    transport: u8,
    keep_checksum: bool,
    checksum_xor: u16,
}

#[derive(Clone, Copy)]
#[repr(i32)]
enum FinishError {
    Layout = 1,
    UdpLength,
    Ipv4FragmentLength,
    Ipv4FragmentBounds,
    Ipv6FragmentLength,
    Ipv6FragmentBounds,
}

fn finish_packet(packet: &mut [u8], options: &Finish) -> Result<usize, FinishError> {
    let actual_length = packet.len();
    let ip_length = options.ip_length;
    if ip_length > actual_length
        || match options.version {
            4 => ip_length < IPV4_HEADER,
            6 => ip_length < IPV6_HEADER,
            _ => true,
        }
    {
        return Err(FinishError::Layout);
    }
    if !options.keep_checksum {
        let (header, transport) = packet.split_at_mut(ip_length);
        fix_transport_checksum(header, transport, options)?;
    }
    if options.version == 4 {
        let fragment = get_u16(packet, 6);
        let length = if fragment & 0x3fff != 0 {
            let length = usize::from(get_u16(packet, 2));
            if !(ip_length..=actual_length).contains(&length) {
                return Err(FinishError::Ipv4FragmentLength);
            }
            let offset = usize::from(fragment & 0x1fff) * 8;
            if length + offset > actual_length {
                return Err(FinishError::Ipv4FragmentBounds);
            }
            if offset != 0 {
                packet.copy_within(ip_length + offset..length + offset, ip_length);
            }
            length
        } else {
            put_u16(packet, 2, actual_length as u16);
            actual_length
        };
        fix_ipv4_checksum(&mut packet[..ip_length]);
        Ok(length)
    } else if let Some(fragment) = ipv6_extension(packet, IPV6_FRAGMENT) {
        let end = fragment + 8;
        let length = IPV6_HEADER + usize::from(get_u16(packet, 4));
        if end > length {
            return Err(FinishError::Ipv6FragmentLength);
        }
        if length > actual_length {
            return Err(FinishError::Ipv6FragmentBounds);
        }
        let offset = usize::from(get_u16(packet, fragment + 2) & 0xfff8);
        if length + offset > actual_length {
            return Err(FinishError::Ipv6FragmentBounds);
        }
        if offset != 0 {
            packet.copy_within(end + offset..length + offset, end);
        }
        Ok(length)
    } else {
        put_u16(packet, 4, (actual_length - IPV6_HEADER) as u16);
        Ok(actual_length)
    }
}

#[cfg(windows)]
pub(super) fn finish_assembly(
    packet: &mut [u8],
    ip_length: usize,
    version: u8,
    transport: u8,
    keep_checksum: bool,
    checksum_xor: u16,
) -> Result<usize, i32> {
    finish_packet(
        packet,
        &Finish {
            ip_length,
            version,
            transport,
            keep_checksum,
            checksum_xor,
        },
    )
    .map_err(|error| error as i32)
}

fn fix_transport_checksum(
    ip: &[u8],
    transport: &mut [u8],
    options: &Finish,
) -> Result<(), FinishError> {
    let (offset, minimum, protocol) = match options.transport {
        6 => (16, TCP_HEADER, 6),
        17 => (6, UDP_HEADER, 17),
        1 if options.version == 6 => (2, ICMP_HEADER, 58),
        1 => (2, ICMP_HEADER, 1),
        _ => return Ok(()),
    };
    if transport.len() < minimum {
        return Err(FinishError::Layout);
    }
    if protocol == 17 {
        let length = u16::try_from(transport.len()).map_err(|_| FinishError::UdpLength)?;
        put_u16(transport, 4, length);
    }
    put_u16(transport, offset, 0);
    let checksum = transport_checksum(ip, transport, protocol, options.version == 6);
    transport[offset..offset + 2].copy_from_slice(&(checksum ^ options.checksum_xor).to_le_bytes());
    Ok(())
}

pub(super) fn transport_checksum(ip: &[u8], transport: &[u8], protocol: u32, ipv6: bool) -> u16 {
    let sum = u64::from(internet_sum(transport));
    if protocol == 1 {
        !fold(sum)
    } else {
        let addresses = if ipv6 { &ip[8..40] } else { &ip[12..20] };
        let length_protocol = (transport.len() as u32)
            .wrapping_add(protocol)
            .to_be_bytes();
        !fold(sum + u64::from(internet_sum(addresses)) + u64::from(internet_sum(&length_protocol)))
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_finish_packet(
    output: *mut u8,
    length: *mut usize,
    options: *const Finish,
) -> i32 {
    let length = unsafe { &mut *length };
    let packet = unsafe { slice::from_raw_parts_mut(output, *length) };
    match finish_packet(packet, unsafe { &*options }) {
        Ok(written) => {
            *length = written;
            0
        }
        Err(error) => error as i32,
    }
}
