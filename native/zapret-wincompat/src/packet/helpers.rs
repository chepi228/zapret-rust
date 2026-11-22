//! Direct wire helpers for validated native packet headers.
use super::{input, ipv4_header_len, ipv6_header_present};
use std::{ptr, slice};

#[unsafe(no_mangle)]
extern "C" fn zapret_packet_net32_add(value: u32, increment: u32) -> u32 {
    u32::from_be(value).wrapping_add(increment).to_be()
}
#[unsafe(no_mangle)]
extern "C" fn zapret_packet_net16_add(value: u16, increment: u16) -> u16 {
    u16::from_be(value).wrapping_add(increment).to_be()
}
#[inline]
unsafe fn option(tcp: *const u8, kind: u8) -> *const u8 {
    if tcp.is_null() {
        return ptr::null();
    }
    let end = usize::from(unsafe { tcp.add(12).read() } >> 4) * 4;
    let mut offset = 20;
    while offset < end {
        let current = unsafe { tcp.add(offset).read() };
        match current {
            0 => return ptr::null(),
            1 => {
                // Skip padding runs without a branch for each NOP byte. Never
                // read beyond the declared TCP header, including short tails.
                let remaining = end - offset;
                if remaining >= 8 {
                    let different =
                        u64::from_le(unsafe { tcp.add(offset).cast::<u64>().read_unaligned() })
                            ^ 0x0101_0101_0101_0101;
                    offset += if different == 0 {
                        8
                    } else {
                        different.trailing_zeros() as usize / 8
                    };
                } else if remaining >= 4 {
                    let different =
                        u32::from_le(unsafe { tcp.add(offset).cast::<u32>().read_unaligned() })
                            ^ 0x0101_0101;
                    offset += if different == 0 {
                        4
                    } else {
                        different.trailing_zeros() as usize / 8
                    };
                } else {
                    offset += 1;
                }
            }
            _ => {
                if offset + 1 >= end {
                    return ptr::null();
                }
                let length = usize::from(unsafe { tcp.add(offset + 1).read() });
                if length < 2 || length > end - offset {
                    return ptr::null();
                }
                if current == kind {
                    return unsafe { tcp.add(offset) };
                }
                offset += length;
            }
        }
    }
    ptr::null()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_tcp_find_option(tcp: *const u8, kind: u8) -> *mut u8 {
    unsafe { option(tcp, kind) }.cast_mut()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_tcp_find_scale_factor(tcp: *const u8) -> u8 {
    let found = unsafe { option(tcp, 3) };
    if !found.is_null() && unsafe { found.add(1).read() } == 3 {
        unsafe { found.add(2).read() }
    } else {
        255
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_tcp_find_mss(tcp: *const u8) -> u16 {
    let found = unsafe { option(tcp, 2) };
    if !found.is_null() && unsafe { found.add(1).read() } == 4 {
        u16::from_be(unsafe { found.add(2).cast::<u16>().read_unaligned() })
    } else {
        0
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_tcp_synack_segment(tcp: *const u8) -> bool {
    !tcp.is_null() && unsafe { tcp.add(13).read() } & 0x3f == 0x12
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_tcp_syn_segment(tcp: *const u8) -> bool {
    !tcp.is_null() && unsafe { tcp.add(13).read() } & 0x3f == 0x02
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_extract_ports(
    tcp: *const u8,
    udp: *const u8,
    protocol: *mut u8,
    source: *mut u16,
    destination: *mut u16,
) {
    let header = if tcp.is_null() { udp } else { tcp };
    if !source.is_null() {
        unsafe {
            source.write_unaligned(if header.is_null() {
                0
            } else {
                u16::from_be(header.cast::<u16>().read_unaligned())
            })
        };
    }
    if !destination.is_null() {
        unsafe {
            destination.write_unaligned(if header.is_null() {
                0
            } else {
                u16::from_be(header.add(2).cast::<u16>().read_unaligned())
            })
        };
    }
    if !protocol.is_null() {
        unsafe {
            protocol.write(if !tcp.is_null() {
                6
            } else if !udp.is_null() {
                17
            } else {
                59
            })
        };
    }
}
unsafe fn endpoint(output: *mut u8, address: *const u8, port: *const u8, ipv6: bool) {
    if output.is_null() {
        return;
    }
    unsafe {
        output
            .cast::<u16>()
            .write_unaligned(if ipv6 { 23 } else { 2 });
        output
            .add(2)
            .cast::<u16>()
            .write_unaligned(if port.is_null() {
                0
            } else {
                port.cast::<u16>().read_unaligned()
            });
        if ipv6 {
            output.add(4).cast::<u32>().write_unaligned(0);
            ptr::copy_nonoverlapping(address, output.add(8), 16);
            output.add(24).cast::<u32>().write_unaligned(0);
        } else {
            ptr::copy_nonoverlapping(address, output.add(4), 4);
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_extract_dst(
    data: *const u8,
    length: usize,
    output: *mut u8,
) -> bool {
    if output.is_null() || length > isize::MAX as usize || length != 0 && data.is_null() {
        return false;
    }
    let input = unsafe { input(data, length) };
    if ipv4_header_len(input).is_some() {
        unsafe { endpoint(output, data.add(16), ptr::null(), false) };
        true
    } else if ipv6_header_present(input) {
        unsafe { endpoint(output, data.add(24), ptr::null(), true) };
        true
    } else {
        false
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_extract_endpoints(
    ipv4: *const u8,
    ipv6: *const u8,
    tcp: *const u8,
    udp: *const u8,
    source: *mut u8,
    destination: *mut u8,
) {
    let header = if tcp.is_null() { udp } else { tcp };
    let dest_port = if header.is_null() {
        ptr::null()
    } else {
        unsafe { header.add(2) }
    };
    unsafe {
        if !ipv4.is_null() {
            endpoint(destination, ipv4.add(16), dest_port, false);
            endpoint(source, ipv4.add(12), header, false);
        } else if !ipv6.is_null() {
            endpoint(destination, ipv6.add(24), dest_port, true);
            endpoint(source, ipv6.add(8), header, true);
        } else {
            if !source.is_null() {
                source.write_bytes(0, 128);
            }
            if !destination.is_null() {
                destination.write_bytes(0, 128);
            }
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_reverse_ip(ipv4: *mut u8, ipv6: *mut u8) {
    unsafe {
        if !ipv4.is_null() {
            ptr::swap_nonoverlapping(ipv4.add(12).cast::<[u8; 4]>(), ipv4.add(16).cast(), 1);
            ipv4.add(10).cast::<u16>().write_unaligned(0);
            let length = usize::from(ipv4.read() & 15) * 4;
            let checksum = !crate::checksum::internet_sum(slice::from_raw_parts(ipv4, length));
            ipv4.add(10).cast::<u16>().write_unaligned(checksum.to_le());
        }
        if !ipv6.is_null() {
            ptr::swap_nonoverlapping(ipv6.add(8).cast::<[u8; 16]>(), ipv6.add(24).cast(), 1);
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_reverse_tcp(tcp: *mut u8) {
    if tcp.is_null() {
        return;
    }
    unsafe {
        ptr::swap_nonoverlapping(tcp.cast::<[u8; 2]>(), tcp.add(2).cast(), 1);
        ptr::swap_nonoverlapping(tcp.add(4).cast::<[u8; 4]>(), tcp.add(8).cast(), 1);
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_ttl46(ipv4: *const u8, ipv6: *const u8) -> u8 {
    if !ipv4.is_null() {
        unsafe { ipv4.add(8).read() }
    } else if !ipv6.is_null() {
        unsafe { ipv6.add(7).read() }
    } else {
        0
    }
}
#[unsafe(no_mangle)]
extern "C" fn zapret_packet_family_from_proto(protocol: u8) -> u16 {
    match protocol {
        0 => 2,
        41 => 23,
        _ => 0,
    }
}
