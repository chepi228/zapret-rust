//! Mutate checksum fields within the same Rust frame as checksum arithmetic.
use super::{csum_ipv6_magic, csum_tcpudp_magic, internet_sum};
use std::slice;

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_checksum_ip4(ip: *mut u8) {
    if ip.is_null() {
        return;
    }
    unsafe {
        ip.add(10).cast::<u16>().write_unaligned(0);
        let length = usize::from(ip.read() & 15) * 4;
        let checksum = !internet_sum(slice::from_raw_parts(ip, length));
        ip.add(10).cast::<u16>().write_unaligned(checksum.to_le());
    }
}
#[inline]
unsafe fn transport(
    data: *mut u8,
    length: usize,
    source: *const u8,
    destination: *const u8,
    ipv6: bool,
    protocol: u8,
    offset: usize,
) {
    if data.is_null() || source.is_null() || destination.is_null() || length > isize::MAX as usize {
        return;
    }
    unsafe {
        data.add(offset).cast::<u16>().write_unaligned(0);
        let sum = internet_sum(slice::from_raw_parts(data, length)).to_le();
        let checksum = if ipv6 {
            csum_ipv6_magic(source, destination, length, protocol, sum)
        } else {
            csum_tcpudp_magic(
                source.cast::<u32>().read_unaligned(),
                destination.cast::<u32>().read_unaligned(),
                length,
                protocol,
                sum,
            )
        };
        data.add(offset).cast::<u16>().write_unaligned(checksum);
    }
}
#[inline]
unsafe fn selected(
    data: *mut u8,
    length: usize,
    ipv4: *const u8,
    ipv6: *const u8,
    protocol: u8,
    offset: usize,
) {
    unsafe {
        if !ipv4.is_null() {
            transport(
                data,
                length,
                ipv4.add(12),
                ipv4.add(16),
                false,
                protocol,
                offset,
            );
        } else if !ipv6.is_null() {
            transport(
                data,
                length,
                ipv6.add(8),
                ipv6.add(24),
                true,
                protocol,
                offset,
            );
        }
    }
}
macro_rules! transport_exports {
    ($v4:ident, $v6:ident, $selected:ident, $protocol:expr, $offset:expr) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $v4(
            data: *mut u8,
            length: usize,
            source: *const u8,
            destination: *const u8,
        ) {
            unsafe { transport(data, length, source, destination, false, $protocol, $offset) };
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $v6(
            data: *mut u8,
            length: usize,
            source: *const u8,
            destination: *const u8,
        ) {
            unsafe { transport(data, length, source, destination, true, $protocol, $offset) };
        }
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $selected(
            data: *mut u8,
            length: usize,
            ipv4: *const u8,
            ipv6: *const u8,
        ) {
            unsafe { selected(data, length, ipv4, ipv6, $protocol, $offset) };
        }
    };
}
transport_exports!(
    zapret_checksum_tcp4,
    zapret_checksum_tcp6,
    zapret_checksum_tcp,
    6,
    16
);
transport_exports!(
    zapret_checksum_udp4,
    zapret_checksum_udp6,
    zapret_checksum_udp,
    17,
    6
);
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_checksum_icmp4(data: *mut u8, length: usize) {
    if data.is_null() || length > isize::MAX as usize {
        return;
    }
    unsafe {
        data.add(2).cast::<u16>().write_unaligned(0);
        let checksum = !internet_sum(slice::from_raw_parts(data, length));
        data.add(2).cast::<u16>().write_unaligned(checksum.to_le());
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_checksum_icmp6(data: *mut u8, length: usize, ipv6: *const u8) {
    if !ipv6.is_null() {
        unsafe { transport(data, length, ipv6.add(8), ipv6.add(24), true, 58, 2) };
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_checksum_icmp(
    data: *mut u8,
    length: usize,
    ipv6: *const u8,
) {
    unsafe {
        if ipv6.is_null() {
            zapret_checksum_icmp4(data, length);
        } else {
            zapret_checksum_icmp6(data, length, ipv6);
        }
    }
}
