//! Checksum input preparation between C-owned Lua string and userdata calls.
use super::wire::{
    zapret_checksum_icmp, zapret_checksum_ip4, zapret_checksum_tcp, zapret_checksum_udp,
};
use crate::packet::{ipv4_header_len, ipv6_header_present, tcp_header_len};
use std::{ffi::c_char, ptr, slice};

#[repr(C)]
struct Entry {
    name: *const c_char,
    header_error: *const c_char,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_checksum_entry(kind: u32) -> Entry {
    let (name, error) = match kind {
        0 => (c"csum_tcp_fix", c"invalid tcp header"),
        1 => (c"csum_udp_fix", c"invalid udp header"),
        2 => (c"csum_icmp_fix", c"invalid icmp header"),
        _ => (c"csum_ip4_fix", c"invalid ip header"),
    };
    Entry {
        name: name.as_ptr(),
        header_error: error.as_ptr(),
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_checksum_error(stage: u32) -> *const c_char {
    match stage {
        0 => c"invalid ip header",
        1 => c"invalid payload length",
        _ => c"invalid checksum state",
    }
    .as_ptr()
}

// Raw pointers refer to rooted C-owned Lua strings. No Rust borrow or resource
// survives a call: C can allocate VM userdata or raise an error between steps.
#[repr(C)]
struct Plan {
    ip: *const u8,
    header: *const u8,
    payload: *const u8,
    header_length: usize,
    payload_length: usize,
    total_length: usize,
    kind: u32,
    family: u8,
    stage: u8,
}

fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

unsafe fn input<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if length > isize::MAX as usize || data.is_null() && length != 0 {
        None
    } else if length == 0 {
        Some(&[])
    } else {
        Some(unsafe { slice::from_raw_parts(data, length) })
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_checksum_ipv4(
    data: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
) -> bool {
    if length > 60 || length > capacity || output.is_null() {
        return false;
    }
    let Some(bytes) = (unsafe { input(data, length) }) else {
        return false;
    };
    if ipv4_header_len(bytes).is_none() {
        return false;
    }
    unsafe {
        ptr::copy(data, output, length);
        zapret_checksum_ip4(output);
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_checksum_begin(
    kind: u32,
    data: *const u8,
    length: usize,
    output: *mut Plan,
) -> bool {
    if kind > 2 || !valid(output) {
        return false;
    }
    let Some(bytes) = (unsafe { input(data, length) }) else {
        return false;
    };
    let family = if ipv4_header_len(bytes).is_some() {
        4
    } else if ipv6_header_present(bytes) {
        6
    } else {
        return false;
    };
    unsafe {
        output.write(Plan {
            ip: data,
            header: ptr::null(),
            payload: ptr::null(),
            header_length: 0,
            payload_length: 0,
            total_length: 0,
            kind,
            family,
            stage: 1,
        })
    };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_checksum_header(
    plan: *mut Plan,
    data: *const u8,
    length: usize,
) -> bool {
    if !valid(plan) || unsafe { (*plan).stage != 1 } {
        return false;
    }
    let Some(bytes) = (unsafe { input(data, length) }) else {
        return false;
    };
    let accepted = match unsafe { (*plan).kind } {
        0 => tcp_header_len(bytes).is_some(),
        1 | 2 => length >= 8,
        _ => false,
    };
    if !accepted {
        return false;
    }
    unsafe {
        (*plan).header = data;
        (*plan).header_length = length;
        (*plan).stage = 2;
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_checksum_payload(
    plan: *mut Plan,
    data: *const u8,
    length: usize,
) -> bool {
    if !valid(plan)
        || unsafe { (*plan).stage != 2 }
        || length > 65_535
        || data.is_null() && length != 0
    {
        return false;
    }
    let Some(total) = (unsafe { (*plan).header_length })
        .checked_add(length)
        .filter(|&length| length <= isize::MAX as usize)
    else {
        return false;
    };
    unsafe {
        (*plan).payload = data;
        (*plan).payload_length = length;
        (*plan).total_length = total;
        (*plan).stage = 3;
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_checksum_finish(
    plan: *const Plan,
    output: *mut u8,
    capacity: usize,
) -> bool {
    if !valid(plan) || output.is_null() {
        return false;
    }
    let plan = unsafe { &*plan };
    if plan.stage != 3
        || !matches!(plan.family, 4 | 6)
        || plan.ip.is_null()
        || plan.kind > 2
        || plan.header.is_null()
        || plan.header_length < if plan.kind == 0 { 20 } else { 8 }
        || plan.payload_length > 65_535
        || plan.payload.is_null() && plan.payload_length != 0
        || plan.header_length.checked_add(plan.payload_length) != Some(plan.total_length)
        || plan.total_length > isize::MAX as usize
        || plan.total_length > capacity
    {
        return false;
    }
    let (ipv4, ipv6) = if plan.family == 4 {
        (plan.ip, ptr::null())
    } else {
        (ptr::null(), plan.ip)
    };
    // Output is new Lua userdata, disjoint from the immutable input strings.
    unsafe {
        ptr::copy_nonoverlapping(plan.header, output, plan.header_length);
        if plan.payload_length != 0 {
            ptr::copy_nonoverlapping(
                plan.payload,
                output.add(plan.header_length),
                plan.payload_length,
            );
        }
        match plan.kind {
            0 => zapret_checksum_tcp(output, plan.total_length, ipv4, ipv6),
            1 => zapret_checksum_udp(output, plan.total_length, ipv4, ipv6),
            2 => zapret_checksum_icmp(output, plan.total_length, ipv6),
            _ => unreachable!(),
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn ipv4_checksum_retains_trailing_bytes_and_input_at_an_unaligned_address() {
        let mut storage = [0xa5; 28];
        let input = &mut storage[1..26];
        input[..20].copy_from_slice(&[
            0x45, 0, 0, 25, 0, 1, 0, 0, 64, 17, 0x12, 0x34, 192, 0, 2, 1, 198, 51, 100, 2,
        ]);
        let before = storage;
        let mut output = [0xcc; 27];
        assert!(unsafe {
            zapret_lua_checksum_ipv4(storage[1..].as_ptr(), 25, output[1..].as_mut_ptr(), 25)
        });
        assert_eq!(storage, before);
        assert_eq!(&output[21..26], &[0xa5; 5]);
        assert_eq!(output[0], 0xcc);
        assert_eq!(output[26], 0xcc);
        let sum: u32 = output[1..21]
            .chunks_exact(2)
            .map(|bytes| u32::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            .sum();
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
    }

    fn ip() -> [u8; 20] {
        [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
        ]
    }

    #[test]
    fn plan_keeps_odd_headers_payload_and_original_udp_fields() {
        let ip = ip();
        let header = [0x12, 0x34, 0, 53, 0, 8, 0xab, 0xcd, 0xef];
        let payload = b"a\0bc";
        let mut plan = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_checksum_begin(1, ip.as_ptr(), ip.len(), plan.as_mut_ptr()) });
        let mut plan = unsafe { plan.assume_init() };
        assert!(!unsafe {
            zapret_lua_checksum_payload(&mut plan, payload.as_ptr(), payload.len())
        });
        assert!(unsafe { zapret_lua_checksum_header(&mut plan, header.as_ptr(), header.len()) });
        assert!(unsafe { zapret_lua_checksum_payload(&mut plan, payload.as_ptr(), payload.len()) });
        let mut output = [0xa5; 14];
        assert!(unsafe { zapret_lua_checksum_finish(&plan, output.as_mut_ptr(), output.len()) });
        assert_eq!(&output[..6], &header[..6]);
        assert_eq!(output[8], header[8]);
        assert_eq!(&output[9..13], payload);
        assert_eq!(output[13], 0xa5);
    }

    #[test]
    fn payload_rejection_preserves_plan_before_workspace_allocation() {
        let ip = ip();
        let header = [0; 8];
        let mut plan = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_checksum_begin(2, ip.as_ptr(), ip.len(), plan.as_mut_ptr()) });
        let mut plan = unsafe { plan.assume_init() };
        assert!(unsafe { zapret_lua_checksum_header(&mut plan, header.as_ptr(), header.len()) });
        assert!(!unsafe { zapret_lua_checksum_payload(&mut plan, ptr::dangling(), 65536) });
        assert_eq!(plan.stage, 2);
        assert!(plan.payload.is_null());
        plan.header_length = isize::MAX as usize;
        assert!(!unsafe { zapret_lua_checksum_payload(&mut plan, ptr::dangling(), 1) });
        assert_eq!(plan.stage, 2);
        assert_eq!(size_of::<Plan>(), 6 * size_of::<usize>() + 8);
    }
}
