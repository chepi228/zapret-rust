//! CIDR conversion and immutable masks for the engine's Windows address ABI.
use crate::{
    address::{zapret_lua_ntop, zapret_lua_pton},
    filters::decimal64_prefix,
};
use std::{
    ffi::{CStr, c_char},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{IN_ADDR, IN6_ADDR};

#[repr(C)]
struct Cidr4 {
    address: IN_ADDR,
    prefix: u8,
}

#[repr(C)]
struct Cidr6 {
    address: IN6_ADDR,
    prefix: u8,
}

const _: () = {
    assert!(size_of::<Cidr4>() == 8 && align_of::<Cidr4>() == 4);
    assert!(size_of::<Cidr6>() == 18 && align_of::<Cidr6>() == 2);
    assert!(std::mem::offset_of!(Cidr4, prefix) == 4);
    assert!(std::mem::offset_of!(Cidr6, prefix) == 16);
};

#[repr(C, align(4))]
struct Ipv6Mask([u8; 16]);
const fn masks() -> [Ipv6Mask; 129] {
    let mut result = [const { Ipv6Mask([0; 16]) }; 129];
    let mut zeros = 0usize;
    while zeros <= 128 {
        let bits = 128 - zeros;
        let mut index = 0;
        while index < 16 {
            let remaining = bits.saturating_sub(index * 8);
            result[zeros].0[index] = if remaining >= 8 {
                255
            } else if remaining == 0 {
                0
            } else {
                255 << (8 - remaining)
            };
            index += 1;
        }
        zeros += 1;
    }
    result
}
static MASKS: [Ipv6Mask; 129] = masks();

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_prefix_mask4(zeros: u32) -> u32 {
    u32::MAX.checked_shl(zeros).unwrap_or(0)
}
#[unsafe(no_mangle)]
extern "C" fn zapret_prefix_prepare6() {}
#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_prefix_mask6(zeros: u32) -> *const u8 {
    MASKS
        .get(zeros as usize)
        .map_or(ptr::null(), |mask| mask.0.as_ptr())
}

unsafe fn parse_cidr(text: *const c_char, address: *mut u8, prefix: *mut u8, size: usize) -> bool {
    let maximum = (size * 8) as u8;
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
    let (bytes, bits) = if let Some(split) = bytes.iter().position(|&byte| byte == b'/') {
        let Some((bits, _)) = decimal64_prefix(&bytes[split + 1..]) else {
            return false;
        };
        if bits > u64::from(maximum) {
            return false;
        }
        (&bytes[..split], bits as u8)
    } else {
        (bytes, maximum)
    };
    // Every valid textual IPv4/IPv6 representation fits this stack array. The
    // slash is never temporarily overwritten in caller-owned configuration.
    let mut text = [0u8; 46];
    if bytes.len() >= text.len() {
        return false;
    }
    text[..bytes.len()].copy_from_slice(bytes);
    let mut value = [0u8; 16];
    if unsafe { zapret_lua_pton(text.as_ptr().cast(), value.as_mut_ptr(), value.len()) } != size {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), address, size);
        prefix.write(bits);
    }
    true
}

unsafe fn str_cidr(
    address: *const u8,
    prefix: u8,
    output: *mut c_char,
    capacity: usize,
    size: usize,
) {
    let maximum = (size * 8) as u8;
    let mut text = [0u8; 51];
    let mut size = unsafe { zapret_lua_ntop(address, size, text.as_mut_ptr().cast(), 46) };
    if size == 0 {
        return;
    }
    if prefix < maximum {
        text[size] = b'/';
        size += 1;
        if prefix >= 100 {
            text[size] = b'0' + prefix / 100;
            size += 1;
        }
        if prefix >= 10 {
            text[size] = b'0' + (prefix / 10) % 10;
            size += 1;
        }
        text[size] = b'0' + prefix % 10;
        size += 1;
    }
    let length = size.min(capacity - 1);
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), output.cast(), length);
        output.add(length).write(0);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_cidr4(text: *mut c_char, cidr: *mut Cidr4) -> bool {
    !text.is_null()
        && !cidr.is_null()
        && cidr.is_aligned()
        && unsafe {
            parse_cidr(
                text,
                (&raw mut (*cidr).address).cast(),
                &raw mut (*cidr).prefix,
                size_of::<IN_ADDR>(),
            )
        }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_cidr6(text: *mut c_char, cidr: *mut Cidr6) -> bool {
    !text.is_null()
        && !cidr.is_null()
        && cidr.is_aligned()
        && unsafe {
            parse_cidr(
                text,
                (&raw mut (*cidr).address).cast(),
                &raw mut (*cidr).prefix,
                size_of::<IN6_ADDR>(),
            )
        }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_str_cidr4(output: *mut c_char, capacity: usize, cidr: *const Cidr4) {
    if capacity == 0 || output.is_null() || cidr.is_null() || !cidr.is_aligned() {
        return;
    }
    unsafe {
        str_cidr(
            (&raw const (*cidr).address).cast(),
            (*cidr).prefix,
            output,
            capacity,
            size_of::<IN_ADDR>(),
        )
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_str_cidr6(output: *mut c_char, capacity: usize, cidr: *const Cidr6) {
    if capacity == 0 || output.is_null() || cidr.is_null() || !cidr.is_aligned() {
        return;
    }
    unsafe {
        str_cidr(
            (&raw const (*cidr).address).cast(),
            (*cidr).prefix,
            output,
            capacity,
            size_of::<IN6_ADDR>(),
        )
    };
}
