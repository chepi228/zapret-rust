//! Allocation-free helpers shared by engine startup, packet code and Lua.
use crate::system::zapret_random;
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr, slice,
};

unsafe fn sort<T: Ord>(data: *mut T, count: c_int) {
    if let Some(count) = usize::try_from(count).ok().filter(|&count| count > 1) {
        unsafe { slice::from_raw_parts_mut(data, count) }.sort_unstable();
    }
}
unsafe fn unique<T: Copy + PartialEq>(data: *mut T, count: c_int) -> c_int {
    let count = usize::try_from(count).unwrap_or(0);
    if count == 0 {
        return 0;
    }
    let values = unsafe { slice::from_raw_parts_mut(data, count) };
    let mut written = 1;
    for read in 1..count {
        if values[read] != values[written - 1] {
            values[written] = values[read];
            written += 1;
        }
    }
    written as c_int
}
macro_rules! sort_exports {
    ($sort:ident, $unique:ident, $type:ty) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $sort(data: *mut $type, count: c_int) {
            unsafe { sort(data, count) };
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $unique(data: *mut $type, count: c_int) -> c_int {
            unsafe { unique(data, count) }
        }
    };
}
sort_exports!(
    zapret_helper_qsort_size_t,
    zapret_helper_unique_size_t,
    usize
);
sort_exports!(
    zapret_helper_qsort_ssize_t,
    zapret_helper_unique_ssize_t,
    isize
);

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_str_index(
    strings: *const *const c_char,
    count: c_int,
    text: *const c_char,
) -> c_int {
    if count <= 0 {
        return -1;
    }
    let text = unsafe { CStr::from_ptr(text) };
    for index in 0..count {
        if unsafe { CStr::from_ptr(strings.add(index as usize).read()) } == text {
            return index;
        }
    }
    -1
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_rtrim(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    let mut length = unsafe { CStr::from_ptr(text) }.to_bytes().len();
    while length > 0 && matches!(unsafe { text.add(length - 1).read() } as u8, b'\r' | b'\n') {
        length -= 1;
        unsafe { text.add(length).write(0) };
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_replace_char(mut text: *mut c_char, from: c_char, to: c_char) {
    while unsafe { text.read() } != 0 {
        if unsafe { text.read() } == from {
            unsafe { text.write(to) };
        }
        text = unsafe { text.add(1) };
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_strncasestr(
    data: *const c_char,
    needle: *const c_char,
    length: usize,
) -> *const c_char {
    let needle = unsafe { CStr::from_ptr(needle) }.to_bytes();
    if needle.is_empty() {
        return data;
    }
    if length < needle.len() {
        return ptr::null();
    }
    let data_slice = unsafe { slice::from_raw_parts(data.cast::<u8>(), length) };
    data_slice
        .windows(needle.len())
        .position(|bytes| bytes.eq_ignore_ascii_case(needle))
        .map_or(ptr::null(), |index| unsafe { data.add(index) })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_is_identifier(text: *const c_char) -> bool {
    identifier(unsafe { CStr::from_ptr(text) }.to_bytes())
}
pub(crate) fn identifier(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_expand_bits(
    target: *mut c_void,
    source: *const c_void,
    source_bits: u32,
    target_bytes: u32,
) {
    let target_bytes = target_bytes as usize;
    let bits = (source_bits as usize).min(target_bytes.saturating_mul(8));
    let whole = bits / 8;
    let remainder = bits % 8;
    let target = target.cast::<u8>();
    let source = source.cast::<u8>();
    let tail = if remainder == 0 {
        0
    } else {
        (unsafe { source.add(whole).read() }) & (0xffu8 << (8 - remainder))
    };
    if whole != 0 {
        unsafe { ptr::copy(source, target, whole) };
    }
    if whole < target_bytes {
        unsafe { target.add(whole).write_bytes(0, target_bytes - whole) };
    }
    if remainder != 0 {
        unsafe { target.add(whole).write(tail) };
    }
}
#[unsafe(no_mangle)]
extern "C" fn zapret_helper_seq_within(value: u32, first: u32, last: u32) -> bool {
    if first <= last {
        first <= value && value <= last
    } else {
        first <= value || value <= last
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_helper_ipv6_addr_is_zero(address: *const c_void) -> bool {
    (unsafe { ptr::read_unaligned(address.cast::<[u8; 16]>()) }) == [0; 16]
}
unsafe fn read_be<const N: usize>(data: *const u8) -> u64 {
    let mut value = 0u64;
    for offset in 0..N {
        value = (value << 8) | u64::from(unsafe { data.add(offset).read() });
    }
    value
}
unsafe fn write_be<const N: usize>(data: *mut u8, value: u64) {
    let bytes = value.to_be_bytes();
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().add(8 - N), data, N) };
}
macro_rules! endian_exports {
    ($read:ident, $write:ident, $type:ty, $bytes:expr) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $read(data: *const u8) -> $type {
            unsafe { read_be::<$bytes>(data) as $type }
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $write(data: *mut u8, value: $type) {
            unsafe { write_be::<$bytes>(data, value as u64) };
        }
    };
}
endian_exports!(zapret_helper_pntoh16, zapret_helper_phton16, u16, 2);
endian_exports!(zapret_helper_pntoh24, zapret_helper_phton24, u32, 3);
endian_exports!(zapret_helper_pntoh32, zapret_helper_phton32, u32, 4);
endian_exports!(zapret_helper_pntoh48, zapret_helper_phton48, u64, 6);
endian_exports!(zapret_helper_pntoh64, zapret_helper_phton64, u64, 8);
#[unsafe(no_mangle)]
extern "C" fn zapret_helper_bswap16(value: u16) -> u16 {
    value.swap_bytes()
}
#[unsafe(no_mangle)]
extern "C" fn zapret_helper_bswap24(value: u32) -> u32 {
    value.swap_bytes() >> 8
}
#[unsafe(no_mangle)]
extern "C" fn zapret_helper_bswap48(value: u64) -> u64 {
    value.swap_bytes() >> 16
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_helper_parse_hex_str(
    mut text: *const c_char,
    output: *mut u8,
    length: *mut usize,
) -> bool {
    let capacity = unsafe { length.replace(0) };
    for index in 0..capacity {
        let byte = unsafe { text.read() } as u8;
        if byte == 0 {
            break;
        }
        let next = unsafe { text.add(1).read() } as u8;
        let Some(value) = hex(byte)
            .zip(hex(next))
            .map(|(high, low)| (high << 4) | low)
        else {
            unsafe { output.add(index).write(0) };
            return false;
        };
        unsafe {
            output.add(index).write(value);
            length.write(index + 1);
        }
        text = unsafe { text.add(2) };
    }
    true
}
#[unsafe(no_mangle)]
extern "C" fn zapret_helper_hex_digit(value: u8) -> c_char {
    (match value {
        0..=9 => b'0' + value,
        10..=15 => b'A' + value - 10,
        _ => b'?',
    }) as c_char
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_helper_fill_random_bytes(
    mut data: *mut u8,
    mut length: usize,
) {
    if length == 0 {
        return;
    }
    if data as usize & 1 != 0 {
        unsafe { data.write(zapret_random() as u8) };
        data = unsafe { data.add(1) };
        length -= 1;
    }
    let mut offset = 0;
    while length - offset >= 2 {
        unsafe { ptr::write_unaligned(data.add(offset).cast::<u16>(), zapret_random() as u16) };
        offset += 2;
    }
    if offset < length {
        unsafe { data.add(offset).write(zapret_random() as u8) };
    }
}
unsafe fn random_alphabet(data: *mut u8, length: usize, digits: bool) {
    for offset in 0..length {
        let random = zapret_random() as u32 % if digits { 36 } else { 26 };
        let value = if digits && random < 10 {
            b'0' + random as u8
        } else {
            b'a' + (random - if digits { 10 } else { 0 }) as u8
        };
        unsafe { data.add(offset).write(value) };
    }
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_helper_fill_random_az(data: *mut u8, length: usize) {
    unsafe { random_alphabet(data, length, false) };
}
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_helper_fill_random_az09(data: *mut u8, length: usize) {
    unsafe { random_alphabet(data, length, true) };
}

unsafe fn binary<const OP: u32>(
    first: *const u8,
    second: *const u8,
    output: *mut u8,
    length: usize,
) {
    let mut offset = 0;
    while length - offset >= 8 {
        let a = unsafe { ptr::read_unaligned(first.add(offset).cast::<u64>()) };
        let b = unsafe { ptr::read_unaligned(second.add(offset).cast::<u64>()) };
        let value = match OP {
            0 => a ^ b,
            1 => a | b,
            _ => a & b,
        };
        unsafe { ptr::write_unaligned(output.add(offset).cast::<u64>(), value) };
        offset += 8;
    }
    while offset < length {
        let a = unsafe { first.add(offset).read() };
        let b = unsafe { second.add(offset).read() };
        let value = match OP {
            0 => a ^ b,
            1 => a | b,
            _ => a & b,
        };
        unsafe { output.add(offset).write(value) };
        offset += 1;
    }
}
macro_rules! binary_exports {
    ($name:ident, $operation:expr) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name(
            first: *const u8,
            second: *const u8,
            output: *mut u8,
            length: usize,
        ) {
            unsafe { binary::<$operation>(first, second, output, length) };
        }
    };
}
binary_exports!(zapret_helper_bxor, 0);
binary_exports!(zapret_helper_bor, 1);
binary_exports!(zapret_helper_band, 2);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expansion_preserves_partial_byte_in_place() {
        let mut bytes = [0xffu8; 4];
        unsafe {
            zapret_helper_expand_bits(bytes.as_mut_ptr().cast(), bytes.as_ptr().cast(), 13, 4)
        };
        assert_eq!(bytes, [0xff, 0xf8, 0, 0]);
    }
}
