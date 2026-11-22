//! Bounded SHA-2 and HKDF primitives for the Lua boundary adapters.
#[cfg(windows)]
mod entry;
use hkdf::Hkdf;
use sha2::{Digest, Sha224, Sha256};
use std::{ptr, slice};

unsafe fn input<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        Some(&[])
    } else if data.is_null() || length > isize::MAX as usize {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(data, length) })
    }
}

fn hash_size(bits: u32) -> Option<usize> {
    match bits {
        224 => Some(28),
        256 => Some(32),
        _ => None,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_hash(
    bits: u32,
    data: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
) -> usize {
    let Some(size) = hash_size(bits) else {
        return 0;
    };
    if capacity < size || output.is_null() {
        return 0;
    }
    let Some(data) = (unsafe { input(data, length) }) else {
        return 0;
    };
    let mut digest = [0; 32];
    match bits {
        224 => digest[..size].copy_from_slice(&Sha224::digest(data)),
        256 => digest[..size].copy_from_slice(&Sha256::digest(data)),
        _ => unreachable!(),
    }
    // All input access has finished, so hashing into the input buffer is valid.
    unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), output, size) };
    size
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_hkdf(
    bits: u32,
    salt: *const u8,
    salt_length: usize,
    key: *const u8,
    key_length: usize,
    info: *const u8,
    info_length: usize,
    output: *mut u8,
    length: usize,
) -> bool {
    let Some(size) = hash_size(bits) else {
        return false;
    };
    // The legacy Lua API returns nil for both zero output and RFC 5869 overflow.
    if length == 0 || length > 255 * size || output.is_null() {
        return false;
    }
    let Some(salt) = (unsafe { input(salt, salt_length) }) else {
        return false;
    };
    let Some(key) = (unsafe { input(key, key_length) }) else {
        return false;
    };
    let Some(info) = (unsafe { input(info, info_length) }) else {
        return false;
    };
    // The Lua adapter allocates a separate output userdata before this call.
    let output = unsafe { slice::from_raw_parts_mut(output, length) };
    match bits {
        224 => Hkdf::<Sha224>::new(Some(salt), key)
            .expand(info, output)
            .is_ok(),
        256 => Hkdf::<Sha256>::new(Some(salt), key)
            .expand(info, output)
            .is_ok(),
        _ => false,
    }
}
