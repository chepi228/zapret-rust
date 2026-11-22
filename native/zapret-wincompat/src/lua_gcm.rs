//! Lua's legacy GCM API returns plaintext and a computed tag on decryption.
//!
//! The runtime nonce adapter follows RustCrypto aes-gcm 0.10.3 (MIT OR
//! Apache-2.0) and NIST SP 800-38D sections 5.2.1.1 and 7.1. AES, counter mode
//! and GHASH use the pinned RustCrypto implementations throughout.
use aes::{
    Aes128Enc, Aes192Enc, Aes256Enc,
    cipher::{
        BlockCipher, BlockEncrypt, BlockSizeUser, InnerIvInit, KeyInit, StreamCipher,
        consts::{U12, U16},
    },
};
use aes_gcm::{AesGcm, Nonce, aead::AeadInPlace};
use ghash::{GHash, universal_hash::UniversalHash};
use std::{ptr, slice};

const MAX_DATA: u64 = (1u64 << 36) - 32;
const MAX_BITS_INPUT: usize = (u64::MAX / 8) as usize;

unsafe fn view<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        Some(&[])
    } else if data.is_null() || length > isize::MAX as usize {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(data, length) })
    }
}
struct Request<'a> {
    encrypt: bool,
    key: &'a [u8],
    iv: &'a [u8],
    associated: &'a [u8],
    input: *const u8,
    length: usize,
    output: *mut u8,
    tag: *mut u8,
}
unsafe fn crypt<C>(request: &Request<'_>) -> bool
where
    C: BlockCipher + KeyInit + BlockEncrypt + Clone + BlockSizeUser<BlockSize = U16>,
{
    let Ok(cipher) = C::new_from_slice(request.key) else {
        return false;
    };
    if request.encrypt
        && request.iv.len() == 12
        && request.associated.len() as u64 <= aes_gcm::A_MAX
    {
        let cipher = AesGcm::<C, U12>::from(cipher);
        if request.length != 0 {
            unsafe { ptr::copy(request.input, request.output, request.length) };
        }
        let output = if request.length == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(request.output, request.length) }
        };
        let Ok(tag) = cipher.encrypt_in_place_detached(
            Nonce::from_slice(request.iv),
            request.associated,
            output,
        ) else {
            return false;
        };
        unsafe { ptr::copy_nonoverlapping(tag.as_ptr(), request.tag, 16) };
        return true;
    }
    let mut hash_key = ghash::Key::default();
    cipher.encrypt_block(&mut hash_key);
    let mut hash = GHash::new(&hash_key);
    let initial = if request.iv.len() == 12 {
        let mut block = ghash::Block::default();
        block[..12].copy_from_slice(request.iv);
        block[15] = 1;
        block
    } else {
        let mut nonce_hash = hash.clone();
        nonce_hash.update_padded(request.iv);
        let mut length = ghash::Block::default();
        length[8..].copy_from_slice(&((request.iv.len() as u64) * 8).to_be_bytes());
        nonce_hash.update(&[length]);
        nonce_hash.finalize()
    };
    let core = ctr::CtrCore::<C, ctr::flavors::Ctr32BE>::inner_iv_init(cipher, &initial);
    let mut counter = ctr::Ctr32BE::<C>::from_core(core);
    let mut mask = ghash::Block::default();
    counter.apply_keystream(&mut mask);
    hash.update_padded(request.associated);
    if !request.encrypt {
        let Some(input) = (unsafe { view(request.input, request.length) }) else {
            return false;
        };
        hash.update_padded(input);
    }
    if request.length != 0 {
        unsafe { ptr::copy(request.input, request.output, request.length) };
    }
    let output = if request.length == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(request.output, request.length) }
    };
    counter.apply_keystream(output);
    if request.encrypt {
        hash.update_padded(output);
    }
    let mut lengths = ghash::Block::default();
    lengths[..8].copy_from_slice(&((request.associated.len() as u64) * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&((request.length as u64) * 8).to_be_bytes());
    hash.update(&[lengths]);
    let mut tag = hash.finalize();
    for (byte, mask) in tag.iter_mut().zip(mask) {
        *byte ^= mask;
    }
    unsafe { ptr::copy_nonoverlapping(tag.as_ptr(), request.tag, 16) };
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_lua_aes_gcm(
    encrypt: bool,
    key: *const u8,
    key_length: usize,
    iv: *const u8,
    iv_length: usize,
    input: *const u8,
    length: usize,
    associated: *const u8,
    associated_length: usize,
    output: *mut u8,
    tag: *mut u8,
) -> bool {
    if !matches!(key_length, 16 | 24 | 32)
        || iv_length == 0
        || iv_length > MAX_BITS_INPUT
        || associated_length > MAX_BITS_INPUT
        || length as u64 > MAX_DATA
        || length > isize::MAX as usize
        || tag.is_null()
        || (length != 0 && (input.is_null() || output.is_null()))
    {
        return false;
    }
    let Some(key) = (unsafe { view(key, key_length) }) else {
        return false;
    };
    let Some(iv) = (unsafe { view(iv, iv_length) }) else {
        return false;
    };
    let Some(associated) = (unsafe { view(associated, associated_length) }) else {
        return false;
    };
    // The Lua output is distinct userdata. Exact in-place input is also valid;
    // associated data and the output/tag buffers must not overlap each other.
    let request = Request {
        encrypt,
        key,
        iv,
        associated,
        input,
        length,
        output,
        tag,
    };
    unsafe {
        match key_length {
            16 => crypt::<Aes128Enc>(&request),
            24 => crypt::<Aes192Enc>(&request),
            _ => crypt::<Aes256Enc>(&request),
        }
    }
}
