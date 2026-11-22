//! AES primitives for Lua's existing single-block and CTR interfaces.
use aes::{
    Aes128, Aes128Enc, Aes192, Aes192Enc, Aes256, Aes256Enc,
    cipher::{Block, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, consts::U16},
};
use std::{ptr, slice};

unsafe fn block<C>(encrypt: bool, key: &[u8], input: *const u8, output: *mut u8) -> bool
where
    C: KeyInit + BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let Ok(cipher) = C::new_from_slice(key) else {
        return false;
    };
    let mut value = Block::<C>::default();
    unsafe { ptr::copy_nonoverlapping(input, value.as_mut_ptr(), 16) };
    if encrypt {
        cipher.encrypt_block(&mut value);
    } else {
        cipher.decrypt_block(&mut value);
    }
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), output, 16) };
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_lua_aes_block(
    encrypt: bool,
    key: *const u8,
    key_length: usize,
    input: *const u8,
    output: *mut u8,
) -> bool {
    if !matches!(key_length, 16 | 24 | 32) {
        return false;
    }
    let key = unsafe { slice::from_raw_parts(key, key_length) };
    unsafe {
        match key_length {
            16 => block::<Aes128>(encrypt, key, input, output),
            24 => block::<Aes192>(encrypt, key, input, output),
            _ => block::<Aes256>(encrypt, key, input, output),
        }
    }
}

unsafe fn xor_block(input: *const u8, output: *mut u8, stream: &[u8], size: usize) {
    for (index, &byte) in stream[..size].iter().enumerate() {
        let value = unsafe { input.add(index).read() } ^ byte;
        unsafe { output.add(index).write(value) };
    }
}

unsafe fn ctr<C>(
    key: &[u8],
    iv: *const u8,
    input: *const u8,
    length: usize,
    output: *mut u8,
) -> bool
where
    C: KeyInit + BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let Ok(cipher) = C::new_from_slice(key) else {
        return false;
    };
    let mut counter = u128::from_be_bytes(unsafe { ptr::read_unaligned(iv.cast::<[u8; 16]>()) });
    let mut offset = 0;
    let mut streams = [Block::<C>::default(); 8];
    while length - offset >= 128 {
        for (index, stream) in streams.iter_mut().enumerate() {
            stream.copy_from_slice(&counter.wrapping_add(index as u128).to_be_bytes());
        }
        cipher.encrypt_blocks(&mut streams);
        for stream in &streams {
            unsafe { xor_block(input.add(offset), output.add(offset), stream, 16) };
            offset += 16;
        }
        counter = counter.wrapping_add(8);
    }
    while offset < length {
        let mut stream = Block::<C>::clone_from_slice(&counter.to_be_bytes());
        cipher.encrypt_block(&mut stream);
        let size = (length - offset).min(16);
        unsafe { xor_block(input.add(offset), output.add(offset), &stream, size) };
        offset += size;
        counter = counter.wrapping_add(1);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_lua_aes_ctr(
    key: *const u8,
    key_length: usize,
    iv: *const u8,
    input: *const u8,
    length: usize,
    output: *mut u8,
) -> bool {
    if !matches!(key_length, 16 | 24 | 32) || length > isize::MAX as usize {
        return false;
    }
    let key = unsafe { slice::from_raw_parts(key, key_length) };
    unsafe {
        match key_length {
            16 => ctr::<Aes128Enc>(key, iv, input, length, output),
            24 => ctr::<Aes192Enc>(key, iv, input, length, output),
            _ => ctr::<Aes256Enc>(key, iv, input, length, output),
        }
    }
}
