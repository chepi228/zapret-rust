use super::{bytes, tls};
use std::{mem::MaybeUninit, ptr, slice};
mod decrypt;
pub(crate) use decrypt::decrypt;

fn variable(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let length = 1usize << (data.get(*cursor)? >> 6);
    let end = cursor.checked_add(length)?;
    let field = data.get(*cursor..end)?;
    let mut value = u64::from(field[0] & 0x3f);
    for byte in &field[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *cursor = end;
    Some(value)
}

pub(super) fn long_header(data: &[u8]) -> bool {
    data.len() >= 9 && data[0] & 0x80 != 0
}

fn version(data: &[u8]) -> u32 {
    if !long_header(data) {
        return 0;
    }
    u32::from_be_bytes([data[1], data[2], data[3], data[4]])
}

fn version_two(version: u32) -> bool {
    matches!(version, 0x709a50c4 | 0x6b3343cf)
}

#[unsafe(no_mangle)]
extern "C" fn QUICDraftVersion(version: u32) -> u8 {
    match version {
        value if value >> 8 == 0xff0000 => value as u8,
        0xfaceb001 => 22,
        0xfaceb002 | 0xfaceb00e | 0x51303530 | 0x54303530 | 0x54303531 => 27,
        value if value & 0x0f0f0f0f == 0x0a0a0a0a => 29,
        1 => 34,
        value if version_two(value) => 100,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn QUICExtractVersion(data: *const u8, length: usize) -> u32 {
    version(unsafe { bytes(data, length) })
}

#[repr(C)]
struct ConnectionId {
    length: u8,
    data: [u8; 20],
}

#[unsafe(no_mangle)]
unsafe extern "C" fn QUICExtractDCID(
    data: *const u8,
    length: usize,
    output: &mut ConnectionId,
) -> bool {
    let data = unsafe { bytes(data, length) };
    if !long_header(data) || data[5] == 0 || data[5] > 20 {
        return false;
    }
    let length = usize::from(data[5]);
    let Some(id) = data.get(6..6 + length) else {
        return false;
    };
    output.length = length as u8;
    output.data[..length].copy_from_slice(id);
    true
}

pub(super) fn initial(data: &[u8]) -> bool {
    if data.len() < 128 {
        return false;
    }
    let version = version(data);
    if QUICDraftVersion(version) < 11
        || data[0] & 0xf0 != if version_two(version) { 0xd0 } else { 0xc0 }
    {
        return false;
    }
    let mut cursor = 5;
    for _ in 0..2 {
        let Some(length) = data.get(cursor).copied().filter(|length| *length <= 20) else {
            return false;
        };
        cursor += 1 + usize::from(length);
    }
    let Some(token_length) = variable(data, &mut cursor) else {
        return false;
    };
    let Some(token_end) = cursor.checked_add(token_length as usize) else {
        return false;
    };
    cursor = token_end;
    let Some(payload_length) = variable(data, &mut cursor) else {
        return false;
    };
    cursor
        .checked_add(payload_length as usize)
        .is_some_and(|end| end <= data.len())
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn IsQUICCryptoHello(
    data: *const u8,
    length: usize,
    hello_offset: *mut usize,
    hello_length: *mut usize,
) -> bool {
    let data = unsafe { bytes(data, length) };
    if data.len() < 3 || data[0] != 6 {
        return false;
    }
    let mut cursor = 1;
    let Some(0) = variable(data, &mut cursor) else {
        return false;
    };
    let Some(length) = variable(data, &mut cursor) else {
        return false;
    };
    let Some(end) = cursor.checked_add(length as usize) else {
        return false;
    };
    let Some(hello) = data.get(cursor..end) else {
        return false;
    };
    if !tls::handshake_hello(hello, 1, true) {
        return false;
    }
    if !hello_offset.is_null() {
        unsafe {
            *hello_offset = cursor;
        }
    }
    if !hello_length.is_null() {
        unsafe {
            *hello_length = length as usize;
        }
    }
    true
}

#[derive(Clone, Copy, Default)]
struct Fragment {
    start: usize,
    length: usize,
}

pub(crate) fn defragment(input: &[u8], output: &mut [MaybeUninit<u8>]) -> Option<(usize, bool)> {
    if output.len() < 10 {
        return None;
    }
    let data = &mut output[10..];
    let mut fragments = [Fragment::default(); 128];
    let mut count = 0;
    let mut cursor = 0;
    let mut initialized = 0;
    let mut high = 0;
    while let Some(kind) = input.get(cursor).copied() {
        cursor += 1;
        if kind <= 1 {
            continue;
        }
        if kind != 6 || count == fragments.len() {
            return None;
        }
        let offset = variable(input, &mut cursor)? as usize;
        let length = variable(input, &mut cursor)? as usize;
        let end = offset.checked_add(length)?;
        let next = cursor.checked_add(length)?;
        let source = input.get(cursor..next)?;
        if end > data.len() {
            return None;
        }
        cursor = next;
        if fragments[..count]
            .iter()
            .any(|fragment| fragment.start == offset && fragment.length == length)
        {
            continue;
        }
        if initialized < offset {
            data[initialized..offset].fill(MaybeUninit::new(0));
        }
        initialized = initialized.max(end);
        high = high.max(end);
        // The ranges were checked above. The output scratch need not have
        // been initialized before building the covered prefix.
        unsafe {
            ptr::copy_nonoverlapping(
                source.as_ptr(),
                data[offset..end].as_mut_ptr().cast(),
                length,
            );
        }
        fragments[count] = Fragment {
            start: offset,
            length,
        };
        count += 1;
    }
    if count == 0 {
        return None;
    }
    fragments[..count].sort_unstable_by_key(|fragment| fragment.start);
    let mut covered = 0;
    let mut full = true;
    for fragment in &fragments[..count] {
        full &= fragment.start <= covered;
        covered = covered.max(fragment.start + fragment.length);
    }
    output[0].write(6);
    output[1].write(0);
    for (target, byte) in output[2..10]
        .iter_mut()
        .zip((high as u64 | 0xc000_0000_0000_0000).to_be_bytes())
    {
        target.write(byte);
    }
    Some((high + 10, full))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn QUICDefragCrypto(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: &mut usize,
    full: &mut bool,
) -> bool {
    if *output_length < 10 {
        return false;
    }
    let input = unsafe { bytes(input, input_length) };
    let output =
        unsafe { slice::from_raw_parts_mut(output.cast::<MaybeUninit<u8>>(), *output_length) };
    let Some((length, complete)) = defragment(input, output) else {
        return false;
    };
    *output_length = length;
    *full = complete;
    true
}
