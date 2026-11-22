use super::wire::{be16, be24, bytes, copy_lower};
use core::{ffi::c_char, ops::Range};

pub(super) fn handshake_length(data: &[u8]) -> Option<usize> {
    be24(data, 1).map(|length| length + 4)
}

pub(crate) fn record_length(data: &[u8]) -> Option<usize> {
    be16(data, 3).map(|length| length + 5)
}

pub(crate) fn handshake_full(data: &[u8]) -> bool {
    handshake_length(data).is_some_and(|length| length <= data.len())
}

pub(crate) fn record_full(data: &[u8]) -> bool {
    record_length(data).is_some_and(|length| length <= data.len())
}

pub(super) fn handshake_hello(data: &[u8], kind: u8, partial: bool) -> bool {
    data.len() >= 6
        && (if kind == 0 {
            matches!(data[0], 1 | 2)
        } else {
            data[0] == kind
        })
        && data[4] == 3
        && data[5] <= 3
        && (partial || handshake_full(data))
}

pub(super) fn hello(data: &[u8], kind: u8, partial: bool) -> bool {
    data.len() >= 6
        && data[0] == 0x16
        && data[1] == 3
        && data[2] <= 3
        && (partial || record_full(data))
        && handshake_hello(&data[5..], kind, partial)
}

pub(super) fn client_partial(data: &[u8]) -> bool {
    hello(data, 1, true)
}

pub(super) fn server_partial(data: &[u8]) -> bool {
    hello(data, 2, true)
}

pub(super) fn handshake_extensions_offset(data: &[u8]) -> Option<usize> {
    let session_length = usize::from(*data.get(38)?);
    let mut offset = 39 + session_length;
    let cipher_length = be16(data, offset)?;
    offset += 2;
    if data[0] == 1 {
        offset += cipher_length;
    }
    let compression_length = usize::from(*data.get(offset)?);
    offset += 1;
    if data[0] == 1 {
        offset += compression_length;
    }
    be16(data, offset)?;
    if offset + 2 > handshake_length(data)? {
        return None;
    }
    Some(offset)
}

pub(super) fn extensions_offset(data: &[u8]) -> Option<usize> {
    let offset = handshake_extensions_offset(data.get(5..)?)? + 5;
    (offset + 2 <= record_length(data)?).then_some(offset)
}

pub(super) fn handshake_extension(data: &[u8], kind: u16, partial: bool) -> Option<Range<usize>> {
    if !partial && !handshake_full(data) {
        return None;
    }
    let offset = handshake_extensions_offset(data)?;
    let length = be16(data, offset)?;
    let mut start = offset + 2;
    let available = data.len() - start;
    let length = if partial {
        length.min(available)
    } else {
        if length > available {
            return None;
        }
        length
    };
    let end = start + length;
    while end - start >= 4 {
        let extension_kind = be16(data, start)?;
        let extension_length = be16(data, start + 2)?;
        start += 4;
        let next = start + extension_length;
        if next > end {
            break;
        }
        if extension_kind == usize::from(kind) {
            return (next <= handshake_length(data)?).then_some(start..next);
        }
        start = next;
    }
    None
}

pub(super) fn find_extension(data: &[u8], kind: u16, partial: bool) -> Option<Range<usize>> {
    if !hello(data, 0, partial) {
        return None;
    }
    let record_end = record_length(data)?.min(data.len());
    let body = data.get(5..record_end)?;
    handshake_extension(body, kind, partial).map(|range| range.start + 5..range.end + 5)
}

pub(super) fn sni_length(extension: &[u8]) -> Option<usize> {
    if extension.len() < 5 || extension[2] != 0 {
        return None;
    }
    let list_length = be16(extension, 0)?;
    let name_length = be16(extension, 3)?;
    (list_length >= name_length + 3 && list_length <= extension.len() - 2).then_some(name_length)
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn TLSVersionStr(version: u16) -> *const c_char {
    match version {
        0x0300 => c"SSL 3.0",
        0x0301 => c"TLS 1.0",
        0x0302 => c"TLS 1.1",
        0x0303 => c"TLS 1.2",
        0x0304 => c"TLS 1.3",
        value if value & 0x0f0f == 0x0a0a && value >> 12 == (value >> 4) & 0xf => c"GREASE",
        _ => c"UNKNOWN",
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSHandshakeDataLen(data: *const u8) -> usize {
    be24(unsafe { bytes(data, 4) }, 1).unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSHandshakeLen(data: *const u8) -> usize {
    (unsafe { TLSHandshakeDataLen(data) }) + 4
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSHandshakeFull(data: *const u8, length: usize) -> bool {
    handshake_full(unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSRecordDataLen(data: *const u8) -> u16 {
    be16(unsafe { bytes(data, 5) }, 3).unwrap_or(0) as u16
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSRecordLen(data: *const u8) -> usize {
    usize::from(unsafe { TLSRecordDataLen(data) }) + 5
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSRecordFull(data: *const u8, length: usize) -> bool {
    record_full(unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn IsTLSClientHelloPartial(data: *const u8, length: usize) -> bool {
    client_partial(unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn IsTLSServerHelloPartial(data: *const u8, length: usize) -> bool {
    server_partial(unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSHandshakeHello(
    data: *const u8,
    length: usize,
    kind: u8,
    partial: bool,
) -> bool {
    handshake_hello(unsafe { bytes(data, length) }, kind, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSHandshakeClientHello(
    data: *const u8,
    length: usize,
    partial: bool,
) -> bool {
    handshake_hello(unsafe { bytes(data, length) }, 1, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSHandshakeServerHello(
    data: *const u8,
    length: usize,
    partial: bool,
) -> bool {
    handshake_hello(unsafe { bytes(data, length) }, 2, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSHello(data: *const u8, length: usize, kind: u8, partial: bool) -> bool {
    hello(unsafe { bytes(data, length) }, kind, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSClientHello(data: *const u8, length: usize, partial: bool) -> bool {
    hello(unsafe { bytes(data, length) }, 1, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IsTLSServerHello(data: *const u8, length: usize, partial: bool) -> bool {
    hello(unsafe { bytes(data, length) }, 2, partial)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSFindExtLenOffsetInHandshake(
    data: *const u8,
    length: usize,
    offset: &mut usize,
) -> bool {
    let Some(found) = handshake_extensions_offset(unsafe { bytes(data, length) }) else {
        return false;
    };
    *offset = found;
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSFindExtLen(data: *const u8, length: usize, offset: &mut usize) -> bool {
    let Some(found) = extensions_offset(unsafe { bytes(data, length) }) else {
        return false;
    };
    *offset = found;
    true
}

unsafe fn store_extension(
    data: *const u8,
    range: Option<Range<usize>>,
    extension: *mut *const u8,
    length: *mut usize,
) -> bool {
    let Some(range) = range else { return false };
    // The original API writes its two outputs together.
    if !extension.is_null() && !length.is_null() {
        unsafe {
            *extension = data.add(range.start);
            *length = range.len();
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSFindExtInHandshake(
    data: *const u8,
    length: usize,
    kind: u16,
    extension: *mut *const u8,
    extension_length: *mut usize,
    partial: bool,
) -> bool {
    let range = handshake_extension(unsafe { bytes(data, length) }, kind, partial);
    unsafe { store_extension(data, range, extension, extension_length) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSFindExt(
    data: *const u8,
    length: usize,
    kind: u16,
    extension: *mut *const u8,
    extension_length: *mut usize,
    partial: bool,
) -> bool {
    let range = find_extension(unsafe { bytes(data, length) }, kind, partial);
    unsafe { store_extension(data, range, extension, extension_length) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSAdvanceToHostInSNI(
    extension: *mut *const u8,
    length: &mut usize,
    name_length: &mut usize,
) -> bool {
    let data = unsafe { bytes(*extension, *length) };
    if data.len() < 5 || data[2] != 0 {
        return false;
    }
    *name_length = be16(data, 3).unwrap_or(0);
    if sni_length(data).is_none() {
        return false;
    }
    unsafe {
        *extension = (*extension).add(5);
    }
    *length -= 5;
    true
}

unsafe fn extract_host(
    data: &[u8],
    range: Option<Range<usize>>,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    let Some(range) = range else { return false };
    let extension = &data[range];
    let Some(length) = sni_length(extension) else {
        return false;
    };
    unsafe {
        copy_lower(&extension[5..5 + length], output, capacity);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn TLSHelloExtractHost(
    data: *const u8,
    length: usize,
    output: *mut c_char,
    capacity: usize,
    partial: bool,
) -> bool {
    let data = unsafe { bytes(data, length) };
    unsafe { extract_host(data, find_extension(data, 0, partial), output, capacity) }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn TLSHelloExtractHostFromHandshake(
    data: *const u8,
    length: usize,
    output: *mut c_char,
    capacity: usize,
    partial: bool,
) -> bool {
    let data = unsafe { bytes(data, length) };
    unsafe {
        extract_host(
            data,
            handshake_extension(data, 0, partial),
            output,
            capacity,
        )
    }
}
