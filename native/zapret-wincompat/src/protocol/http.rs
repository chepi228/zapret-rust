use super::{bytes, copy_lower, positions};
use std::{
    ffi::{CStr, c_char},
    ptr,
};

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"OPTIONS ",
    b"PUT ",
    b"DELETE ",
    b"CONNECT ",
    b"TRACE ",
    b"PATCH ",
];

fn token(data: &[u8]) -> Option<&[u8]> {
    let end = data
        .iter()
        .position(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))?;
    let rest = &data[end..];
    if !matches!(rest[0], b' ' | b'\t') {
        return None;
    }
    Some(skip_horizontal_space(rest))
}

fn skip_horizontal_space(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(data.len());
    &data[start..]
}

pub(super) fn request(data: &[u8]) -> bool {
    if !METHODS.iter().any(|method| data.starts_with(method)) {
        return false;
    }
    token(data)
        .and_then(token)
        .is_some_and(|rest| rest.len() >= 10 && rest.starts_with(b"HTTP/1."))
}

pub(super) fn reply(data: &[u8]) -> bool {
    data.len() > 14
        && data.starts_with(b"HTTP/1.")
        && matches!(data[7], b'0' | b'1')
        && data[8] == b' '
        && data[9..12].iter().all(u8::is_ascii_digit)
}

pub(super) fn host_offset(data: &[u8]) -> Option<usize> {
    data.windows(6)
        .position(|part| part.eq_ignore_ascii_case(b"\nhost:"))
        .map(|offset| offset + 1)
}

pub(super) fn header<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let offset = if name.is_empty() {
        0
    } else {
        data.windows(name.len())
            .position(|part| part.eq_ignore_ascii_case(name))?
    };
    let value = skip_horizontal_space(data.get(offset + name.len()..)?);
    let length = value
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n' | b' ' | b'\t'))
        .unwrap_or(value.len());
    (length != 0).then_some(&value[..length])
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HttpReplyCode(data: *const u8) -> i32 {
    let data = unsafe { bytes(data, 12) };
    (i32::from(data[9]) - 48) * 100 + (i32::from(data[10]) - 48) * 10 + i32::from(data[11]) - 48
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HttpFindHost(host: *mut *mut u8, data: *mut u8, length: usize) -> bool {
    if unsafe { (*host).is_null() } {
        let offset = host_offset(unsafe { bytes(data, length) });
        unsafe {
            *host = offset.map_or(ptr::null_mut(), |offset| data.add(offset));
        }
    }
    unsafe { !(*host).is_null() }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HttpExtractHeader(
    data: *const u8,
    length: usize,
    name: *const c_char,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    let Some(value) = header(
        unsafe { bytes(data, length) },
        unsafe { CStr::from_ptr(name) }.to_bytes(),
    ) else {
        return false;
    };
    unsafe {
        copy_lower(value, output, capacity);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn HttpExtractHost(
    data: *const u8,
    length: usize,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    let Some(value) = header(unsafe { bytes(data, length) }, b"\nHost:") else {
        return false;
    };
    unsafe {
        copy_lower(value, output, capacity);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn HttpReplyLooksLikeDPIRedirect(
    data: *const u8,
    length: usize,
    host: *const c_char,
) -> bool {
    let data = unsafe { bytes(data, length) };
    if host.is_null() || !reply(data) {
        return false;
    }
    let host = unsafe { CStr::from_ptr(host) }.to_bytes();
    if host.is_empty() || !matches!(unsafe { HttpReplyCode(data.as_ptr()) }, 302 | 307) {
        return false;
    }
    let Some(location) = header(data, b"\nLocation:") else {
        return false;
    };
    // The existing comparison uses its bounded, lowercased C string.
    let mut buffer = [0u8; 256];
    unsafe {
        copy_lower(location, buffer.as_mut_ptr().cast(), buffer.len());
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let location = &buffer[..end];
    let Some(redirect) = location
        .strip_prefix(b"http://")
        .or_else(|| location.strip_prefix(b"https://"))
    else {
        return false;
    };
    let end = redirect
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(redirect.len());
    let redirect = &redirect[..end];
    let Some((offset, _)) = positions::second_level(redirect) else {
        return false;
    };
    positions::second_level(host).is_none_or(|(host_offset, _)| {
        !host[host_offset..].eq_ignore_ascii_case(&redirect[offset..])
    })
}
