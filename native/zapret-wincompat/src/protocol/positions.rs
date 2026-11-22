use super::{bytes, http, names, tls};
#[cfg(windows)]
mod lua;
use std::{
    ffi::{CStr, c_char},
    slice,
};

const ABSOLUTE: u32 = 0;
const HOST: u32 = 1;
const HOST_END: u32 = 2;
const SLD: u32 = 3;
const MIDSLD: u32 = 4;
const ENDSLD: u32 = 5;
const METHOD: u32 = 6;
const EXTENSIONS: u32 = 7;
const SNI: u32 = 8;

#[repr(C)]
struct Position {
    offset: i16,
    marker: u32,
}

// Return the second-to-last label and its length. A trailing dot is retained.
pub(super) fn second_level(host: &[u8]) -> Option<(usize, usize)> {
    let end = host.iter().rposition(|byte| *byte == b'.')?;
    if end == 0 {
        return None;
    }
    let start = host[..end]
        .iter()
        .rposition(|byte| *byte == b'.')
        .map_or(0, |offset| offset + 1);
    Some((start, end - start))
}

fn checked(length: usize, base: usize, offset: i16) -> isize {
    base.checked_add_signed(isize::from(offset))
        .filter(|value| *value < length)
        .map_or(-1, |value| value as isize)
}

fn absolute(marker: u32, offset: i16, length: usize) -> isize {
    if marker != ABSOLUTE {
        return -1;
    }
    checked(length, if offset < 0 { length } else { 0 }, offset)
}

fn host(marker: u32, offset: i16, data: &[u8], start: usize, length: usize) -> isize {
    let base = match marker {
        HOST => start,
        HOST_END => match start.checked_add(length) {
            Some(end) => end,
            None => return -1,
        },
        SLD | MIDSLD | ENDSLD => {
            let Some(name) = data.get(start..start.saturating_add(length)) else {
                return -1;
            };
            let Some((label, size)) = second_level(name) else {
                return -1;
            };
            let middle = if size == 1 { 1 } else { size / 2 };
            start
                + label
                + match marker {
                    SLD => 0,
                    ENDSLD => size,
                    _ => middle,
                }
        }
        _ => return -1,
    };
    checked(data.len(), base, offset)
}

fn http_position(marker: u32, offset: i16, data: &[u8]) -> isize {
    match marker {
        METHOD => {
            if data.len() < 12 {
                return -1;
            }
            let mut start = 0;
            for _ in 0..2 {
                if matches!(data[start], b'\r' | b'\n') {
                    start += 1;
                }
            }
            let method_length = data[start..]
                .iter()
                .take(9)
                .take_while(|byte| byte.is_ascii_uppercase())
                .count();
            if method_length < 3 || data[start + method_length] != b' ' {
                return -1;
            }
            checked(data.len(), start, offset)
        }
        HOST..=ENDSLD => {
            let Some(start) = http::host_offset(data).filter(|start| start + 7 < data.len()) else {
                return -1;
            };
            let mut start = start + 5;
            if matches!(data[start], b' ' | b'\t') {
                start += 1;
            }
            let length = if marker == HOST {
                0
            } else {
                data[start..]
                    .iter()
                    .position(|byte| matches!(byte, b'\r' | b'\n'))
                    .unwrap_or(data.len() - start)
            };
            host(marker, offset, data, start, length)
        }
        _ => absolute(marker, offset, data.len()),
    }
}

fn tls_position(marker: u32, offset: i16, data: &[u8]) -> isize {
    match marker {
        HOST..=ENDSLD | SNI => {
            let Some(extension) = tls::find_extension(data, 0, true) else {
                return -1;
            };
            if marker == SNI {
                return checked(data.len(), extension.start, offset);
            }
            let Some(name_length) = tls::sni_length(&data[extension.clone()]) else {
                return -1;
            };
            host(marker, offset, data, extension.start + 5, name_length)
        }
        EXTENSIONS => {
            tls::extensions_offset(data).map_or(-1, |start| checked(data.len(), start, offset))
        }
        _ => absolute(marker, offset, data.len()),
    }
}

fn resolve(data: &[u8], payload: u32, position: &Position) -> isize {
    match payload {
        7 => http_position(position.marker, position.offset, data),
        9 => tls_position(position.marker, position.offset, data),
        _ => absolute(position.marker, position.offset, data.len()),
    }
}

fn parse_number(text: &[u8], offset: &mut i16) -> Option<bool> {
    if !text
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-'))
    {
        return None;
    }
    // Keep the platform integer conversion used by the existing configuration API.
    let signed = usize::from(matches!(text[0], b'+' | b'-'));
    let digits = &text[signed..];
    let end = digits
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(digits.len());
    let digits = &digits[..end];
    let first = digits
        .iter()
        .position(|byte| *byte != b'0')
        .unwrap_or(digits.len());
    let digits = &digits[first..];
    // Leading zeros can be arbitrarily long. Thirty significant digits exceed
    // the platform integer range, so the bounded conversion retains overflow.
    let mut number = [0u8; 32];
    if signed != 0 {
        number[0] = text[0];
    }
    let length = digits.len().min(30);
    number[signed..signed + length].copy_from_slice(&digits[..length]);
    let value = unsafe { libc::atoi(number.as_ptr().cast()) };
    *offset = value as i16;
    Some(i32::from(*offset) == value)
}

fn parse(text: &[u8], output: &mut Position) -> bool {
    if parse_number(text, &mut output.offset) == Some(true) {
        output.marker = ABSOLUTE;
        return true;
    }
    let end = text
        .iter()
        .position(|byte| matches!(byte, b'+' | b'-'))
        .unwrap_or(text.len());
    if end >= 32 {
        return false;
    }
    output.marker = names::index(&names::MARKERS, &text[..end]);
    if output.marker == names::MARKERS.len() as u32 {
        return false;
    }
    if end == text.len() {
        output.offset = 0;
        return true;
    }
    parse_number(&text[end..], &mut output.offset) == Some(true)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn posmarker_parse(text: *const c_char, output: &mut Position) -> bool {
    parse(unsafe { CStr::from_ptr(text) }.to_bytes(), output)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn posmarker_list_parse(
    text: *const c_char,
    output: *mut Position,
    count: &mut i32,
) -> bool {
    let text = unsafe { CStr::from_ptr(text) }.to_bytes();
    if text.is_empty() {
        *count = 0;
        return true;
    }
    if *count <= 0 {
        return false;
    }
    let mut remaining = text;
    for index in 0..*count as usize {
        let next = remaining.iter().position(|byte| *byte == b',');
        let end = next.unwrap_or(remaining.len());
        if next.is_some() && end >= 32 {
            return false;
        }
        if !parse(&remaining[..end], unsafe { &mut *output.add(index) }) {
            return false;
        }
        let Some(end) = next else {
            *count = (index + 1) as i32;
            return true;
        };
        remaining = &remaining[end + 1..];
    }
    false
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AnyProtoPos(
    marker: u32,
    offset: i16,
    _data: *const u8,
    length: usize,
) -> isize {
    absolute(marker, offset, length)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HttpPos(marker: u32, offset: i16, data: *const u8, length: usize) -> isize {
    http_position(marker, offset, unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSPos(marker: u32, offset: i16, data: *const u8, length: usize) -> isize {
    tls_position(marker, offset, unsafe { bytes(data, length) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ResolvePos(
    data: *const u8,
    length: usize,
    payload: u32,
    position: &Position,
) -> isize {
    resolve(unsafe { bytes(data, length) }, payload, position)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ResolveMultiPos(
    data: *const u8,
    length: usize,
    payload: u32,
    markers: *const Position,
    marker_count: i32,
    output: *mut isize,
    count: &mut i32,
) {
    *count = 0;
    if marker_count <= 0 {
        return;
    }
    let data = unsafe { bytes(data, length) };
    let markers = unsafe { slice::from_raw_parts(markers, marker_count as usize) };
    let output = unsafe { slice::from_raw_parts_mut(output, marker_count as usize) };
    let mut found = 0;
    for marker in markers {
        let value = resolve(data, payload, marker);
        // Preserve the original scratch value when a marker is unresolved.
        output[found] = value;
        if value != -1 {
            found += 1;
        }
    }
    output[..found].sort_unstable();
    let mut unique = 0;
    for index in 0..found {
        if index == 0 || output[index] != output[index - 1] {
            output[unique] = output[index];
            unique += 1;
        }
    }
    *count = unique as i32;
}
