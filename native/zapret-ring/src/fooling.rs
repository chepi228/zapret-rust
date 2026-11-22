use std::ops::Range;

/// Matches the drive/root forms accepted by the engine's Windows Lua helpers.
pub fn windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    matches!(bytes.first(), Some(b'/' | b'\\'))
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

pub fn tcp_fallback(sequence: u32, has_md5: bool) -> (u32, bool) {
    (sequence.wrapping_sub(10_000), !has_md5)
}

/// Arguments and results use half-open byte ranges within one payload.
pub fn host_split(length: usize, start: usize, end: usize) -> Option<[Range<usize>; 4]> {
    if start >= end || end > length {
        return None;
    }
    Some([0..start, start..end, end..length, start..end])
}
