//! In-place ClientHello transformations. Validate the complete edit before writing.
use super::{be16, be24, tls, wire::length_with_delta};
#[cfg(windows)]
mod lua;
use std::{
    ffi::{CStr, c_char},
    mem::MaybeUninit,
    ops::Range,
    slice,
};

const RND: u32 = 1;
const RND_SNI: u32 = 2;
const SNI: u32 = 4;
const DUP_SID: u32 = 8;
const PAD_ENCAP: u32 = 16;
const SID_SKIPPED: u8 = 1;
const PADDING_OVERFLOW: u8 = 2;
#[cfg(windows)]
const APPLIED_TLS_FLAGS: &CStr = c"applied tls mod flags=0x%x\n";

#[repr(C)]
struct FakeTlsMod {
    sni: [u8; 256],
    flags: u32,
}

#[cfg(windows)]
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_tls_report_applied(
    options: *const FakeTlsMod,
    applied: bool,
    log: crate::logging::LogSink,
) {
    if applied {
        let flags = unsafe { (*options).flags };
        if flags != 0 {
            unsafe { log(APPLIED_TLS_FLAGS.as_ptr(), flags) };
        }
    }
}

fn parse_list(mut text: &[u8], options: &mut FakeTlsMod) -> bool {
    options.flags = 0;
    options.sni[0] = 0;
    while !text.is_empty() {
        let end = text
            .iter()
            .position(|&byte| byte == b',')
            .unwrap_or(text.len());
        // Retain the pinned parser's 140-byte option buffer, including its NUL.
        let option = &text[..end.min(139)];
        let equal = option.iter().position(|&byte| byte == b'=');
        let name = &option[..equal.unwrap_or(option.len())];
        match name {
            b"rnd" => options.flags |= RND,
            b"rndsni" => options.flags |= RND_SNI,
            b"dupsid" => options.flags |= DUP_SID,
            b"padencap" => options.flags |= PAD_ENCAP,
            b"sni" => {
                options.flags |= SNI;
                let Some(value) = equal
                    .map(|at| &option[at + 1..])
                    .filter(|value| !value.is_empty())
                else {
                    return false;
                };
                options.sni[..value.len()].copy_from_slice(value);
                options.sni[value.len()..].fill(0);
            }
            b"none" => {}
            _ => return false,
        }
        text = &text[(end + usize::from(end < text.len()))..];
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    InvalidHello,
    MissingSni,
    InvalidSni,
    InvalidConfiguration,
    EmptyRandomSni,
    NoSpace,
    LengthOverflow,
    PaddingNotLast,
}

struct SniEdit<'a> {
    host: Range<usize>,
    replacement: Option<&'a [u8]>,
    extension: usize,
    lengths: [usize; 3],
}

struct Plan<'a> {
    size: usize,
    record: usize,
    handshake: usize,
    extensions: Option<(usize, usize)>,
    sni: Option<SniEdit<'a>>,
    padding: Option<(usize, usize, bool)>,
    warnings: u8,
}

fn adjusted(value: usize, delta: isize, maximum: usize) -> Result<usize, Error> {
    length_with_delta(value, delta, maximum).ok_or(Error::LengthOverflow)
}

fn plan<'a>(
    options: &'a FakeTlsMod,
    data: &[u8],
    capacity: usize,
    payload: Option<usize>,
) -> Result<Plan<'a>, Error> {
    if !tls::hello(data, 1, false)
        || data
            .get(43)
            .is_none_or(|&length| data.len() < 44 + usize::from(length))
    {
        return Err(Error::InvalidHello);
    }
    let mut result = Plan {
        size: data.len(),
        record: be16(data, 3).ok_or(Error::InvalidHello)?,
        handshake: be24(data, 6).ok_or(Error::InvalidHello)?,
        extensions: None,
        sni: None,
        padding: None,
        warnings: 0,
    };
    if options.flags & (RND_SNI | SNI | PAD_ENCAP) != 0 {
        let offset = tls::extensions_offset(data).ok_or(Error::InvalidHello)?;
        result.extensions = Some((offset, be16(data, offset).ok_or(Error::InvalidHello)?));
    }
    let mut delta = 0;
    if options.flags & (RND_SNI | SNI) != 0 {
        let extension = tls::find_extension(data, 0, false).ok_or(Error::MissingSni)?;
        let length = tls::sni_length(&data[extension.clone()]).ok_or(Error::InvalidSni)?;
        let host = extension.start + 5..extension.start + 5 + length;
        let replacement = if options.flags & SNI != 0 {
            let end = options
                .sni
                .iter()
                .position(|&byte| byte == 0)
                .ok_or(Error::InvalidConfiguration)?;
            delta = end as isize - length as isize;
            Some(&options.sni[..end])
        } else {
            None
        };
        if options.flags & RND_SNI != 0 && replacement.map_or(length, <[u8]>::len) == 0 {
            return Err(Error::EmptyRandomSni);
        }
        let lengths = [extension.start - 2, extension.start, host.start - 2].map(|offset| {
            be16(data, offset)
                .ok_or(Error::InvalidSni)
                .and_then(|value| adjusted(value, delta, 0xffff))
        });
        let [a, b, c] = lengths;
        result.sni = Some(SniEdit {
            host,
            replacement,
            extension: extension.start,
            lengths: [a?, b?, c?],
        });
        result.size = result
            .size
            .checked_add_signed(delta)
            .filter(|&size| size <= capacity)
            .ok_or(Error::NoSpace)?;
        result.record = adjusted(result.record, delta, 0xffff)?;
        result.handshake = adjusted(result.handshake, delta, 0xffffff)?;
        if let Some((_, length)) = result.extensions.as_mut() {
            *length = adjusted(*length, delta, 0xffff)?;
        }
    }
    if let Some(payload_length) = payload.filter(|_| options.flags & PAD_ENCAP != 0) {
        let (offset, length, append) = if let Some(extension) = tls::find_extension(data, 21, false)
        {
            if extension.end != data.len() {
                return Err(Error::PaddingNotLast);
            }
            (
                adjusted(extension.start - 2, delta, capacity)?,
                extension.len(),
                false,
            )
        } else {
            let offset = result.size.checked_add(2).ok_or(Error::NoSpace)?;
            result.size = result
                .size
                .checked_add(4)
                .filter(|&size| size <= capacity)
                .ok_or(Error::NoSpace)?;
            result.record = adjusted(result.record, 4, 0xffff)?;
            result.handshake = adjusted(result.handshake, 4, 0xffffff)?;
            if let Some((_, length)) = result.extensions.as_mut() {
                *length = adjusted(*length, 4, 0xffff)?;
            }
            (offset, 0, true)
        };
        let encap = [
            result.record,
            result.handshake,
            result.extensions.ok_or(Error::InvalidHello)?.1,
            length,
        ]
        .map(|length| length.checked_add(payload_length));
        match encap {
            [
                Some(record),
                Some(handshake),
                Some(extensions),
                Some(padding),
            ] if record <= 0xffff
                && handshake <= 0xffffff
                && extensions <= 0xffff
                && padding <= 0xffff =>
            {
                result.record = record;
                result.handshake = handshake;
                if let Some((_, length)) = result.extensions.as_mut() {
                    *length = extensions;
                }
                result.padding = Some((offset, padding, append));
            }
            _ => {
                // An unusable real payload is nonfatal, as in the pinned engine.
                result.warnings |= PADDING_OVERFLOW;
                result.padding = Some((offset, length, append));
            }
        }
    }
    if result.size > capacity {
        return Err(Error::NoSpace);
    }
    Ok(result)
}

fn put16(data: &mut [u8], offset: usize, value: usize) {
    data[offset..offset + 2].copy_from_slice(&(value as u16).to_be_bytes());
}

fn random_bytes(mut data: &mut [u8], random: &mut impl FnMut() -> u32) {
    // Preserve the pinned helper's draw order, including its alignment rule.
    if !data.is_empty() && data.as_ptr() as usize & 1 != 0 {
        data[0] = random() as u8;
        data = &mut data[1..];
    }
    let mut pairs = data.chunks_exact_mut(2);
    for pair in &mut pairs {
        pair.copy_from_slice(&(random() as u16).to_le_bytes());
    }
    if let Some(last) = pairs.into_remainder().first_mut() {
        *last = random() as u8;
    }
}

fn random_sni(host: &mut [u8], random: &mut impl FnMut() -> u32) {
    host[0] = b'a' + (random() % 26) as u8;
    let end = if host.len() >= 7 {
        host.len() - 4
    } else {
        host.len()
    };
    for byte in &mut host[1..end] {
        let value = (random() % 36) as u8;
        *byte = if value < 10 {
            b'0' + value
        } else {
            b'a' + value - 10
        };
    }
    if host.len() >= 7 {
        let length = host.len();
        host[length - 4] = b'.';
        let tld = [b"com", b"org", b"net", b"edu", b"gov", b"biz"][(random() % 6) as usize];
        host[length - 3..].copy_from_slice(tld);
    }
}

#[cfg(test)]
fn apply(
    options: &FakeTlsMod,
    payload: Option<&[u8]>,
    payload_length: usize,
    data: &mut [u8],
    size: usize,
    random: &mut impl FnMut() -> u32,
) -> Result<(usize, u8), Error> {
    let edit = plan(
        options,
        data.get(..size).ok_or(Error::NoSpace)?,
        data.len(),
        payload.map(|_| payload_length),
    )?;
    Ok(commit(options, payload, data, size, edit, random))
}

fn commit(
    options: &FakeTlsMod,
    payload: Option<&[u8]>,
    data: &mut [u8],
    size: usize,
    mut edit: Plan<'_>,
    random: &mut impl FnMut() -> u32,
) -> (usize, u8) {
    if let Some(sni) = edit.sni {
        let length = sni.replacement.map_or(sni.host.len(), <[u8]>::len);
        if let Some(replacement) = sni.replacement {
            if replacement.len() != sni.host.len() {
                data.copy_within(sni.host.end..size, sni.host.start + replacement.len());
            }
            data[sni.host.start..sni.host.start + replacement.len()].copy_from_slice(replacement);
            for (offset, value) in [sni.extension - 2, sni.extension, sni.host.start - 2]
                .into_iter()
                .zip(sni.lengths)
            {
                put16(data, offset, value);
            }
        }
        if options.flags & RND_SNI != 0 {
            random_sni(&mut data[sni.host.start..sni.host.start + length], random);
        }
    }
    let sid_length = usize::from(data[43]);
    if options.flags & RND != 0 {
        random_bytes(&mut data[11..43], random);
        random_bytes(&mut data[44..44 + sid_length], random);
    }
    if let Some(payload) = payload.filter(|_| options.flags & DUP_SID != 0) {
        let source = payload
            .get(44..44 + sid_length)
            .filter(|_| tls::client_partial(payload) && payload.get(43) == Some(&data[43]));
        if let Some(source) = source {
            data[44..44 + sid_length].copy_from_slice(source);
        } else {
            edit.warnings |= SID_SKIPPED;
        }
    }
    if let Some((offset, length, append)) = edit.padding {
        if append {
            put16(data, offset - 2, 21);
        }
        put16(data, offset, length);
    }
    put16(data, 3, edit.record);
    data[6..9].copy_from_slice(&(edit.handshake as u32).to_be_bytes()[1..]);
    if let Some((offset, length)) = edit.extensions {
        put16(data, offset, length);
    }
    (edit.size, edit.warnings)
}

type Reporter = Option<extern "C" fn(*const c_char)>;

fn report(reporter: Reporter, message: &'static CStr) {
    if let Some(reporter) = reporter {
        reporter(message.as_ptr());
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSMod_parse_list(text: *const c_char, options: *mut FakeTlsMod) -> bool {
    if text.is_null() || options.is_null() {
        return false;
    }
    // The C entry supplies a terminated option string and one writable ABI record.
    parse_list(unsafe { CStr::from_ptr(text) }.to_bytes(), unsafe {
        &mut *options
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_tls_mod(
    options: *const FakeTlsMod,
    payload: *const u8,
    payload_length: usize,
    data: *mut u8,
    size: *mut usize,
    capacity: usize,
    reporter: Reporter,
) -> bool {
    if options.is_null() || data.is_null() || size.is_null() || capacity > isize::MAX as usize {
        return false;
    }
    let options = unsafe { &*options };
    let original_size = unsafe { *size };
    if original_size > capacity {
        return false;
    }
    // Only session-id copying reads the payload. Snapshot its bounded prefix
    // before borrowing the output, including when the C caller aliases the two.
    let mut prefix = MaybeUninit::<[u8; 44 + 255]>::uninit();
    let copied = if !payload.is_null() && options.flags & DUP_SID != 0 {
        payload_length.min(44 + 255)
    } else {
        0
    };
    if copied != 0 {
        unsafe { std::ptr::copy_nonoverlapping(payload, prefix.as_mut_ptr().cast::<u8>(), copied) };
    }
    // Only the copied prefix is initialized; padencap alone never reads payload bytes.
    let snapshot = unsafe { slice::from_raw_parts(prefix.as_ptr().cast::<u8>(), copied) };
    let payload = (!payload.is_null()).then_some(snapshot);
    let input = unsafe { slice::from_raw_parts(data, original_size) };
    let result = plan(options, input, capacity, payload.map(|_| payload_length)).map(|edit| {
        // C allocators initialize only the fake's current prefix. Initialize
        // newly exposed bytes before creating a Rust slice over the larger edit.
        let initialized = original_size.max(edit.size);
        if initialized > original_size {
            unsafe {
                std::ptr::write_bytes(data.add(original_size), 0, initialized - original_size)
            };
        }
        let buffer = unsafe { slice::from_raw_parts_mut(data, initialized) };
        commit(options, payload, buffer, original_size, edit, &mut || {
            crate::system::zapret_random() as u32
        })
    });
    match result {
        Ok((length, warnings)) => {
            unsafe { *size = length };
            if warnings & SID_SKIPPED != 0 {
                report(reporter, c"(nonfatal) cannot apply dupsid tls mod. payload session id is unavailable or incompatible\n");
            }
            if warnings & PADDING_OVERFLOW != 0 {
                report(
                    reporter,
                    c"(nonfatal) cannot apply padencap tls mod. length overflow\n",
                );
            }
            true
        }
        Err(error) => {
            report(
                reporter,
                match error {
                    Error::NoSpace => c"cannot apply tls mod. not enough buffer space\n",
                    Error::LengthOverflow => c"cannot apply tls mod. TLS length overflow\n",
                    Error::PaddingNotLast => {
                        c"cannot apply padencap tls mod. padding is not the final extension\n"
                    }
                    Error::MissingSni | Error::InvalidSni | Error::EmptyRandomSni => {
                        c"cannot apply tls mod. missing or invalid SNI\n"
                    }
                    Error::InvalidHello | Error::InvalidConfiguration => {
                        c"cannot apply tls mod. invalid TLS structure or options\n"
                    }
                },
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(text: &[u8]) -> FakeTlsMod {
        let mut options = FakeTlsMod {
            sni: [0; 256],
            flags: 0,
        };
        assert!(parse_list(text, &mut options));
        options
    }

    fn hello(host: &[u8], session: &[u8], padding: Option<usize>) -> Vec<u8> {
        let mut data = vec![0x16, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3];
        data.extend_from_slice(&[0; 32]);
        data.push(session.len() as u8);
        data.extend_from_slice(session);
        data.extend_from_slice(&[0, 2, 0x13, 1, 1, 0, 0, 0]);
        let extensions = 50 + session.len();
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        data.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        data.extend_from_slice(host);
        if let Some(length) = padding {
            data.extend_from_slice(&21u16.to_be_bytes());
            data.extend_from_slice(&(length as u16).to_be_bytes());
            data.resize(data.len() + length, 0);
        }
        let length = data.len();
        put16(&mut data, 3, length - 5);
        data[6..9].copy_from_slice(&((length - 9) as u32).to_be_bytes()[1..]);
        put16(&mut data, extensions, length - extensions - 2);
        data
    }

    #[test]
    fn parser_retains_truncation_trailing_comma_and_partial_failure_state() {
        let mut parsed = options(b"rnd=ignored,none,dupsid,");
        assert_eq!(parsed.flags, RND | DUP_SID);
        assert!(!parse_list(b"rnd,sni=", &mut parsed));
        assert_eq!(parsed.flags, RND | SNI);
        assert!(!parse_list(b"rnd,,dupsid", &mut parsed));
        let mut text = b"sni=".to_vec();
        text.extend_from_slice(&[b'a'; 400]);
        assert!(parse_list(&text, &mut parsed));
        assert_eq!(parsed.sni.iter().position(|&byte| byte == 0), Some(135));
        assert!(parse_list(b"", &mut parsed));
        assert_eq!(parsed.flags, 0);
    }

    #[test]
    fn sni_edits_preserve_suffix_and_all_nested_lengths() {
        for host in [b"a.b".as_slice(), b"longer.hostname.example.net"] {
            let mut data = hello(b"example.com", b"session", Some(12));
            let original_size = data.len();
            let opts = options(&[b"sni=", host].concat());
            data.resize(original_size + 256, 0xa5);
            let (length, warnings) =
                apply(&opts, None, 0, &mut data, original_size, &mut || 0).unwrap();
            assert_eq!(warnings, 0);
            assert_eq!(length, original_size - 11 + host.len());
            assert_eq!(be16(&data, 3), Some(length - 5));
            assert_eq!(be24(&data, 6), Some(length - 9));
            let extension = tls::find_extension(&data[..length], 0, false).unwrap();
            assert_eq!(&data[extension.start + 5..extension.end], host);
            let padding = tls::find_extension(&data[..length], 21, false).unwrap();
            assert_eq!(padding.end, length);
            assert_eq!(&data[padding], &[0; 12]);
        }
    }

    #[test]
    fn fatal_padding_error_preserves_buffer_size_and_random_state() {
        let mut data = hello(b"example.com", b"", Some(4));
        data.extend_from_slice(&[0, 43, 0, 0]);
        let length = data.len();
        put16(&mut data, 3, length - 5);
        data[6..9].copy_from_slice(&((length - 9) as u32).to_be_bytes()[1..]);
        put16(&mut data, 50, length - 52);
        data.resize(length + 256, 0xa5);
        let before = data.clone();
        let mut draws = 0;
        let result = apply(
            &options(b"sni=longer.example.net,rnd,padencap"),
            Some(&[]),
            0,
            &mut data,
            length,
            &mut || {
                draws += 1;
                0
            },
        );
        assert_eq!(result, Err(Error::PaddingNotLast));
        assert_eq!(data, before);
        assert_eq!(draws, 0);
    }

    #[test]
    fn record_growth_overflow_is_rejected_without_changing_the_fake() {
        let base = hello(b"a.b", b"", Some(0)).len();
        let mut data = hello(b"a.b", b"", Some(65540 - base));
        assert_eq!(data.len(), 65540);
        let length = data.len();
        data.resize(length + 256, 0xa5);
        let before = data.clone();
        assert_eq!(
            apply(
                &options(b"sni=a.longer.example.com"),
                None,
                0,
                &mut data,
                length,
                &mut || 0
            ),
            Err(Error::LengthOverflow)
        );
        assert_eq!(data, before);
    }

    #[test]
    fn payload_length_overflow_is_nonfatal_and_cannot_wrap_padding() {
        let mut data = hello(b"a.b", b"", None);
        let length = data.len();
        data.resize(length + 4, 0xa5);
        let (size, warnings) = apply(
            &options(b"padencap"),
            Some(&[]),
            usize::MAX,
            &mut data,
            length,
            &mut || 0,
        )
        .unwrap();
        assert_eq!((size, warnings), (length + 4, PADDING_OVERFLOW));
        assert_eq!(be16(&data, 3), Some(size - 5));
        assert_eq!(&data[length..], &[0, 21, 0, 0]);
    }

    #[test]
    fn padding_encapsulation_updates_headers_but_does_not_copy_payload() {
        for padding in [None, Some(9)] {
            let mut data = hello(b"a.b", b"", padding);
            let length = data.len();
            data.resize(length + 64, 0xa5);
            let (size, warnings) = apply(
                &options(b"sni=example.net,padencap"),
                Some(&[]),
                50,
                &mut data,
                length,
                &mut || 0,
            )
            .unwrap();
            let extra = if padding.is_none() { 4 } else { 0 };
            assert_eq!(size, length + 8 + extra);
            assert_eq!(warnings, 0);
            assert_eq!(be16(&data, 3), Some(size - 5 + 50));
            let pad_header = size - padding.unwrap_or(0) - 4;
            assert_eq!(be16(&data, pad_header), Some(21));
            assert_eq!(be16(&data, pad_header + 2), Some(padding.unwrap_or(0) + 50));
        }
    }

    #[test]
    fn abi_snapshots_an_aliased_session_id_before_randomizing_output() {
        let mut data = hello(b"a.b", b"original-session", Some(0));
        let before = data[44..60].to_vec();
        let mut size = data.len();
        let opts = options(b"rnd,dupsid");
        assert!(unsafe {
            zapret_tls_mod(
                &opts,
                data.as_ptr(),
                size,
                data.as_mut_ptr(),
                &mut size,
                data.len(),
                None,
            )
        });
        assert_eq!(&data[44..60], before);
    }

    #[test]
    fn abi_rejects_bad_capacity_and_does_not_change_input_or_size() {
        let mut data = hello(b"a.b", b"", None);
        let before = data.clone();
        let mut size = data.len();
        assert!(!unsafe {
            zapret_tls_mod(
                &options(b"rnd"),
                std::ptr::null(),
                0,
                data.as_mut_ptr(),
                &mut size,
                data.len() - 1,
                None,
            )
        });
        assert_eq!(data, before);
        assert_eq!(size, before.len());
    }

    #[test]
    fn abi_grows_into_uninitialized_allocation_capacity() {
        let original = hello(b"a.b", b"", None);
        let mut data = Vec::with_capacity(original.len() + 256);
        data.extend_from_slice(&original);
        let mut size = data.len();
        assert!(unsafe {
            zapret_tls_mod(
                &options(b"sni=longer.example.net,padencap"),
                data.as_ptr(),
                original.len(),
                data.as_mut_ptr(),
                &mut size,
                data.capacity(),
                None,
            )
        });
        // The successful edit initialized the full returned prefix.
        unsafe {
            data.set_len(size);
        }
        assert_eq!(size, original.len() - 3 + 18 + 4);
        assert_eq!(&data[61..79], b"longer.example.net");
    }

    #[test]
    fn malformed_and_truncated_fakes_cannot_partially_write_or_escape_capacity() {
        let original = hello(b"example.com", b"session", Some(4));
        for index in 0..original.len() {
            for value in (0..=255).step_by(17) {
                for flags in [RND, SNI, RND_SNI, DUP_SID, PAD_ENCAP, RND | SNI | PAD_ENCAP] {
                    let mut data = original.clone();
                    data[index] = value;
                    let size = if value % 2 == 0 { index } else { data.len() };
                    let boundary = data.len() + 8;
                    data.resize(boundary + 16, 0xa5);
                    let before = data.clone();
                    let mut config = options(b"sni=a.b");
                    config.flags = flags;
                    let mut draws = 0;
                    let result = apply(
                        &config,
                        Some(&original),
                        original.len(),
                        &mut data[..boundary],
                        size,
                        &mut || {
                            draws += 1;
                            0
                        },
                    );
                    if result.is_err() {
                        assert_eq!(data, before);
                        assert_eq!(draws, 0);
                    }
                    assert_eq!(&data[boundary..], &[0xa5; 16]);
                }
            }
        }
    }
}
