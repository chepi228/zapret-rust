//! DNS-to-hostname cache feeding. All framing is checked before cache writes.
use crate::logging::LogSink;
use std::{ffi::c_char, ptr, slice};

type Cache = unsafe extern "C" fn(*const u8, *const u8, *const c_char, bool) -> bool;

#[repr(align(4))]
struct CacheAddress([u8; 16]);

#[repr(C)]
struct Report {
    log: LogSink,
    format_address: unsafe extern "C" fn(*const u8, usize, *mut c_char, usize) -> usize,
}

enum Event {
    NoAnswers,
    Query,
    UnsupportedQuery,
    Address,
    UnsupportedAnswer,
}

fn word(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn name(data: &[u8], start: usize, output: &mut [u8; 256]) -> Option<usize> {
    let mut at = start;
    let mut end = None;
    let mut length = 0;
    // Pointer targets are 14-bit offsets. This bounds cyclic chains without
    // recursion, allocation, or an arbitrary maximum compression depth.
    let mut visited = None;
    loop {
        let head = *data.get(at)?;
        match head & 0xc0 {
            0xc0 => {
                let target = (usize::from(head & 0x3f) << 8) | usize::from(*data.get(at + 1)?);
                let bit = 1u64 << (target % 64);
                #[expect(
                    clippy::unnecessary_lazy_evaluations,
                    reason = "Initialize the 2 KiB table only on the first pointer hop"
                )]
                let visited = visited.get_or_insert_with(|| [0u64; 256]);
                if visited[target / 64] & bit != 0 {
                    return None;
                }
                visited[target / 64] |= bit;
                end.get_or_insert(at + 2);
                at = target;
            }
            0 => {
                at += 1;
                if head == 0 {
                    output[length] = 0;
                    return Some(end.unwrap_or(at));
                }
                let label = data.get(at..at + usize::from(head))?;
                // The cache represents names as unescaped, NUL-terminated
                // text. These bytes would alias a different hostname there.
                if label.contains(&0) || label.contains(&b'.') {
                    return None;
                }
                let separator = usize::from(length != 0);
                if length + separator + label.len() > 253 {
                    return None;
                }
                if separator != 0 {
                    output[length] = b'.';
                    length += 1;
                }
                for byte in label {
                    output[length] = byte.to_ascii_lowercase();
                    length += 1;
                }
                at += label.len();
            }
            _ => return None,
        }
    }
}

fn skip_name(data: &[u8], mut at: usize) -> Option<usize> {
    let start = at;
    loop {
        let head = *data.get(at)?;
        match head & 0xc0 {
            0xc0 => {
                let target = (usize::from(head & 0x3f) << 8) | usize::from(*data.get(at + 1)?);
                // Owners are not used as cache keys. Check their wire framing
                // and pointer range without resolving the referenced name.
                return (target < data.len() && at + 2 - start <= 255).then_some(at + 2);
            }
            0 => {
                at += usize::from(head) + 1;
                if at > data.len() || at - start > 255 {
                    return None;
                }
                if head == 0 {
                    return Some(at);
                }
            }
            _ => return None,
        }
    }
}

#[derive(Clone, Copy)]
struct Answer {
    next: usize,
    offset: usize,
    length: usize,
    kind: u16,
    internet_class: bool,
}

fn answer(data: &[u8], at: usize) -> Option<Answer> {
    let at = skip_name(data, at)?;
    let (header, rest) = data.get(at..)?.split_first_chunk::<10>()?;
    let [
        type_high,
        type_low,
        class_high,
        class_low,
        _,
        _,
        _,
        _,
        length_high,
        length_low,
    ] = *header;
    let length = usize::from(u16::from_be_bytes([length_high, length_low]));
    rest.get(..length)?;
    Some(Answer {
        next: at + 10 + length,
        offset: at + 10,
        length,
        kind: u16::from_be_bytes([type_high, type_low]),
        internet_class: [class_high, class_low] == [0, 1],
    })
}

unsafe fn publish(
    answer: Answer,
    data: *const u8,
    host: &[u8; 256],
    cache: Cache,
    report: Option<&Report>,
) -> bool {
    if !answer.internet_class {
        return true;
    }
    if matches!((answer.kind, answer.length), (1, 4) | (28, 16)) {
        let address = unsafe { data.add(answer.offset) };
        unsafe { emit(report, Event::Address, answer.kind, host, address) };
        // Wire addresses may be unaligned and logging may update their bytes.
        let mut aligned = CacheAddress([0; 16]);
        unsafe { ptr::copy_nonoverlapping(address, aligned.0.as_mut_ptr(), answer.length) };
        let pointer = aligned.0.as_ptr();
        let (ipv4, ipv6) = if answer.kind == 1 {
            (pointer, ptr::null())
        } else {
            (ptr::null(), pointer)
        };
        return unsafe { cache(ipv4, ipv6, host.as_ptr().cast(), false) };
    }
    if !matches!(answer.kind, 1 | 28) {
        unsafe {
            emit(
                report,
                Event::UnsupportedAnswer,
                answer.kind,
                host,
                ptr::null(),
            )
        };
    }
    true
}

unsafe fn emit(
    report: Option<&Report>,
    event: Event,
    kind: u16,
    name: &[u8; 256],
    address: *const u8,
) {
    let Some(report) = report else { return };
    let log = report.log;
    let host = name.as_ptr().cast::<c_char>();
    unsafe {
        match event {
            Event::NoAnswers => log(c"skipping DNS response without answer\n".as_ptr()),
            Event::Query => log(
                c"DNS query type %u for '%s'\n".as_ptr(),
                u32::from(kind),
                host,
            ),
            Event::UnsupportedQuery => log(
                c"skipping DNS query type %u for '%s'\n".as_ptr(),
                u32::from(kind),
                host,
            ),
            Event::Address => {
                let width = if kind == 1 { 4 } else { 16 };
                let mut text = [0; 65]; // INET6_ADDRSTRLEN
                if (report.format_address)(address, width, text.as_mut_ptr(), text.len()) == 0 {
                    return;
                }
                log(
                    c"DNS response type %u : %s\n".as_ptr(),
                    u32::from(kind),
                    text.as_ptr(),
                )
            }
            Event::UnsupportedAnswer => {
                log(c"skipping DNS response type %u\n".as_ptr(), u32::from(kind))
            }
        };
    }
}

unsafe fn feed(data: *const u8, length: usize, cache: Cache, report: Option<&Report>) -> bool {
    // Borrow the wire for parsing. Keep only raw pointers across logger calls.
    let view = || {
        if length == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(data, length) }
        }
    };
    let Some(&[_, _, flags, _, q_hi, q_lo, a_hi, a_lo, ..]) = view().first_chunk::<12>() else {
        return false;
    };
    let questions = u16::from_be_bytes([q_hi, q_lo]);
    let answers = usize::from(u16::from_be_bytes([a_hi, a_lo]));
    if flags & 0x80 == 0 || questions == 0 {
        return false;
    }
    let mut host = [0; 256];
    if answers == 0 {
        unsafe { emit(report, Event::NoAnswers, 0, &host, ptr::null()) };
        return false;
    }
    let mut at = 12;
    for _ in 0..questions {
        // Retain the engine's policy: at most one non-root question name.
        if host[0] != 0 {
            return false;
        }
        let data = view();
        let Some(next) = name(data, at, &mut host) else {
            return false;
        };
        let Some(kind) = word(data, next) else {
            return false;
        };
        if word(data, next + 2) != Some(1) {
            return false;
        }
        if !matches!(kind, 1 | 28) {
            unsafe { emit(report, Event::UnsupportedQuery, kind, &host, ptr::null()) };
            return false;
        }
        unsafe { emit(report, Event::Query, kind, &host, ptr::null()) };
        at = next + 4;
    }
    if host[0] == 0 {
        return false;
    }
    let Some(first) = answer(view(), at) else {
        return false;
    };
    if answers == 1 {
        return unsafe { publish(first, data, &host, cache, report) };
    }
    // Cache the first few parsed answers on the stack. Larger responses
    // still stay allocation-free and are checked before we publish any.
    let mut saved = [first; 4];
    at = first.next;
    for index in 1..answers {
        let Some(record) = answer(view(), at) else {
            return false;
        };
        if let Some(slot) = saved.get_mut(index) {
            *slot = record;
        }
        at = record.next;
    }
    at = saved.last().unwrap().next;
    for record in saved.into_iter().take(answers) {
        if !unsafe { publish(record, data, &host, cache, report) } {
            return false;
        }
    }
    for _ in saved.len()..answers {
        let Some(record) = answer(view(), at) else {
            return false;
        };
        if !unsafe { publish(record, data, &host, cache, report) } {
            return false;
        }
        at = record.next;
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_feed_dns_response(
    data: *const u8,
    length: usize,
    enabled: bool,
    debug: bool,
    cache: Cache,
    report: *const Report,
) -> bool {
    if !enabled {
        return true;
    }
    let report = debug.then(|| unsafe { &*report });
    unsafe { feed(data, length, cache, report) }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn unused(_: *const u8, _: *const u8, _: *const c_char, _: bool) -> bool {
        panic!("unexpected cache insertion")
    }

    #[test]
    fn truncated_headers_and_disabled_cache_do_not_read_input() {
        unsafe {
            assert!(zapret_feed_dns_response(
                ptr::null(),
                usize::MAX,
                false,
                true,
                unused,
                ptr::null(),
            ))
        };
        for length in 0..12 {
            assert!(!unsafe { feed([0; 12].as_ptr(), length, unused, None) });
        }
    }

    #[test]
    fn compressed_names_and_cycles_are_bounded() {
        let bytes = b"\x03COM\0\x03WWW\xc0\0\xc0\x05";
        let mut host = [0; 256];
        assert_eq!(name(bytes, 11, &mut host), Some(13));
        assert_eq!(&host[..12], b"www.com\0\0\0\0\0");
        for bytes in [
            b"\xc0\0".as_slice(),
            b"\xc0\x02\xc0\0",
            b"\xc0",
            b"\xc0\x40",
            b"\x40bad",
        ] {
            assert_eq!(name(bytes, 0, &mut host), None);
        }
    }

    #[test]
    fn cache_keys_reject_ambiguous_and_overlong_names() {
        let mut host = [0; 256];
        for bytes in [b"\x03a\0b\0".as_slice(), b"\x03a.b\0"] {
            assert_eq!(name(bytes, 0, &mut host), None);
        }
        let mut wire = Vec::new();
        for length in [63, 63, 63, 61] {
            wire.push(length);
            wire.extend(std::iter::repeat_n(b'A', usize::from(length)));
        }
        wire.push(0);
        assert_eq!(wire.len(), 255);
        assert_eq!(name(&wire, 0, &mut host), Some(255));
        wire[192] = 62;
        wire.insert(254, b'A');
        assert_eq!(name(&wire, 0, &mut host), None);
    }

    #[test]
    fn malformed_later_answer_has_no_cache_side_effect() {
        let mut wire = b"\0\x01\x80\0\0\x01\0\x02\0\0\0\0\x01A\0\0\x01\0\x01".to_vec();
        wire.extend_from_slice(b"\xc0\x0c\0\x01\0\x01\0\0\0\0\0\x04\x7f\0\0\x01");
        wire.extend_from_slice(b"\xc0\x0c\0\x1c\0\x01");
        assert!(!unsafe { feed(wire.as_ptr(), wire.len(), unused, None) });
    }
}
