//! Engine option filters shared by the parser and the profile selector.
use crate::packet_policy::{Limit, Range};
use std::ffi::{CStr, c_char, c_void};

pub(super) const SKIP: u8 = 0;
pub(super) const ANY: u8 = 1;
const EXACT: u8 = 2;

#[repr(C)]
pub(super) struct PortFilter {
    pub(super) from: u16,
    pub(super) to: u16,
    pub(super) negated: bool,
}

impl PortFilter {
    pub(super) fn matches(&self, port: u16) -> bool {
        port != 0
            && (((self.from == 0 && self.to == 0) || (self.from..=self.to).contains(&port))
                ^ self.negated)
    }
}

#[repr(C)]
pub(super) struct IcmpFilter {
    pub(super) mode: u8,
    pub(super) kind: u8,
    pub(super) code: u8,
    pub(super) code_valid: bool,
}

impl IcmpFilter {
    pub(super) fn matches(&self, kind: u8, code: u8) -> bool {
        unsafe { Self::matches_fields(self, kind, code) }
    }

    unsafe fn matches_fields(filter: *const Self, kind: u8, code: u8) -> bool {
        // The native caller only needs to populate fields used by this mode.
        unsafe {
            let mode = (&raw const (*filter).mode).read();
            mode == ANY
                || mode == EXACT
                    && (&raw const (*filter).kind).read() == kind
                    && (!(&raw const (*filter).code_valid).read()
                        || (&raw const (*filter).code).read() == code)
        }
    }
}

#[repr(C)]
pub(super) struct IpProtocolFilter {
    pub(super) mode: u8,
    pub(super) protocol: u8,
}

impl IpProtocolFilter {
    pub(super) fn matches(&self, protocol: u8) -> bool {
        unsafe { Self::matches_fields(self, protocol) }
    }

    unsafe fn matches_fields(filter: *const Self, protocol: u8) -> bool {
        unsafe {
            let mode = (&raw const (*filter).mode).read();
            mode == ANY || mode == EXACT && (&raw const (*filter).protocol).read() == protocol
        }
    }
}

// Retain the decimal syntax of the old scanf parser while checking every
// operation. Oversized input and nonzero negative values cannot wrap into
// an otherwise valid filter.
pub(super) fn decimal64_prefix(mut text: &[u8]) -> Option<(u64, &[u8])> {
    while let Some((b' ' | b'\t'..=b'\r', rest)) = text.split_first() {
        text = rest;
    }
    let negative = text.starts_with(b"-");
    if negative || text.starts_with(b"+") {
        text = &text[1..];
    }
    let (mut number, mut digits) = (0u64, 0usize);
    while let Some(&byte) = text.get(digits).filter(|byte| byte.is_ascii_digit()) {
        number = number
            .checked_mul(10)?
            .checked_add(u64::from(byte - b'0'))?;
        digits += 1;
    }
    (digits != 0 && (!negative || number == 0)).then_some((number, &text[digits..]))
}

pub(super) fn decimal_prefix(text: &[u8]) -> Option<(u32, &[u8])> {
    let (value, tail) = decimal64_prefix(text)?;
    Some((u32::try_from(value).ok()?, tail))
}

fn number(text: &[u8]) -> Option<u32> {
    let (value, tail) = decimal_prefix(text)?;
    tail.is_empty().then_some(value)
}

pub(super) fn port_filter(text: &[u8]) -> Option<PortFilter> {
    if text == b"*" {
        return Some(PortFilter {
            from: 1,
            to: u16::MAX,
            negated: false,
        });
    }
    let (negated, body) = text
        .strip_prefix(b"~")
        .map_or((false, text), |body| (true, body));
    let (from, tail) = decimal_prefix(body)?;
    let to = if tail.is_empty() {
        from
    } else {
        number(tail.strip_prefix(b"-")?)?
    };
    let (from, to) = (u16::try_from(from).ok()?, u16::try_from(to).ok()?);
    (from <= to).then_some(PortFilter {
        from,
        to,
        negated: negated || to == 0,
    })
}

fn wildcard(text: &[u8]) -> Option<u8> {
    match text {
        b"*" => Some(ANY),
        b"-" => Some(SKIP),
        _ => None,
    }
}

pub(super) fn icmp_filter(text: &[u8]) -> Option<IcmpFilter> {
    if let Some(mode) = wildcard(text) {
        return Some(IcmpFilter {
            mode,
            kind: 0,
            code: 0,
            code_valid: false,
        });
    }
    let (kind, rest) = decimal_prefix(text)?;
    let kind = u8::try_from(kind).ok()?;
    let code_valid = !rest.is_empty();
    let code = if code_valid {
        u8::try_from(number(rest.strip_prefix(b":")?)?).ok()?
    } else {
        0
    };
    Some(IcmpFilter {
        mode: EXACT,
        kind,
        code,
        code_valid,
    })
}

pub(super) fn ip_filter(text: &[u8]) -> Option<IpProtocolFilter> {
    if let Some(mode) = wildcard(text) {
        return Some(IpProtocolFilter {
            mode,
            protocol: 255,
        });
    }
    Some(IpProtocolFilter {
        mode: EXACT,
        protocol: u8::try_from(number(text)?).ok()?,
    })
}

fn limit(text: &[u8]) -> Option<Limit> {
    let (&mode, rest) = text.split_first()?;
    let value = match mode {
        b'a' | b'x' => 0,
        b'n' | b'd' | b's' | b'p' | b'b' => decimal_prefix(rest)?.0,
        _ => return None,
    };
    Some(Limit { mode, value })
}

fn range_filter(text: &[u8]) -> Option<Range> {
    const ALWAYS: Limit = Limit {
        mode: b'a',
        value: 0,
    };
    let (from, delimiter) = if matches!(text.first(), Some(b'-' | b'<')) {
        (ALWAYS, Some(0))
    } else {
        let from = limit(text)?;
        let delimiter = if from.mode == b'x' {
            None
        } else {
            text.iter()
                .position(|&b| b == b'-')
                .or_else(|| text.iter().position(|&b| b == b'<'))
        };
        (from, delimiter)
    };
    if let Some(index) = delimiter {
        let upper = &text[index + 1..];
        let to = if upper.is_empty() {
            ALWAYS
        } else {
            limit(upper)?
        };
        Some(Range {
            from,
            to,
            upper_cutoff: text[index] == b'<',
        })
    } else {
        matches!(from.mode, b'a' | b'x').then_some(Range {
            from,
            to: from,
            upper_cutoff: false,
        })
    }
}

unsafe fn parse_into<T>(
    text: *const c_char,
    output: *mut T,
    parse: fn(&[u8]) -> Option<T>,
) -> bool {
    if text.is_null() || output.is_null() || !output.is_aligned() {
        return false;
    }
    let Some(value) = parse(unsafe { CStr::from_ptr(text) }.to_bytes()) else {
        return false;
    };
    unsafe { output.write(value) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_pf_parse(text: *const c_char, output: *mut PortFilter) -> bool {
    unsafe { parse_into(text, output, port_filter) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_icf_parse(text: *const c_char, output: *mut IcmpFilter) -> bool {
    unsafe { parse_into(text, output, icmp_filter) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipp_parse(text: *const c_char, output: *mut IpProtocolFilter) -> bool {
    unsafe { parse_into(text, output, ip_filter) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_range_parse(text: *const c_char, output: *mut Range) -> bool {
    unsafe { parse_into(text, output, range_filter) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_pf_match(port: u16, filter: *const PortFilter) -> bool {
    port != 0 && !filter.is_null() && filter.is_aligned() && unsafe { (*filter).matches(port) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_icf_match(kind: u8, code: u8, filter: *const IcmpFilter) -> bool {
    !filter.is_null() && unsafe { IcmpFilter::matches_fields(filter, kind, code) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipp_match(protocol: u8, filter: *const IpProtocolFilter) -> bool {
    !filter.is_null() && unsafe { IpProtocolFilter::matches_fields(filter, protocol) }
}

type Push<T> = unsafe extern "C" fn(*mut c_void, *const T) -> bool;

unsafe fn filter_list<T>(
    text: *const c_char,
    head: *mut c_void,
    parse: fn(&[u8]) -> Option<T>,
    push: Push<T>,
) -> bool {
    if text.is_null() {
        return true;
    }
    for part in unsafe { CStr::from_ptr(text) }
        .to_bytes()
        .split(|&byte| byte == b',')
    {
        let Some(value) = parse(part) else {
            return false;
        };
        if !unsafe { push(head, &value) } {
            return false;
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_port_list(
    text: *const c_char,
    head: *mut c_void,
    push: Push<PortFilter>,
) -> bool {
    unsafe { filter_list(text, head, port_filter, push) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_icmp_list(
    text: *const c_char,
    head: *mut c_void,
    push: Push<IcmpFilter>,
) -> bool {
    unsafe { filter_list(text, head, icmp_filter, push) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_ip_list(
    text: *const c_char,
    head: *mut c_void,
    push: Push<IpProtocolFilter>,
) -> bool {
    unsafe { filter_list(text, head, ip_filter, push) }
}

pub(crate) fn file_spec(text: &[u8]) -> Option<(u64, usize)> {
    Some(match text.first() {
        Some(b'+') => {
            let (value, _) = decimal64_prefix(&text[1..])?;
            let advance = text
                .iter()
                .position(|&byte| byte == b'@')
                .map_or(text.len(), |at| at + 1);
            (value, advance)
        }
        Some(b'@') => (0, 1),
        _ => (0, 0),
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_filespec(filename: *mut *const c_char, offset: *mut u64) -> bool {
    let pointer = unsafe { filename.read() };
    let text = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    let Some((value, advance)) = file_spec(text) else {
        return false;
    };
    unsafe {
        filename.write(pointer.add(advance));
        offset.write(value);
    }
    true
}
