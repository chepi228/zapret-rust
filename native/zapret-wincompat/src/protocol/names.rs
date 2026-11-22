use std::{
    ffi::{CStr, c_char},
    ptr, slice,
};

const PROTOCOLS: [&CStr; 16] = [
    c"all",
    c"unknown",
    c"known",
    c"http",
    c"tls",
    c"dtls",
    c"quic",
    c"wireguard",
    c"dht",
    c"discord",
    c"stun",
    c"xmpp",
    c"dns",
    c"mtproto",
    c"bt",
    c"utp_bt",
];
const PAYLOADS: [&CStr; 31] = [
    c"all",
    c"unknown",
    c"empty",
    c"known",
    c"ipv4",
    c"ipv6",
    c"icmp",
    c"http_req",
    c"http_reply",
    c"tls_client_hello",
    c"tls_server_hello",
    c"dtls_client_hello",
    c"dtls_server_hello",
    c"quic_initial",
    c"wireguard_initiation",
    c"wireguard_response",
    c"wireguard_cookie",
    c"wireguard_keepalive",
    c"wireguard_data",
    c"dht",
    c"discord_ip_discovery",
    c"stun",
    c"xmpp_stream",
    c"xmpp_starttls",
    c"xmpp_proceed",
    c"xmpp_features",
    c"dns_query",
    c"dns_response",
    c"mtproto_initial",
    c"bt_handshake",
    c"utp_bt_handshake",
];
pub(super) const MARKERS: [&CStr; 9] = [
    c"abs", c"host", c"endhost", c"sld", c"midsld", c"endsld", c"method", c"extlen", c"sniext",
];

fn name(names: &[&CStr], index: u32) -> *const c_char {
    names
        .get(index as usize)
        .map_or(ptr::null(), |name| name.as_ptr())
}

pub(super) fn index(names: &[&CStr], value: &[u8]) -> u32 {
    names
        .iter()
        .position(|name| name.to_bytes() == value)
        .unwrap_or(names.len()) as u32
}

#[cfg(windows)]
pub(super) fn payload_index(value: &CStr) -> Option<u32> {
    let id = index(&PAYLOADS, value.to_bytes());
    (id < PAYLOADS.len() as u32).then_some(id)
}

unsafe fn parse_mask(names: &[&CStr], text: *const c_char, out: *mut u64) -> bool {
    let mut mask = 0u64;
    if !text.is_null() {
        for part in unsafe { CStr::from_ptr(text) }
            .to_bytes()
            .split(|&byte| byte == b',')
        {
            let id = index(names, part);
            if id == 0 {
                mask = 0;
                break;
            }
            if id as usize == names.len() {
                return false;
            }
            mask |= 1u64 << id;
        }
    }
    unsafe { out.write(mask) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_l7_list(text: *const c_char, out: *mut u64) -> bool {
    unsafe { parse_mask(&PROTOCOLS, text, out) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_parse_payload_list(text: *const c_char, out: *mut u64) -> bool {
    unsafe { parse_mask(&PAYLOADS, text, out) }
}

fn matches(value: u32, filter: u64, known: u32, last: usize) -> bool {
    filter == 0
        || filter & 1u64.checked_shl(value).unwrap_or(0) != 0
        || filter & (1u64 << known) != 0 && value > known && (value as usize) < last
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn l7proto_str(value: u32) -> *const c_char {
    name(&PROTOCOLS, value)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn l7proto_from_name(value: *const c_char) -> u32 {
    index(&PROTOCOLS, unsafe { CStr::from_ptr(value) }.to_bytes())
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn l7_proto_match(value: u32, filter: u64) -> bool {
    matches(value, filter, 2, PROTOCOLS.len())
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn l7payload_str(value: u32) -> *const c_char {
    name(&PAYLOADS, value)
}

// Borrowed payload labels for execution-plan table construction between calls.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_plan_payload_next(mask: u64, cursor: *mut u32) -> *const c_char {
    if cursor.is_null() || !cursor.is_aligned() {
        return ptr::null();
    }
    let next = unsafe { &mut *cursor };
    if mask == 0 {
        if *next == 0 {
            *next = PAYLOADS.len() as u32;
            return PAYLOADS[0].as_ptr();
        }
        return ptr::null();
    }
    while (*next as usize) < PAYLOADS.len() {
        let index = *next;
        *next += 1;
        if mask & (1u64 << index) != 0 {
            return PAYLOADS[index as usize].as_ptr();
        }
    }
    ptr::null()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn l7payload_from_name(value: *const c_char) -> u32 {
    index(&PAYLOADS, unsafe { CStr::from_ptr(value) }.to_bytes())
}

#[unsafe(no_mangle)]
pub(crate) extern "C" fn l7_payload_match(value: u32, filter: u64) -> bool {
    matches(value, filter, 3, PAYLOADS.len())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn l7_payload_str_list(
    filter: u64,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    if capacity == 0 {
        return false;
    }
    let buffer = unsafe { slice::from_raw_parts_mut(output.cast::<u8>(), capacity) };
    if filter == 0 {
        if capacity < 4 {
            return false;
        }
        buffer[..4].copy_from_slice(b"all\0");
        return true;
    }
    buffer[0] = 0;
    let mut length = 0;
    for (index, name) in PAYLOADS.iter().enumerate() {
        if filter & (1u64 << index) == 0 {
            continue;
        }
        let separator = usize::from(length != 0);
        let end = length + separator + name.to_bytes().len();
        if end >= capacity {
            return false;
        }
        if separator != 0 {
            buffer[length] = b',';
        }
        buffer[length + separator..=end].copy_from_slice(name.to_bytes_with_nul());
        length = end;
    }
    true
}

#[unsafe(no_mangle)]
extern "C" fn posmarker_name(value: u32) -> *const c_char {
    name(&MARKERS, value)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn posmarker_from_name(value: *const c_char) -> u32 {
    index(&MARKERS, unsafe { CStr::from_ptr(value) }.to_bytes())
}
