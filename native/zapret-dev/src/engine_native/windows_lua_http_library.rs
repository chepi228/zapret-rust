//! Byte-oriented HTTP and URL utilities for the Lua-facing rule API.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"http_dissect_header", dissect_header),
    (c"http_dissect_headers", dissect_headers),
    (c"http_dissect_req", dissect_request),
    (c"http_dissect_reply", dissect_reply),
    (c"http_reconstruct_headers", reconstruct_headers),
    (c"http_reconstruct_req", reconstruct_request),
    (c"dissect_url", dissect_url),
    (c"dissect_nld", dissect_nld),
];

fn blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

unsafe extern "C-unwind" fn dissect_header(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    if vm.kind(1) != STRING {
        return call_original(vm);
    }
    let (bytes, length) = vm.text(1);
    let header = unsafe { slice::from_raw_parts(bytes, length) };
    let Some(division) = header.iter().position(|&byte| byte == b':') else {
        vm.nil();
        return 1;
    };
    let start = header[division + 1..]
        .iter()
        .position(|&byte| !blank(byte))
        .map(|offset| division + 1 + offset);
    vm.bytes(&header[..division]);
    vm.bytes(start.map_or(b"", |offset| &header[offset..]));
    vm.integer(division as isize);
    vm.integer(start.map_or(length, |offset| offset + 1) as isize);
    4
}

unsafe extern "C-unwind" fn dissect_headers(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 36) };
    vm.pad_arguments(2);
    let headers = vm.table(0);
    let mut index = 0;
    while vm.truth(2) {
        let next = vm.call_global(c"find_next_line", &[1, 2], 2);
        let eol = next - 1;
        let start = vm.arithmetic_number(2);
        let header = vm.substring(1, start, Some(vm.arithmetic_number(eol)));
        if vm.length(header) == 0 {
            vm.push(headers);
            vm.push(next);
            return 2;
        }
        let last = vm.call_global(c"http_dissect_header", &[header], 4);
        let name = last - 3;
        if vm.truth(name) {
            let values = vm.table(7);
            vm.path(GLOBALS, &[c"string", c"lower"]);
            vm.push(name);
            vm.call(1, 1);
            vm.set(values, c"header_low");
            vm.assign(values, c"header", name);
            vm.assign(values, c"value", last - 2);
            vm.assign(values, c"pos_start", 2);
            vm.assign(values, c"pos_end", eol);
            vm.push_number(start + vm.arithmetic_number(last - 1) - 1.0);
            vm.set(values, c"pos_header_end");
            vm.push_number(start + vm.arithmetic_number(last) - 1.0);
            vm.set(values, c"pos_value_start");
            index += 1;
            vm.raw_array_put(headers, index, values);
        }
        vm.push(next);
        vm.replace(2);
        vm.reset(headers);
    }
    vm.push(headers);
    vm.nil();
    2
}

fn fill_message(vm: Stack, message: c_int, begin_headers: c_int) {
    let body = vm.call_global(c"http_dissect_headers", &[1, begin_headers], 2);
    vm.assign(message, c"pos_headers_end", body);
    vm.assign(message, c"headers", body - 1);
    if vm.truth(body) {
        vm.substring(1, vm.arithmetic_number(body), None);
        vm.set(message, c"body");
    }
}

fn populate_request(vm: Stack, line: c_int, header_offset: c_int) -> c_int {
    let (bytes, length) = vm.text(line);
    let request = unsafe { slice::from_raw_parts(bytes, length) };
    let parsed = (|| {
        let method_end = request.iter().position(|&byte| blank(byte))?;
        let uri_start = method_end
            + request[method_end..]
                .iter()
                .position(|&byte| !blank(byte))?;
        let uri_end = request[uri_start..]
            .iter()
            .position(|&byte| blank(byte))
            .map_or(length, |offset| uri_start + offset);
        let version = request[uri_end..]
            .iter()
            .position(|&byte| !blank(byte))
            .map(|offset| {
                let tail = &request[uri_end + offset..];
                let end = tail
                    .iter()
                    .position(|&byte| matches!(byte, b'\r' | b'\n'))
                    .unwrap_or(tail.len());
                &tail[..end]
            });
        Some((
            &request[..method_end],
            &request[uri_start..uri_end],
            version,
        ))
    })();
    let Some((method, uri, version)) = parsed else {
        vm.nil();
        return 1;
    };
    let message = vm.table(6);
    vm.bytes(method);
    vm.set(message, c"method");
    vm.bytes(uri);
    vm.set(message, c"uri");
    if let Some(version) = version {
        vm.bytes(version);
        vm.set(message, c"http_ver");
    }
    fill_message(vm, message, header_offset);
    vm.push(message);
    1
}

unsafe extern "C-unwind" fn dissect_request(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 35) };
    if vm.truth(1) && vm.kind(1) != STRING {
        return call_original(vm);
    }
    if !vm.truth(1) {
        vm.nil();
        return 1;
    }
    vm.integer(1);
    let offset = vm.top();
    while vm.truth(offset) {
        let next = vm.call_global(c"find_next_line", &[1, offset], 2);
        let line = vm.substring(
            1,
            vm.arithmetic_number(offset),
            Some(vm.arithmetic_number(next - 1)),
        );
        if vm.length(line) > 0 {
            return populate_request(vm, line, next);
        }
        vm.push(next);
        vm.replace(offset);
        vm.reset(offset);
    }
    vm.nil();
    1
}

unsafe extern "C-unwind" fn dissect_reply(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 30) };
    if vm.truth(1) && vm.kind(1) != STRING {
        return call_original(vm);
    }
    if !vm.truth(1) {
        vm.nil();
        return 1;
    }
    let (bytes, length) = vm.text(1);
    let http = unsafe { slice::from_raw_parts(bytes, length) };
    if matches!(http.get(..8), Some(b"HTTP/1.1" | b"HTTP/1.0"))
        && let Some(count) = http.get(9..).and_then(|tail| {
            tail.iter()
                .position(|&byte| blank(byte) || matches!(byte, b'\r' | b'\n'))
        })
    {
        vm.bytes(&http[9..9 + count]);
        let code = vm.call_global(c"tonumber", &[vm.top()], 1);
        if vm.truth(code) {
            vm.integer((10 + count) as isize);
            let next = vm.call_global(c"find_next_line", &[1, vm.top()], 2);
            let message = vm.table(4);
            vm.assign(message, c"code", code);
            fill_message(vm, message, next);
            vm.push(message);
            return 1;
        }
    }
    vm.nil();
    1
}

unsafe extern "C-unwind" fn format_header(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(1);
    vm.field(1, c"header");
    vm.bytes(b": ");
    vm.field(1, c"value");
    vm.push(capture(1));
    vm.concat(4);
    1
}

fn end_of_line(vm: Stack, flag: c_int) {
    vm.bytes(if vm.truth(flag) { b"\n" } else { b"\r\n" });
}

unsafe extern "C-unwind" fn reconstruct_headers(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 9) };
    vm.pad_arguments(2);
    if vm.truth(1) {
        end_of_line(vm, 2);
        vm.closure(format_header, 1);
        if vm.truth(vm.call_global(c"barray", &[1, vm.top()], 1)) {
            return 1;
        }
    }
    vm.bytes(b"");
    1
}

unsafe extern "C-unwind" fn reconstruct_request(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    vm.pad_arguments(2);
    vm.field(1, c"method");
    vm.bytes(b" ");
    vm.field(1, c"uri");
    let version = vm.field(1, c"http_ver");
    if vm.truth(version) {
        vm.bytes(b" ");
        vm.field(1, c"http_ver");
        vm.concat(2);
        vm.replace(version);
    } else {
        vm.bytes(b"");
        vm.replace(version);
    }
    end_of_line(vm, 2);
    let headers = vm.field(1, c"headers");
    vm.call_global(c"http_reconstruct_headers", &[headers, 2], 1);
    vm.replace(headers);
    end_of_line(vm, 2);
    let body = vm.field(1, c"body");
    if !vm.truth(body) {
        vm.bytes(b"");
        vm.replace(body);
    }
    vm.concat(8);
    1
}

fn find_scheme(bytes: &[u8], offset: usize) -> Option<(usize, usize)> {
    bytes[offset..]
        .windows(3)
        .enumerate()
        .find_map(|(relative, sequence)| {
            if sequence != b"://" || relative == 0 {
                return None;
            }
            let colon = offset + relative;
            let begin = bytes[offset..colon]
                .iter()
                .rposition(|byte| !byte.is_ascii_lowercase())
                .map_or(offset, |last| offset + last + 1);
            (begin < colon).then_some((begin, colon))
        })
}

unsafe extern "C-unwind" fn dissect_url(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 11) };
    if vm.kind(1) != STRING {
        return call_original(vm);
    }
    let (bytes, length) = vm.text(1);
    let url = unsafe { slice::from_raw_parts(bytes, length) };
    let Some(begin) = url.iter().position(|&b| !blank(b)) else {
        vm.nil();
        return 1;
    };
    let mut cursor = begin;
    let scheme = find_scheme(url, begin).map(|(start, colon)| {
        cursor = colon + 3;
        &url[start..colon]
    });
    let mut credentials = None;
    if let Some(relative) = url[cursor..].iter().position(|&b| matches!(b, b'@' | b'/')) {
        let separator = cursor + relative;
        if url[separator] == b'@' {
            credentials = Some(&url[cursor..separator]);
            cursor = separator + 1;
        }
    }
    let separator = url[cursor..]
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .map(|i| cursor + i);
    let (authority, uri) = match separator {
        Some(i) if i != begin => (Some(&url[cursor..i]), Some(&url[i..])),
        Some(_) => (None, Some(&url[begin..])),
        None if scheme.is_some() => (Some(&url[cursor..]), None),
        None => (None, Some(&url[cursor..])),
    };
    let (domain, port) = if let Some(authority) = authority
        && let Some(colon) = authority.iter().position(|&byte| byte == b':')
    {
        (Some(&authority[..colon]), Some(&authority[colon + 1..]))
    } else {
        (authority, None)
    };
    let result = vm.table(5);
    for (field, value) in [
        (c"proto", scheme),
        (c"creds", credentials),
        (c"domain", domain),
        (c"port", port),
        (c"uri", uri),
    ] {
        if let Some(value) = value {
            vm.bytes(value);
            vm.set(result, field);
        }
    }
    1
}

unsafe extern "C-unwind" fn dissect_nld(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    if vm.truth(1) && vm.kind(1) != STRING {
        return call_original(vm);
    }
    if vm.kind(1) == STRING && vm.kind(2) == NUMBER {
        let (bytes, length) = vm.text(1);
        let domain = unsafe { slice::from_raw_parts(bytes, length) };
        let level = vm.number(2);
        let mut labels = 1;
        for (index, &byte) in domain.iter().enumerate().rev() {
            if byte != b'.' {
                continue;
            }
            if labels as f64 == level {
                vm.bytes(&domain[index + 1..]);
                return 1;
            }
            labels += 1;
        }
        if labels as f64 == level {
            vm.push(1);
            return 1;
        }
    }
    vm.nil();
    1
}
