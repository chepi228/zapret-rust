//! Binary strings and local path helpers for the bundled Lua library.
use super::call_original as original;
use super::*;

fn push_text(vm: Stack, data: *const u8, size: usize) {
    unsafe { lua_pushlstring(vm.0, data, size) };
}

fn printable(byte: u8) -> bool {
    (b' '..=127).contains(&byte)
}

unsafe extern "C-unwind" fn string2hex(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING {
        return original(vm);
    }
    let (input, size) = vm.text(1);
    if size == 0 {
        vm.bytes(b"");
        return 1;
    }
    let Some(length) = size.checked_mul(3).and_then(|n| n.checked_sub(1)) else {
        return vm.error(c"hex string too long");
    };
    let result = vm.buffer(length);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    unsafe {
        for (i, &byte) in slice::from_raw_parts(input, size).iter().enumerate() {
            let out = result.add(i * 3);
            if i > 0 {
                out.sub(1).write(b' ');
            }
            out.write(HEX[(byte >> 4) as usize]);
            out.add(1).write(HEX[(byte & 15) as usize]);
        }
    }
    push_text(vm, result, length);
    1
}

unsafe extern "C-unwind" fn has_nonprintable(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING {
        return original(vm);
    }
    let (input, size) = vm.text(1);
    let first = unsafe { slice::from_raw_parts(input, size) }
        .iter()
        .copied()
        .find(|&byte| !printable(byte) && !matches!(byte, b'\r' | b'\n' | b'\t'));
    if let Some(byte) = first {
        vm.bytes(&[byte]);
    } else {
        vm.nil();
    }
    1
}

unsafe extern "C-unwind" fn make_readable(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING {
        return original(vm);
    }
    let (input, size) = vm.text(1);
    let input = unsafe { slice::from_raw_parts(input, size) };
    let count = input.iter().filter(|&&byte| !printable(byte)).count();
    if count == 0 {
        vm.push(1);
    } else {
        let result = vm.buffer(size);
        for (i, &byte) in input.iter().enumerate() {
            unsafe {
                result
                    .add(i)
                    .write(if printable(byte) { byte } else { b'.' })
            };
        }
        push_text(vm, result, size);
    }
    vm.integer(count as isize);
    2
}

unsafe extern "C-unwind" fn str_or_hex(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    let base = vm.top();
    if base == 0 {
        return original(vm);
    }
    vm.field(GLOBALS, c"has_nonprintable");
    vm.push(1);
    vm.call(1, 1);
    let matched = vm.truth(-1);
    vm.reset(base);
    if matched {
        vm.field(GLOBALS, c"string2hex");
        vm.push(1);
        vm.call(1, MULTRET);
        vm.top() - base
    } else {
        vm.push(1);
        1
    }
}

unsafe extern "C-unwind" fn hexdump(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    if !vm.truth(1) {
        vm.nil();
        return 1;
    }
    if vm.kind(1) != STRING || vm.kind(2) != NUMBER || vm.number(2) < 0.0 {
        return original(vm);
    }
    let (data, size) = vm.text(1);
    let maximum = vm.number(2);
    let truncated = size as f64 > maximum;
    let length = if truncated { maximum as usize } else { size };
    vm.field(GLOBALS, c"string2hex");
    push_text(vm, data, length);
    vm.call(1, 1);
    vm.bytes(if truncated { b" ... " } else { b"  " });
    vm.field(GLOBALS, c"make_readable");
    push_text(vm, data, length);
    vm.call(1, 1);
    vm.bytes(if truncated { b" ... " } else { b"" });
    vm.concat(4);
    1
}

unsafe extern "C-unwind" fn logical_xor(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 1) };
    if vm.truth(1) {
        vm.boolean(!vm.truth(2));
    } else {
        vm.push(2);
    }
    1
}

unsafe extern "C-unwind" fn in_list(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING {
        return original(vm);
    }
    let found = if vm.kind(2) == STRING {
        let (items, size) = vm.text(1);
        let (value, length) = vm.text(2);
        let items = unsafe { slice::from_raw_parts(items, size) };
        let value = unsafe { slice::from_raw_parts(value, length) };
        !value.is_empty() && items.split(|&byte| byte == b',').any(|item| item == value)
    } else {
        false
    };
    vm.boolean(found);
    1
}

unsafe extern "C-unwind" fn pattern(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING || vm.kind(2) != NUMBER || vm.kind(3) != NUMBER {
        return original(vm);
    }
    let (data, size) = vm.text(1);
    let offset = vm.number(2);
    let length = vm.number(3);
    let begin = offset as i32;
    let count = length as i32;
    if size == 0
        || begin == i32::MIN
        || offset != f64::from(begin)
        || length != f64::from(count)
        || count < 0
    {
        return original(vm);
    }
    let mut pos = (i64::from(begin) - 1).rem_euclid(size as i64) as usize;
    let count = count as usize;
    let result = vm.buffer(count);
    for i in 0..count {
        unsafe { result.add(i).write(data.add(pos).read()) };
        pos += 1;
        if pos == size {
            pos = 0;
        }
    }
    push_text(vm, result, count);
    1
}

unsafe extern "C-unwind" fn find_next_line(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != STRING || (vm.kind(2) > NIL && vm.kind(2) != NUMBER) {
        return original(vm);
    }
    let (data, size) = vm.text(1);
    let position = vm.number(2);
    if !position.is_finite() || position < f64::from(i32::MIN) || position > f64::from(i32::MAX) {
        return original(vm);
    }
    let pos = position as isize;
    let start = if pos < 0 {
        size.saturating_sub(pos.unsigned_abs())
    } else {
        pos.saturating_sub(1).max(0) as usize
    };
    let input = unsafe { slice::from_raw_parts(data, size) };
    let end = input
        .get(start..)
        .and_then(|rest| rest.iter().position(|&byte| matches!(byte, b'\r' | b'\n')))
        .map(|index| index + start);
    vm.integer(end.unwrap_or(size) as isize);
    if let Some(end) = end {
        let mut next = end + 1;
        if input[end] == b'\r' && input.get(next) == Some(&b'\n') {
            next += 1;
        }
        if next < size {
            vm.integer((next + 1) as isize);
            return 2;
        }
    }
    vm.nil();
    2
}

unsafe extern "C-unwind" fn append_path(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 5) };
    if vm.kind(1) != STRING || vm.kind(2) != STRING {
        return original(vm);
    }
    let (path, size) = vm.text(1);
    let slash = size > 0 && unsafe { path.add(size - 1).read() == b'/' };
    vm.push(1);
    if !slash {
        vm.bytes(b"/");
    }
    vm.push(2);
    vm.concat(if slash { 2 } else { 3 });
    1
}

unsafe extern "C-unwind" fn writable_file_name(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    if vm.top() == 0 {
        return original(vm);
    }
    vm.field(GLOBALS, c"is_absolute_path");
    vm.push(1);
    vm.call(1, 1);
    if vm.truth(-1) {
        vm.push(1);
        return 1;
    }
    let os = vm.field(GLOBALS, c"os");
    vm.field(os, c"getenv");
    vm.bytes(b"WRITABLE");
    vm.call(1, 1);
    let dir = vm.top();
    if !vm.truth(dir) {
        vm.push(1);
        return 1;
    }
    vm.field(GLOBALS, c"append_path");
    vm.push(dir);
    vm.push(1);
    vm.call(2, MULTRET);
    vm.top() - dir
}

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    let entries: &[(&CStr, Callback)] = &[
        (c"string2hex", string2hex),
        (c"has_nonprintable", has_nonprintable),
        (c"make_readable", make_readable),
        (c"str_or_hex", str_or_hex),
        (c"hexdump", hexdump),
        (c"logical_xor", logical_xor),
        (c"in_list", in_list),
        (c"pattern", pattern),
        (c"find_next_line", find_next_line),
        (c"append_path", append_path),
        (c"writable_file_name", writable_file_name),
    ];
    let table = vm.table(
        (entries.len()
            + windows_lua_library_files::ENTRIES.len()
            + windows_lua_rule_data::ENTRIES.len()
            + windows_lua_http_library::ENTRIES.len()
            + windows_lua_stock::ENTRIES.len()) as c_int,
    );
    bind_entries(vm, table, entries, &[]);
    bind_entries(vm, table, windows_lua_library_files::ENTRIES, &[]);
    bind_entries(vm, table, windows_lua_rule_data::ENTRIES, &[]);
    bind_entries(vm, table, windows_lua_http_library::ENTRIES, &[]);
    bind_entries(vm, table, windows_lua_stock::ENTRIES, &[]);
    1
}
