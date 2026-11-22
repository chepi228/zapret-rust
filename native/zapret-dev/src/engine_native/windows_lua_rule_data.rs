//! Data lookup, copying and position normalization for the bundled rules.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"deepcopy", deepcopy),
    (c"blob_exist", blob_exist),
    (c"blob", blob),
    (c"blob_or_def", blob_or_def),
    (c"tls_mod_shim", tls_mod_shim),
    (c"zero_based_pos", zero_based_pos),
    (c"delete_pos_1", delete_pos_1),
    (c"array_search", array_search),
    (c"array_field_search", array_field_search),
    (c"genhost", genhost),
    (c"host_ip", host_ip),
    (c"host_or_ip", host_or_ip),
    (c"seq_ge", seq_ge),
    (c"seq_gt", seq_gt),
    (c"seq_lt", seq_lt),
    (c"seq_le", seq_le),
    (c"seq_within", seq_within),
];

fn copy_shell(vm: Stack, original: c_int, copies: c_int) -> (c_int, bool) {
    if vm.kind(original) != TABLE {
        return (original, false);
    }
    let known = vm.item(copies, original);
    if vm.truth(known) {
        return (known, false);
    }
    let copy = vm.table(0);
    vm.set_item(copies, original, copy);
    (copy, true)
}

fn copy_frame(vm: Stack, original: c_int, copy: c_int, parent: Option<c_int>) -> c_int {
    let frame = vm.table(10);
    vm.assign(frame, c"source", original);
    vm.assign(frame, c"result", copy);
    if let Some(parent) = parent {
        vm.assign(frame, c"parent", parent);
    }
    vm.field(GLOBALS, c"next");
    vm.set(frame, c"iterator");
    frame
}

// Frames live in Lua so a deep graph consumes neither a Rust call frame nor an
// additional Lua C call for each nested table. The copy map also handles cycles.
unsafe extern "C-unwind" fn deepcopy(lua: *mut LuaState) -> c_int {
    const COPY_VALUE: isize = 1;
    const COPY_ENTRY: isize = 2;
    const COPY_METATABLE: isize = 3;
    let vm = unsafe { Stack::enter(lua, 28) };
    vm.pad_arguments(2);
    let copies = if vm.truth(2) { 2 } else { vm.table(0) };
    let (copy, new) = copy_shell(vm, 1, copies);
    if new {
        let frame = copy_frame(vm, 1, copy, None);
        loop {
            let original = vm.field(frame, c"source");
            let result = vm.field(frame, c"result");
            let phase = vm.field(frame, c"phase");
            match vm.number(phase) as isize {
                COPY_VALUE => {
                    let value = vm.field(frame, c"value");
                    let (out, new) = copy_shell(vm, value, copies);
                    vm.assign(frame, c"copied_value", out);
                    vm.integer(COPY_ENTRY);
                    vm.set(frame, c"phase");
                    if new {
                        copy_frame(vm, value, out, Some(frame));
                        vm.replace(frame);
                    }
                }
                COPY_ENTRY => {
                    let key = vm.field(frame, c"copied_key");
                    vm.set_item(result, key, vm.field(frame, c"copied_value"));
                    vm.nil();
                    vm.set(frame, c"phase");
                }
                COPY_METATABLE => {
                    let meta = vm.field(frame, c"metatable");
                    vm.call_global(c"setmetatable", &[result, meta], 0);
                    let parent = vm.field(frame, c"parent");
                    if vm.kind(parent) == NIL {
                        break;
                    }
                    vm.replace(frame);
                }
                _ => {
                    vm.field(frame, c"iterator");
                    vm.push(original);
                    vm.field(frame, c"cursor");
                    vm.call(2, 2);
                    let value = vm.top();
                    let key = value - 1;
                    if vm.kind(key) != NIL {
                        vm.assign(frame, c"cursor", key);
                        vm.assign(frame, c"value", value);
                        let (out, new) = copy_shell(vm, key, copies);
                        vm.assign(frame, c"copied_key", out);
                        vm.integer(COPY_VALUE);
                        vm.set(frame, c"phase");
                        if new {
                            copy_frame(vm, key, out, Some(frame));
                            vm.replace(frame);
                        }
                    } else {
                        let meta = vm.call_global(c"getmetatable", &[original], 1);
                        let (out, new) = copy_shell(vm, meta, copies);
                        vm.assign(frame, c"metatable", out);
                        vm.integer(COPY_METATABLE);
                        vm.set(frame, c"phase");
                        if new {
                            copy_frame(vm, meta, out, Some(frame));
                            vm.replace(frame);
                        }
                    }
                }
            }
            vm.reset(frame);
        }
    }
    vm.push(copy);
    1
}

fn hex_prefix(vm: Stack, name: c_int) -> bool {
    vm.text_is(vm.substring(name, 1.0, Some(2.0)), b"0x")
}

unsafe extern "C-unwind" fn blob_exist(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    if !vm.truth(2) {
        vm.push(2);
    } else if hex_prefix(vm, 2) {
        vm.boolean(true);
    } else if !vm.truth(vm.item(vm.field(GLOBALS, c"_G"), 2)) {
        vm.item(1, 2);
    }
    1
}

unsafe extern "C-unwind" fn blob(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    if vm.truth(2) && vm.kind(2) != STRING {
        return call_original(vm);
    }
    vm.pad_arguments(3);
    if !vm.truth(2) || vm.length(2) == 0 {
        if !vm.truth(3) {
            return vm.error(c"empty blob name");
        }
        vm.push(3);
        return 1;
    }
    if hex_prefix(vm, 2) {
        let text = vm.substring(2, 3.0, None);
        let value = vm.call_global(c"parse_hex", &[text], 1);
        if !vm.truth(value) {
            vm.call_message(c"error", b"invalid hex string : ", &[(2, b"")]);
        }
        vm.push(value);
    } else {
        let mut value = vm.item(1, 2);
        if !vm.truth(value) {
            value = vm.item(vm.field(GLOBALS, c"_G"), 2);
            if !vm.truth(value) {
                vm.call_message(c"error", b"blob '", &[(2, b"' unavailable")]);
            }
        }
        vm.call_global(c"tostring", &[value], 1);
    }
    1
}

unsafe extern "C-unwind" fn blob_or_def(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(3);
    if vm.truth(2) && vm.truth(vm.call_global(c"blob", &[1, 2, 3], 1)) {
        return 1;
    }
    vm.push(3);
    1
}

unsafe extern "C-unwind" fn tls_mod_shim(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 24) };
    vm.pad_arguments(4);
    vm.path(GLOBALS, &[c"string", c"find"]);
    vm.push(3);
    vm.bytes(b"sni=%%[^,]+");
    vm.call(2, 2);
    let p2 = vm.top();
    let p1 = p2 - 1;
    if vm.truth(p1) {
        let p1 = vm.arithmetic_number(p1);
        let p2 = vm.arithmetic_number(p2);
        let variable = vm.substring(3, p1 + 5.0, Some(p2));
        let mut value = vm.item(1, variable);
        if !vm.truth(value) {
            value = vm.item(vm.field(GLOBALS, c"_G"), variable);
        }
        if !vm.truth(value) {
            vm.call_message(
                c"error",
                b"tls_mod_shim: non-existent var '",
                &[(variable, b"'")],
            );
        }
        vm.substring(3, 1.0, Some(p1 + 3.0));
        vm.call_global(c"tostring", &[value], 1);
        vm.substring(3, p2 + 1.0, None);
        vm.concat(3);
        vm.replace(3);
    }
    let top = vm.top();
    vm.call_global(c"tls_mod", &[2, 3, 4], MULTRET);
    vm.top() - top
}

fn iterate(vm: Stack, cursor: c_int) -> Option<c_int> {
    vm.push(cursor - 2);
    vm.push(cursor - 1);
    vm.push(cursor);
    vm.call(2, 2);
    let value = vm.top();
    if vm.kind(value - 1) == NIL {
        return None;
    }
    vm.push(value - 1);
    vm.replace(cursor);
    Some(value)
}

unsafe extern "C-unwind" fn zero_based_pos(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(1);
    if !vm.truth(1) {
        vm.nil();
        return 1;
    }
    let out = vm.table(0);
    let cursor = vm.call_global(c"ipairs", &[1], 3);
    while iterate(vm, cursor).is_some() {
        let entry = vm.item(1, cursor);
        if vm.kind(entry) == NUMBER {
            vm.push_number(vm.number(entry) - 1.0);
        } else {
            vm.push(entry);
        }
        vm.set_item(out, cursor, vm.top());
        vm.reset(cursor);
    }
    vm.push(out);
    1
}

unsafe extern "C-unwind" fn delete_pos_1(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 15) };
    vm.pad_arguments(1);
    let top = vm.top();
    let mut index = 1;
    while index <= vm.length(1) {
        let entry = vm.array_item(1, index);
        if vm.kind(entry) == NUMBER && vm.number(entry) == 1.0 {
            vm.path(GLOBALS, &[c"table", c"remove"]);
            vm.push(1);
            vm.integer(index as isize);
            vm.call(2, 0);
        } else {
            index += 1;
        }
        vm.reset(top);
    }
    vm.push(1);
    1
}

fn array_search_impl(vm: Stack, field: bool) -> c_int {
    vm.pad_arguments(if field { 3 } else { 2 });
    let cursor = vm.call_global(c"pairs", &[1], 3);
    while let Some(value) = iterate(vm, cursor) {
        let found = if field {
            vm.kind(value) == TABLE && vm.equal(vm.item(value, 2), 3)
        } else {
            vm.equal(value, 2)
        };
        if found {
            vm.push(cursor);
            return 1;
        }
        vm.reset(cursor);
    }
    0
}

unsafe extern "C-unwind" fn array_search(lua: *mut LuaState) -> c_int {
    array_search_impl(unsafe { Stack::enter(lua, 15) }, false)
}

unsafe extern "C-unwind" fn array_field_search(lua: *mut LuaState) -> c_int {
    array_search_impl(unsafe { Stack::enter(lua, 16) }, true)
}

fn random_label(vm: Stack, length: f64) {
    vm.integer(1);
    vm.call_global(c"brandom_az", &[vm.top()], 1);
    vm.replace(vm.top() - 1);
    vm.push_number(length - 1.0);
    vm.call_global(c"brandom_az09", &[vm.top()], 1);
    vm.replace(vm.top() - 1);
    vm.concat(2);
}

unsafe extern "C-unwind" fn genhost(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    if vm.kind(1) != NUMBER || (vm.truth(2) && vm.kind(2) != STRING) {
        return call_original(vm);
    }
    let len = vm.number(1);
    if vm.truth(2) && vm.length(2) > 0 {
        let width = vm.length(2) as f64;
        if len <= width {
            vm.substring(2, width - len + 1.0, None);
            return 1;
        }
        if len != width + 1.0 {
            random_label(vm, len - width - 1.0);
        }
        vm.bytes(b".");
        vm.push(2);
        vm.concat(if len == width + 1.0 { 2 } else { 3 });
    } else if len >= 7.0 {
        let domains: &[&[u8]] = &[b"com", b"org", b"net", b"edu", b"gov", b"biz"];
        vm.path(GLOBALS, &[c"math", c"random"]);
        vm.integer(domains.len() as isize);
        vm.call(1, 1);
        let index = vm.arithmetic_number(vm.top());
        let Some(domain) = domains.get((index as usize).wrapping_sub(1)) else {
            return vm.error(c"genhost: invalid domain index");
        };
        random_label(vm, len - domain.len() as f64 - 1.0);
        vm.bytes(b".");
        vm.bytes(domain);
        vm.concat(3);
    } else {
        random_label(vm, len);
    }
    1
}

unsafe extern "C-unwind" fn host_ip(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    let ip = vm.path(1, &[c"target", c"ip"]);
    if vm.truth(ip) && vm.truth(vm.call_global(c"ntop", &[ip], 1)) {
        return 1;
    }
    let ip6 = vm.path(1, &[c"target", c"ip6"]);
    if vm.truth(ip6) {
        vm.call_global(c"ntop", &[ip6], 1);
    }
    1
}

unsafe extern "C-unwind" fn host_or_ip(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    let track = vm.field(1, c"track");
    if vm.truth(track) && vm.truth(vm.field(track, c"hostname")) {
        return 1;
    }
    let top = vm.top();
    vm.call_global(c"host_ip", &[1], MULTRET);
    vm.top() - top
}

fn seq_lt_impl(vm: Stack) -> bool {
    vm.pad_arguments(2);
    vm.push_number(-vm.arithmetic_number(2));
    let delta = vm.call_global(c"u32add", &[1, vm.top()], 1);
    vm.integer(0x8000_0000);
    let sign = vm.call_global(c"bitand", &[delta, vm.top()], 1);
    vm.integer(0);
    !vm.equal(sign, -1)
}

unsafe extern "C-unwind" fn seq_ge(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.boolean(!seq_lt_impl(vm));
    1
}

unsafe extern "C-unwind" fn seq_gt(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    if vm.equal(1, 2) {
        vm.boolean(false);
    } else {
        vm.call_global(c"seq_ge", &[1, 2], 1);
    }
    1
}

unsafe extern "C-unwind" fn seq_lt(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.boolean(seq_lt_impl(vm));
    1
}

unsafe extern "C-unwind" fn seq_le(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(2);
    vm.pad_arguments(2);
    vm.boolean(vm.equal(1, 2) || seq_lt_impl(vm));
    1
}

unsafe extern "C-unwind" fn seq_within(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(3);
    if vm.truth(vm.call_global(c"seq_ge", &[1, 2], 1)) {
        vm.call_global(c"seq_le", &[1, 3], 1);
    }
    1
}
