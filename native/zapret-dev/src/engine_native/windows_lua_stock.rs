//! Runtime utilities exposed by the bundled rule library.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"argdebug", argdebug),
    (c"barray", barray),
    (c"btable", btable),
    (c"desync_orchestrator_example", orchestrator_example),
    (c"detect_payload_str", detect_payload_str),
    (c"hexdump_dlog", hexdump_dlog),
    (c"luaexec", luaexec),
    (c"pass", pass),
    (c"pktdebug", pktdebug),
    (c"pos_range_str", pos_range_str),
    (c"pos_str", pos_str),
    (c"posdebug", posdebug),
    (c"var_debug", var_debug),
];

pub(super) fn run_inline(
    vm: Stack,
    desync: c_int,
    parameter: &CStr,
    suffix: &[u8],
    missing: &CStr,
) -> c_int {
    if !vm.truth(vm.path(desync, &[c"arg", parameter])) {
        return vm.error(missing);
    }
    vm.field(desync, c"func_instance");
    vm.bytes(suffix);
    vm.concat(2);
    let name = vm.top();
    let globals = vm.field(GLOBALS, c"_G");
    if !vm.truth(vm.item(globals, name)) {
        let source = vm.path(desync, &[c"arg", parameter]);
        let error = vm.call_global(c"load", &[source, name], 2);
        vm.set_item(globals, name, error - 1);
        if !vm.truth(vm.item(globals, name)) {
            vm.call_global(c"error", &[error], 0);
        }
    }
    vm.bytes(b"desync");
    let key = vm.top();
    vm.set_item(globals, key, desync);
    let result = vm.call_global(c"pcall", &[vm.item(globals, name)], 2);
    vm.nil();
    vm.set_item(globals, key, vm.top());
    if !vm.truth(result - 1) {
        vm.call_global(c"error", &[result], 0);
    }
    result
}

unsafe extern "C-unwind" fn luaexec(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 31) };
    vm.pad_arguments(2);
    let result = run_inline(vm, 2, c"code", b"_code", c"luaexec: no 'code' parameter");
    if vm.truth(result) {
        vm.push(result);
    } else {
        vm.field(GLOBALS, c"VERDICT_PASS");
    }
    1
}

unsafe extern "C-unwind" fn pass(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    vm.log(b"pass", &[]);
    0
}

unsafe extern "C-unwind" fn pktdebug(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(2);
    vm.log(b"desync:", &[]);
    vm.call_global(c"var_debug", &[2], 0);
    0
}

unsafe extern "C-unwind" fn argdebug(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(2);
    vm.call_global(c"var_debug", &[vm.field(2, c"arg")], 0);
    0
}

fn append_position_group(vm: Stack, message: c_int, reverse: bool) {
    let top = vm.top();
    let modes = vm.table(0);
    for (index, mode) in [b"n", b"d", b"b", b"s", b"p"].into_iter().enumerate() {
        vm.bytes(mode);
        vm.raw_array_put(modes, index as c_int + 1, vm.top());
        vm.reset(modes);
    }
    let cursor = vm.call_global(c"pairs", &[modes], 3);
    while let Some(mode) = vm.next_pair(cursor) {
        vm.push(message);
        vm.bytes(b" ");
        vm.push(mode);
        vm.boolean(reverse);
        let direction = vm.top();
        vm.call_global(c"pos_get", &[2, mode, direction], 1);
        vm.replace(direction);
        vm.concat(4);
        vm.replace(message);
        vm.reset(cursor);
    }
    vm.reset(top);
}

unsafe extern "C-unwind" fn posdebug(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 44) };
    vm.pad_arguments(2);
    let track = vm.field(2, c"track");
    if !vm.truth(track) {
        vm.log(b"posdebug: no track", &[]);
        return 0;
    }
    let direction: &[u8] = if vm.truth(vm.field(2, c"outgoing")) {
        b"out"
    } else {
        b"in"
    };
    let delta = vm.path(track, &[c"pos", c"dt"]);
    vm.bytes(b"posdebug: ");
    vm.bytes(direction);
    vm.bytes(b" time +");
    vm.push(delta);
    vm.bytes(b"s direct");
    vm.concat(5);
    let message = vm.top();
    append_position_group(vm, message, false);
    vm.bytes(b" reverse");
    vm.concat(2);
    append_position_group(vm, message, true);
    let payload = vm.length(vm.path(2, &[c"dis", c"payload"]));
    vm.reset(message);
    vm.bytes(b" payload ");
    vm.integer(payload as isize);
    vm.concat(3);
    for (field, label) in [
        (c"reasm_data", b" reasm ".as_slice()),
        (c"decrypt_data", b" decrypt "),
    ] {
        let value = vm.field(2, field);
        let length = vm.truth(value).then(|| vm.length(value));
        vm.reset(message);
        if let Some(length) = length {
            vm.bytes(label);
            vm.integer(length as isize);
            vm.concat(3);
        }
    }
    let count = vm.field(2, c"replay_piece_count");
    if vm.truth(count) {
        let piece = vm.field(2, c"replay_piece");
        vm.push(message);
        vm.bytes(b" replay ");
        vm.push(piece);
        vm.bytes(b"/");
        vm.push(count);
        vm.concat(5);
        vm.replace(message);
    }
    vm.call_global(c"DLOG", &[message], 0);
    0
}

unsafe extern "C-unwind" fn detect_payload_str(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 23) };
    vm.pad_arguments(2);
    let pattern = vm.path(2, &[c"arg", c"pattern"]);
    if !vm.truth(pattern) {
        return vm.error(c"detect_payload_str: missing 'pattern'");
    }
    let mut data = vm.field(2, c"reasm_data");
    if !vm.truth(data) {
        data = vm.path(2, &[c"dis", c"payload"]);
    }
    let detected = if vm.truth(data) {
        vm.path(GLOBALS, &[c"string", c"find"]);
        vm.push(data);
        vm.push(pattern);
        vm.integer(1);
        vm.boolean(true);
        vm.call(4, 1);
        vm.truth(-1)
    } else {
        false
    };
    let payload = vm.path(2, &[c"arg", c"payload"]);
    if !vm.truth(payload) {
        vm.bytes(b"?");
        vm.replace(payload);
    }
    let label: &[u8] = if detected {
        b"detect_payload_str: detected '"
    } else {
        b"detect_payload_str: not detected '"
    };
    vm.log(label, &[(payload, b"'")]);
    let selected = vm.path(
        2,
        &[c"arg", if detected { c"payload" } else { c"undetected" }],
    );
    if vm.truth(selected) {
        vm.assign(2, c"l7payload", selected);
    }
    0
}

unsafe extern "C-unwind" fn orchestrator_example(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(2);
    vm.log(b"orchestrator: taking over upcoming desync instances", &[]);
    vm.call_global(c"orchestrate", &[1, 2], 0);
    vm.tail_global(c"replay_execution_plan", &[2])
}

unsafe extern "C-unwind" fn pos_range_str(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 21) };
    vm.pad_arguments(1);
    let from_mode = vm.path(1, &[c"from", c"mode"]);
    let from_pos = vm.path(1, &[c"from", c"pos"]);
    let exclusive = vm.truth(vm.field(1, c"upper_cutoff"));
    let to_mode = vm.path(1, &[c"to", c"mode"]);
    let to_pos = vm.path(1, &[c"to", c"pos"]);
    vm.push(from_mode);
    vm.push(from_pos);
    vm.bytes(if exclusive { b"<" } else { b"-" });
    vm.push(to_mode);
    vm.push(to_pos);
    vm.concat(5);
    1
}

unsafe extern "C-unwind" fn pos_str(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(2);
    let mode = vm.field(2, c"mode");
    vm.call_global(c"pos_get", &[1, vm.field(2, c"mode")], 1);
    vm.replace(mode + 1);
    vm.concat(2);
    1
}

fn pack_value(vm: Stack, packed: c_int, index: c_int, value: c_int) {
    vm.push(2);
    vm.push(value);
    vm.call(1, 1);
    vm.raw_array_put(packed, index, vm.top());
}

unsafe extern "C-unwind" fn barray(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(2);
    if !vm.truth(1) {
        return 0;
    }
    let packed = vm.table(0);
    for index in 1..=vm.length(1) {
        pack_value(vm, packed, index as c_int, vm.array_item(1, index));
        vm.reset(packed);
    }
    let top = vm.top();
    vm.table_operation(c"concat", &[packed], MULTRET) - top
}

unsafe extern "C-unwind" fn btable(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 16) };
    vm.pad_arguments(2);
    if !vm.truth(1) {
        return 0;
    }
    let packed = vm.table(0);
    let cursor = vm.call_global(c"pairs", &[1], 3);
    let mut index = 1;
    while let Some(value) = vm.next_pair(cursor) {
        pack_value(vm, packed, index, value);
        index += 1;
        vm.reset(cursor);
    }
    let top = vm.top();
    vm.table_operation(c"concat", &[packed], MULTRET) - top
}

fn indent(vm: Stack) -> c_int {
    let top = vm.top();
    vm.path(GLOBALS, &[c"string", c"rep"]);
    vm.bytes(b" ");
    vm.push_number(2.0 * vm.arithmetic_number(2));
    vm.call(2, 1);
    vm.replace(top + 1);
    top + 1
}

unsafe extern "C-unwind" fn debug_value(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 25) };
    if vm.kind(1) == TABLE {
        let cursor = vm.call_global(c"pairs", &[1], 3);
        while vm.next_pair(cursor).is_some() {
            let prefix = indent(vm);
            vm.bytes(b".");
            vm.call_global(c"tostring", &[cursor], 1);
            vm.concat(3);
            vm.call_global(c"DLOG", &[prefix], 0);
            vm.field(capture(1), c"visit");
            vm.item(1, cursor);
            vm.push_number(vm.arithmetic_number(2) + 1.0);
            vm.call(2, 0);
            vm.reset(cursor);
        }
    } else {
        let prefix = indent(vm);
        vm.call_global(c"type", &[1], 1);
        vm.bytes(b" ");
        vm.call_global(
            if vm.kind(1) == STRING {
                c"str_or_hex"
            } else {
                c"make_readable"
            },
            &[1],
            1,
        );
        vm.concat(4);
        vm.call_global(c"DLOG", &[prefix], 0);
    }
    0
}

unsafe extern "C-unwind" fn var_debug(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(1);
    // Keep the callback itself rooted in its upvalue for recursive visits.
    let root = vm.table(1);
    vm.push(root);
    vm.closure(debug_value, 1);
    vm.set(root, c"visit");
    vm.field(root, c"visit");
    vm.push(1);
    vm.integer(0);
    vm.call(2, 0);
    0
}

unsafe extern "C-unwind" fn hexdump_dlog(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(1);
    vm.tail_global(c"hexdump", &[1, vm.field(GLOBALS, c"HEXDUMP_DLOG_MAX")])
}
