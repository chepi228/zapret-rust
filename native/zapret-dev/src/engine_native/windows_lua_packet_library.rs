//! Shared packet preparation and replay helpers for Lua rules.
use super::*;

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != FUNCTION {
        return vm.error(c"packet helpers require a Lua comparison callback");
    }
    let entries: &[(&CStr, Callback)] = &[
        (c"pos_counter_overflow", pos_counter_overflow),
        (c"pos_get_pos", pos_get_pos),
        (c"pos_get", pos_get),
        (c"pos_check_from", pos_check_from),
        (c"pos_check_to", pos_check_to),
        (c"pos_check_range", pos_check_range),
        (c"is_retransmission", is_retransmission),
        (c"rawsend_opts", rawsend_opts),
        (c"rawsend_opts_base", rawsend_opts_base),
        (c"reconstruct_opts", reconstruct_opts),
        (c"desync_opts", desync_opts),
        (c"direction_check", direction_check),
        (c"direction_cutoff_opposite", direction_cutoff_opposite),
        (c"payload_match_filter", payload_match_filter),
        (c"payload_check", payload_check),
        (c"replay_first", replay_first),
        (c"replay_drop_key", replay_drop_key),
        (c"replay_drop_set", replay_drop_set),
        (c"replay_drop", replay_drop),
        (c"rawsend_dissect_ipfrag", rawsend_dissect_ipfrag),
        (c"rawsend_dissect_segmented", rawsend_dissect_segmented),
        (c"rawsend_payload_segmented", rawsend_payload_segmented),
        (c"apply_ip_id", apply_ip_id),
    ];
    let table = vm.table(
        (entries.len()
            + windows_lua_header_policy::ENTRIES.len()
            + windows_lua_ip_frag::ENTRIES.len()
            + windows_lua_ip_helpers::ENTRIES.len()
            + windows_lua_tls_library::ENTRIES.len()) as c_int,
    );
    bind_entries(vm, table, entries, &[1]);
    bind_entries(vm, table, windows_lua_header_policy::ENTRIES, &[1]);
    bind_entries(vm, table, windows_lua_ip_frag::ENTRIES, &[1]);
    bind_entries(vm, table, windows_lua_ip_helpers::ENTRIES, &[1]);
    bind_entries(vm, table, windows_lua_tls_library::ENTRIES, &[1]);
    1
}

fn dissection(vm: Stack, value: c_int) -> c_int {
    if vm.truth(value) {
        value
    } else {
        vm.field(1, c"dis")
    }
}

fn optional_field(vm: Stack, table: c_int, key: &CStr) -> c_int {
    if vm.truth(table) {
        vm.field(table, key)
    } else {
        table
    }
}

fn tracking_position(vm: Stack, track: c_int, reverse: bool) -> c_int {
    let pos = vm.field(track, c"pos");
    if reverse {
        let reversed = vm.field(pos, c"reverse");
        if vm.truth(reversed) {
            return reversed;
        }
    }
    vm.field(pos, c"direct")
}

unsafe extern "C-unwind" fn pos_counter_overflow(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(3);
    let track = vm.field(1, c"track");
    if vm.truth(track) && (vm.text_is(2, b"s") || vm.text_is(2, b"p")) {
        let pos = tracking_position(vm, track, vm.truth(3));
        let tcp = vm.field(pos, c"tcp");
        let overflow = optional_field(vm, tcp, c"rseq_over_2G");
        vm.push(overflow);
    } else {
        vm.boolean(false);
    }
    1
}

unsafe extern "C-unwind" fn pos_get_pos(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(2);
    if vm.truth(1) {
        for (mode, field) in [
            (b"n", c"pcounter"),
            (b"d", c"pdcounter"),
            (b"b", c"pbcounter"),
        ] {
            if vm.text_is(2, mode) {
                vm.field(1, field);
                return 1;
            }
        }
        let tcp = vm.field(1, c"tcp");
        if vm.truth(tcp) {
            if vm.text_is(2, b"s") {
                vm.field(tcp, c"rseq");
                return 1;
            }
            if vm.text_is(2, b"p") {
                vm.field(tcp, c"pos");
                return 1;
            }
        }
    }
    vm.integer(0);
    1
}

unsafe extern "C-unwind" fn pos_get(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(3);
    let track = vm.field(1, c"track");
    if vm.truth(track) {
        let position = tracking_position(vm, track, vm.truth(3));
        let top = vm.top();
        vm.call_global(c"pos_get_pos", &[position, 2], MULTRET);
        return vm.top() - top;
    }
    vm.integer(0);
    1
}

fn check_boundary(vm: Stack, boundary: &CStr, upper: bool) -> c_int {
    let bound = vm.field(2, boundary);
    let mode = vm.field(bound, c"mode");
    let allowed = if vm.text_is(mode, b"x")
        || vm.truth(vm.call_global(c"pos_counter_overflow", &[1, mode], 1))
    {
        false
    } else if vm.text_is(mode, b"a") {
        true
    } else if vm.truth(vm.field(1, c"track")) {
        let measured = vm.call_global(c"pos_get", &[1, vm.field(bound, c"mode")], 1);
        let limit = vm.field(bound, c"pos");
        if upper {
            vm.less(measured, limit)
                || (!vm.truth(vm.field(2, c"upper_cutoff")) && vm.equal(measured, limit))
        } else {
            vm.less_equal(limit, measured)
        }
    } else {
        false
    };
    vm.boolean(allowed);
    1
}

unsafe extern "C-unwind" fn pos_check_from(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 28) };
    vm.pad_arguments(2);
    check_boundary(vm, c"from", false)
}

unsafe extern "C-unwind" fn pos_check_to(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 28) };
    vm.pad_arguments(2);
    check_boundary(vm, c"to", true)
}

unsafe extern "C-unwind" fn pos_check_range(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    let lower = vm.call_global(c"pos_check_from", &[1, 2], 1);
    if vm.truth(lower) {
        vm.call_global(c"pos_check_to", &[1, 2], 1);
    }
    1
}

unsafe extern "C-unwind" fn is_retransmission(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    let track = vm.field(1, c"track");
    if vm.truth(track) {
        let tcp = vm.path(track, &[c"pos", c"direct", c"tcp"]);
        if vm.truth(tcp) {
            vm.call_global(
                c"seq_ge",
                &[vm.field(tcp, c"uppos_prev"), vm.field(tcp, c"pos")],
                1,
            );
        }
    }
    1
}

fn raw_options(vm: Stack, repeats: bool) -> c_int {
    vm.pad_arguments(1);
    let result = vm.table(if repeats { 3 } else { 2 });
    if repeats {
        vm.path(1, &[c"arg", c"repeats"]);
        vm.set(result, c"repeats");
        vm.reset(result);
    }
    for key in [c"ifout", c"fwmark"] {
        let override_value = vm.path(1, &[c"arg", key]);
        if vm.truth(override_value) {
            vm.push(override_value)
        } else {
            vm.field(1, key);
        }
        vm.set(result, key);
        vm.reset(result);
    }
    1
}

unsafe extern "C-unwind" fn rawsend_opts(lua: *mut LuaState) -> c_int {
    raw_options(unsafe { Stack::enter(lua, 12) }, true)
}

unsafe extern "C-unwind" fn rawsend_opts_base(lua: *mut LuaState) -> c_int {
    raw_options(unsafe { Stack::enter(lua, 12) }, false)
}

unsafe extern "C-unwind" fn reconstruct_opts(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(1);
    let out = vm.table(1);
    vm.path(1, &[c"arg", c"badsum"]);
    vm.set(out, c"badsum");
    vm.reset(out);
    1
}

unsafe extern "C-unwind" fn desync_opts(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    let out = vm.table(5);
    vm.call_global(c"rawsend_opts", &[1], 1);
    vm.set(out, c"rawsend");
    vm.call_global(c"reconstruct_opts", &[1], 1);
    vm.set(out, c"reconstruct");
    for name in [c"ipfrag", c"ipid", c"fooling"] {
        vm.field(1, c"arg");
        vm.set(out, name);
    }
    1
}

fn default_arg(vm: Stack, desync: c_int, key: &CStr, fallback: c_int, default: &[u8]) -> c_int {
    let value = vm.path(desync, &[c"arg", key]);
    if vm.truth(value) {
        value
    } else if vm.truth(fallback) {
        fallback
    } else {
        vm.bytes(default);
        vm.top()
    }
}

unsafe extern "C-unwind" fn direction_check(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    let direction = default_arg(vm, 1, c"dir", 2, b"out");
    let outgoing = vm.truth(vm.field(1, c"outgoing"));
    let forbidden: &[u8] = if outgoing { b"in" } else { b"out" };
    vm.boolean(!vm.text_is(direction, forbidden));
    1
}

unsafe extern "C-unwind" fn direction_cutoff_opposite(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(3);
    let direction = default_arg(vm, 2, c"dir", 3, b"out");
    let inbound = vm.text_is(direction, b"in");
    if inbound || vm.text_is(direction, b"out") {
        vm.boolean(inbound);
        vm.call_global(c"instance_cutoff_shim", &[1, 2, vm.top()], 0);
    }
    0
}

unsafe extern "C-unwind" fn payload_match_filter(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(3);
    let filter = if vm.truth(2) {
        2
    } else if vm.truth(3) {
        3
    } else {
        vm.bytes(b"known");
        vm.top()
    };
    let negate = vm.text_is(vm.substring(filter, 1.0, Some(1.0)), b"~");
    let filter = if negate {
        vm.substring(filter, 2.0, None)
    } else {
        filter
    };
    vm.bytes(b"all");
    let mut applied = vm.call_global(c"in_list", &[filter, vm.top()], 1);
    if !vm.truth(applied) {
        applied = vm.call_global(c"in_list", &[filter, 1], 1);
        if !vm.truth(applied) {
            vm.bytes(b"known");
            applied = vm.call_global(c"in_list", &[filter, vm.top()], 1);
            if vm.truth(applied) {
                vm.boolean(!vm.text_is(1, b"unknown") && !vm.text_is(1, b"empty"));
                applied = vm.top();
            }
        }
    }
    vm.boolean(negate);
    vm.boolean(!vm.equal(applied, -1));
    1
}

unsafe extern "C-unwind" fn payload_check(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 24) };
    vm.pad_arguments(2);
    let payload = vm.field(1, c"l7payload");
    let requested = vm.path(1, &[c"arg", c"payload"]);
    let pass = vm.call_global(c"payload_match_filter", &[payload, requested, 2], 1);
    if !vm.truth(pass) && vm.truth(vm.field(GLOBALS, c"b_debug")) {
        let filter = default_arg(vm, 1, c"payload", 2, b"known");
        vm.log(
            b"payload_check: payload '",
            &[
                (vm.field(1, c"l7payload"), b"' does not pass '"),
                (filter, b"' filter"),
            ],
        );
    }
    vm.push(pass);
    1
}

unsafe extern "C-unwind" fn replay_first(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    vm.pad_arguments(1);
    if !vm.truth(vm.field(1, c"replay")) {
        vm.boolean(true);
    } else {
        let part = vm.field(1, c"replay_piece");
        vm.integer(1);
        vm.boolean(vm.equal(part, -1));
    }
    1
}

unsafe extern "C-unwind" fn replay_drop_key(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 6) };
    vm.pad_arguments(1);
    vm.field(1, c"func_instance");
    vm.bytes(b"_replay_drop");
    vm.concat(2);
    1
}

unsafe extern "C-unwind" fn replay_drop_set(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(2);
    if vm.truth(vm.field(1, c"track")) {
        let key = vm.call_global(c"replay_drop_key", &[1], 1);
        let enabled = vm.kind(2) == NIL || vm.truth(2);
        if !enabled || vm.truth(vm.field(1, c"replay")) {
            let state = vm.path(1, &[c"track", c"lua_state"]);
            if enabled {
                vm.boolean(true)
            } else {
                vm.nil()
            }
            vm.set_item(state, key, vm.top());
        }
    }
    0
}

unsafe extern "C-unwind" fn replay_drop(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(1);
    if vm.truth(vm.field(1, c"track")) {
        let replay = vm.field(1, c"replay");
        let drop = if vm.truth(replay) {
            let state = vm.path(1, &[c"track", c"lua_state"]);
            vm.item(state, vm.call_global(c"replay_drop_key", &[1], 1))
        } else {
            replay
        };
        if !vm.truth(vm.field(1, c"replay")) || vm.truth(vm.field(1, c"replay_piece_last")) {
            vm.boolean(false);
            vm.call_global(c"replay_drop_set", &[1, vm.top()], 0);
        }
        if vm.truth(drop) {
            vm.log(
                b"dropping replay packet because reasm was already sent",
                &[],
            );
            vm.boolean(true);
            return 1;
        }
    }
    vm.boolean(false);
    1
}

fn send_fragment(vm: Stack, ip: c_int, fragment: c_int, options: c_int) -> bool {
    vm.log(b"sending ip fragment ", &[(ip, b"")]);
    let raw = vm.field(2, c"rawsend");
    vm.truth(vm.call_global(c"rawsend_dissect", &[fragment, raw, options], 1))
}

fn send_fragments(vm: Stack, table: c_int, options: c_int, reverse: bool) -> bool {
    if reverse {
        let top = vm.top();
        for index in (1..=vm.length(table)).rev() {
            vm.integer(index as isize);
            let ip = vm.top();
            let fragment = vm.item(table, ip);
            if !send_fragment(vm, ip, fragment, options) {
                return false;
            }
            vm.reset(top);
        }
    } else {
        vm.call_global(c"ipairs", &[table], 3);
        let key = vm.top();
        loop {
            vm.push(key - 2);
            vm.push(key - 1);
            vm.push(key);
            vm.call(2, 2);
            if vm.kind(key + 1) == NIL {
                break;
            }
            vm.push(key + 1);
            vm.replace(key);
            if !send_fragment(vm, key, key + 2, options) {
                return false;
            }
            vm.reset(key);
        }
    }
    true
}

unsafe extern "C-unwind" fn rawsend_dissect_ipfrag(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 39) };
    vm.pad_arguments(2);
    let options = optional_field(vm, 2, c"ipfrag");
    let name = optional_field(vm, options, c"ipfrag");
    if vm.truth(name) && !vm.truth(vm.field(1, c"frag")) {
        if vm.text_is(name, b"") {
            vm.bytes(b"ipfrag2");
            vm.replace(name);
        }
        let globals = vm.field(GLOBALS, c"_G");
        if vm.kind(vm.item(globals, name)) != FUNCTION {
            let repr = vm.call_global(c"tostring", &[name], 1);
            vm.call_message(
                c"error",
                b"rawsend_dissect_ipfrag: ipfrag function '",
                &[(repr, b"' does not exist")],
            );
        }
        vm.item(globals, name);
        vm.push(1);
        vm.push(options);
        vm.call(2, 1);
        let fragments = vm.top();
        let mut reconstruct = vm.field(2, c"reconstruct");
        if vm.truth(reconstruct) {
            reconstruct = vm.call_global(c"deepcopy", &[reconstruct], 1);
        }
        if !vm.truth(reconstruct) {
            reconstruct = vm.table(1);
        }
        vm.boolean(true);
        vm.set(reconstruct, c"ip6_preserve_next");
        if vm.truth(fragments) {
            let reverse = vm.truth(vm.path(2, &[c"ipfrag", c"ipfrag_disorder"]));
            vm.boolean(send_fragments(vm, fragments, reconstruct, reverse));
            return 1;
        }
    }
    let raw = optional_field(vm, 2, c"rawsend");
    let reconstruct = optional_field(vm, 2, c"reconstruct");
    let top = vm.top();
    vm.call_global(c"rawsend_dissect", &[1, raw, reconstruct], MULTRET);
    vm.top() - top
}

fn set_urgent(vm: Stack, copy: c_int, size: f64, position: f64, pointer: f64) {
    let tcp = vm.field(copy, c"tcp");
    let flags = vm.field(tcp, c"th_flags");
    let urgent = vm.field(GLOBALS, c"TH_URG");
    let zero = pointer == 0.0 && position == 1.0;
    let in_segment = pointer >= position && pointer < position + size;
    let mask = if zero || in_segment {
        vm.call_global(c"bitor", &[flags, urgent], 1)
    } else {
        let invert = vm.call_global(c"bitnot", &[urgent], 1);
        vm.call_global(c"bitand", &[flags, invert], 1)
    };
    vm.assign(tcp, c"th_flags", mask);
    if !zero {
        vm.push_number(if in_segment {
            pointer - position + 1.0
        } else {
            0.0
        });
        vm.set(tcp, c"th_urp");
    }
}

fn send_segments(
    vm: Stack,
    copy: c_int,
    tcp: c_int,
    maximum: f64,
    payload: c_int,
    options: c_int,
) -> bool {
    let urgent_pointer = vm.field(tcp, c"th_urp");
    let urgent = vm.call_global(
        c"bitand",
        &[vm.field(tcp, c"th_flags"), vm.field(GLOBALS, c"TH_URG")],
        1,
    );
    vm.integer(0);
    let urgent = !vm.equal(urgent, -1);
    let top = vm.top();
    let mut position = 1.0;
    let length = vm.length(payload) as f64;
    while position <= length {
        let remaining = length - position + 1.0;
        let size = if remaining > maximum {
            maximum
        } else {
            remaining
        };
        if urgent {
            set_urgent(
                vm,
                copy,
                size,
                position,
                vm.arithmetic_number(urgent_pointer),
            );
        }
        vm.substring(payload, position, Some(position + size - 1.0));
        vm.set(copy, c"payload");
        vm.call_global(
            c"apply_ip_id",
            &[1, copy, optional_field(vm, options, c"ipid")],
            0,
        );
        if !vm.truth(vm.call_global(c"rawsend_dissect_ipfrag", &[copy, options], 1)) {
            return false;
        }
        let tcp = vm.field(copy, c"tcp");
        let seq = vm.field(tcp, c"th_seq");
        vm.push_number(size);
        vm.call_global(c"u32add", &[seq, vm.top()], 1);
        vm.set(tcp, c"th_seq");
        position += size;
        vm.reset(top);
    }
    true
}

unsafe extern "C-unwind" fn rawsend_dissect_segmented(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 60) };
    vm.pad_arguments(4);
    let dis = dissection(vm, 2);
    let copy = vm.call_global(c"deepcopy", &[dis], 1);
    let options = if vm.truth(4) {
        4
    } else {
        vm.call_global(c"desync_opts", &[1], 1)
    };
    vm.call_global(
        c"apply_fooling",
        &[1, copy, optional_field(vm, options, c"fooling")],
        0,
    );
    let tcp = vm.field(dis, c"tcp");
    if vm.truth(tcp) {
        let mss = if vm.truth(3) {
            3
        } else {
            vm.field(1, c"tcp_mss")
        };
        let extra = vm.call_global(c"l3l4_extra_len", &[copy], 1);
        if vm.less_equal(mss, extra) {
            vm.boolean(false);
            return 1;
        }
        let maximum = vm.arithmetic_number(mss) - vm.arithmetic_number(extra);
        let payload = vm.field(copy, c"payload");
        if vm.length(payload) as f64 > maximum {
            let payload = vm.field(copy, c"payload");
            vm.boolean(send_segments(vm, copy, tcp, maximum, payload, options));
            return 1;
        }
    }
    vm.call_global(
        c"apply_ip_id",
        &[1, copy, optional_field(vm, options, c"ipid")],
        0,
    );
    let top = vm.top();
    vm.call_global(c"rawsend_dissect_ipfrag", &[copy, options], MULTRET);
    vm.top() - top
}

unsafe extern "C-unwind" fn rawsend_payload_segmented(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(4);
    vm.integer(0);
    let mut dis = vm.field(1, c"dis");
    if vm.truth(2) || (vm.truth(3) && !vm.equal(3, dis - 1)) {
        let copy = vm.call_global(c"deepcopy", &[dis], 1);
        dis = if vm.truth(copy) {
            copy
        } else {
            vm.field(1, c"dis")
        };
    }
    if vm.truth(2) {
        vm.assign(dis, c"payload", 2);
    }
    let tcp = vm.field(dis, c"tcp");
    if vm.truth(tcp) && vm.truth(3) {
        let sequence = vm.field(tcp, c"th_seq");
        vm.push_number(vm.arithmetic_number(sequence) + vm.arithmetic_number(3));
        vm.set(tcp, c"th_seq");
    }
    vm.nil();
    let top = vm.top();
    vm.call_global(c"rawsend_dissect_segmented", &[1, dis, top, 4], MULTRET);
    vm.top() - top
}

unsafe extern "C-unwind" fn apply_ip_id(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 26) };
    vm.pad_arguments(4);
    let ip = vm.field(dissection(vm, 2), c"ip");
    if !vm.truth(ip) {
        return 0;
    }
    let options = if vm.truth(3) { 3 } else { vm.field(1, c"arg") };
    let mode = vm.field(options, c"ip_id");
    let mode = if vm.truth(mode) { mode } else { 4 };
    if vm.text_is(mode, b"seq") || !vm.truth(mode) {
        let track = vm.field(1, c"track");
        let target = if vm.truth(track) && vm.truth(vm.field(options, c"ip_id_conn")) {
            vm.field(track, c"lua_state")
        } else {
            1
        };
        let mut last = vm.field(target, c"ip_id");
        if !vm.truth(last) {
            last = vm.field(ip, c"ip_id");
        }
        vm.assign(ip, c"ip_id", last);
        let used = vm.field(ip, c"ip_id");
        vm.push_number(vm.arithmetic_number(used) + 1.0);
        vm.set(target, c"ip_id");
    } else if vm.text_is(mode, b"zero") {
        vm.integer(0);
        vm.set(ip, c"ip_id");
    } else if vm.text_is(mode, b"rnd") {
        vm.path(GLOBALS, &[c"math", c"random"]);
        vm.integer(1);
        vm.integer(0xFFFF);
        vm.call(2, 1);
        vm.set(ip, c"ip_id");
    }
    0
}
