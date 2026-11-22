//! Segment-range, replay and urgent-pointer rules.
use super::*;

pub(super) unsafe extern "C-unwind" fn pos_normalize(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(3);
    if vm.less_equal(2, 1) && vm.less(1, 3) {
        vm.push_number(vm.arithmetic_number(1) - vm.arithmetic_number(2) + 1.0);
    } else {
        vm.nil();
    }
    1
}

pub(super) unsafe extern "C-unwind" fn pos_array_normalize(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(3);
    let top = vm.top();
    let mut index = 1;
    while index <= vm.length(1) {
        let value = vm.array_item(1, index);
        let new = vm.call_global(c"pos_normalize", &[value, 2, 3], 1);
        vm.integer(index as isize);
        let key = vm.top();
        vm.set_item(1, key, new);
        if vm.truth(vm.item(1, key)) {
            index += 1;
        } else {
            vm.table_operation(c"remove", &[1, key], 0);
        }
        vm.reset(top);
    }
    0
}

pub(super) unsafe extern "C-unwind" fn multidisorder_legacy(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 68) };
    let rule = Rule::new(vm, b"multidisorder_legacy");
    if rule.type_or_cutoff(c"tcp").is_none() {
        return 0;
    }
    rule.0.cutoff_opposite();
    let data = rule.payload();
    let full = vm.field(2, c"reasm_data");
    if vm.length(data) == 0 || !rule.0.direction_payload() {
        return 0;
    }
    let offset = vm.field(2, c"reasm_offset");
    let offset = if vm.truth(offset) {
        vm.arithmetic_number(offset)
    } else {
        0.0
    };
    let low = offset + 1.0;
    let high = low + vm.length(data) as f64;
    vm.push_number(low);
    vm.push_number(high);
    let upper = vm.top();
    let marker = rule.0.position_arg();
    if rule.0.debug() {
        rule.0.log(b": split pos: ", &[(marker, b"")]);
    }
    let positions = rule.0.resolve(c"resolve_multi_pos", full, marker);
    if rule.0.debug() {
        rule.0.log_positions(b": resolved split pos: ", positions);
    }
    vm.push_number(low - 1.0);
    vm.push_number(high - 2.0);
    rule.0.log(
        b": reasm piece range: ",
        &[(vm.top() - 1, b"-"), (vm.top(), b"")],
    );
    vm.call_global(c"pos_array_normalize", &[positions, upper - 1, upper], 0);
    vm.call_global(c"delete_pos_1", &[positions], 0);
    if vm.length(positions) == 0 {
        rule.0.log(b": no normalized split pos in this packet", &[]);
        if vm.truth(vm.call_global(c"rawsend_payload_segmented", &[2], 1)) {
            return rule.verdict(c"VERDICT_DROP");
        }
        return 0;
    }
    if rule.0.debug() {
        rule.0.log_positions(b": normalized split pos: ", positions);
    }
    let marker = rule.0.arg(c"seqovl");
    vm.nil();
    let mut overlap = vm.top();
    if vm.truth(marker) {
        let resolved = rule.0.resolve(c"resolve_pos", full, marker);
        if !vm.truth(resolved) {
            rule.0.log(
                b": seqovl cancelled because could not resolve marker '",
                &[(marker, b"'")],
            );
        } else {
            vm.push_number(vm.arithmetic_number(resolved) - 1.0);
            rule.0.log(b": resolved seqovl pos: ", &[(vm.top(), b"")]);
            overlap = vm.call_global(c"pos_normalize", &[resolved, upper - 1, upper], 1);
            if vm.truth(overlap) {
                vm.push_number(vm.arithmetic_number(overlap) - 1.0);
                rule.0.log(b": normalized seqovl pos: ", &[(vm.top(), b"")]);
            } else {
                rule.0.log(
                    b": normalized seqovl pos is outside of the reasm piece range",
                    &[],
                );
            }
        }
    }
    vm.tail_global(c"multidisorder_send", &[2, data, overlap, positions])
}

pub(super) unsafe extern "C-unwind" fn tcpseg(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 75) };
    let rule = Rule::new(vm, b"tcpseg");
    if rule.type_or_cutoff(c"tcp").is_none() {
        return 0;
    }
    rule.0.cutoff_opposite();
    let marker = rule.0.arg(c"pos");
    if !vm.truth(marker) {
        return vm.error(c"tcpseg: no pos specified");
    }
    if vm.truth(rule.0.arg(c"optional")) {
        let name = rule.0.arg(c"blob");
        if vm.truth(name) && !rule.0.available_blob(name) {
            rule.0.log(b": blob '", &[(name, b"' not found. skipped")]);
            return 0;
        }
    }
    let data = vm.call_global(c"blob_or_def", &[2, rule.0.arg(c"blob")], 1);
    let data = if vm.truth(data) {
        data
    } else {
        rule.reassembled()
    };
    if vm.length(data) == 0 || !rule.0.direction_payload() {
        return 0;
    }
    if !rule.0.replay_first() {
        rule.0.log(b": not acting on further replay pieces", &[]);
        return 0;
    }
    if rule.0.debug() {
        rule.0.log(b": pos: ", &[(marker, b"")]);
    }
    let positions = rule.0.resolve(c"resolve_range", data, marker);
    if !vm.truth(positions) {
        rule.0.log(b": range cannot be resolved", &[]);
        return 0;
    }
    if rule.0.debug() {
        rule.0.log_positions(b": resolved range: ", positions);
    }
    let first = vm.arithmetic_number(vm.array_item(positions, 1));
    let last = vm.arithmetic_number(vm.array_item(positions, 2));
    let part = vm.substring(data, first, Some(last));
    let overlap = rule.0.numeric_overlap();
    if overlap > 0.0 {
        rule.0.prepend_overlap(part, overlap);
    }
    rule.0
        .log_part(b": sending ", part, first - 1.0, last - 1.0, Some(overlap));
    vm.push_number(first - 1.0 - overlap);
    vm.call_global(c"rawsend_payload_segmented", &[2, part, vm.top()], 0);
    0
}

fn shift_sequence(vm: Stack, field: &CStr, offset: isize, message: &[u8]) {
    let header = vm.path(2, &[c"dis", c"tcp"]);
    let previous = vm.field(header, field);
    vm.integer(offset);
    let altered = vm.call_global(c"u32add", &[previous, vm.top()], 1);
    vm.log(
        message,
        &[(vm.field(header, field), b" => "), (altered, b"")],
    );
    vm.assign(vm.path(2, &[c"dis", c"tcp"]), field, altered);
}

fn stream_position(vm: Stack, reverse: bool) -> c_int {
    vm.bytes(b"s");
    let mode = vm.top();
    vm.boolean(reverse);
    vm.call_global(c"pos_get", &[2, mode, mode + 1], 1)
}

fn urgent_byte(rule: &Rule) -> c_int {
    let vm = rule.vm();
    let literal = rule.0.arg(c"char");
    if vm.truth(literal) {
        return literal;
    }
    let number = rule.0.arg(c"byte");
    if vm.truth(number) {
        let byte = vm.call_global(c"bu8", &[number], 1);
        if vm.truth(byte) {
            return byte;
        }
    }
    vm.bytes(b"\0");
    vm.top()
}

fn urgent_pointer(rule: &Rule, data: c_int, tcp: c_int) -> Option<f64> {
    let vm = rule.vm();
    let marker = rule.0.arg(c"urp");
    let (pointer, on_wire) = if !vm.truth(marker) || vm.text_is(marker, b"b") {
        (1.0, 0.0)
    } else if vm.text_is(marker, b"e") {
        let index = vm.length(data) as f64 + 1.0;
        (index, index)
    } else {
        let position = rule.0.resolve(c"resolve_pos", data, marker);
        if !vm.truth(position) {
            rule.0
                .log(b": cannot resolve urp marker '", &[(marker, b"'")]);
            rule.0.cutoff();
            return None;
        }
        let position = vm.arithmetic_number(position);
        vm.push_number(position - 1.0);
        rule.0.log(b": resolved urp marker to ", &[(vm.top(), b"")]);
        (position, position)
    };
    vm.push_number(on_wire);
    vm.set(tcp, c"th_urp");
    rule.0.log(b": th_urp ", &[(vm.field(tcp, c"th_urp"), b"")]);
    Some(pointer)
}

fn send_urgent(rule: &Rule, data: c_int) -> c_int {
    let vm = rule.vm();
    let byte = urgent_byte(rule);
    if vm.length(byte) != 1 {
        return vm.error(c"oob: OOB must be exactly one byte");
    }
    let dissect = rule.copy_packet();
    let tcp = vm.field(dissect, c"tcp");
    let Some(pointer) = urgent_pointer(rule, data, tcp) else {
        return 0;
    };
    vm.substring(data, 1.0, Some(pointer - 1.0));
    vm.push(byte);
    vm.substring(data, pointer, None);
    vm.concat(3);
    vm.set(dissect, c"payload");
    let flags = vm.field(tcp, c"th_flags");
    let urgent = vm.field(GLOBALS, c"TH_URG");
    vm.call_global(c"bitor", &[flags, urgent], 1);
    vm.set(tcp, c"th_flags");
    rule.0.log(b": sending OOB", &[]);
    if !vm.truth(vm.call_global(c"rawsend_dissect_segmented", &[2, dissect], 1)) {
        rule.0.cutoff();
        return 0;
    }
    if !vm.truth(vm.field(2, c"replay")) {
        rule.0.cutoff();
    }
    rule.verdict(c"VERDICT_DROP")
}

pub(super) unsafe extern "C-unwind" fn oob(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 100) };
    let rule = Rule::new(vm, b"oob");
    let track = vm.field(2, c"track");
    if !vm.truth(track) {
        return 0;
    }
    let Some(tcp) = rule.type_or_cutoff(c"tcp") else {
        return 0;
    };
    vm.field(2, c"func_instance");
    vm.bytes(b"_syn");
    vm.concat(2);
    let key = vm.top();
    let state = vm.field(track, c"lua_state");
    if !vm.truth(vm.item(state, key)) {
        let (syn, _, both) = rule.flag_names();
        if !rule.sequence_matches(tcp, both, syn) {
            rule.0.log(
                b": must be applied since the very beginning of the tcp connection - SYN packet",
                &[],
            );
            rule.0.cutoff();
            return 0;
        }
        vm.boolean(true);
        vm.set_item(state, key, vm.top());
    }
    let outgoing = vm.truth(vm.field(2, c"outgoing"));
    let pos = stream_position(vm, !outgoing);
    vm.integer(1);
    let one = vm.top();
    if !outgoing {
        if vm.less(one, pos) {
            rule.0
                .log(b": unexpected outgoing position ", &[(pos, b"")]);
            rule.0.cutoff();
            return 0;
        }
        shift_sequence(vm, c"th_ack", 1, b"oob: increasing incoming ack : ");
        return rule.verdict(c"VERDICT_MODIFY");
    }
    if vm.less_equal(pos, one) {
        shift_sequence(vm, c"th_seq", -1, b"oob: decreasing outgoing seq : ");
    }
    vm.integer(0);
    if vm.equal(pos, -1) {
        return rule.verdict(c"VERDICT_MODIFY");
    }
    if vm.equal(pos, one) {
        let data = rule.reassembled();
        if vm.length(data) == 0 {
            return rule.verdict(c"VERDICT_MODIFY");
        }
        return send_urgent(&rule, data);
    }
    if vm.truth(vm.field(2, c"replay")) {
        rule.0.log(b": dropping replay piece", &[]);
        if vm.truth(vm.field(2, c"replay_piece_last")) {
            rule.0.cutoff();
        }
        return rule.verdict(c"VERDICT_DROP");
    }
    rule.0.cutoff();
    0
}
