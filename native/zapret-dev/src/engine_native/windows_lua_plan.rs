//! Rule plan orchestration with Lua-owned arguments, instances and callbacks.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"instance_cutoff_shim", instance_cutoff_shim),
    (c"cutoff_shim_check", cutoff_shim_check),
    (c"apply_arg_prefix", apply_arg_prefix),
    (c"apply_execution_plan", apply_execution_plan),
    (c"verdict_aggregate", verdict_aggregate),
    (
        c"plan_instance_execute_preapplied",
        plan_instance_execute_preapplied,
    ),
    (c"plan_instance_execute", plan_instance_execute),
    (c"plan_instance_pop", plan_instance_pop),
    (c"plan_clear", plan_clear),
    (c"orchestrate", orchestrate),
    (c"desync_copy", desync_copy),
    (c"replay_execution_plan", replay_execution_plan),
    (c"cond_lua", cond_lua),
    (c"require_iff", require_iff),
    (c"condition", condition),
    (c"per_instance_condition", per_instance_condition),
    (c"stopif", stopif),
    (c"repeater", repeater),
];

unsafe extern "C-unwind" fn instance_cutoff_shim(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 32) };
    vm.pad_arguments(3);
    if vm.truth(1) {
        vm.call_global(c"instance_cutoff", &[1, 3], 0);
        return 0;
    }
    let track = vm.field(2, c"track");
    let name = vm.field(2, c"func_instance");
    if !vm.truth(track) {
        vm.log(
            b"instance_cutoff_shim: cannot cutoff '",
            &[(name, b"' because conntrack is absent")],
        );
        return 0;
    }
    let state = vm.field(track, c"lua_state");
    let mut bucket = vm.field(state, c"cutoff_shim");
    if !vm.truth(bucket) {
        bucket = vm.table(0);
        vm.assign(state, c"cutoff_shim", bucket);
    }
    let mut cut = vm.item(bucket, name);
    if !vm.truth(cut) {
        cut = vm.table(2);
        vm.set_item(bucket, name, cut);
    }
    let both = vm.kind(3) == NIL;
    vm.boolean(true);
    let yes = vm.top();
    if both {
        vm.set_item(cut, yes, yes);
        vm.boolean(false);
        vm.set_item(cut, vm.top(), yes);
    } else {
        vm.set_item(cut, 3, yes);
    }
    if vm.truth(vm.field(GLOBALS, c"b_debug")) {
        vm.boolean(both || !vm.truth(3));
        let inbound = vm.call_global(c"tostring", &[vm.top()], 1);
        let outbound = vm.call_global(c"tostring", &[if both { yes } else { 3 }], 1);
        vm.log(
            b"instance_cutoff_shim: cutoff '",
            &[(name, b"' in="), (inbound, b" out="), (outbound, b"")],
        );
    }
    0
}

unsafe extern "C-unwind" fn cutoff_shim_check(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 23) };
    vm.pad_arguments(1);
    let track = vm.field(1, c"track");
    if !vm.truth(track) {
        vm.log(
            b"cutoff_shim_check: cannot check '",
            &[(
                vm.field(1, c"func_instance"),
                b"' cutoff because conntrack is absent",
            )],
        );
        vm.boolean(false);
        return 1;
    }
    let mut cutoff = vm.path(track, &[c"lua_state", c"cutoff_shim"]);
    if vm.truth(cutoff) {
        cutoff = vm.item(cutoff, vm.field(1, c"func_instance"));
        if vm.truth(cutoff) {
            cutoff = vm.item(cutoff, vm.field(1, c"outgoing"));
        }
    }
    if vm.truth(cutoff) && vm.truth(vm.field(GLOBALS, c"b_debug")) {
        let label: &[u8] = if vm.truth(vm.field(1, c"outgoing")) {
            b"' out cutoff"
        } else {
            b"' in cutoff"
        };
        vm.log(
            b"cutoff_shim_check: '",
            &[(vm.field(1, c"func_instance"), label)],
        );
    }
    vm.push(cutoff);
    1
}

unsafe extern "C-unwind" fn apply_arg_prefix(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 35) };
    vm.pad_arguments(1);
    let arg = vm.field(1, c"arg");
    if vm.truth(vm.field(arg, c"__prefix_applied")) {
        return 0;
    }
    vm.call_global(c"pairs", &[arg], 3);
    let key = vm.top();
    loop {
        vm.push(key - 2);
        vm.push(key - 1);
        vm.push(key);
        vm.call(2, 2);
        let value = vm.top();
        if vm.kind(value - 1) == NIL {
            break;
        }
        vm.push(value - 1);
        vm.replace(key);
        let prefix = vm.substring(value, 1.0, Some(1.0));
        let length = vm.text_is(prefix, b"#");
        if length || vm.text_is(prefix, b"%") {
            let name = vm.substring(value, 2.0, None);
            let data = vm.call_global(c"blob", &[1, name], 1);
            let value = if length {
                vm.integer(if vm.kind(data) == STRING {
                    vm.length(data) as isize
                } else {
                    0
                });
                vm.call_global(c"tostring", &[vm.top()], 1)
            } else {
                data
            };
            vm.set_item(vm.field(1, c"arg"), key, value);
        } else if vm.text_is(prefix, b"\\") {
            let prefix = vm.substring(value, 2.0, Some(2.0));
            if vm.text_is(prefix, b"#") || vm.text_is(prefix, b"%") {
                let normalized = vm.substring(value, 2.0, None);
                vm.set_item(vm.field(1, c"arg"), key, normalized);
            }
        }
        vm.reset(key);
    }
    let arg = vm.field(1, c"arg");
    vm.boolean(true);
    vm.set(arg, c"__prefix_applied");
    0
}

unsafe extern "C-unwind" fn apply_execution_plan(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    vm.pad_arguments(2);
    for field in [c"func", c"func_n", c"func_instance"] {
        vm.field(2, field);
        vm.set(1, field);
    }
    vm.call_global(c"deepcopy", &[vm.field(2, c"arg")], 1);
    vm.set(1, c"arg");
    0
}

unsafe extern "C-unwind" fn verdict_aggregate(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 31) };
    vm.pad_arguments(2);
    let pass = vm.field(GLOBALS, c"VERDICT_PASS");
    let first = if vm.truth(1) { 1 } else { pass };
    let second = if vm.truth(2) { 2 } else { pass };
    let bit = vm.field(GLOBALS, c"VERDICT_PRESERVE_NEXT");
    let first_bit = vm.call_global(c"bitand", &[first, bit], 1);
    let second_bit = vm.call_global(c"bitand", &[second, bit], 1);
    let preserve = vm.call_global(c"bitor", &[first_bit, second_bit], 1);
    let first = vm.call_global(c"bitand", &[first, vm.field(GLOBALS, c"VERDICT_MASK")], 1);
    let second = vm.call_global(c"bitand", &[second, vm.field(GLOBALS, c"VERDICT_MASK")], 1);
    let drop = vm.field(GLOBALS, c"VERDICT_DROP");
    let verdict = if vm.equal(first, drop) || vm.equal(second, drop) {
        drop
    } else {
        let modify = vm.field(GLOBALS, c"VERDICT_MODIFY");
        if vm.equal(first, modify) || vm.equal(second, modify) {
            modify
        } else {
            pass
        }
    };
    let top = vm.top();
    vm.call_global(c"bitor", &[verdict, preserve], MULTRET);
    vm.top() - top
}

unsafe extern "C-unwind" fn plan_instance_execute_preapplied(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 44) };
    vm.pad_arguments(3);
    if vm.truth(vm.call_global(c"cutoff_shim_check", &[1], 1)) {
        vm.log(
            b"plan_instance_execute: not calling '",
            &[(
                vm.field(1, c"func_instance"),
                b"' because of voluntary cutoff",
            )],
        );
    } else if !vm.truth(vm.call_global(
        c"payload_match_filter",
        &[vm.field(1, c"l7payload"), vm.field(3, c"payload_filter")],
        1,
    )) {
        vm.log(
            b"plan_instance_execute: not calling '",
            &[
                (vm.field(1, c"func_instance"), b"' because payload '"),
                (vm.field(1, c"l7payload"), b"' does not match filter '"),
                (vm.field(3, c"payload_filter"), b"'"),
            ],
        );
    } else if !vm.truth(vm.call_global(c"pos_check_range", &[1, vm.field(3, c"range")], 1)) {
        let name = vm.field(1, c"func_instance");
        let from = vm.call_global(c"pos_str", &[1, vm.path(3, &[c"range", c"from"])], 1);
        let to = vm.call_global(c"pos_str", &[1, vm.path(3, &[c"range", c"to"])], 1);
        let range = vm.call_global(c"pos_range_str", &[vm.field(3, c"range")], 1);
        vm.log(
            b"plan_instance_execute: not calling '",
            &[
                (name, b"' because pos "),
                (from, b" "),
                (to, b" is out of range '"),
                (range, b"'"),
            ],
        );
    } else {
        vm.call_global(c"apply_arg_prefix", &[1], 0);
        let arg = vm.field(1, c"arg");
        vm.nil();
        vm.set(arg, c"__prefix_applied");
        vm.log(
            b"plan_instance_execute: calling '",
            &[(vm.field(1, c"func_instance"), b"'")],
        );
        vm.field(GLOBALS, c"verdict_aggregate");
        vm.push(2);
        let globals = vm.field(GLOBALS, c"_G");
        let name = vm.field(3, c"func");
        vm.item(globals, name);
        vm.replace(globals);
        vm.reset(globals);
        vm.nil();
        vm.push(1);
        vm.call(2, MULTRET);
        vm.call(vm.top() - globals + 2, 1);
        vm.replace(2);
    }
    vm.push(2);
    1
}

unsafe extern "C-unwind" fn plan_instance_execute(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 13) };
    vm.pad_arguments(3);
    vm.call_global(c"apply_execution_plan", &[1, 3], 0);
    let top = vm.top();
    vm.call_global(c"plan_instance_execute_preapplied", &[1, 2, 3], MULTRET);
    vm.top() - top
}

fn table_remove(vm: Stack, table: c_int, index: Option<isize>) -> c_int {
    let top = vm.top();
    vm.path(GLOBALS, &[c"table", c"remove"]);
    vm.push(table);
    if let Some(index) = index {
        vm.integer(index);
    }
    vm.call(if index.is_some() { 2 } else { 1 }, 1);
    vm.replace(top + 1);
    top + 1
}

unsafe extern "C-unwind" fn plan_instance_pop(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    let plan = vm.field(1, c"plan");
    if vm.truth(plan)
        && vm.length(plan) > 0
        && vm.truth(table_remove(vm, vm.field(1, c"plan"), Some(1)))
    {
        return 1;
    }
    vm.nil();
    1
}

unsafe extern "C-unwind" fn plan_clear(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(2);
    let top = vm.top();
    let mut count = 0;
    loop {
        let limit = vm.truth(2);
        if limit {
            vm.integer(count);
            if !vm.less(-1, 2) {
                break;
            }
        }
        let plan = vm.field(1, c"plan");
        if !vm.truth(table_remove(vm, plan, limit.then_some(1))) {
            break;
        }
        count += 1;
        vm.reset(top);
    }
    0
}

unsafe extern "C-unwind" fn orchestrate(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    if !vm.truth(vm.field(2, c"plan")) {
        vm.call_global(c"execution_plan_cancel", &[1], 0);
        vm.call_global(c"execution_plan", &[1], 1);
        vm.set(2, c"plan");
    }
    0
}

unsafe extern "C-unwind" fn desync_copy(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 13) };
    vm.pad_arguments(1);
    let copy = vm.call_global(c"deepcopy", &[1], 1);
    let track = vm.field(1, c"track");
    if vm.truth(track) {
        let target = vm.field(copy, c"track");
        vm.field(track, c"lua_state");
        vm.set(target, c"lua_state");
    }
    let plan = vm.field(1, c"plan");
    if vm.truth(plan) {
        vm.assign(copy, c"plan", plan);
    }
    vm.push(copy);
    1
}

fn within_limit(vm: Stack, count: isize, limit: c_int) -> bool {
    if !vm.truth(limit) {
        return true;
    }
    let top = vm.top();
    vm.integer(count);
    let within = vm.less(-1, limit);
    vm.reset(top);
    within
}

unsafe extern "C-unwind" fn replay_execution_plan(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    vm.pad_arguments(2);
    let verdict = vm.field(GLOBALS, c"VERDICT_PASS");
    let mut count = 0;
    while within_limit(vm, count, 2) {
        let next = vm.call_global(c"plan_instance_pop", &[1], 1);
        if !vm.truth(next) {
            break;
        }
        vm.call_global(c"plan_instance_execute", &[1, verdict, next], 1);
        vm.replace(verdict);
        vm.reset(verdict);
        count += 1;
    }
    if vm.truth(2) {
        vm.integer(count);
        if vm.less_equal(2, -1) {
            vm.log(
                b"replay_execution_plan: reached max instances limit ",
                &[(2, b"")],
            );
        }
    }
    vm.push(verdict);
    1
}

unsafe extern "C-unwind" fn cond_lua(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 32) };
    vm.pad_arguments(1);
    let result = windows_lua_stock::run_inline(
        vm,
        1,
        c"cond_code",
        b"_cond_cond_code",
        c"cond_lua: no 'cond_code' parameter",
    );
    vm.push(result);
    1
}

unsafe extern "C-unwind" fn require_iff(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 17) };
    vm.pad_arguments(2);
    let iff = vm.path(1, &[c"arg", c"iff"]);
    if !vm.truth(iff) {
        vm.call_message(c"error", b"", &[(2, b": missing 'iff' function")]);
    }
    if vm.kind(vm.item(vm.field(GLOBALS, c"_G"), iff)) != FUNCTION {
        vm.call_message(
            c"error",
            b"",
            &[(2, b": invalid 'iff' function '"), (iff, b"'")],
        );
    }
    0
}

fn test_iff(vm: Stack, desync: c_int, name: c_int, invert_table: c_int, invert: &CStr) -> bool {
    let globals = vm.field(GLOBALS, c"_G");
    vm.item(globals, name);
    vm.push(desync);
    vm.call(1, 1);
    let selected = vm.top();
    let neg = vm.field(invert_table, invert);
    vm.truth(vm.call_global(c"logical_xor", &[selected, neg], 1))
}

fn evaluate_condition(vm: Stack, label: &[u8]) -> bool {
    vm.bytes(label);
    vm.call_global(c"require_iff", &[2, vm.top()], 0);
    vm.call_global(c"orchestrate", &[1, 2], 0);
    let args = vm.field(2, c"arg");
    test_iff(vm, 2, vm.field(args, c"iff"), args, c"neg")
}

unsafe extern "C-unwind" fn condition(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 31) };
    vm.pad_arguments(2);
    if evaluate_condition(vm, b"condition") {
        vm.log(b"condition: true", &[]);
    } else {
        vm.log(b"condition: false", &[]);
        let max = vm.call_global(c"tonumber", &[vm.path(2, &[c"arg", c"instances"])], 1);
        vm.call_global(c"plan_clear", &[2, max], 0);
        let remaining = vm.length(vm.field(2, c"plan"));
        if remaining > 0 {
            vm.integer(remaining as isize);
            vm.log(
                b"condition: executing remaining ",
                &[(vm.top(), b" instance(s)")],
            );
        }
    }
    let top = vm.top();
    vm.call_global(c"replay_execution_plan", &[2], MULTRET);
    vm.top() - top
}

unsafe extern "C-unwind" fn per_instance_condition(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 42) };
    vm.pad_arguments(2);
    vm.call_global(c"orchestrate", &[1, 2], 0);
    let verdict = vm.field(GLOBALS, c"VERDICT_PASS");
    let max = vm.call_global(c"tonumber", &[vm.path(2, &[c"arg", c"instances"])], 1);
    let mut count = 0;
    while within_limit(vm, count, max) {
        let instance = vm.call_global(c"plan_instance_pop", &[2], 1);
        if !vm.truth(instance) {
            break;
        }
        let args = vm.field(instance, c"arg");
        let name = vm.field(args, c"cond");
        if vm.truth(name) {
            if vm.kind(vm.item(vm.field(GLOBALS, c"_G"), name)) != FUNCTION {
                vm.call_message(
                    c"error",
                    b"per_instance_condition: invalid 'iff' function '",
                    &[(name, b"'")],
                );
            }
            vm.call_global(c"apply_execution_plan", &[2, instance], 0);
            if test_iff(vm, 2, vm.field(args, c"cond"), args, c"cond_neg") {
                vm.call_global(
                    c"plan_instance_execute_preapplied",
                    &[2, verdict, instance],
                    1,
                );
                vm.replace(verdict);
            } else {
                vm.log(
                    b"per_instance_condition: condition not satisfied. skipping '",
                    &[(vm.field(instance, c"func_instance"), b"'")],
                );
            }
        } else {
            vm.log(
                b"per_instance_condition: no 'cond' arg in '",
                &[(vm.field(instance, c"func_instance"), b"'. skipping")],
            );
        }
        count += 1;
        vm.reset(max);
    }
    let remaining = vm.length(vm.field(2, c"plan"));
    if remaining > 0 {
        vm.integer(remaining as isize);
        vm.log(
            b"per_instance_condition: executing remaining ",
            &[(vm.top(), b" instance(s) unconditionally")],
        );
    }
    aggregate_replay(vm, 2, verdict)
}

fn aggregate_replay(vm: Stack, desync: c_int, verdict: c_int) -> c_int {
    let base = vm.top();
    vm.field(GLOBALS, c"verdict_aggregate");
    vm.push(verdict);
    vm.call_global(c"replay_execution_plan", &[desync], MULTRET);
    vm.call(vm.top() - base - 1, MULTRET);
    vm.top() - base
}

unsafe extern "C-unwind" fn stopif(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 25) };
    vm.pad_arguments(2);
    if evaluate_condition(vm, b"stopif") {
        vm.log(b"stopif: true", &[]);
        vm.call_global(c"plan_clear", &[2], 0);
    } else {
        vm.log(b"stopif: false", &[]);
    }
    0
}

unsafe extern "C-unwind" fn repeater(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 55) };
    vm.pad_arguments(2);
    let repeats = vm.call_global(c"tonumber", &[vm.path(2, &[c"arg", c"repeats"])], 1);
    if !vm.truth(repeats) {
        return vm.error(c"repeater: missing 'repeats'");
    }
    let mut iff = vm.path(2, &[c"arg", c"iff"]);
    if !vm.truth(iff) {
        vm.bytes(b"cond_true");
        iff = vm.top();
    }
    let globals = vm.field(GLOBALS, c"_G");
    if vm.kind(vm.item(globals, iff)) != FUNCTION {
        vm.call_message(
            c"error",
            b"repeater: invalid 'iff' function '",
            &[(iff, b"'")],
        );
    }
    vm.call_global(c"orchestrate", &[1, 2], 0);
    let plan = vm.field(2, c"plan");
    if vm.length(plan) == 0 {
        vm.log(
            b"repeater: execution plan is empty - nothing to repeat",
            &[],
        );
        return 0;
    }
    let args = vm.field(2, c"arg");
    let neg = vm.field(args, c"neg");
    let stop = vm.field(args, c"stop");
    let clear = vm.field(args, c"clear");
    let verdict = vm.field(GLOBALS, c"VERDICT_PASS");
    let amount = vm.call_global(c"tonumber", &[vm.field(args, c"instances")], 1);
    let amount = if vm.truth(amount) {
        vm.arithmetic_number(amount)
    } else {
        1.0
    };
    let plan_size = vm.length(vm.field(2, c"plan")) as f64;
    let amount = if amount > plan_size {
        plan_size
    } else {
        amount
    };
    let label = vm.field(2, c"func_instance");
    let plan = vm.call_global(c"deepcopy", &[vm.field(2, c"plan")], 1);
    let mut round = 1.0;
    while round <= vm.arithmetic_number(repeats) {
        vm.item(globals, iff);
        vm.push(2);
        vm.call(1, 1);
        let result = vm.call_global(c"logical_xor", &[vm.top(), neg], 1);
        if !vm.truth(result) {
            vm.log(b"repeater: break by iff", &[]);
            vm.reset(plan);
            break;
        }
        vm.push_number(round);
        vm.log(
            b"repeater: ",
            &[(label, b" "), (vm.top(), b"/"), (repeats, b"")],
        );
        let end = vm.length(vm.field(2, c"plan")) as f64 - amount;
        vm.reset(plan);
        loop {
            let next = vm.call_global(c"plan_instance_pop", &[2], 1);
            vm.call_global(c"plan_instance_execute", &[2, verdict, next], 1);
            vm.replace(verdict);
            let length = vm.length(vm.field(2, c"plan")) as f64;
            vm.reset(plan);
            if length <= end {
                break;
            }
        }
        vm.call_global(c"deepcopy", &[plan], 1);
        vm.set(2, c"plan");
        round += 1.0;
    }
    let mut removed = 1.0;
    while removed <= amount {
        table_remove(vm, vm.field(2, c"plan"), Some(1));
        vm.reset(plan);
        removed += 1.0;
    }
    if vm.truth(clear) {
        vm.call_global(c"plan_clear", &[2], 0);
    }
    if vm.truth(clear) || vm.truth(stop) {
        vm.push(verdict);
        1
    } else {
        aggregate_replay(vm, 2, verdict)
    }
}
