//! Orchestrate the stock circular profile while Lua owns its records and callbacks.
use super::*;

unsafe extern "C" {
    fn floor(number: f64) -> f64;
}

unsafe extern "C-unwind" {
    fn lua_error(lua: *mut LuaState) -> c_int;
}

fn log(vm: Stack, prefix: &[u8], value: Option<c_int>, suffix: &[u8]) {
    let top = vm.top();
    vm.field(GLOBALS, c"DLOG");
    vm.bytes(prefix);
    if let Some(value) = value {
        vm.push(value);
        vm.bytes(suffix);
        vm.concat(3);
    }
    vm.call(1, 0);
    vm.reset(top);
}

fn bad_strategy(vm: Stack, argument: c_int) {
    vm.bytes(b"circular: strategy number '");
    vm.call_global(c"tostring", &[argument], 1);
    vm.bytes(b"' is invalid");
    vm.concat(3);
    unsafe { lua_error(vm.0) };
}

fn number(vm: Stack, instance: c_int) -> c_int {
    let function = vm.field(GLOBALS, c"tonumber");
    let arg = vm.field(instance, c"arg");
    vm.field(arg, c"strategy");
    vm.replace(arg);
    vm.call(1, 1);
    function
}

fn count_strategies(vm: Stack, desync: c_int, host: c_int) {
    let top = vm.top();
    if !vm.truth(vm.field(host, c"ctstrategy")) {
        let unique = vm.table(0);
        vm.field(GLOBALS, c"pairs");
        vm.field(desync, c"plan");
        vm.call(1, 3);
        let key = vm.top();
        let mut count = 0;
        loop {
            vm.push(key - 2);
            vm.push(key - 1);
            vm.push(key);
            vm.call(2, 2);
            let instance = vm.top();
            if vm.kind(instance - 1) == NIL {
                break;
            }
            vm.push(instance - 1);
            vm.replace(key);
            let args = vm.field(instance, c"arg");
            let strategy = vm.field(args, c"strategy");
            if vm.truth(strategy) {
                let value = number(vm, instance);
                if !vm.truth(value) || unsafe { luaL_checknumber(vm.0, value) } < 1.0 {
                    let args = vm.field(instance, c"arg");
                    let value = vm.field(args, c"strategy");
                    bad_strategy(vm, value);
                    return;
                }
                let index = number(vm, instance);
                let assigned = vm.item(unique, index);
                if !vm.truth(assigned) {
                    vm.boolean(true);
                    vm.set_item(unique, index, vm.top());
                    count += 1;
                }
                let args = vm.field(instance, c"arg");
                if vm.truth(vm.field(args, c"final")) {
                    vm.push(value);
                    vm.set(host, c"final");
                }
            }
            vm.reset(key);
        }
        if count != vm.length(unique) {
            vm.error(c"circular: strategies numbers must start from 1 and increment. gaps are not allowed.");
            return;
        }
        vm.integer(count as isize);
        vm.set(host, c"ctstrategy");
    }
    vm.reset(top);
}

fn rotate(vm: Stack, desync: c_int, host: c_int) {
    let top = vm.top();
    let final_strategy = vm.field(host, c"final");
    let selected = vm.field(host, c"nstrategy");
    if vm.equal(final_strategy, selected) {
        vm.reset(top);
        return;
    }
    let conn = vm.call_global(c"automate_conn_record", &[desync], 1);
    let failed = vm.call_global(c"automate_failure_check", &[desync, host, conn], 1);
    if vm.truth(failed) {
        let selected = vm.field(host, c"nstrategy");
        let count = vm.field(host, c"ctstrategy");
        unsafe {
            let selected = luaL_checknumber(vm.0, selected);
            let count = luaL_checknumber(vm.0, count);
            // Lua's modulo operation uses a quotient rounded toward -infinity.
            vm.push_number(selected - floor(selected / count) * count + 1.0);
        }
        vm.set(host, c"nstrategy");
        log(
            vm,
            b"circular: rotate strategy to ",
            Some(vm.field(host, c"nstrategy")),
            b"",
        );
        let selected = vm.field(host, c"nstrategy");
        if vm.equal(selected, vm.field(host, c"final")) {
            log(
                vm,
                b"circular: final strategy ",
                Some(vm.field(host, c"final")),
                b" reached. will rotate no more.",
            );
        }
    }
    vm.reset(top);
}

pub(super) unsafe extern "C-unwind" fn circular(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 48) };
    while vm.top() < 2 {
        vm.nil();
    }
    const DESYNC: c_int = 2;
    vm.call_global(c"orchestrate", &[1, DESYNC], 0);
    if !vm.truth(vm.field(DESYNC, c"track")) {
        vm.field(GLOBALS, c"DLOG_ERR");
        vm.bytes(b"circular: conntrack is missing but required");
        vm.call(1, 0);
        return 0;
    }
    let host = vm.call_global(c"automate_host_record", &[DESYNC], 1);
    if !vm.truth(host) {
        log(vm, b"circular: passing with no tampering", None, b"");
        return 0;
    }
    count_strategies(vm, DESYNC, host);
    let count = vm.field(host, c"ctstrategy");
    if vm.kind(count) == NUMBER && vm.number(count) == 0.0 {
        return vm.error(c"circular: add strategy=N tag argument to each following instance ! N must start from 1 and increment");
    }
    if !vm.truth(vm.field(host, c"nstrategy")) {
        log(vm, b"circular: start from strategy 1", None, b"");
        vm.integer(1);
        vm.set(host, c"nstrategy");
    }
    let verdict = vm.field(GLOBALS, c"VERDICT_PASS");
    rotate(vm, DESYNC, host);
    log(
        vm,
        b"circular: current strategy ",
        Some(vm.field(host, c"nstrategy")),
        b"",
    );
    vm.reset(verdict);
    loop {
        let part = vm.call_global(c"plan_instance_pop", &[DESYNC], 1);
        if !vm.truth(part) {
            vm.push(verdict);
            return 1;
        }
        let args = vm.field(part, c"arg");
        if vm.truth(vm.field(args, c"strategy")) {
            let strategy = number(vm, part);
            if vm.equal(strategy, vm.field(host, c"nstrategy")) {
                vm.call_global(c"plan_instance_execute", &[DESYNC, verdict, part], 1);
                vm.replace(verdict);
            }
        }
        vm.reset(verdict);
    }
}
