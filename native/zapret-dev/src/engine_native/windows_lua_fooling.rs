//! Apply the existing add-on strategies with live LuaJIT observations.
use super::*;

fn member(vm: Stack, table: c_int, index: c_int) -> c_int {
    unsafe { lua_rawgeti(vm.0, table, index) };
    vm.top()
}

fn callback(vm: Stack, name: &CStr, arguments: &[c_int], results: c_int) -> c_int {
    vm.field(GLOBALS, name);
    for &index in arguments {
        vm.push(index);
    }
    vm.call(arguments.len() as c_int, results);
    vm.top()
}

fn option(vm: Stack, tcp: c_int, kind: &CStr) -> c_int {
    vm.field(GLOBALS, c"find_tcp_option");
    vm.field(tcp, c"options");
    vm.field(GLOBALS, kind);
    vm.call(2, 1);
    vm.top()
}

fn log(vm: Stack, message: &[u8]) {
    vm.field(GLOBALS, c"DLOG");
    vm.bytes(message);
    vm.call(1, 0);
}

unsafe extern "C-unwind" fn ts_or_md5(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 32) };
    if vm.top() == 0 {
        vm.nil();
    }
    let tcp = vm.field(1, c"tcp");
    if !vm.truth(tcp) || vm.truth(option(vm, tcp, c"TCP_KIND_TS")) {
        return 0;
    }
    let top = vm.top();
    vm.push(capture(1));
    vm.field(GLOBALS, c"tonumber");
    vm.field(tcp, c"th_seq");
    vm.call(1, 1);
    let has_md5 = vm.kind(option(vm, tcp, c"TCP_KIND_MD5")) != NIL;
    // Replace the option index by the boolean expected by the backend.
    vm.reset(top + 2);
    vm.boolean(has_md5);
    vm.call(2, 2);
    let seq = top + 1;
    if vm.truth(seq + 1) {
        let options = vm.field(tcp, c"options");
        if !vm.truth(options) {
            vm.table(0);
            vm.set(tcp, c"options");
        }
        let table = vm.field(GLOBALS, c"table");
        vm.field(table, c"insert");
        vm.field(tcp, c"options");
        let entry = vm.table(2);
        vm.field(GLOBALS, c"TCP_KIND_MD5");
        vm.set(entry, c"kind");
        vm.field(GLOBALS, c"brandom");
        vm.integer(16);
        vm.call(1, 1);
        vm.set(entry, c"data");
        vm.call(2, 0);
    }
    vm.push(seq);
    vm.set(tcp, c"th_seq");
    log(vm, b"ts_or_md5: no tcp timestamp in this connection. fake gets md5 option and seq-10000 instead");
    0
}

pub(super) fn send_options(vm: Stack, desync: c_int, fake: bool) -> c_int {
    let out = vm.table(5);
    callback(
        vm,
        if fake {
            c"rawsend_opts"
        } else {
            c"rawsend_opts_base"
        },
        &[desync],
        1,
    );
    vm.set(out, c"rawsend");
    if fake {
        callback(vm, c"reconstruct_opts", &[desync], 1);
    } else {
        vm.table(0);
    }
    vm.set(out, c"reconstruct");
    vm.table(0);
    vm.set(out, c"ipfrag");
    vm.field(desync, c"arg");
    vm.set(out, c"ipid");
    if fake {
        vm.field(desync, c"arg");
    } else {
        let table = vm.table(1);
        let arg = vm.field(desync, c"arg");
        vm.field(arg, c"tcp_ts_up");
        vm.set(table, c"tcp_ts_up");
        vm.reset(table);
    }
    vm.set(out, c"fooling");
    out
}

fn send_parts(vm: Stack, desync: c_int, data: c_int, range: c_int) -> bool {
    let original = send_options(vm, desync, false);
    let fake = send_options(vm, desync, true);
    let top = vm.top();
    vm.push(capture(1));
    vm.integer(vm.length(data) as isize);
    vm.integer(1);
    let first = vm.top();
    unsafe { lua_gettable(vm.0, range) };
    let start = unsafe { luaL_checknumber(vm.0, first) } - 1.0;
    unsafe { lua_pushnumber(vm.0, start) };
    vm.replace(first);
    vm.integer(2);
    unsafe { lua_gettable(vm.0, range) };
    vm.call(3, MULTRET);
    let last = vm.top();
    unsafe { luaL_checkstack(vm.0, 16, c"hostfakesplit_alt".as_ptr()) };
    let ranges = vm.table(0);
    for index in top + 1..=last {
        vm.push(index);
        unsafe { lua_rawseti(vm.0, ranges, index - top) };
    }
    let length = vm.length(ranges);
    for index in (1..=length).step_by(2) {
        let start = member(vm, ranges, index as c_int);
        let end = member(vm, ranges, (index + 1) as c_int);
        let part = if index == 3 {
            vm.field(GLOBALS, c"genhost");
            let width = unsafe { luaL_checknumber(vm.0, end) - luaL_checknumber(vm.0, start) };
            unsafe { lua_pushnumber(vm.0, width) };
            let arg = vm.field(desync, c"arg");
            vm.field(arg, c"host");
            vm.replace(arg);
            vm.call(2, 1);
            vm.top()
        } else {
            let strings = vm.field(GLOBALS, c"string");
            vm.field(strings, c"sub");
            vm.push(data);
            unsafe {
                let offset = luaL_checknumber(vm.0, start);
                lua_pushnumber(vm.0, offset + 1.0);
            }
            vm.push(end);
            vm.call(3, 1);
            vm.top()
        };
        let options = if index == 3 { fake } else { original };
        let sent = callback(
            vm,
            c"rawsend_payload_segmented",
            &[desync, part, start, options],
            1,
        );
        if !vm.truth(sent) {
            return false;
        }
        vm.reset(ranges);
    }
    true
}

unsafe extern "C-unwind" fn hostfakesplit_alt(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 64) };
    while vm.top() < 2 {
        vm.nil();
    }
    const DESYNC: c_int = 2;
    let dis = vm.field(DESYNC, c"dis");
    if !vm.truth(vm.field(dis, c"tcp")) {
        let dis = vm.field(DESYNC, c"dis");
        if !vm.truth(vm.field(dis, c"icmp")) {
            callback(vm, c"instance_cutoff_shim", &[1, DESYNC], 0);
        }
        return 0;
    }
    callback(vm, c"direction_cutoff_opposite", &[1, DESYNC], 0);
    let data = vm.field(DESYNC, c"reasm_data");
    let data = if vm.truth(data) {
        data
    } else {
        let dis = vm.field(DESYNC, c"dis");
        vm.field(dis, c"payload")
    };
    if vm.length(data) > 0
        && vm.truth(callback(vm, c"direction_check", &[DESYNC], 1))
        && vm.truth(callback(vm, c"payload_check", &[DESYNC], 1))
    {
        if vm.truth(callback(vm, c"replay_first", &[DESYNC], 1)) {
            vm.field(GLOBALS, c"resolve_range");
            vm.push(data);
            vm.field(DESYNC, c"l7payload");
            vm.bytes(b"host,endhost-1");
            vm.boolean(true);
            vm.call(4, 1);
            let range = vm.top();
            if vm.truth(range) {
                if send_parts(vm, DESYNC, data, range) {
                    callback(vm, c"replay_drop_set", &[DESYNC], 0);
                    vm.field(GLOBALS, c"VERDICT_DROP");
                } else {
                    vm.field(GLOBALS, c"VERDICT_PASS");
                }
                return 1;
            }
            log(vm, b"hostfakesplit_alt: host range cannot be resolved");
        } else {
            log(
                vm,
                b"hostfakesplit_alt: not acting on further replay pieces",
            );
        }
        if vm.truth(callback(vm, c"replay_drop", &[DESYNC], 1)) {
            vm.field(GLOBALS, c"VERDICT_DROP");
            return 1;
        }
    }
    0
}

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 6) };
    vm.push(1);
    vm.closure(ts_or_md5, 1);
    vm.push(2);
    vm.closure(hostfakesplit_alt, 1);
    2
}
