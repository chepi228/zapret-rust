//! The ring DLL owns the LRU. LuaJIT roots the host records and connection pins.
use super::*;

fn autostate(vm: Stack) -> c_int {
    let state = vm.field(GLOBALS, c"autostate");
    if vm.truth(state) {
        return state;
    }
    let state = vm.table(0);
    vm.push(state);
    vm.set(GLOBALS, c"autostate");
    state
}

fn ensure_table(vm: Stack, table: c_int, key: c_int) -> c_int {
    let value = vm.item(table, key);
    if vm.truth(value) {
        return value;
    }
    let value = vm.table(0);
    vm.set_item(table, key, value);
    value
}

fn host_key(vm: Stack, desync: c_int) -> c_int {
    let name = vm.path(desync, &[c"arg", c"hostkey"]);
    if vm.truth(name) {
        let globals = vm.field(GLOBALS, c"_G");
        if vm.kind(vm.item(globals, name)) != FUNCTION {
            vm.call_message(
                c"error",
                b"automate: invalid hostkey function '",
                &[(name, b"'")],
            );
        }
        vm.item(globals, vm.path(desync, &[c"arg", c"hostkey"]));
    } else {
        vm.field(GLOBALS, c"standard_hostkey");
    }
    vm.push(desync);
    vm.call(1, 1);
    vm.top()
}

fn group_key(vm: Stack, desync: c_int) -> c_int {
    let key = vm.path(desync, &[c"arg", c"key"]);
    if vm.truth(key) && vm.length(key) > 0 {
        vm.path(desync, &[c"arg", c"key"])
    } else {
        vm.field(desync, c"func_instance")
    }
}

fn record_at(vm: Stack, group: c_int, host: c_int) -> c_int {
    let state = autostate(vm);
    let bucket = ensure_table(vm, state, group);
    ensure_table(vm, bucket, host)
}

pub(super) unsafe extern "C-unwind" fn stock_host_record(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 29) };
    vm.pad_arguments(1);
    let host = host_key(vm, 1);
    if !vm.truth(host) {
        vm.log(b"automate: host record key unavailable", &[]);
        vm.nil();
        return 1;
    }
    let group = group_key(vm, 1);
    vm.log(
        b"automate: host record key 'autostate.",
        &[(group, b"."), (host, b"'")],
    );
    vm.push(record_at(vm, group, host));
    1
}

fn remove_item(vm: Stack, table: c_int, key: c_int) {
    let top = vm.top();
    vm.nil();
    vm.set_item(table, key, top + 1);
    vm.reset(top);
}

fn is_empty(vm: Stack, table: c_int) -> bool {
    let top = vm.top();
    vm.field(GLOBALS, c"next");
    vm.push(table);
    vm.call(1, 1);
    let empty = vm.kind(-1) == NIL;
    vm.reset(top);
    empty
}

fn detach(vm: Stack, cache: c_int, id: c_int) {
    let top = vm.top();
    let by_id = vm.field(cache, c"by_id");
    let node = vm.item(by_id, id);
    if !vm.truth(node) {
        vm.reset(top);
        return;
    }
    let group = vm.field(node, c"askey");
    let host = vm.field(node, c"hostkey");
    let state = vm.field(GLOBALS, c"autostate");
    if vm.truth(state) {
        let bucket = vm.item(state, group);
        if vm.truth(bucket) {
            let existing = vm.item(bucket, host);
            let record = vm.field(node, c"record");
            if vm.equal(existing, record) {
                remove_item(vm, bucket, host);
                if is_empty(vm, bucket) {
                    // The original write observes the current global table.
                    let state = vm.field(GLOBALS, c"autostate");
                    remove_item(vm, state, group);
                }
            }
        }
    }
    let groups = vm.field(cache, c"nodes");
    let nodes = vm.item(groups, group);
    remove_item(vm, nodes, host);
    if is_empty(vm, nodes) {
        let groups = vm.field(cache, c"nodes");
        remove_item(vm, groups, group);
    }
    remove_item(vm, by_id, id);
    vm.boolean(false);
    vm.set(node, c"active");
    let record = vm.field(node, c"record");
    vm.boolean(true);
    vm.set(record, c"ring_cache_evicted");
    vm.reset(top);
}

fn put_field(vm: Stack, table: c_int, name: &CStr, value: c_int) {
    vm.push(value);
    vm.set(table, name);
}

fn lookup(vm: Stack, cache: c_int, desync: c_int, group: c_int, host: c_int) -> c_int {
    if !vm.truth(host) {
        vm.nil();
        return 1;
    }
    let native = capture(1);
    let track = vm.field(desync, c"track");
    let state = vm.truth(track).then(|| vm.field(track, c"lua_state"));
    if let Some(state) = state.filter(|&state| vm.truth(state)) {
        let pin = vm.field(state, c"ring_host_pin");
        if vm.truth(pin)
            && vm.equal(vm.field(pin, c"token"), vm.field(cache, c"token"))
            && vm.equal(vm.field(pin, c"askey"), group)
            && vm.equal(vm.field(pin, c"hostkey"), host)
        {
            vm.field(native, c"host_touch");
            vm.field(cache, c"native");
            let node = vm.field(pin, c"node");
            vm.field(node, c"id");
            vm.replace(node);
            vm.call(2, 0);
            let node = vm.field(pin, c"node");
            vm.field(node, c"record");
            return 1;
        }
    }

    vm.field(native, c"host_access");
    vm.field(cache, c"native");
    vm.push(group);
    vm.push(host);
    vm.call(3, 3);
    let created = vm.top();
    let id = created - 2;
    let evicted = created - 1;
    if vm.truth(evicted) {
        detach(vm, cache, evicted);
    }
    let by_id = vm.field(cache, c"by_id");
    let node = vm.item(by_id, id);
    let node = if vm.truth(created) {
        let autos = autostate(vm);
        let bucket = ensure_table(vm, autos, group);
        let record = ensure_table(vm, bucket, host);
        let groups = vm.field(cache, c"nodes");
        let nodes = ensure_table(vm, groups, group);
        let node = vm.table(5);
        put_field(vm, node, c"id", id);
        put_field(vm, node, c"askey", group);
        put_field(vm, node, c"hostkey", host);
        put_field(vm, node, c"record", record);
        vm.boolean(true);
        vm.set(node, c"active");
        vm.set_item(by_id, id, node);
        vm.set_item(nodes, host, node);
        node
    } else {
        node
    };
    if let Some(state) = state.filter(|&state| vm.truth(state)) {
        let pin = vm.table(4);
        vm.field(cache, c"token");
        vm.set(pin, c"token");
        put_field(vm, pin, c"askey", group);
        put_field(vm, pin, c"hostkey", host);
        put_field(vm, pin, c"node", node);
        put_field(vm, state, c"ring_host_pin", pin);
    }
    vm.field(node, c"record");
    1
}

unsafe extern "C-unwind" fn protected_lookup(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 64) };
    lookup(vm, 1, 2, 3, 4)
}

pub(super) unsafe extern "C-unwind" fn bind_lookup(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 2) };
    vm.push(1);
    vm.closure(protected_lookup, 1);
    1
}

unsafe extern "C-unwind" fn cache_create(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 28) };
    vm.pad_arguments(1);
    let state = capture(1);
    let native = vm.field(state, c"native");
    let numeric = vm.kind(1) == NUMBER && vm.number(1).is_finite();
    vm.boolean(vm.kind(1) == NIL);
    let absent = vm.top();
    if numeric {
        vm.push(1)
    } else {
        vm.nil()
    }
    let capacity = vm.call_field(native, c"host_capacity", &[absent, vm.top()], 1);
    vm.bytes(b"invalid host cache capacity");
    let capacity = vm.call_global(c"assert", &[capacity, vm.top()], 1);
    let cache = vm.table(6);
    vm.call_field(native, c"host_new", &[capacity], 1);
    vm.set(cache, c"native");
    vm.assign(cache, c"capacity", capacity);
    for field in [c"nodes", c"by_id", c"token"] {
        vm.table(0);
        vm.set(cache, field);
    }
    vm.field(state, c"get");
    vm.set(cache, c"get");
    vm.call_field(state, c"attach", &[cache], 1);
    1
}

unsafe extern "C-unwind" fn cache_get(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 23) };
    vm.pad_arguments(2);
    let host = host_key(vm, 2);
    if !vm.truth(host) {
        vm.nil();
        return 1;
    }
    let group = group_key(vm, 2);
    let top = vm.top();
    vm.call_field(capture(1), c"lookup", &[1, 2, group, host], MULTRET);
    vm.top() - top
}

unsafe extern "C-unwind" fn selected_record(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 48) };
    vm.pad_arguments(1);
    let state = capture(1);
    if vm.truth(vm.field(state, c"disabled"))
        || !vm.text_is(vm.path(1, &[c"arg", c"hostcache"]), b"bounded")
    {
        let top = vm.top();
        vm.call_field(state, c"stock", &[1], MULTRET);
        return vm.top() - top;
    }
    let host = host_key(vm, 1);
    if !vm.truth(host) {
        vm.nil();
        return 1;
    }
    let group = group_key(vm, 1);
    let lookup = vm.field(state, c"lookup");
    let cache = vm.field(state, c"cache");
    let result = vm.protected(lookup, &[cache, 1, group, host]);
    if vm.truth(result - 1) {
        return 1;
    }
    vm.nil();
    vm.set(state, c"cache");
    vm.boolean(true);
    vm.set(state, c"disabled");
    let error = vm.call_global(c"tostring", &[result], 1);
    vm.call_message(
        c"DLOG_ERR",
        b"host cache: ",
        &[(error, b". using standard host records")],
    );
    vm.push(record_at(vm, group, host));
    1
}

pub(super) unsafe extern "C-unwind" fn bind_cache(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    if vm.kind(1) != TABLE {
        return vm.error(c"host cache requires a state table");
    }
    let entries: &[(&CStr, Callback)] = &[
        (c"new", cache_create),
        (c"get", cache_get),
        (c"record", selected_record),
    ];
    let module = vm.table(entries.len() as c_int);
    for &(name, function) in entries {
        vm.push(1);
        vm.closure(function, 1);
        vm.set(module, name);
    }
    1
}

unsafe extern "C-unwind" fn cache_index(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 6) };
    if vm.text_is(2, b"count") {
        let native = vm.field(capture(1), c"native");
        let cache = vm.field(1, c"native");
        vm.call_field(native, c"host_count", &[cache], 1);
        1
    } else {
        0
    }
}

unsafe extern "C-unwind" fn attach(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    let metatable = vm.table(1);
    vm.push(capture(1));
    vm.closure(cache_index, 1);
    vm.set(metatable, c"__index");
    unsafe { lua_setmetatable(lua, 1) };
    vm.push(1);
    1
}

pub(super) fn install(vm: Stack, native: c_int) {
    let state = vm.table(6);
    vm.assign(state, c"native", native);
    vm.closure(stock_host_record, 0);
    vm.set(state, c"stock");
    vm.push(native);
    vm.closure(protected_lookup, 1);
    vm.set(state, c"lookup");
    for (name, function) in [(c"get", cache_get as Callback), (c"attach", attach)] {
        vm.push(state);
        vm.closure(function, 1);
        vm.set(state, name);
    }
    let module = vm.table(2);
    vm.bytes(b"Rust");
    vm.set(module, c"backend");
    vm.push(state);
    vm.closure(cache_create, 1);
    vm.set(module, c"new");
    vm.call_field(module, c"new", &[], 1);
    vm.set(state, c"cache");
    vm.assign(GLOBALS, c"ring_host_cache", module);
    vm.push(state);
    vm.closure(selected_record, 1);
    vm.set(GLOBALS, c"automate_host_record");
}
