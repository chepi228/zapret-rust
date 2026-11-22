//! Execute the ring store's existing Rust effect and timer transitions on LuaJIT.
use super::*;

fn state() -> c_int {
    capture(1)
}

fn effect(vm: Stack, name: &[u8], args: &[c_int], results: c_int) -> c_int {
    vm.field(state(), c"effect");
    vm.bytes(name);
    for &arg in args {
        vm.push(arg);
    }
    vm.call(1 + args.len() as c_int, results);
    vm.top()
}

fn scheduler(vm: Stack, name: &[u8], args: &[c_int], results: c_int) -> c_int {
    vm.field(state(), c"scheduler");
    vm.field(state(), c"timer_context");
    vm.bytes(name);
    for &arg in args {
        vm.push(arg);
    }
    vm.call(2 + args.len() as c_int, results);
    vm.top()
}

fn backend(vm: Stack, name: &CStr, args: &[c_int], results: c_int) -> c_int {
    vm.field(state(), c"native");
    let table = vm.top();
    vm.call_field(table, name, args, results);
    for index in 0..results {
        vm.push(table + index + 1);
        vm.replace(table + index);
    }
    vm.reset(table - 1 + results);
    vm.top()
}

fn callback(vm: Stack, function: Callback) {
    vm.push(state());
    vm.closure(function, 1);
}

fn clear_roots(vm: Stack) {
    vm.table(0);
    vm.set(state(), c"roots");
}

fn remove_root(vm: Stack, serial: c_int) {
    let top = vm.top();
    let roots = vm.field(state(), c"roots");
    vm.nil();
    vm.set_item(roots, serial, vm.top());
    vm.reset(top);
}

fn log(vm: Stack, error: c_int, retry: bool) {
    let top = vm.top();
    let error = if retry {
        vm.call_global(c"tostring", &[error], 1);
        vm.field(state(), c"retry_suffix");
        vm.concat(2);
        vm.top()
    } else {
        error
    };
    let logger = vm.field(GLOBALS, c"DLOG_ERR");
    if vm.kind(logger) == FUNCTION {
        vm.field(state(), c"log_prefix");
        vm.call_global(c"tostring", &[error], 1);
        vm.concat(2);
        vm.protected(logger, &[vm.top()]);
    }
    vm.reset(top);
}

fn commit(vm: Stack, store: c_int, ok: bool, mono: c_int) {
    let native = vm.field(store, c"native");
    vm.boolean(ok);
    backend(vm, c"store_commit", &[native, vm.top(), mono], 0);
}

fn after(vm: Stack, operation: &[u8], ok: c_int, err: c_int, store: c_int, mono: c_int) {
    let top = vm.top();
    vm.bytes(operation);
    let operation = vm.top();
    let last = effect(vm, b"after_plan", &[operation, ok], 2);
    for index in [last - 1, last] {
        let top = vm.top();
        if vm.text_is(index, b"legacy_commit") {
            let now = vm.call_global(c"clock_getfloattime", &[], 1);
            commit(vm, store, true, now);
        } else if vm.text_is(index, b"legacy_discard") {
            backend(vm, c"store_discard", &[vm.field(store, c"native")], 0);
        } else if vm.text_is(index, b"defer") {
            commit(vm, store, false, mono);
        } else if vm.text_is(index, b"log") {
            log(vm, err, false);
        } else if vm.text_is(index, b"clear") {
            scheduler(vm, b"clear", &[], 0);
            clear_roots(vm);
        }
        vm.reset(top);
    }
    vm.reset(top);
}

fn snapshot(vm: Stack, store: c_int) -> c_int {
    let native = vm.field(store, c"native");
    vm.field(store, c"now");
    vm.call(0, 1);
    backend(vm, c"store_snapshot", &[native, vm.top()], 1)
}

unsafe extern "C-unwind" fn default_validation(lua: *mut LuaState) -> c_int {
    unsafe { Stack::enter(lua, 1) }.boolean(false);
    1
}

unsafe extern "C-unwind" fn arm(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 16) };
    let timer = vm.field(GLOBALS, c"timer_set");
    vm.boolean(vm.kind(timer) == FUNCTION);
    let error = effect(vm, b"timer_check", &[vm.top()], 1);
    if vm.truth(error) {
        vm.call_global(c"error", &[error], 0);
    }
    let name = vm.field(state(), c"timer_name");
    let run = vm.field(state(), c"timer");
    let delay = vm.field(state(), c"timer_delay");
    let once = vm.field(state(), c"timer_once");
    vm.tail_global(c"timer_set", &[name, run, delay, once])
}

fn schedule(vm: Stack) {
    let top = vm.top();
    if vm.truth(scheduler(vm, b"wants_timer", &[], 1)) {
        let now = vm.call_global(c"clock_getfloattime", &[], 1);
        if !vm.truth(scheduler(vm, b"prepare_timer", &[now], 1)) {
            clear_roots(vm);
        } else {
            callback(vm, arm);
            let error = vm.protected(vm.top(), &[]);
            vm.boolean(false);
            vm.boolean(vm.equal(error, -1));
            let success = effect(vm, b"timer_success", &[error - 1, vm.top()], 1);
            let warnings = scheduler(vm, b"timer_result", &[now, success], 1);
            if !vm.truth(success) {
                clear_roots(vm);
                let count = vm.arithmetic_number(warnings) as usize;
                for _ in 0..count {
                    log(vm, error, false);
                }
            }
        }
    }
    vm.reset(top);
}

fn update(vm: Stack, changed: Option<c_int>) {
    let top = vm.top();
    let handle = vm.field(1, c"native");
    let serial = if let Some(changed) = changed {
        let legacy = vm.field(1, c"legacy");
        vm.boolean(vm.truth(legacy));
        let legacy = vm.top();
        let file = vm.field(1, c"file");
        vm.boolean(vm.truth(file));
        scheduler(
            vm,
            b"prepare_update",
            &[handle, legacy, vm.top(), changed],
            2,
        )
    } else {
        scheduler(vm, b"prepare_update", &[handle], 2)
    };
    if vm.truth(serial - 1) {
        let writer = vm.field(GLOBALS, c"writefile");
        let file = vm.field(1, c"file");
        let value = snapshot(vm, 1);
        let err = vm.protected(writer, &[file, value]);
        after(vm, b"legacy", err - 1, err, 1, 0);
    }
    if vm.truth(serial) {
        vm.set_item(vm.field(state(), c"roots"), serial, 1);
        if vm.truth(scheduler(vm, b"retain", &[handle], 1)) {
            schedule(vm);
        } else {
            remove_root(vm, serial);
        }
    }
    vm.reset(top);
}

unsafe extern "C-unwind" fn discard(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    let serial = scheduler(vm, b"discard", &[vm.field(1, c"native")], 1);
    if vm.truth(serial) {
        remove_root(vm, serial);
    }
    0
}

fn legal_key(vm: Stack, put: bool) -> bool {
    vm.boolean(put);
    let first = vm.top();
    let string = vm.kind(2) == STRING;
    vm.boolean(string);
    vm.integer(if put && string {
        vm.length(2) as isize
    } else {
        0
    });
    vm.truth(effect(vm, b"key", &[first, first + 1, first + 2], 1))
}

fn push_finite(vm: Stack, source: c_int) {
    if vm.kind(source) == NUMBER && vm.number(source).is_finite() {
        vm.push(source);
    } else {
        vm.nil();
    }
}

fn reading(vm: Stack, write: bool) -> c_int {
    let handle = vm.field(1, c"native");
    vm.field(1, c"now");
    vm.call(0, 1);
    let clock = vm.top();
    let now = vm.call_global(c"clock_getfloattime", &[], 1);
    if write {
        backend(vm, c"store_put", &[handle, 2, 3, clock, now], 1)
    } else {
        backend(vm, c"store_get", &[handle, 2, clock, now], 1)
    }
}

unsafe extern "C-unwind" fn get(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 70) };
    vm.pad_arguments(2);
    if !legal_key(vm, false) {
        vm.nil();
        return 1;
    }
    let value = reading(vm, false);
    update(vm, None);
    vm.push(value);
    1
}

unsafe extern "C-unwind" fn put(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 88) };
    vm.pad_arguments(3);
    if legal_key(vm, true) {
        vm.field(2, c"find");
        vm.push(2);
        vm.bytes(b"%s");
        vm.call(2, 1);
        let whitespace = vm.truth(-1);
        let absent = vm.kind(3) == NIL;
        vm.boolean(whitespace);
        let first = vm.top();
        vm.boolean(absent);
        if !whitespace && !absent {
            push_finite(vm, 3)
        } else {
            vm.nil()
        }
        if vm.truth(effect(vm, b"value", &[first, first + 1, first + 2], 1)) {
            let changed = reading(vm, true);
            update(vm, Some(changed));
            vm.push(changed);
            return 1;
        }
    }
    vm.boolean(false);
    1
}

unsafe extern "C-unwind" fn atomic_write(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 42) };
    let top = vm.top();
    vm.nil();
    let action = vm.top();
    vm.nil();
    let message = vm.top();
    vm.nil();
    let detail = vm.top();
    let mut ok = false;
    loop {
        vm.boolean(ok);
        let status = vm.top();
        vm.boolean(vm.truth(detail));
        let next = effect(vm, b"atomic", &[action, status, vm.top()], 2);
        vm.push(next - 1);
        vm.replace(action);
        vm.push(next);
        vm.replace(message);
        vm.reset(detail);
        if !vm.truth(action) {
            break;
        }
        if vm.text_is(action, b"write") {
            vm.call_global(c"writefile", &[vm.field(1, c"temp"), 2], 0);
        } else if vm.text_is(action, b"verify") {
            let read = vm.call_global(c"readfile", &[vm.field(1, c"temp")], 1);
            ok = vm.equal(read, 2);
        } else if vm.text_is(action, b"rename") {
            vm.path(GLOBALS, &[c"os", c"rename"]);
            vm.field(1, c"temp");
            vm.field(1, c"file");
            vm.call(2, 2);
            vm.replace(detail);
            ok = vm.truth(-1);
        } else {
            let reason = if vm.truth(message) { message } else { detail };
            vm.call_global(c"error", &[reason], 0);
        }
        vm.reset(detail);
    }
    vm.reset(top);
    0
}

unsafe extern "C-unwind" fn publish(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 50) };
    vm.nil();
    let action = vm.top();
    vm.nil();
    let value = vm.top();
    vm.nil();
    let text = vm.top();
    let mut ok = false;
    loop {
        vm.boolean(ok);
        let status = vm.top();
        vm.boolean(true);
        vm.boolean(vm.equal(value, -1));
        effect(vm, b"publish", &[action, status, vm.top()], 1);
        vm.replace(action);
        vm.reset(text);
        if !vm.truth(action) {
            break;
        }
        if vm.text_is(action, b"validate") {
            let validator = vm.field(1, c"validate");
            let result = vm.protected(validator, &[]);
            ok = vm.truth(result - 1);
            vm.replace(value);
        } else if vm.text_is(action, b"snapshot") {
            snapshot(vm, 1);
            vm.replace(text);
        } else if vm.text_is(action, b"discard") {
            vm.call_method(1, c"discard", &[], 0);
        } else if vm.text_is(action, b"atomic") {
            callback(vm, atomic_write);
            let result = vm.protected(vm.top(), &[1, text]);
            ok = vm.truth(result - 1);
            vm.replace(value);
        } else if vm.text_is(action, b"commit") {
            commit(vm, 1, ok, 2);
        } else if vm.text_is(action, b"remove") {
            let remove = vm.path(GLOBALS, &[c"os", c"remove"]);
            vm.protected(remove, &[vm.field(1, c"temp")]);
        } else if vm.text_is(action, b"retry_log") {
            log(vm, value, true);
        }
        vm.reset(text);
    }
    0
}

unsafe extern "C-unwind" fn dispatch(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 64) };
    let now = vm.call_global(c"clock_getfloattime", &[], 1);
    let serial = scheduler(vm, b"select", &[now], 1);
    loop {
        let retired = scheduler(vm, b"retired", &[], 1);
        if !vm.truth(retired) {
            break;
        }
        remove_root(vm, retired);
        vm.reset(serial);
    }
    if vm.truth(serial) {
        let store = vm.item(vm.field(state(), c"roots"), serial);
        callback(vm, publish);
        let result = vm.protected(vm.top(), &[store, now]);
        after(vm, b"flush", result - 1, result, store, now);
        let removed = scheduler(vm, b"finish", &[vm.field(store, c"native")], 1);
        if vm.truth(removed) {
            remove_root(vm, removed);
        }
    }
    0
}

unsafe extern "C-unwind" fn timer(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 42) };
    scheduler(vm, b"fired", &[], 0);
    callback(vm, dispatch);
    let result = vm.protected(vm.top(), &[]);
    after(vm, b"dispatch", result - 1, result, 0, 0);
    schedule(vm);
    0
}

fn store_limit(vm: Stack, limits: c_int, index: c_int) {
    let top = vm.top();
    let names = vm.field(state(), c"limit_names");
    let name = vm.array_item(names, index as usize);
    let value = vm.item(1, name);
    vm.integer(index as isize);
    let ordinal = vm.top();
    vm.boolean(!vm.truth(value));
    push_finite(vm, value);
    let result = effect(vm, b"limit", &[ordinal, ordinal + 1, ordinal + 2], 1);
    let invalid = vm.field(state(), c"invalid_limit");
    let limit = vm.call_global(c"assert", &[result, invalid], 1);
    vm.raw_array_put(limits, index, limit);
    vm.reset(top);
}

unsafe extern "C-unwind" fn create(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 75) };
    vm.pad_arguments(1);
    if !vm.truth(1) {
        vm.table(0);
        vm.replace(1);
    }
    let file = vm.field(1, c"file");
    let mut now = vm.field(1, c"now");
    if !vm.truth(now) {
        now = vm.call_field(state(), c"make_clock", &[], 1);
    }
    let limits = vm.table(0);
    for index in 1..=3 {
        store_limit(vm, limits, index);
    }
    vm.boolean(vm.kind(file) != NIL);
    let provided = vm.top();
    vm.boolean(vm.truth(file));
    let construction = effect(vm, b"construction", &[provided, vm.top()], 2);
    let read = vm.truth(construction - 1);
    vm.nil();
    let text = vm.top();
    if read {
        let reader = vm.field(GLOBALS, c"readfile");
        let value = vm.protected(reader, &[file]);
        let string = vm.truth(value - 1) && vm.kind(value) == STRING;
        vm.boolean(string);
        let is_string = vm.top();
        vm.integer(if string { vm.length(value) as isize } else { 0 });
        let size = vm.top();
        let bound = vm.array_item(limits, 2);
        let action = effect(vm, b"initial_file", &[value - 1, is_string, size, bound], 1);
        if vm.text_is(action, b"borrow") {
            vm.push(value);
            vm.replace(text);
        } else if vm.text_is(action, b"empty") {
            vm.bytes(b"");
            vm.replace(text);
        }
        vm.reset(text);
    }
    let store = vm.table(6);
    let first = vm.array_item(limits, 1);
    let bytes = vm.array_item(limits, 2);
    let ttl = vm.array_item(limits, 3);
    vm.push(now);
    vm.call(0, 1);
    let wall = vm.top();
    let legacy = vm.field(1, c"legacy");
    vm.boolean(true);
    vm.boolean(vm.equal(legacy, -1));
    backend(
        vm,
        c"store_new",
        &[first, bytes, ttl, construction, text, wall, vm.top()],
        1,
    );
    vm.set(store, c"native");
    vm.assign(store, c"file", file);
    vm.assign(store, c"now", now);
    let enabled = vm.field(1, c"legacy");
    vm.boolean(vm.equal(enabled, legacy + 1));
    vm.set(store, c"legacy");
    let validate = vm.field(1, c"validate");
    if vm.truth(validate) {
        vm.push(validate)
    } else {
        vm.closure(default_validation, 0)
    }
    vm.set(store, c"validate");
    if read {
        vm.push(file);
        vm.field(state(), c"temp_suffix");
        let getpid = vm.field(GLOBALS, c"getpid");
        if vm.kind(getpid) == FUNCTION {
            vm.call(0, 1);
        } else {
            vm.integer(0);
            vm.replace(getpid);
        }
        vm.call_global(c"tostring", &[getpid], 1);
        vm.replace(getpid);
        vm.concat(3);
        vm.set(store, c"temp");
    }
    vm.call_field(state(), c"attach", &[store], 1);
    1
}

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 6) };
    if vm.kind(1) != TABLE {
        return vm.error(c"ring store requires a state table");
    }
    let functions: &[(&CStr, Callback)] = &[
        (c"new", create),
        (c"get", get),
        (c"put", put),
        (c"discard", discard),
        (c"timer", timer),
    ];
    let module = vm.table(functions.len() as c_int);
    for &(name, function) in functions {
        vm.push(1);
        vm.closure(function, 1);
        vm.set(module, name);
    }
    1
}

unsafe extern "C-unwind" fn clock(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 3) };
    vm.path(GLOBALS, &[c"os", c"time"]);
    vm.call(0, 1);
    1
}

unsafe extern "C-unwind" fn make_clock(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 1) };
    vm.closure(clock, 0);
    1
}

unsafe extern "C-unwind" fn index(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    if vm.kind(2) == NIL {
        return 0;
    }
    let methods = vm.field(state(), c"methods");
    let method = vm.item(methods, 2);
    if vm.truth(method) {
        return 1;
    }
    let stats = vm.field(state(), c"stats");
    let field = vm.item(stats, 2);
    if !vm.truth(field) {
        return 0;
    }
    let store = vm.field(1, c"native");
    backend(vm, c"store_stat", &[store, field], 1);
    1
}

unsafe extern "C-unwind" fn attach(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 2) };
    vm.field(state(), c"metatable");
    unsafe { lua_setmetatable(lua, 1) };
    vm.push(1);
    1
}

pub(super) fn install(vm: Stack, native: c_int) {
    let state = vm.table(13);
    for name in [c"store_scheduler", c"store_effect"] {
        if vm.kind(vm.field(native, name)) != FUNCTION {
            vm.error(c"unsupported ring store bridge");
        }
    }
    vm.assign(state, c"native", native);
    for (name, source) in [
        (c"scheduler", c"store_scheduler"),
        (c"effect", c"store_effect"),
    ] {
        vm.assign(state, name, vm.field(native, source));
    }
    vm.integer(0);
    vm.call_field(native, c"context_new", &[vm.top()], 1);
    vm.set(state, c"timer_context");
    vm.table(0);
    vm.set(state, c"roots");
    vm.bytes(b"metadata");
    let last = vm.call_field(native, c"store_effect", &[vm.top()], 7);
    for (offset, name) in [
        c"invalid_limit",
        c"temp_suffix",
        c"timer_name",
        c"timer_delay",
        c"timer_once",
        c"log_prefix",
        c"retry_suffix",
    ]
    .into_iter()
    .enumerate()
    {
        vm.assign(state, name, last - 6 + offset as c_int);
    }
    vm.reset(state);
    vm.bytes(b"schema");
    let last = vm.call_field(native, c"store_effect", &[vm.top()], 7);
    let limits = vm.table(0);
    for ordinal in 1..=3 {
        vm.raw_array_put(limits, ordinal, last - 7 + ordinal);
    }
    vm.set(state, c"limit_names");
    let stats = vm.table(4);
    for ordinal in 1..=4 {
        vm.integer(ordinal as isize);
        vm.set_item(stats, last - 4 + ordinal, vm.top());
        vm.reset(stats);
    }
    vm.set(state, c"stats");
    vm.reset(state);
    vm.closure(make_clock, 0);
    vm.set(state, c"make_clock");
    for (name, function) in [(c"attach", attach as Callback), (c"timer", timer)] {
        vm.push(state);
        vm.closure(function, 1);
        vm.set(state, name);
    }
    let methods = vm.table(3);
    for (name, function) in [
        (c"get", get as Callback),
        (c"put", put),
        (c"discard", discard),
    ] {
        vm.push(state);
        vm.closure(function, 1);
        vm.set(methods, name);
    }
    vm.set(state, c"methods");
    let metatable = vm.table(1);
    vm.push(state);
    vm.closure(index, 1);
    vm.set(metatable, c"__index");
    vm.set(state, c"metatable");
    let module = vm.table(2);
    vm.bytes(b"Rust");
    vm.set(module, c"backend");
    vm.push(state);
    vm.closure(create, 1);
    vm.set(module, c"new");
    vm.set(GLOBALS, c"ring_store");
}
