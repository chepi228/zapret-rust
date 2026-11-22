//! Read profile context and retain per-profile stores in the LuaJIT registry.
use super::*;

fn state() -> c_int {
    capture(1)
}

fn backend(vm: Stack, name: &CStr, args: &[c_int], results: c_int) -> c_int {
    vm.call_field(vm.field(state(), c"native"), name, args, results)
}

fn wall_clock(vm: Stack) -> c_int {
    vm.path(GLOBALS, &[c"os", c"time"]);
    vm.call(0, 1);
    vm.top()
}

fn writable(vm: Stack) -> c_int {
    vm.path(GLOBALS, &[c"os", c"getenv"]);
    vm.bytes(b"WRITABLE");
    vm.call(1, 1);
    vm.top()
}

fn read_marker(vm: Stack, dir: c_int, filename: &[u8]) -> c_int {
    let reader = vm.field(GLOBALS, c"readfile");
    vm.push(dir);
    vm.bytes(filename);
    vm.concat(2);
    let text = vm.protected(reader, &[vm.top()]);
    if !vm.truth(text - 1) {
        vm.nil();
        vm.replace(text);
    }
    text
}

fn profile_state(vm: Stack, desync: c_int) -> c_int {
    let value = vm.path(desync, &[c"arg", c"state"]);
    if !vm.truth(value) {
        vm.bytes(b"");
        vm.replace(value);
    }
    value
}

#[derive(Clone, Copy)]
enum Marker {
    Network,
    Link,
}

fn poll(vm: Stack, desync: c_int, force: bool, which: Marker) -> c_int {
    let link = matches!(which, Marker::Link);
    let context = vm.field(state(), c"context");
    let mono = vm.call_global(c"clock_getfloattime", &[], 1);
    let profile = profile_state(vm, desync);
    vm.boolean(force);
    let force_value = vm.top();
    vm.boolean(link);
    let link_value = vm.top();
    let observed = backend(
        vm,
        c"context_poll",
        &[context, profile, mono, force_value, link_value],
        6,
    );
    if !vm.truth(observed - 5) {
        return observed - 4;
    }
    let dir = writable(vm);
    let allowed = vm.truth(dir)
        && (link
            || vm.text_is(
                vm.path(desync, &[c"arg", c"context"]),
                b"network-context.txt",
            ));
    let text = if allowed {
        read_marker(
            vm,
            dir,
            if link {
                b"/link-guard.txt"
            } else {
                b"/network-context.txt"
            },
        )
    } else {
        vm.nil();
        vm.top()
    };
    let wall = wall_clock(vm);
    backend(
        vm,
        c"context_observe",
        &[context, text, wall, mono, link_value],
        0,
    );
    let profile = profile_state(vm, desync);
    backend(vm, c"context_read", &[context, profile, mono], 5) - 4
}

fn network(vm: Stack, desync: c_int, force: bool) -> c_int {
    if !vm.truth(vm.path(desync, &[c"arg", c"context"])) {
        vm.bytes(b"legacy");
        vm.integer(0);
        return vm.top() - 1;
    }
    let key = poll(vm, desync, force, Marker::Network);
    vm.assign(state(), c"network_epoch", key + 2);
    key
}

unsafe extern "C-unwind" fn context(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 61) };
    vm.pad_arguments(2);
    vm.boolean(true);
    let key = network(vm, 1, vm.equal(2, -1));
    vm.push(key);
    vm.push(key + 1);
    2
}

unsafe extern "C-unwind" fn link_context(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 61) };
    vm.pad_arguments(1);
    let file = vm.path(1, &[c"arg", c"link_guard"]);
    if vm.text_is(file, b"link-guard.txt") {
        let key = poll(vm, 1, false, Marker::Link);
        vm.push(key + 3);
        vm.push(key + 4);
    } else {
        vm.integer(0);
        vm.boolean(false);
    }
    2
}

unsafe extern "C-unwind" fn state_path(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(3);
    if vm.kind(1) == STRING && vm.kind(2) == STRING && vm.kind(3) == STRING {
        let top = vm.top();
        let backend = vm.field(state(), c"native");
        vm.call_field(backend, c"state_path", &[1, 2, 3], MULTRET);
        return vm.top() - top - 1;
    }
    vm.nil();
    1
}

fn saved_file(vm: Stack, dir: c_int, name: c_int, key: c_int) -> c_int {
    if vm.truth(dir) && vm.truth(name) {
        if vm.truth(vm.path(1, &[c"arg", c"context"])) {
            let file = vm.call_global(c"ring_state_path", &[dir, name, key], 1);
            if vm.truth(file) {
                return file;
            }
        }
        if !vm.truth(vm.path(1, &[c"arg", c"context"])) {
            let file = backend(vm, c"legacy_state_path", &[dir, name], 1);
            if vm.truth(file) {
                return file;
            }
        }
    }
    vm.nil();
    vm.top()
}

fn options(vm: Stack, file: c_int, key: c_int, name: c_int) -> c_int {
    let opts = vm.table(4);
    vm.assign(opts, c"file", file);
    vm.boolean(!vm.truth(vm.path(1, &[c"arg", c"context"])));
    vm.set(opts, c"legacy");
    if vm.truth(vm.path(1, &[c"arg", c"context"])) {
        vm.field(state(), c"epoch_clock");
        vm.set(opts, c"now");
    }
    let probe = vm.table(1);
    let arg = vm.table(2);
    vm.assign(arg, c"state", name);
    vm.path(1, &[c"arg", c"context"]);
    vm.set(arg, c"context");
    vm.set(probe, c"arg");
    vm.call_field(state(), c"validator", &[probe, key, key + 1], 1);
    vm.set(opts, c"validate");
    opts
}

unsafe extern "C-unwind" fn memory(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 121) };
    vm.pad_arguments(1);
    let key = vm.path(1, &[c"arg", c"key"]);
    let key = if vm.truth(key) {
        key
    } else {
        vm.field(1, c"func_instance")
    };
    let current = network(vm, 1, false);
    let memory = vm.field(state(), c"memory");
    let old = vm.item(memory, key);
    if vm.truth(old) {
        if vm.equal(vm.field(old, c"revision"), current + 1)
            && vm.equal(vm.field(old, c"context"), current)
        {
            vm.push(old);
            return 1;
        }
        let store = vm.field(old, c"store");
        vm.call_method(store, c"discard", &[], 0);
    }
    let dir = writable(vm);
    let name = vm.path(1, &[c"arg", c"state"]);
    let file = saved_file(vm, dir, name, current);
    let opts = options(vm, file, current, name);
    let ring_store = vm.field(GLOBALS, c"ring_store");
    let store = vm.call_field(ring_store, c"new", &[opts], 1);
    let result = vm.table(3);
    vm.assign(result, c"store", store);
    vm.assign(result, c"context", current);
    vm.assign(result, c"revision", current + 1);
    vm.set_item(memory, key, result);
    1
}

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    if vm.kind(1) != TABLE {
        return vm.error(c"ring context requires a state table");
    }
    let entries: &[(&CStr, Callback)] = &[
        (c"context", context),
        (c"link_context", link_context),
        (c"memory", memory),
        (c"state_path", state_path),
    ];
    let module = vm.table(entries.len() as c_int);
    for &(name, function) in entries {
        vm.push(1);
        vm.closure(function, 1);
        vm.set(module, name);
    }
    1
}

unsafe extern "C-unwind" fn epoch_clock(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 2) };
    vm.field(state(), c"network_epoch");
    1
}

unsafe extern "C-unwind" fn validates_epoch(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 61) };
    let key = network(vm, capture(2), true);
    vm.boolean(
        vm.kind(capture(3)) != NIL && vm.equal(key, capture(3)) && vm.equal(key + 1, capture(4)),
    );
    1
}

unsafe extern "C-unwind" fn validator(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    vm.push(state());
    vm.push(1);
    vm.push(2);
    vm.push(3);
    vm.closure(validates_epoch, 4);
    1
}

pub(super) fn install(vm: Stack, native: c_int) -> (c_int, c_int) {
    let state = vm.table(6);
    vm.assign(state, c"native", native);
    let now = wall_clock(vm);
    vm.call_field(native, c"context_new", &[now], 1);
    vm.set(state, c"context");
    vm.table(0);
    vm.set(state, c"memory");
    vm.integer(0);
    vm.set(state, c"network_epoch");
    for (name, function) in [
        (c"epoch_clock", epoch_clock as Callback),
        (c"validator", validator),
    ] {
        vm.push(state);
        vm.closure(function, 1);
        vm.set(state, name);
    }
    vm.assign(
        GLOBALS,
        c"ring_network_key",
        vm.field(native, c"network_key"),
    );
    vm.assign(GLOBALS, c"ring_link_guard", vm.field(native, c"link_guard"));
    vm.push(state);
    vm.closure(state_path, 1);
    vm.set(GLOBALS, c"ring_state_path");
    vm.push(state);
    vm.closure(memory, 1);
    vm.push(state);
    vm.closure(link_context, 1);
    (vm.top() - 1, vm.top())
}
