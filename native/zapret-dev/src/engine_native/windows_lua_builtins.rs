//! Publish the standard Rust rules without evaluating the compatibility scripts.
use super::*;

#[path = "windows_lua_tls_names.rs"]
mod tls;

const REGISTRY: c_int = -10_000;
const INSTALLED: &CStr = c"zapret.builtin_rules";

fn install_rules(vm: Stack, bind: Callback, compare: bool) {
    let top = vm.top();
    vm.boolean(true);
    vm.closure(bind, 1);
    if compare {
        vm.closure(less_equal, 0);
    }
    vm.call(c_int::from(compare), 1);
    let table = vm.top();
    vm.nil();
    while unsafe { lua_next(vm.0, table) } != 0 {
        vm.push(GLOBALS);
        vm.set_item(vm.top(), table + 1, table + 2);
        vm.reset(table + 1);
    }
    vm.reset(top);
}

fn metamethod(vm: Stack, index: c_int, name: &CStr) -> Option<c_int> {
    if unsafe { lua_getmetatable(vm.0, index) } == 0 {
        return None;
    }
    vm.bytes(name.to_bytes());
    unsafe { lua_rawget(vm.0, -2) };
    (vm.kind(-1) != NIL).then(|| vm.top())
}

fn compare(vm: Stack, name: &CStr, first: c_int, second: c_int) -> Option<bool> {
    let left = metamethod(vm, first, name)?;
    let right = metamethod(vm, second, name)?;
    if unsafe { lua_rawequal(vm.0, left, right) } == 0 {
        return None;
    }
    vm.push(left);
    vm.push(first);
    vm.push(second);
    vm.call(2, 1);
    Some(vm.truth(-1))
}

unsafe extern "C-unwind" fn less_equal(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    let top = vm.top();
    let result = match (vm.kind(1), vm.kind(2)) {
        (NUMBER, NUMBER) => vm.number(1) <= vm.number(2),
        (STRING, STRING) => !vm.less(2, 1),
        (first, second) if first == second => {
            if let Some(value) = compare(vm, c"__le", 1, 2) {
                value
            } else {
                vm.reset(top);
                let Some(value) = compare(vm, c"__lt", 2, 1) else {
                    return vm.error(c"cannot compare rule arguments");
                };
                !value
            }
        }
        _ => return vm.error(c"cannot compare rule arguments"),
    };
    vm.boolean(result);
    1
}

fn publish_constants(vm: Stack) {
    vm.integer(6);
    vm.set(GLOBALS, c"NFQWS2_COMPAT_VER_REQUIRED");
    if !vm.truth(vm.field(GLOBALS, c"HEXDUMP_DLOG_MAX")) {
        vm.integer(32);
        vm.set(GLOBALS, c"HEXDUMP_DLOG_MAX");
    }
    for (name, mask) in [(c"NOT3", 3), (c"NOT7", 7)] {
        vm.integer(mask);
        vm.call_global(c"bitnot", &[vm.top()], 1);
        vm.set(GLOBALS, name);
    }
    tls::publish(vm);
    let pid = vm.call_global(c"getpid", &[], 1);
    let tid = vm.call_global(c"gettid", &[], 1);
    let seconds = vm.call_global(c"clock_gettime", &[], 1);
    let seed = vm.call_global(c"bitxor", &[pid, tid, seconds], 1);
    let math = vm.field(GLOBALS, c"math");
    vm.call_field(math, c"randomseed", &[seed], 0);
}

pub(super) unsafe fn initialize(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 40) };
    if vm.truth(vm.field(REGISTRY, INSTALLED)) {
        return 0;
    }
    let native = vm.field(GLOBALS, c"zapret_ring_native");
    if !vm.text_is(vm.field(native, c"backend"), b"Rust")
        || vm.number(vm.field(native, c"api_version")) != 1.0
        || vm.number(vm.field(GLOBALS, c"NFQWS2_COMPAT_VER")) != 6.0
    {
        return vm.error(c"unsupported engine or Rust ring ABI");
    }
    vm.reset(native);
    publish_constants(vm);
    vm.reset(native);
    install_rules(vm, windows_lua_lib_utils::bind, false);
    install_rules(vm, windows_lua_automation::bind, true);
    install_rules(vm, windows_lua_packet_library::bind, true);
    install_rules(vm, windows_lua_strategies::bind, true);
    vm.assign(
        GLOBALS,
        c"is_absolute_path",
        vm.field(native, c"windows_absolute_path"),
    );
    vm.closure(windows_lua_fooling::bind, 0);
    vm.field(native, c"tcp_fallback");
    vm.field(native, c"host_split");
    vm.call(2, 2);
    vm.set(GLOBALS, c"hostfakesplit_alt");
    vm.set(GLOBALS, c"ts_or_md5");
    vm.closure(windows_lua_rotation::circular, 0);
    vm.set(GLOBALS, c"circular");

    for install in [
        windows_lua_host_cache::install,
        windows_lua_store::install,
        windows_lua_autoring::install,
    ] {
        vm.reset(native);
        install(vm, native);
    }
    let modules = vm.field(GLOBALS, c"zapret_native_modules");
    vm.boolean(true);
    vm.set(modules, c"bundled_rules_installed");
    vm.boolean(true);
    vm.set(REGISTRY, INSTALLED);
    0
}
