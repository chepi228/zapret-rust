//! Rust implementations of bundled modules. LuaJIT owns all VM values.
#[path = "windows_lua_automation.rs"]
mod windows_lua_automation;
#[path = "windows_lua_autoring.rs"]
mod windows_lua_autoring;
#[path = "windows_lua_builtins.rs"]
mod windows_lua_builtins;
#[path = "windows_lua_fooling.rs"]
mod windows_lua_fooling;
#[path = "windows_lua_header_policy.rs"]
mod windows_lua_header_policy;
#[path = "windows_lua_host_cache.rs"]
mod windows_lua_host_cache;
#[path = "windows_lua_http_library.rs"]
mod windows_lua_http_library;
#[path = "windows_lua_ip_frag.rs"]
mod windows_lua_ip_frag;
#[path = "windows_lua_ip_helpers.rs"]
mod windows_lua_ip_helpers;
#[path = "windows_lua_lib_utils.rs"]
mod windows_lua_lib_utils;
#[path = "windows_lua_library_files.rs"]
mod windows_lua_library_files;
#[path = "windows_lua_packet_library.rs"]
mod windows_lua_packet_library;
#[path = "windows_lua_plan.rs"]
mod windows_lua_plan;
#[path = "windows_lua_ring_context.rs"]
mod windows_lua_ring_context;
#[path = "windows_lua_rotation.rs"]
mod windows_lua_rotation;
#[path = "windows_lua_rule_data.rs"]
mod windows_lua_rule_data;
#[path = "windows_lua_stock.rs"]
mod windows_lua_stock;
#[path = "windows_lua_store.rs"]
mod windows_lua_store;
#[path = "windows_lua_strategies.rs"]
mod windows_lua_strategies;
#[path = "windows_lua_tls_library.rs"]
mod windows_lua_tls_library;

use super::LuaState;
use core::{
    ffi::{CStr, c_char, c_int, c_void},
    slice,
};

const GLOBALS: c_int = -10_002;
const NIL: c_int = 0;
const BOOLEAN: c_int = 1;
const NUMBER: c_int = 3;
const STRING: c_int = 4;
const TABLE: c_int = 5;
const FUNCTION: c_int = 6;
const MULTRET: c_int = -1;

type Callback = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;

unsafe extern "C-unwind" {
    fn luaL_checkstack(lua: *mut LuaState, size: c_int, message: *const c_char);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tonumber(lua: *mut LuaState, index: c_int) -> f64;
    fn lua_isnumber(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushnumber(lua: *mut LuaState, value: f64);
    fn luaL_checknumber(lua: *mut LuaState, index: c_int) -> f64;
    fn lua_objlen(lua: *mut LuaState, index: c_int) -> usize;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const u8;
    fn lua_equal(lua: *mut LuaState, first: c_int, second: c_int) -> c_int;
    fn lua_lessthan(lua: *mut LuaState, first: c_int, second: c_int) -> c_int;
    fn lua_pushvalue(lua: *mut LuaState, index: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushlstring(lua: *mut LuaState, value: *const u8, size: usize);
    fn lua_pushcclosure(lua: *mut LuaState, function: Callback, upvalues: c_int);
    fn lua_replace(lua: *mut LuaState, index: c_int);
    fn lua_rawgeti(lua: *mut LuaState, index: c_int, item: c_int);
    fn lua_rawget(lua: *mut LuaState, index: c_int);
    fn lua_rawseti(lua: *mut LuaState, index: c_int, item: c_int);
    fn lua_insert(lua: *mut LuaState, index: c_int);
    fn lua_next(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_gettable(lua: *mut LuaState, index: c_int);
    fn lua_setfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_settable(lua: *mut LuaState, index: c_int);
    fn lua_createtable(lua: *mut LuaState, array: c_int, records: c_int);
    fn lua_getmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_setmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_rawequal(lua: *mut LuaState, first: c_int, second: c_int) -> c_int;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_call(lua: *mut LuaState, arguments: c_int, results: c_int);
    fn lua_pcall(lua: *mut LuaState, arguments: c_int, results: c_int, error: c_int) -> c_int;
    fn lua_concat(lua: *mut LuaState, count: c_int);
}

const fn capture(slot: c_int) -> c_int {
    GLOBALS - slot
}

// Indices refer to the current callback frame. A frame owns no Rust resources
// when a protected LuaJIT error crosses its Win64 SEH boundary.
#[derive(Clone, Copy)]
struct Stack(*mut LuaState);

impl Stack {
    unsafe fn enter(lua: *mut LuaState, slots: c_int) -> Self {
        unsafe { luaL_checkstack(lua, slots, c"native module".as_ptr()) };
        Self(lua)
    }

    fn top(self) -> c_int {
        unsafe { lua_gettop(self.0) }
    }

    fn pad_arguments(self, count: c_int) {
        if self.top() < count {
            self.reset(count);
        }
    }

    fn reset(self, top: c_int) {
        unsafe { lua_settop(self.0, top) };
    }

    fn kind(self, index: c_int) -> c_int {
        unsafe { lua_type(self.0, index) }
    }

    fn truth(self, index: c_int) -> bool {
        unsafe { lua_toboolean(self.0, index) != 0 }
    }

    fn number(self, index: c_int) -> f64 {
        unsafe { lua_tonumber(self.0, index) }
    }

    fn arithmetic_number(self, index: c_int) -> f64 {
        unsafe { luaL_checknumber(self.0, index) }
    }

    fn numeric(self, index: c_int) -> bool {
        unsafe { lua_isnumber(self.0, index) != 0 }
    }

    fn push_number(self, value: f64) {
        unsafe { lua_pushnumber(self.0, value) };
    }

    fn length(self, index: c_int) -> usize {
        unsafe { lua_objlen(self.0, index) }
    }

    fn equal(self, first: c_int, second: c_int) -> bool {
        unsafe { lua_equal(self.0, first, second) != 0 }
    }

    fn less(self, first: c_int, second: c_int) -> bool {
        unsafe { lua_lessthan(self.0, first, second) != 0 }
    }

    fn less_equal(self, first: c_int, second: c_int) -> bool {
        if self.kind(first) == NUMBER && self.kind(second) == NUMBER {
            self.number(first) <= self.number(second)
        } else {
            let top = self.top();
            let first = if first < 0 { top + first + 1 } else { first };
            let second = if second < 0 { top + second + 1 } else { second };
            self.push(capture(2));
            self.push(first);
            self.push(second);
            self.call(2, 1);
            let result = self.truth(-1);
            self.reset(top);
            result
        }
    }

    fn text(self, index: c_int) -> (*const u8, usize) {
        let mut size = 0;
        let data = unsafe { lua_tolstring(self.0, index, &mut size) };
        (data, size)
    }

    fn push(self, index: c_int) {
        unsafe { lua_pushvalue(self.0, index) };
    }

    fn nil(self) {
        unsafe { lua_pushnil(self.0) };
    }

    fn boolean(self, value: bool) {
        unsafe { lua_pushboolean(self.0, c_int::from(value)) };
    }

    fn integer(self, value: isize) {
        unsafe { lua_pushinteger(self.0, value) };
    }

    fn bytes(self, value: &[u8]) {
        unsafe { lua_pushlstring(self.0, value.as_ptr(), value.len()) };
    }

    fn buffer(self, size: usize) -> *mut u8 {
        unsafe { lua_newuserdata(self.0, size).cast() }
    }

    fn replace(self, index: c_int) {
        unsafe { lua_replace(self.0, index) };
    }

    fn field(self, table: c_int, name: &CStr) -> c_int {
        unsafe { lua_getfield(self.0, table, name.as_ptr()) };
        self.top()
    }

    fn path(self, table: c_int, names: &[&CStr]) -> c_int {
        let mut current = table;
        for &name in names {
            current = self.field(current, name);
        }
        current
    }

    fn item(self, table: c_int, key: c_int) -> c_int {
        self.push(key);
        unsafe { lua_gettable(self.0, table) };
        self.top()
    }

    fn array_item(self, table: c_int, key: usize) -> c_int {
        self.integer(key as isize);
        unsafe { lua_gettable(self.0, table) };
        self.top()
    }

    fn set(self, table: c_int, name: &CStr) {
        unsafe { lua_setfield(self.0, table, name.as_ptr()) };
    }

    fn assign(self, table: c_int, name: &CStr, value: c_int) {
        self.push(value);
        self.set(table, name);
    }

    fn set_item(self, table: c_int, key: c_int, value: c_int) {
        self.push(key);
        self.push(value);
        unsafe { lua_settable(self.0, table) };
    }

    fn table(self, records: c_int) -> c_int {
        unsafe { lua_createtable(self.0, 0, records) };
        self.top()
    }

    fn closure(self, function: Callback, upvalues: c_int) {
        unsafe { lua_pushcclosure(self.0, function, upvalues) };
    }

    fn call(self, arguments: c_int, results: c_int) {
        unsafe { lua_call(self.0, arguments, results) };
    }

    fn call_global(self, name: &CStr, arguments: &[c_int], results: c_int) -> c_int {
        self.call_field(GLOBALS, name, arguments, results)
    }

    fn call_field(self, object: c_int, name: &CStr, arguments: &[c_int], results: c_int) -> c_int {
        self.field(object, name);
        for &index in arguments {
            self.push(index);
        }
        self.call(arguments.len() as c_int, results);
        self.top()
    }

    fn call_method(self, object: c_int, name: &CStr, arguments: &[c_int], results: c_int) -> c_int {
        self.field(object, name);
        self.push(object);
        for &index in arguments {
            self.push(index);
        }
        self.call(arguments.len() as c_int + 1, results);
        self.top()
    }

    fn tail_global(self, name: &CStr, arguments: &[c_int]) -> c_int {
        let top = self.top();
        self.call_global(name, arguments, MULTRET);
        self.top() - top
    }

    fn protected(self, function: c_int, arguments: &[c_int]) -> c_int {
        self.field(GLOBALS, c"pcall");
        self.push(function);
        for &index in arguments {
            self.push(index);
        }
        self.call(1 + arguments.len() as c_int, 2);
        self.top()
    }

    fn table_operation(self, operation: &CStr, arguments: &[c_int], results: c_int) -> c_int {
        let top = self.top();
        self.path(GLOBALS, &[c"table", operation]);
        for &index in arguments {
            self.push(index);
        }
        self.call(arguments.len() as c_int, results);
        // Drop the table library left underneath the results.
        let results = self.top() - top - 1;
        for result in 0..results {
            self.push(top + 2 + result);
            self.replace(top + 1 + result);
        }
        self.reset(top + results);
        self.top()
    }

    fn raw_array_put(self, table: c_int, index: c_int, value: c_int) {
        self.push(value);
        unsafe { lua_rawseti(self.0, table, index) };
    }

    fn next_pair(self, cursor: c_int) -> Option<c_int> {
        self.push(cursor - 2);
        self.push(cursor - 1);
        self.push(cursor);
        self.call(2, 2);
        if self.kind(cursor + 1) == NIL {
            return None;
        }
        self.push(cursor + 1);
        self.replace(cursor);
        Some(cursor + 2)
    }

    fn concat(self, count: c_int) {
        unsafe { lua_concat(self.0, count) };
    }

    fn text_is(self, index: c_int, value: &[u8]) -> bool {
        if self.kind(index) != STRING {
            return false;
        }
        let (text, length) = self.text(index);
        unsafe { slice::from_raw_parts(text, length) == value }
    }

    fn log(self, start: &[u8], fragments: &[(c_int, &[u8])]) {
        self.call_message(c"DLOG", start, fragments);
    }

    fn call_message(self, function: &CStr, start: &[u8], fragments: &[(c_int, &[u8])]) {
        self.field(GLOBALS, function);
        self.bytes(start);
        let mut count = 1;
        for &(value, suffix) in fragments {
            self.push(value);
            self.bytes(suffix);
            count += 2;
        }
        self.concat(count);
        self.call(1, 0);
    }

    fn substring(self, data: c_int, first: f64, last: Option<f64>) -> c_int {
        let top = self.top();
        self.path(GLOBALS, &[c"string", c"sub"]);
        self.push(data);
        self.push_number(first);
        let arguments = if let Some(last) = last {
            self.push_number(last);
            3
        } else {
            2
        };
        self.call(arguments, 1);
        self.replace(top + 1);
        top + 1
    }

    fn error(self, message: &CStr) -> c_int {
        unsafe { luaL_error(self.0, c"%s".as_ptr(), message.as_ptr()) }
    }
}

fn call_original(vm: Stack) -> c_int {
    if vm.kind(capture(1)) != FUNCTION {
        return vm.error(c"invalid arguments for built-in rule");
    }
    let arguments = vm.top();
    vm.push(capture(1));
    unsafe { lua_insert(vm.0, 1) };
    vm.call(arguments, MULTRET);
    vm.top()
}

fn bind_entries(vm: Stack, table: c_int, entries: &[(&CStr, Callback)], helpers: &[c_int]) {
    for &(name, callback) in entries {
        let original = vm.field(GLOBALS, name);
        if vm.kind(capture(1)) == BOOLEAN {
            vm.nil();
            vm.replace(original);
        } else if vm.kind(original) != FUNCTION {
            vm.reset(table);
            continue;
        }
        for &helper in helpers {
            vm.push(helper);
        }
        vm.closure(callback, 1 + helpers.len() as c_int);
        vm.set(table, name);
    }
}

pub(super) unsafe extern "C-unwind" fn initialize_builtins(lua: *mut LuaState) -> c_int {
    unsafe { windows_lua_builtins::initialize(lua) }
}

pub(super) unsafe fn register(lua: *mut LuaState) {
    let vm = unsafe { Stack::enter(lua, 4) };
    let table = vm.table(12);
    vm.closure(windows_lua_automation::bind, 0);
    vm.set(table, c"automation");
    vm.closure(windows_lua_autoring::bind, 0);
    vm.set(table, c"autoring");
    vm.closure(windows_lua_host_cache::bind_lookup, 0);
    vm.set(table, c"host_cache_lookup");
    vm.closure(windows_lua_host_cache::bind_cache, 0);
    vm.set(table, c"host_cache");
    vm.closure(windows_lua_host_cache::stock_host_record, 0);
    vm.set(table, c"stock_host_record");
    vm.closure(windows_lua_lib_utils::bind, 0);
    vm.set(table, c"library_utils");
    vm.closure(windows_lua_packet_library::bind, 0);
    vm.set(table, c"packet_utils");
    vm.closure(windows_lua_fooling::bind, 0);
    vm.set(table, c"fooling");
    vm.closure(windows_lua_rotation::circular, 0);
    vm.set(table, c"circular");
    vm.closure(windows_lua_strategies::bind, 0);
    vm.set(table, c"strategies");
    vm.closure(windows_lua_store::bind, 0);
    vm.set(table, c"ring_store");
    vm.closure(windows_lua_ring_context::bind, 0);
    vm.set(table, c"ring_context");
    vm.set(GLOBALS, c"zapret_native_modules");
}
