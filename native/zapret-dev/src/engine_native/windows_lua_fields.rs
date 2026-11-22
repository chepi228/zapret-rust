//! Raw table publication helpers for the pinned Windows Lua ABI.
#![no_std]

use core::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

const REGISTRY_INDEX: c_int = -10000;
const GLOBALS_INDEX: c_int = -10002;

unsafe extern "C-unwind" {
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushnumber(lua: *mut LuaState, value: f64);
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_pushlstring(lua: *mut LuaState, value: *const c_char, length: usize);
    fn lua_pushlightuserdata(lua: *mut LuaState, value: *mut c_void);
    fn lua_createtable(lua: *mut LuaState, array_count: c_int, field_count: c_int);
    fn lua_getfield(lua: *mut LuaState, index: c_int, field: *const c_char);
    fn lua_rawgeti(lua: *mut LuaState, index: c_int, key: c_int);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
}

// Always push the key, then the value, then perform the same raw store. LuaJIT
// can report an error at any of these steps while the caller retains the table.
macro_rules! field_push {
    ($name:ident, $key_push:ident, $key_type:ty, $value_push:ident $(, $value:ident: $ty:ty)*) => {
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $name(lua: *mut LuaState, key: $key_type $(, $value: $ty)*) {
            unsafe {
                $key_push(lua, key);
                $value_push(lua $(, $value)*);
                lua_rawset(lua, -3);
            }
        }
    };
}

macro_rules! field_pair {
    ($field:ident, $item:ident, $push:ident $(, $value:ident: $ty:ty)*) => {
        field_push!($field, lua_pushstring, *const c_char, $push $(, $value: $ty)*);
        field_push!($item, lua_pushinteger, isize, $push $(, $value: $ty)*);
    };
}

unsafe fn push_bool(lua: *mut LuaState, value: bool) {
    unsafe { lua_pushboolean(lua, c_int::from(value)) };
}

unsafe fn push_long(lua: *mut LuaState, value: i64) {
    // The common engine headers publish wide Lua 5.1 values as numbers on x86.
    #[cfg(target_pointer_width = "32")]
    unsafe {
        lua_pushnumber(lua, value as f64);
    }
    #[cfg(target_pointer_width = "64")]
    unsafe {
        lua_pushinteger(lua, value as isize);
    }
}

unsafe fn push_table(lua: *mut LuaState) {
    unsafe { lua_createtable(lua, 0, 0) };
}

unsafe fn push_reference(lua: *mut LuaState, reference: c_int) {
    unsafe { lua_rawgeti(lua, REGISTRY_INDEX, reference) };
}

unsafe fn push_global(lua: *mut LuaState, name: *const c_char) {
    unsafe { lua_getfield(lua, GLOBALS_INDEX, name) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_raw(lua: *mut LuaState, data: *const c_void, length: usize) {
    unsafe {
        if data.is_null() {
            lua_pushnil(lua);
        } else {
            lua_pushlstring(lua, data.cast(), length);
        }
    }
}

field_pair!(lua_pushf_nil, lua_pushi_nil, lua_pushnil);
field_pair!(lua_pushf_int, lua_pushi_int, lua_pushinteger, value: isize);
field_pair!(lua_pushf_lint, lua_pushi_lint, push_long, value: i64);
field_pair!(lua_pushf_number, lua_pushi_number, lua_pushnumber, value: f64);
field_pair!(lua_pushf_bool, lua_pushi_bool, push_bool, value: bool);
field_pair!(lua_pushf_str, lua_pushi_str, lua_pushstring, value: *const c_char);
field_pair!(
    lua_pushf_lstr, lua_pushi_lstr, lua_pushlstring, data: *const c_char, length: usize
);
field_pair!(
    lua_pushf_raw, lua_pushi_raw, lua_push_raw, data: *const c_void, length: usize
);
field_pair!(lua_pushf_table, lua_pushi_table, push_table);
field_push!(lua_pushf_reg, lua_pushstring, *const c_char, push_reference, reference: c_int);
field_push!(lua_pushf_lud, lua_pushstring, *const c_char, lua_pushlightuserdata, data: *mut c_void);
field_push!(lua_pushf_global, lua_pushstring, *const c_char, push_global, name: *const c_char);
