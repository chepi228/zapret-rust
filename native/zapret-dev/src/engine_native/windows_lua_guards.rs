//! Primitive LuaJIT guards called from protected Windows VM entries.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    ptr,
};

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

const LUA_TSTRING: c_int = 4;

unsafe extern "C" {
    fn zapret_lua_arity_error(actual: c_int, min: c_int, max: c_int, range: bool) -> *const c_char;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn luaL_checktype(lua: *mut LuaState, index: c_int, kind: c_int);
    fn lua_tolstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_check_argc(lua: *mut LuaState, name: *const c_char, count: c_int) {
    unsafe {
        let actual = lua_gettop(lua);
        let format = zapret_lua_arity_error(actual, count, count, false);
        if !format.is_null() {
            luaL_error(lua, format, name, count, actual);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_check_argc_range(
    lua: *mut LuaState,
    name: *const c_char,
    minimum: c_int,
    maximum: c_int,
) {
    unsafe {
        let actual = lua_gettop(lua);
        let format = zapret_lua_arity_error(actual, minimum, maximum, true);
        if !format.is_null() {
            luaL_error(lua, format, name, minimum, maximum, actual);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_reqlstring(
    lua: *mut LuaState,
    index: c_int,
    size: *mut usize,
) -> *const c_char {
    unsafe {
        luaL_checktype(lua, index, LUA_TSTRING);
        lua_tolstring(lua, index, size)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_reqstring(lua: *mut LuaState, index: c_int) -> *const c_char {
    unsafe { lua_reqlstring(lua, index, ptr::null_mut()) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_absindex(lua: *mut LuaState, index: c_int) -> c_int {
    if index < 0 {
        (unsafe { lua_gettop(lua) }) + index + 1
    } else {
        index
    }
}
