//! System snapshot and calendar fields on a protected Win64 LuaJIT frame.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct Field {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    number: f64,
    kind: u32,
    text: [u8; 128],
}

#[repr(C)]
struct Calendar {
    fields: [c_int; 9],
}

#[repr(C)]
struct TimeCursor {
    time: Calendar,
    index: u32,
}

type TimeConvert = unsafe extern "C" fn(*mut Calendar) -> i64;
const LUA_TNUMBER: c_int = 3;

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Field>() == 2 * pointer + 152 && offset_of!(Field, text) == 2 * pointer + 20);
    assert!(size_of::<Calendar>() == 36 && align_of::<Calendar>() == 4);
    assert!(size_of::<TimeCursor>() == 40 && offset_of!(TimeCursor, index) == 36);
};

unsafe extern "C" {
    fn zapret_lua_system_field(mode: u32, index: u32, view: *const c_void, out: *mut Field)
    -> bool;
    fn zapret_lua_time_begin(tag: c_int, cursor: *mut TimeCursor) -> u32;
    fn zapret_lua_time_next(cursor: *const TimeCursor, name: *mut *const c_char) -> u32;
    fn zapret_lua_time_observe(cursor: *mut TimeCursor, tag: c_int, number: i64) -> u32;
    fn zapret_lua_time_error_format(status: u32, field: bool) -> *const c_char;
}

unsafe extern "C-unwind" {
    fn lua_createtable(lua: *mut LuaState, array: c_int, records: c_int);
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tointeger(lua: *mut LuaState, index: c_int) -> isize;
    fn lua_pushinteger(lua: *mut LuaState, number: isize);
    fn lua_pushnumber(lua: *mut LuaState, number: f64);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushf_lint(lua: *mut LuaState, name: *const c_char, number: i64);
    fn lua_pushf_number(lua: *mut LuaState, name: *const c_char, number: f64);
    fn lua_pushf_str(lua: *mut LuaState, name: *const c_char, text: *const c_char);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_lua_system_project(
    lua: *mut LuaState,
    mode: u32,
    view: *const c_void,
) -> c_int {
    let mut field = MaybeUninit::<Field>::uninit();
    let mut index = 0_u32;
    unsafe {
        loop {
            // Each field is observed after the prior VM operation completes.
            if !zapret_lua_system_field(mode, index, view, field.as_mut_ptr()) {
                return luaL_error(lua, c"invalid system view metadata".as_ptr());
            }
            let value = field.assume_init_read();
            match value.kind {
                0 => return value.integer as c_int,
                1 => lua_createtable(lua, 0, value.integer as c_int),
                2 => lua_pushf_lint(lua, value.name, value.integer),
                3 => lua_pushf_number(lua, value.name, value.number),
                4 => lua_pushf_str(lua, value.name, value.data),
                5 => lua_pushf_str(lua, value.name, value.text.as_ptr().cast()),
                6 => lua_pushinteger(lua, value.integer as isize),
                7 => lua_pushnumber(lua, value.number),
                8 => lua_pushnil(lua),
                _ => return luaL_error(lua, c"invalid system view field".as_ptr()),
            }
            index = index.wrapping_add(1);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_timex(lua: *mut LuaState, convert: TimeConvert) {
    let mut cursor = MaybeUninit::<TimeCursor>::uninit();
    let mut name = ptr::null();
    unsafe {
        let status = zapret_lua_time_begin(lua_type(lua, 1), cursor.as_mut_ptr());
        if status != 0 {
            luaL_error(lua, zapret_lua_time_error_format(status, false));
            return;
        }
        loop {
            let status = zapret_lua_time_next(cursor.as_ptr(), &raw mut name);
            match status {
                0 => break,
                1 => {}
                _ => {
                    luaL_error(lua, zapret_lua_time_error_format(status, false));
                    return;
                }
            }
            lua_getfield(lua, 1, name);
            let tag = lua_type(lua, -1);
            let value = if tag == LUA_TNUMBER {
                lua_tointeger(lua, -1) as i64
            } else {
                0
            };
            let status = zapret_lua_time_observe(cursor.as_mut_ptr(), tag, value);
            if status != 0 {
                luaL_error(lua, zapret_lua_time_error_format(status, true), name);
                return;
            }
            lua_settop(lua, -2);
        }
        let seconds = convert(&raw mut (*cursor.as_mut_ptr()).time);
        native_lua_system_project(lua, 6, (&raw const seconds).cast());
    }
}
