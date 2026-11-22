//! Publish the existing position policy's results in the pinned Win64 LuaJIT.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, offset_of},
};

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

#[repr(C)]
struct Entry {
    name: *const c_char,
    maximum: c_int,
}

#[repr(C)]
struct Flag {
    index: c_int,
    mask: u32,
}

#[repr(C)]
struct PositionResult {
    values: [i64; 128],
    count: u32,
    kind: u32,
}

const _: () = {
    assert!(size_of::<Entry>() == 16 && size_of::<Flag>() == 8);
    assert!(size_of::<PositionResult>() == 1032 && offset_of!(PositionResult, count) == 1024);
};

unsafe extern "C" {
    fn zapret_lua_position_entry(mode: u32) -> Entry;
    fn zapret_lua_position_flag(mode: u32, argc: c_int, previous: u32) -> Flag;
    fn zapret_lua_position_error(status: u32) -> *const c_char;
    fn zapret_lua_positions(
        mode: u32,
        data: *const u8,
        length: usize,
        payload: *const c_char,
        markers: *const c_char,
        flags: u32,
        output: *mut PositionResult,
    ) -> u32;
}

unsafe extern "C-unwind" {
    fn lua_check_argc_range(lua: *mut LuaState, name: *const c_char, min: c_int, max: c_int);
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn lua_reqstring(lua: *mut LuaState, index: c_int) -> *const c_char;
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushinteger(lua: *mut LuaState, value: i64);
    fn lua_createtable(lua: *mut LuaState, array_capacity: c_int, record_capacity: c_int);
    fn lua_pushi_int(lua: *mut LuaState, index: i64, value: i64);
}

unsafe fn positions(lua: *mut LuaState, mode: u32) -> c_int {
    unsafe {
        let entry = zapret_lua_position_entry(mode);
        lua_check_argc_range(lua, entry.name, 3, entry.maximum);
        let argc = lua_gettop(lua);

        let mut length = 0;
        let data = lua_reqlstring(lua, 1, &mut length);
        let payload = lua_reqstring(lua, 2);
        let markers = lua_reqstring(lua, 3);
        let mut flags = 0;
        let mut flag = zapret_lua_position_flag(mode, argc, 0);
        while flag.mask != 0 {
            if lua_toboolean(lua, flag.index) != 0 {
                flags |= flag.mask;
            }
            flag = zapret_lua_position_flag(mode, argc, flag.mask);
        }

        let mut result = MaybeUninit::uninit();
        let status = zapret_lua_positions(
            mode,
            data.cast(),
            length,
            payload,
            markers,
            flags,
            result.as_mut_ptr(),
        );
        if status != 0 {
            let format = zapret_lua_position_error(status);
            return match status {
                1 => luaL_error(lua, format, payload),
                2 => luaL_error(lua, format, markers),
                _ => luaL_error(lua, format),
            };
        }

        // LuaJIT can reenter here or unwind across this frame. The result owns no resources.
        let result = result.assume_init_ref();
        match result.kind {
            0 => lua_pushnil(lua),
            1 => lua_pushinteger(lua, result.values[0]),
            _ => {
                lua_createtable(lua, 0, 0);
                let values = result.values.iter().take(result.count as usize);
                for (index, &value) in values.enumerate() {
                    lua_pushi_int(lua, index as i64 + 1, value);
                }
            }
        }
        if lua_gettop(lua) != argc + 1 {
            return luaL_error(lua, c"stack guard failure".as_ptr());
        }
        1
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_resolve_pos(lua: *mut LuaState) -> c_int {
    unsafe { positions(lua, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_resolve_multi_pos(lua: *mut LuaState) -> c_int {
    unsafe { positions(lua, 1) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_resolve_range(lua: *mut LuaState) -> c_int {
    unsafe { positions(lua, 2) }
}
