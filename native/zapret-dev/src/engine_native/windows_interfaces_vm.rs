//! Local interface table projection on a protected Windows Lua frame.
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
struct Adapter {
    opaque: [u8; 0],
}

type AdapterQuery =
    unsafe extern "system" fn(u32, u32, *const c_void, *mut Adapter, *mut u32) -> u32;

#[repr(C, align(8))]
struct Cursor([MaybeUninit<u8>; 2 * size_of::<usize>() + 16]);

#[repr(C)]
struct Field {
    name: *const c_char,
    data: *const u8,
    number: i64,
    length: usize,
    kind: u32,
    bytes: [u8; 16],
    label: [u8; 16],
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Cursor>() == 2 * pointer + 16 && align_of::<Cursor>() == 8);
    assert!(size_of::<Field>() == if pointer == 8 { 72 } else { 56 });
    assert!(offset_of!(Field, kind) == 3 * pointer + 8);
    assert!(offset_of!(Field, bytes) == 3 * pointer + 12);
    assert!(offset_of!(Field, label) == 3 * pointer + 28);
};

unsafe extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *const c_void,
        adapters: *mut Adapter,
        size: *mut u32,
    ) -> u32;
}

unsafe extern "C" {
    fn zapret_lua_interfaces_read(
        adapters: *mut Adapter,
        size: *mut u32,
        query: AdapterQuery,
    ) -> bool;
    fn zapret_lua_interfaces_begin(adapters: *const Adapter, cursor: *mut Cursor) -> bool;
    fn zapret_lua_interfaces_next(cursor: *mut Cursor, field: *mut Field) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_remove(lua: *mut LuaState, index: c_int);
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_createtable(lua: *mut LuaState, array: c_int, records: c_int);
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_rawgeti(lua: *mut LuaState, index: c_int, key: c_int);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushstring(lua: *mut LuaState, text: *const c_char);
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, size: usize);
    fn lua_pushf_lint(lua: *mut LuaState, name: *const c_char, number: i64);
    fn lua_pushf_str(lua: *mut LuaState, name: *const c_char, text: *const c_char);
    fn lua_pushf_lstr(lua: *mut LuaState, name: *const c_char, data: *const c_char, size: usize);
    fn lua_pushf_table(lua: *mut LuaState, name: *const c_char);
    fn lua_pushi_table(lua: *mut LuaState, index: isize);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn one_result(lua: *mut LuaState, entry_top: c_int) -> c_int {
    unsafe {
        if entry_top.wrapping_add(1) != lua_gettop(lua) {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
    1
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_get_ifaddrs(lua: *mut LuaState) -> c_int {
    let mut size = 0;
    unsafe {
        let entry_top = lua_gettop(lua);
        if !zapret_lua_interfaces_read(ptr::null_mut(), &raw mut size, GetAdaptersAddresses) {
            lua_pushnil(lua);
            return one_result(lua, entry_top);
        }
        // Lua owns the adapter buffer across allocating and reentrant VM calls.
        let adapters = lua_newuserdata(lua, size as usize).cast();
        if !zapret_lua_interfaces_read(adapters, &raw mut size, GetAdaptersAddresses) {
            lua_settop(lua, -2);
            lua_pushnil(lua);
            return one_result(lua, entry_top);
        }
        lua_createtable(lua, 0, 0);
        let mut cursor = MaybeUninit::<Cursor>::uninit();
        let mut field = MaybeUninit::<Field>::uninit();
        if !zapret_lua_interfaces_begin(adapters, cursor.as_mut_ptr()) {
            return luaL_error(lua, c"invalid interface view storage".as_ptr());
        }
        loop {
            if !zapret_lua_interfaces_next(cursor.as_mut_ptr(), field.as_mut_ptr()) {
                return luaL_error(lua, c"invalid interface view cursor".as_ptr());
            }
            let value = field.assume_init_read();
            match value.kind {
                0 => {
                    lua_remove(lua, -2);
                    return one_result(lua, entry_top);
                }
                1 => {
                    let label = value.label.as_ptr().cast();
                    lua_pushf_table(lua, label);
                    lua_getfield(lua, -1, label);
                }
                2 => lua_pushf_str(lua, value.name, value.data.cast()),
                3 => lua_pushf_lstr(lua, value.name, value.data.cast(), value.length),
                4 => lua_pushf_lint(lua, value.name, value.number),
                5 => {
                    lua_pushf_table(lua, value.name);
                    lua_getfield(lua, -1, value.name);
                }
                6 => {
                    lua_pushi_table(lua, value.number as isize);
                    lua_rawgeti(lua, -1, value.number as c_int);
                }
                7 => {
                    lua_pushstring(lua, value.name);
                    if value.length != 0 {
                        lua_pushlstring(lua, value.bytes.as_ptr().cast(), value.length);
                    } else {
                        lua_pushnil(lua);
                    }
                    lua_rawset(lua, -3);
                }
                8 => lua_settop(lua, -2),
                9 => lua_settop(lua, -3),
                _ => return luaL_error(lua, c"invalid interface view field".as_ptr()),
            }
        }
    }
}
