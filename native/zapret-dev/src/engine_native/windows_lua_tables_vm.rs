//! Lua publication of positions, ranges and named values.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

#[repr(C)]
struct TableAction {
    name: *const c_char,
    data: *const c_void,
    number: i64,
    kind: u32,
    flag: u32,
}

#[repr(C)]
struct RangeState {
    source: *const c_void,
    name: *const c_char,
    mode: u32,
    phase: u32,
}

#[repr(C)]
struct BlobState {
    blob: *const c_char,
    field: *const c_char,
    index: c_int,
    mode: u32,
    phase: u32,
    success: u32,
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<TableAction>() == 2 * pointer + 16);
    assert!(size_of::<RangeState>() == 2 * pointer + 8);
    assert!(size_of::<BlobState>() == 2 * pointer + 16);
};

const LUA_GLOBALSINDEX: c_int = -10002;

unsafe extern "C" {
    fn zapret_lua_range_begin(
        mode: u32,
        source: *const c_void,
        name: *const c_char,
        state: *mut RangeState,
        action: *mut TableAction,
    ) -> bool;
    fn zapret_lua_range_step(state: *mut RangeState, action: *mut TableAction) -> bool;
    fn zapret_lua_blob_begin(
        mode: u32,
        index: c_int,
        field: *const c_char,
        blob: *const c_char,
        state: *mut BlobState,
        action: *mut TableAction,
    ) -> bool;
    fn zapret_lua_blob_step(state: *mut BlobState, tag: c_int, action: *mut TableAction) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_pushf_table(lua: *mut LuaState, name: *const c_char);
    fn lua_pushf_str(lua: *mut LuaState, name: *const c_char, value: *const c_char);
    fn lua_pushf_lint(lua: *mut LuaState, name: *const c_char, value: i64);
    fn lua_pushf_bool(lua: *mut LuaState, name: *const c_char, value: bool);
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
}

unsafe fn pop(lua: *mut LuaState, count: c_int) {
    unsafe { lua_settop(lua, -1 - count) };
}

unsafe fn range(lua: *mut LuaState, name: *const c_char, source: *const c_void, mode: u32) {
    let top = unsafe { lua_gettop(lua) };
    let mut state = MaybeUninit::uninit();
    let mut next = MaybeUninit::uninit();
    unsafe {
        if !zapret_lua_range_begin(mode, source, name, state.as_mut_ptr(), next.as_mut_ptr()) {
            luaL_error(lua, c"invalid range projection".as_ptr());
            return;
        }
        loop {
            // The next field may depend on a callback from the current VM operation.
            let action = next.assume_init_read();
            match action.kind {
                0 => {
                    if lua_gettop(lua) != top {
                        luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                    return;
                }
                1 => lua_pushf_table(lua, action.name),
                2 => lua_getfield(lua, -1, action.name),
                3 => {
                    let text = [action.number as c_char, 0];
                    lua_pushf_str(lua, action.name, text.as_ptr());
                }
                4 => lua_pushf_lint(lua, action.name, action.number),
                5 => pop(lua, action.number as c_int),
                6 => range(lua, action.name, action.data, 0),
                7 => lua_pushf_bool(lua, action.name, action.number != 0),
                _ => {
                    luaL_error(lua, c"invalid range action".as_ptr());
                    return;
                }
            }
            if !zapret_lua_range_step(state.as_mut_ptr(), next.as_mut_ptr()) {
                luaL_error(lua, c"invalid range state".as_ptr());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_pos(
    lua: *mut LuaState,
    name: *const c_char,
    source: *const c_void,
) {
    unsafe { range(lua, name, source, 0) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_range(
    lua: *mut LuaState,
    name: *const c_char,
    source: *const c_void,
) {
    unsafe { range(lua, name, source, 1) };
}

unsafe fn blob(
    lua: *mut LuaState,
    index: c_int,
    field: *const c_char,
    name: *const c_char,
    mode: u32,
) -> bool {
    let mut state = MaybeUninit::uninit();
    let mut next = MaybeUninit::uninit();
    unsafe {
        if !zapret_lua_blob_begin(
            mode,
            index,
            field,
            name,
            state.as_mut_ptr(),
            next.as_mut_ptr(),
        ) {
            luaL_error(lua, c"invalid blob projection".as_ptr());
            return false;
        }
        loop {
            let action = next.assume_init_read();
            let mut tag = 0;
            match action.kind {
                0 => return action.flag != 0,
                1 => lua_pushstring(lua, action.name),
                2 => lua_getfield(lua, action.number as c_int, action.name),
                3 => tag = lua_type(lua, -1),
                4 => pop(lua, action.number as c_int),
                5 => lua_getfield(lua, LUA_GLOBALSINDEX, action.name),
                6 => {
                    lua_tolstring(lua, -1, ptr::null_mut());
                }
                7 => lua_rawset(lua, action.number as c_int),
                8 => {
                    DLOG_ERR(action.data.cast(), action.name);
                }
                _ => {
                    luaL_error(lua, c"invalid blob action".as_ptr());
                    return false;
                }
            }
            if !zapret_lua_blob_step(state.as_mut_ptr(), tag, next.as_mut_ptr()) {
                luaL_error(lua, c"invalid blob state".as_ptr());
                return false;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_blob(
    lua: *mut LuaState,
    index: c_int,
    name: *const c_char,
) -> bool {
    unsafe { blob(lua, index, ptr::null(), name, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_blob(
    lua: *mut LuaState,
    index: c_int,
    field: *const c_char,
    name: *const c_char,
) -> bool {
    unsafe { blob(lua, index, field, name, 1) }
}
