//! Binary-buffer API on a protected Windows Lua frame.
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

#[derive(Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

#[repr(C)]
struct State {
    first: Span,
    second: Span,
    output: *mut u8,
    length: usize,
    mode: u32,
    phase: u32,
}

#[repr(C)]
struct Action {
    data: *const u8,
    length: usize,
    name: *const c_char,
    kind: u32,
    index: c_int,
    argc: u32,
    error: u32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    integer: i64,
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 6 * pointer + 8 && align_of::<State>() == pointer);
    assert!(size_of::<Action>() == 3 * pointer + 16 && size_of::<Value>() == 2 * pointer + 8);
};

unsafe extern "C" {
    fn zapret_lua_buffer_begin(mode: u32, state: *mut State, action: *mut Action) -> bool;
    fn zapret_lua_buffer_step(
        state: *mut State,
        value: *const Value,
        action: *mut Action,
        ops: *const c_void,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_remove(lua: *mut LuaState, index: c_int);
    fn lua_check_argc(lua: *mut LuaState, name: *const c_char, argc: c_int);
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, size: usize);
    fn lua_pushnil(lua: *mut LuaState);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn buffer(lua: *mut LuaState, mode: u32) -> c_int {
    // Lua owns all buffers. Only scalar values and raw pointers survive VM calls,
    // so errors can unwind this frame through LuaJIT's native Windows handler.
    unsafe {
        let entry_top = lua_gettop(lua);
        let mut state = MaybeUninit::<State>::uninit();
        let mut action = MaybeUninit::<Action>::uninit();
        let mut value = Value::default();
        if !zapret_lua_buffer_begin(mode, state.as_mut_ptr(), action.as_mut_ptr()) {
            return luaL_error(lua, c"invalid Lua buffer entry".as_ptr());
        }
        loop {
            // The successful policy transition initializes the whole next action.
            let current = action.assume_init_read();
            match current.kind {
                0 => {
                    let argc = current.argc as c_int;
                    if entry_top.wrapping_add(argc) != lua_gettop(lua) {
                        luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                    return argc;
                }
                1 => lua_check_argc(lua, current.name, current.argc as c_int),
                2 => value.integer = luaL_checkinteger(lua, current.index) as i64,
                3 => {
                    value.span.data =
                        lua_reqlstring(lua, current.index, &raw mut value.span.length).cast();
                }
                4 => {
                    value.span.length = current.length;
                    value.span.data = lua_newuserdata(lua, current.length).cast();
                }
                5 => lua_pushlstring(lua, current.data.cast(), current.length),
                6 => lua_settop(lua, (-1_i32).wrapping_sub(current.index)),
                7 => lua_remove(lua, current.index),
                8 => lua_pushnil(lua),
                9 if current.error == 1 => {
                    return luaL_error(lua, current.data.cast(), current.name);
                }
                9 if matches!(current.error, 2 | 3) => {
                    return luaL_error(lua, current.data.cast());
                }
                _ => return luaL_error(lua, c"invalid Lua buffer action".as_ptr()),
            }
            if !zapret_lua_buffer_step(state.as_mut_ptr(), &value, action.as_mut_ptr(), ptr::null())
            {
                return luaL_error(lua, c"invalid Lua buffer state".as_ptr());
            }
        }
    }
}

macro_rules! entries {
    ($($name:ident = $mode:literal),+ $(,)?) => {
        $(
            #[unsafe(no_mangle)]
            unsafe extern "C-unwind" fn $name(lua: *mut LuaState) -> c_int {
                unsafe { buffer(lua, $mode) }
            }
        )+
    };
}

entries!(
    luacall_brandom = 0,
    luacall_brandom_az = 1,
    luacall_brandom_az09 = 2,
    luacall_bcryptorandom = 3,
    luacall_parse_hex = 4,
    luacall_bxor = 5,
    luacall_bor = 6,
    luacall_band = 7,
);
