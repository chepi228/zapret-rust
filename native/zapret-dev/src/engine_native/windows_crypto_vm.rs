//! Crypto and address conversion callbacks on a protected Windows Lua frame.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem::{MaybeUninit, align_of, offset_of, size_of},
    ptr,
};

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[derive(Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

const POINTER: usize = size_of::<usize>();
const CRYPTO_STATE_SIZE: usize = 9 * POINTER + 48;
const HASH_STATE_SIZE: usize = if POINTER == 8 { 160 } else { 120 };

#[repr(C)]
struct CryptoState([MaybeUninit<usize>; CRYPTO_STATE_SIZE / POINTER]);

#[repr(C)]
struct CryptoAction {
    name: *const c_char,
    data: *const u8,
    length: usize,
    index: c_int,
    kind: u32,
    minimum: c_int,
    maximum: c_int,
    error: u32,
    count: u32,
}

#[derive(Default)]
#[repr(C)]
struct CryptoValue {
    span: Span,
    truth: u32,
}

#[repr(C)]
struct HashState([MaybeUninit<usize>; HASH_STATE_SIZE / POINTER]);

#[repr(C)]
struct HashAction {
    name: *const c_char,
    data: *const u8,
    length: usize,
    kind: u32,
    index: c_int,
    count: u32,
    expected: c_int,
    error: u32,
}

#[derive(Default)]
#[repr(C)]
struct HashValue {
    span: Span,
    integer: i64,
    kind: c_int,
}

const LUA_TNIL: c_int = 0;

const _: () = {
    assert!(size_of::<CryptoState>() == CRYPTO_STATE_SIZE && align_of::<CryptoState>() == POINTER);
    assert!(size_of::<CryptoAction>() == 3 * POINTER + 24);
    assert!(offset_of!(CryptoAction, kind) == 3 * POINTER + 4);
    assert!(
        size_of::<CryptoValue>() == 3 * POINTER && offset_of!(CryptoValue, truth) == 2 * POINTER
    );
    assert!(size_of::<HashState>() == HASH_STATE_SIZE && align_of::<HashState>() == POINTER);
    assert!(size_of::<HashAction>() == if POINTER == 8 { 48 } else { 32 });
    assert!(offset_of!(HashAction, kind) == 3 * POINTER);
    assert!(size_of::<HashValue>() == 2 * POINTER + 16);
    assert!(offset_of!(HashValue, kind) == 2 * POINTER + 8);
};

unsafe extern "C" {
    fn zapret_lua_crypto_begin(
        mode: u32,
        state: *mut CryptoState,
        action: *mut CryptoAction,
    ) -> bool;
    fn zapret_lua_crypto_step(
        state: *mut CryptoState,
        value: *const CryptoValue,
        output: *mut CryptoAction,
        ops: *const c_void,
    ) -> bool;
    fn zapret_lua_hash_ip_entry_begin(
        mode: u32,
        argc: c_int,
        state: *mut HashState,
        action: *mut HashAction,
    ) -> bool;
    fn zapret_lua_hash_ip_entry_step(
        state: *mut HashState,
        value: *const HashValue,
        output: *mut HashAction,
        ops: *const c_void,
    ) -> bool;
    fn zapret_lua_arity_error(argc: c_int, min: c_int, max: c_int, range: bool) -> *const c_char;
}

// Data belongs to Lua or to a plain stack record while the VM can raise.
unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_check_argc(lua: *mut LuaState, name: *const c_char, expected: c_int);
    fn lua_check_argc_range(lua: *mut LuaState, name: *const c_char, min: c_int, max: c_int);
    fn luaL_checklstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn lua_reqstring(lua: *mut LuaState, index: c_int) -> *const c_char;
    fn lua_newuserdata(lua: *mut LuaState, length: usize) -> *mut c_void;
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, length: usize);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_remove(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn crypto(lua: *mut LuaState, mode: u32) -> c_int {
    let mut state = MaybeUninit::<CryptoState>::uninit();
    let mut output = MaybeUninit::<CryptoAction>::uninit();
    let mut value = CryptoValue::default();

    unsafe {
        let entry_top = lua_gettop(lua);
        if !zapret_lua_crypto_begin(mode, state.as_mut_ptr(), output.as_mut_ptr()) {
            return luaL_error(lua, c"invalid Lua crypto entry".as_ptr());
        }
        loop {
            let action = output.assume_init_read();
            let length = &raw mut value.span.length;
            match action.kind {
                0 => {
                    let count = action.count as c_int;
                    if entry_top.wrapping_add(count) != lua_gettop(lua) {
                        luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                    return count;
                }
                1 if action.minimum == action.maximum => {
                    lua_check_argc(lua, action.name, action.minimum);
                }
                1 => lua_check_argc_range(lua, action.name, action.minimum, action.maximum),
                2 => value.truth = u32::from(lua_toboolean(lua, action.index) != 0),
                3 => value.span.data = lua_reqlstring(lua, action.index, length).cast(),
                4 => value.span.data = luaL_checklstring(lua, action.index, length).cast(),
                5 => {
                    if lua_type(lua, action.index) <= LUA_TNIL {
                        value.span = Span::default();
                    } else {
                        value.span.data = lua_reqlstring(lua, action.index, length).cast();
                    }
                }
                6 => {
                    value.span.length = action.length;
                    value.span.data = lua_newuserdata(lua, action.length).cast();
                }
                7 => lua_pushlstring(lua, action.data.cast(), action.length),
                8 => lua_pushnil(lua),
                9 => lua_remove(lua, action.index),
                10 if action.error == 1 => {
                    return luaL_error(
                        lua,
                        action.data.cast(),
                        action.name,
                        action.length as c_uint,
                    );
                }
                10 if matches!(action.error, 2 | 4) => {
                    return luaL_error(lua, action.data.cast(), action.length as c_uint);
                }
                10 if action.error == 3 => return luaL_error(lua, action.data.cast()),
                _ => return luaL_error(lua, c"invalid Lua crypto action".as_ptr()),
            }
            if !zapret_lua_crypto_step(
                state.as_mut_ptr(),
                &raw const value,
                output.as_mut_ptr(),
                ptr::null(),
            ) {
                return luaL_error(lua, c"invalid Lua crypto state".as_ptr());
            }
        }
    }
}

unsafe fn hash_ip(lua: *mut LuaState, mode: u32) -> c_int {
    let mut state = MaybeUninit::<HashState>::uninit();
    let mut output = MaybeUninit::<HashAction>::uninit();
    let mut value = HashValue::default();

    unsafe {
        if !zapret_lua_hash_ip_entry_begin(
            mode,
            lua_gettop(lua),
            state.as_mut_ptr(),
            output.as_mut_ptr(),
        ) {
            return luaL_error(lua, c"invalid Lua hash/IP entry".as_ptr());
        }
        loop {
            let action = output.assume_init_read();
            let length = &raw mut value.span.length;
            match action.kind {
                0 => return action.count as c_int,
                1 => {
                    let actual = action.count as c_int;
                    let expected = action.expected;
                    let format = zapret_lua_arity_error(actual, expected, expected, false);
                    return luaL_error(lua, format, action.name, expected, actual);
                }
                2 => {
                    value.span.data = luaL_checklstring(lua, action.index, ptr::null_mut()).cast();
                    value.span.length = 0;
                }
                3 => value.span.data = lua_reqlstring(lua, action.index, length).cast(),
                4 => value.kind = lua_type(lua, action.index),
                5 => value.span.data = luaL_checklstring(lua, action.index, length).cast(),
                6 => value.integer = luaL_checkinteger(lua, action.index) as i64,
                7 => {
                    value.span.data = lua_newuserdata(lua, action.length).cast();
                    value.span.length = action.length;
                }
                8 => lua_pushlstring(lua, action.data.cast(), action.length),
                9 => lua_pushnil(lua),
                10 => lua_remove(lua, action.index),
                11 if action.error == 1 => {
                    return luaL_error(lua, action.name, action.data.cast::<c_char>());
                }
                11 if matches!(action.error, 2 | 3) => return luaL_error(lua, action.name),
                12 => {
                    value.span.data = lua_reqstring(lua, action.index).cast();
                    value.span.length = 0;
                }
                _ => return luaL_error(lua, c"invalid Lua hash/IP action".as_ptr()),
            }
            if !zapret_lua_hash_ip_entry_step(
                state.as_mut_ptr(),
                &raw const value,
                output.as_mut_ptr(),
                ptr::null(),
            ) {
                return luaL_error(lua, c"invalid Lua hash/IP state".as_ptr());
            }
        }
    }
}

macro_rules! entries {
    ($run:ident, $($name:ident = $mode:literal),+ $(,)?) => {
        $(
            #[unsafe(no_mangle)]
            unsafe extern "C-unwind" fn $name(lua: *mut LuaState) -> c_int {
                unsafe { $run(lua, $mode) }
            }
        )+
    };
}

entries!(
    crypto,
    luacall_aes = 0,
    luacall_aes_ctr = 1,
    luacall_aes_gcm = 2
);
entries!(
    hash_ip,
    luacall_hash = 0,
    luacall_hkdf = 1,
    luacall_ntop = 2,
    luacall_pton = 3
);
