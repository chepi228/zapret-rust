//! Registry context creation and validation for the pinned Win64 LuaJIT.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const REGISTRY: c_int = -10_000;
const LUA_TNIL: c_int = 0;
const CONTEXT_SIZE: usize = 56;
const CONTEXT_OFFSET: usize = 16_880;
const METATABLE: u32 = 0;
const MISSING: u32 = 1;
const INVALID: u32 = 2;
const STORAGE_INVALID: u32 = 7;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct LuaContext {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_context: [MaybeUninit<u8>; CONTEXT_OFFSET],
    context_ref: c_int,
    lua: *mut LuaState,
}

const _: () = {
    assert!(size_of::<Params>() == 16_896);
    assert!(offset_of!(Params, context_ref) == CONTEXT_OFFSET);
    assert!(offset_of!(Params, lua) == 16_888);
};

unsafe extern "C" {
    static mut params: Params;
    fn zapret_lua_context_label(label: u32) -> *const c_char;
    fn zapret_lua_context_init(context: *mut LuaContext) -> bool;
    fn zapret_lua_context_valid(context: *const LuaContext, size: usize) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_getfield(lua: *mut LuaState, index: c_int, key: *const c_char);
    fn lua_setmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_ref(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_checkudata(lua: *mut LuaState, index: c_int, name: *const c_char) -> *mut c_void;
    fn lua_objlen(lua: *mut LuaState, index: c_int) -> usize;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

#[cfg(zapret_engine_production)]
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_raw_packet(lua: *mut LuaState) -> c_int {
    #[repr(C)]
    struct Span {
        data: *const c_char,
        length: usize,
    }
    unsafe extern "C" {
        fn zapret_lua_context_packet(context: *const LuaContext, span: *mut Span) -> bool;
    }
    unsafe extern "C-unwind" {
        fn lua_check_argc(lua: *mut LuaState, name: *const c_char, count: c_int);
        fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, length: usize);
    }
    const RAW_PACKET: u32 = 18;
    const PACKET_INVALID: u32 = 5;
    unsafe {
        lua_check_argc(lua, zapret_lua_context_label(RAW_PACKET), 1);
        let top = lua_gettop(lua);
        let mut span = MaybeUninit::<Span>::uninit();
        if !zapret_lua_context_packet(lua_desync_ctx(lua), span.as_mut_ptr()) {
            return luaL_error(lua, zapret_lua_context_label(PACKET_INVALID));
        }
        let span = span.assume_init();
        lua_pushlstring(lua, span.data, span.length);
        if lua_gettop(lua) != top.wrapping_add(1) {
            return luaL_error(lua, c"stack guard failure".as_ptr());
        }
        1
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_desync_ctx(lua: *mut LuaState) -> *mut LuaContext {
    unsafe {
        if lua_type(lua, 1) == LUA_TNIL {
            luaL_error(lua, zapret_lua_context_label(MISSING));
        }
        let context = luaL_checkudata(lua, 1, zapret_lua_context_label(METATABLE)).cast();
        if !zapret_lua_context_valid(context, lua_objlen(lua, 1)) {
            luaL_error(lua, zapret_lua_context_label(INVALID));
        }
        context
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_desync_ctx_create(lua: *mut LuaState) {
    unsafe {
        let slot = &raw mut params.context_ref;
        if slot.read() != 0 {
            return;
        }
        let top = lua_gettop(lua);
        let context = lua_newuserdata(lua, CONTEXT_SIZE).cast();
        if !zapret_lua_context_init(context) {
            luaL_error(lua, zapret_lua_context_label(STORAGE_INVALID));
            return;
        }
        lua_getfield(lua, REGISTRY, zapret_lua_context_label(METATABLE));
        lua_setmetatable(lua, -2);

        // The registry lookup can run Lua and change the current VM or reference.
        let current_vm = (&raw const params.lua).read();
        let reference = luaL_ref(current_vm, REGISTRY);
        slot.write(reference);
        if lua_gettop(lua) != top {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}
