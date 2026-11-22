//! Timer reference release from a LuaJIT-protected callback.
#![no_std]

use core::ffi::c_int;
use core::mem::{offset_of, size_of};

const LUA_OFFSET: usize = 16_888;
const REGISTRY: c_int = -10_000;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_lua: [u8; LUA_OFFSET],
    lua: *mut LuaState,
}

#[repr(C)]
struct Timer {
    id: u64,
    period: u64,
    fires: u32,
    name: c_int,
    function: c_int,
    data: c_int,
    oneshot: u32,
}

unsafe extern "C" {
    static mut params: Params;
}

unsafe extern "C-unwind" {
    fn luaL_unref(lua: *mut LuaState, table: c_int, reference: c_int);
}

unsafe fn unref(reference: c_int) {
    let lua = unsafe { (&raw const params.lua).read() };
    unsafe { luaL_unref(lua, REGISTRY, reference) };
}

// Only Lua-facing timer callbacks use this entry. The host scheduler keeps
// its VM actions in C because capture and idle callers use a non-unwinding ABI.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_timer_unref(timer: *const Timer) {
    unsafe {
        unref((&raw const (*timer).name).read());
        unref((&raw const (*timer).function).read());
        unref((&raw const (*timer).data).read());
    }
}

const _: () = {
    assert!(size_of::<Params>() == 16_896 && offset_of!(Params, lua) == LUA_OFFSET);
    assert!(size_of::<Timer>() == 40);
    assert!(offset_of!(Timer, name) == 20);
    assert!(offset_of!(Timer, function) == 24);
    assert!(offset_of!(Timer, data) == 28);
};
