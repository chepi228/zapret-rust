//! Publish native address views through the pinned Win64 LuaJIT ABI.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct SocketAddress {
    opaque: [u8; 0],
}

#[repr(C)]
struct AddressView {
    data: *const u8,
    length: usize,
}

const _: () = {
    assert!(size_of::<AddressView>() == 16 && offset_of!(AddressView, length) == 8);
};

unsafe extern "C" {
    fn zapret_lua_packet_address(source: *const SocketAddress, view: *mut AddressView) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_pushlstring(lua: *mut LuaState, value: *const c_char, length: usize);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_ipaddr(lua: *mut LuaState, source: *const SocketAddress) {
    unsafe {
        let mut view = MaybeUninit::<AddressView>::uninit();
        if !zapret_lua_packet_address(source, view.as_mut_ptr()) {
            luaL_error(lua, c"invalid packet address view".as_ptr());
            return;
        }
        let view = view.assume_init();
        if view.data.is_null() {
            lua_pushnil(lua);
        } else {
            lua_pushlstring(lua, view.data.cast(), view.length);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_ipaddr(
    lua: *mut LuaState,
    field: *const c_char,
    source: *const SocketAddress,
) {
    unsafe {
        lua_pushstring(lua, field);
        lua_push_ipaddr(lua, source);
        lua_rawset(lua, -3);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushi_ipaddr(
    lua: *mut LuaState,
    index: isize,
    source: *const SocketAddress,
) {
    unsafe {
        lua_pushinteger(lua, index);
        lua_push_ipaddr(lua, source);
        lua_rawset(lua, -3);
    }
}
