//! Read binary header arguments and publish their decoded views through Win64 LuaJIT.
#![no_std]

use core::ffi::{c_char, c_int};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

unsafe extern "C" {
    fn zapret_lua_header_read_name(kind: u8) -> *const c_char;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_check_argc(lua: *mut LuaState, name: *const c_char, count: c_int);
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn native_lua_push_packet_header(lua: *mut LuaState, kind: u8, data: *const u8, length: usize);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn dissect_header(lua: *mut LuaState, kind: u8) -> c_int {
    // LuaJIT can reenter or unwind across this frame. The input is rooted on
    // the Lua stack and there are no Rust resources to release.
    unsafe {
        let name = zapret_lua_header_read_name(kind);
        if name.is_null() {
            return luaL_error(lua, c"invalid header entry".as_ptr());
        }
        lua_check_argc(lua, name, 1);
        let top = lua_gettop(lua);
        let mut length = 0;
        let data = lua_reqlstring(lua, 1, &mut length);
        if length > isize::MAX as usize || length != 0 && data.is_null() {
            return luaL_error(lua, c"invalid header state".as_ptr());
        }
        native_lua_push_packet_header(lua, kind, data.cast(), length);
        if lua_gettop(lua) != top.wrapping_add(1) {
            return luaL_error(lua, c"stack guard failure".as_ptr());
        }
        1
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_dissect_tcphdr(lua: *mut LuaState) -> c_int {
    unsafe { dissect_header(lua, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_dissect_udphdr(lua: *mut LuaState) -> c_int {
    unsafe { dissect_header(lua, 1) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_dissect_icmphdr(lua: *mut LuaState) -> c_int {
    unsafe { dissect_header(lua, 2) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_dissect_iphdr(lua: *mut LuaState) -> c_int {
    unsafe { dissect_header(lua, 3) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_dissect_ip6hdr(lua: *mut LuaState) -> c_int {
    unsafe { dissect_header(lua, 4) }
}
