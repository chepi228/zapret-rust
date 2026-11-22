//! Publish existing decoded records on the pinned Win64 LuaJIT stack.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const TCP: u32 = 0;
const UDP: u32 = 1;
const ICMP: u32 = 2;
const IPV4: u32 = 3;
const IPV6: u32 = 4;

const DONE: u32 = 0;
const PUSH_NIL: u32 = 1;
const CREATE_TABLE: u32 = 2;
const WRITE_INTEGER: u32 = 3;
const WRITE_BYTES: u32 = 4;
const WRITE_HEADER: u32 = 5;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct Dissect {
    opaque: [u8; 0],
}

#[repr(C)]
struct Action {
    name: *const c_char,
    data: *const u8,
    length: usize,
    number: i64,
    kind: u32,
    header: u32,
}

const _: () = {
    assert!(size_of::<Action>() == 40);
    assert!(offset_of!(Action, number) == 24 && offset_of!(Action, header) == 36);
};

unsafe extern "C" {
    fn strlen(value: *const c_char) -> usize;
    fn zapret_lua_header_field_name(kind: u32) -> *const c_char;
    fn zapret_lua_dissect_field_name() -> *const c_char;
    fn zapret_lua_packet_projection(
        decoded: *const Dissect,
        cursor: *mut u32,
        action: *mut Action,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_pushlstring(lua: *mut LuaState, value: *const c_char, length: usize);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_createtable(lua: *mut LuaState, array: c_int, fields: c_int);
    fn lua_pushf_int(lua: *mut LuaState, name: *const c_char, value: isize);
    fn lua_pushf_raw(lua: *mut LuaState, name: *const c_char, data: *const c_void, length: usize);
    fn native_lua_push_packet_header(lua: *mut LuaState, kind: u8, data: *const u8, length: usize);
}

unsafe fn check_stack(lua: *mut LuaState, expected: c_int) {
    unsafe {
        if lua_gettop(lua) != expected {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}

unsafe fn publish_field(lua: *mut LuaState, kind: u32, data: *const u8, length: usize) {
    unsafe {
        let top = lua_gettop(lua);
        let field = zapret_lua_header_field_name(kind);
        if field.is_null() {
            luaL_error(lua, c"invalid header field".as_ptr());
            return;
        }
        lua_pushlstring(lua, field, strlen(field));
        native_lua_push_packet_header(lua, kind as u8, data, length);
        lua_rawset(lua, -3);
        check_stack(lua, top);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_tcphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { publish_field(lua, TCP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_udphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { publish_field(lua, UDP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_icmphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { publish_field(lua, ICMP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_iphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { publish_field(lua, IPV4, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_ip6hdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { publish_field(lua, IPV6, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_dissect(lua: *mut LuaState, decoded: *const Dissect) {
    let mut cursor = 0;
    let mut action = MaybeUninit::<Action>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        loop {
            // Lua can reenter or change the source before the next field.
            if !zapret_lua_packet_projection(decoded, &mut cursor, action.as_mut_ptr()) {
                luaL_error(lua, c"invalid packet projection".as_ptr());
                return;
            }
            let operation = action.assume_init_read();
            match operation.kind {
                DONE => {
                    check_stack(lua, top.wrapping_add(1));
                    return;
                }
                PUSH_NIL => lua_pushnil(lua),
                CREATE_TABLE => lua_createtable(lua, 0, operation.number as c_int),
                WRITE_INTEGER => lua_pushf_int(lua, operation.name, operation.number as isize),
                WRITE_BYTES => {
                    lua_pushf_raw(lua, operation.name, operation.data.cast(), operation.length)
                }
                WRITE_HEADER => {
                    publish_field(lua, operation.header, operation.data, operation.length)
                }
                _ => {
                    luaL_error(lua, c"invalid packet projection action".as_ptr());
                    return;
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_dissect(lua: *mut LuaState, decoded: *const Dissect) {
    unsafe {
        let field = zapret_lua_dissect_field_name();
        lua_pushlstring(lua, field, strlen(field));
        lua_push_dissect(lua, decoded);
        lua_rawset(lua, -3);
    }
}
