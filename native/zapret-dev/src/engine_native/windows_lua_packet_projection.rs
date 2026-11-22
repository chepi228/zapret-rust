//! Render borrowed metadata into tables on the pinned Win64 LuaJIT stack.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const TCP: u8 = 0;
const UDP: u8 = 1;
const ICMP: u8 = 2;
const IPV4: u8 = 3;
const IPV6: u8 = 4;

const DONE: u32 = 0;
const PUSH_NIL: u32 = 1;
const CREATE_TABLE: u32 = 2;
const WRITE_INTEGER: u32 = 3;
const WRITE_BYTES: u32 = 4;
const PUBLISH_ITEMS: u32 = 5;
const PUSH_NAME: u32 = 6;
const PUSH_INDEX: u32 = 7;
const RAW_SET: u32 = 8;
const RAISE: u32 = 9;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C, align(8))]
struct Cursor {
    storage: [MaybeUninit<u8>; 32],
}

#[repr(C)]
struct HeaderProjection {
    before_cursor: [MaybeUninit<u8>; 56],
    cursor: Cursor,
    after_cursor: [MaybeUninit<u8>; 24],
}

#[repr(C, align(8))]
struct ItemProjection {
    storage: [MaybeUninit<u8>; 48],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Action {
    name: *const c_char,
    data: *const u8,
    length: usize,
    number: i64,
    kind: u32,
    reserved: u32,
}

const _: () = {
    assert!(size_of::<Cursor>() == 32);
    assert!(size_of::<HeaderProjection>() == 112 && offset_of!(HeaderProjection, cursor) == 56);
    assert!(size_of::<ItemProjection>() == 48);
    assert!(size_of::<Action>() == 40 && offset_of!(Action, kind) == 32);
};

unsafe extern "C" {
    fn zapret_lua_packet_header_projection_begin(
        kind: u32,
        data: *const u8,
        length: usize,
        state: *mut HeaderProjection,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_packet_header_projection_step(
        state: *mut HeaderProjection,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_packet_items_prepare(
        kind: u32,
        data: *const u8,
        length: usize,
        cursor: *mut Cursor,
        field: *mut *const c_char,
    ) -> bool;
    fn zapret_lua_packet_items_begin(
        field: *const c_char,
        cursor: *mut Cursor,
        state: *mut ItemProjection,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_packet_items_step(state: *mut ItemProjection, action: *mut Action) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_createtable(lua: *mut LuaState, array: c_int, fields: c_int);
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn lua_pushf_int(lua: *mut LuaState, name: *const c_char, value: isize);
    fn lua_pushf_lint(lua: *mut LuaState, name: *const c_char, value: i64);
    fn lua_pushf_raw(lua: *mut LuaState, name: *const c_char, data: *const c_void, length: usize);
}

unsafe fn check_stack(lua: *mut LuaState, expected: c_int) {
    unsafe {
        if lua_gettop(lua) != expected {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_lua_push_packet_items(
    lua: *mut LuaState,
    field: *const c_char,
    cursor: *mut Cursor,
) {
    let mut state = MaybeUninit::<ItemProjection>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_packet_items_begin(field, cursor, state.as_mut_ptr(), action.as_mut_ptr()) {
            luaL_error(lua, c"invalid packet item projection".as_ptr());
            return;
        }
        loop {
            let operation = action.assume_init_read();
            match operation.kind {
                DONE => {
                    check_stack(lua, top);
                    return;
                }
                CREATE_TABLE => lua_createtable(lua, 0, operation.number as c_int),
                WRITE_INTEGER => lua_pushf_int(lua, operation.name, operation.number as isize),
                WRITE_BYTES => {
                    lua_pushf_raw(lua, operation.name, operation.data.cast(), operation.length)
                }
                PUSH_NAME => lua_pushstring(lua, operation.name),
                PUSH_INDEX => lua_pushinteger(lua, operation.number as isize),
                RAW_SET => lua_rawset(lua, operation.number as c_int),
                RAISE => {
                    luaL_error(lua, c"%s".as_ptr(), operation.name);
                    return;
                }
                _ => {
                    luaL_error(lua, c"invalid packet item action".as_ptr());
                    return;
                }
            }
            // Cursor fields are observed by the policy after each VM operation.
            if !zapret_lua_packet_items_step(state.as_mut_ptr(), action.as_mut_ptr()) {
                luaL_error(lua, c"invalid packet item state".as_ptr());
                return;
            }
        }
    }
}

unsafe fn publish_header_items(lua: *mut LuaState, kind: u8, data: *const u8, length: usize) {
    let mut cursor = MaybeUninit::<Cursor>::uninit();
    let mut field = MaybeUninit::<*const c_char>::uninit();
    unsafe {
        if !zapret_lua_packet_items_prepare(
            u32::from(kind),
            data,
            length,
            cursor.as_mut_ptr(),
            field.as_mut_ptr(),
        ) {
            luaL_error(lua, c"invalid packet item input".as_ptr());
            return;
        }
        native_lua_push_packet_items(lua, field.assume_init(), cursor.as_mut_ptr());
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_lua_push_packet_header(
    lua: *mut LuaState,
    kind: u8,
    data: *const u8,
    length: usize,
) {
    let mut state = MaybeUninit::<HeaderProjection>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_packet_header_projection_begin(
            u32::from(kind),
            data,
            length,
            state.as_mut_ptr(),
            action.as_mut_ptr(),
        ) {
            luaL_error(lua, c"invalid packet header projection".as_ptr());
            return;
        }
        loop {
            let operation = action.assume_init_read();
            match operation.kind {
                DONE => {
                    check_stack(lua, top.wrapping_add(1));
                    return;
                }
                PUSH_NIL => lua_pushnil(lua),
                CREATE_TABLE => lua_createtable(lua, 0, operation.number as c_int),
                WRITE_INTEGER => lua_pushf_lint(lua, operation.name, operation.number),
                WRITE_BYTES => {
                    lua_pushf_raw(lua, operation.name, operation.data.cast(), operation.length)
                }
                PUBLISH_ITEMS => {
                    let cursor = &raw mut (*state.as_mut_ptr()).cursor;
                    native_lua_push_packet_items(lua, operation.name, cursor);
                }
                _ => {
                    luaL_error(lua, c"invalid packet header action".as_ptr());
                    return;
                }
            }
            if !zapret_lua_packet_header_projection_step(state.as_mut_ptr(), action.as_mut_ptr()) {
                luaL_error(lua, c"invalid packet header state".as_ptr());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_tcphdr_options(
    lua: *mut LuaState,
    data: *const u8,
    length: usize,
) {
    unsafe { publish_header_items(lua, TCP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_ip6exthdr(
    lua: *mut LuaState,
    data: *const u8,
    length: usize,
) {
    unsafe { publish_header_items(lua, IPV6, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_tcphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { native_lua_push_packet_header(lua, TCP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_udphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { native_lua_push_packet_header(lua, UDP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_icmphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { native_lua_push_packet_header(lua, ICMP, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_iphdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { native_lua_push_packet_header(lua, IPV4, data, length) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_ip6hdr(lua: *mut LuaState, data: *const u8, length: usize) {
    unsafe { native_lua_push_packet_header(lua, IPV6, data, length) }
}
