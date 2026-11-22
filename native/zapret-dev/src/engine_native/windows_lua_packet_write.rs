//! LuaJIT reconstruction entries around the shared Rust packet writers.
#![no_std]

mod windows_lua_header_write;
mod windows_lua_packet_assembly;
mod windows_lua_packet_dispatch;
mod windows_lua_packet_options;

use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

type Lua = *mut c_void;
const NUMBER: c_int = 3;
const STRING: c_int = 4;
const TABLE: c_int = 5;
const NIL: c_int = 0;

#[repr(C, align(16))]
struct Buffer<const N: usize>([MaybeUninit<u8>; N]);

unsafe extern "C-unwind" {
    fn lua_absindex(lua: Lua, index: c_int) -> c_int;
    fn lua_check_argc(lua: Lua, name: *const c_char, count: c_int);
    fn lua_check_argc_range(lua: Lua, name: *const c_char, low: c_int, high: c_int);
    fn lua_gettop(lua: Lua) -> c_int;
    fn lua_settop(lua: Lua, index: c_int);
    fn lua_getfield(lua: Lua, index: c_int, field: *const c_char);
    fn lua_rawgeti(lua: Lua, index: c_int, item: c_int);
    fn lua_type(lua: Lua, index: c_int) -> c_int;
    fn lua_tointeger(lua: Lua, index: c_int) -> i64;
    fn lua_toboolean(lua: Lua, index: c_int) -> c_int;
    fn lua_tolstring(lua: Lua, index: c_int, length: *mut usize) -> *const u8;
    fn lua_pushlstring(lua: Lua, bytes: *const u8, length: usize);
    fn luaL_checkinteger(lua: Lua, index: c_int) -> i64;
    fn luaL_checktype(lua: Lua, index: c_int, tag: c_int);
    fn luaL_error(lua: Lua, format: *const c_char, ...) -> c_int;
}

unsafe fn pop(lua: Lua, count: c_int) {
    unsafe { lua_settop(lua, -1 - count) };
}

unsafe fn guard(lua: Lua, top: c_int, count: c_int) {
    if unsafe { lua_gettop(lua) } != top.wrapping_add(count) {
        unsafe { luaL_error(lua, c"stack guard failure".as_ptr()) };
    }
}

#[repr(C)]
struct HeaderState {
    buffer: *mut u8,
    data: *const u8,
    length: usize,
    capacity: usize,
    mode: u32,
    phase: u32,
    preserve: u32,
    protocol: u32,
}

#[repr(C)]
struct HeaderAction {
    name: *const c_char,
    data: *mut u8,
    length: usize,
    kind: u32,
    index: i32,
    minimum: i32,
    maximum: i32,
    header: u32,
    count: u32,
}

#[derive(Default)]
#[repr(C)]
struct HeaderValue {
    data: *const u8,
    length: usize,
    success: u32,
    preserve: u32,
    protocol: u32,
}

const _: () = {
    assert!(size_of::<HeaderState>() == 48 && size_of::<HeaderAction>() == 48);
    assert!(size_of::<HeaderValue>() == 32);
};

unsafe extern "C" {
    fn zapret_lua_header_entry_begin(
        mode: u32,
        buffer: *mut u8,
        capacity: usize,
        state: *mut HeaderState,
        action: *mut HeaderAction,
    ) -> bool;
    fn zapret_lua_header_entry_step(
        state: &mut HeaderState,
        value: &HeaderValue,
        action: &mut HeaderAction,
    ) -> bool;
}

unsafe fn reconstruct_header(lua: Lua, mode: u32) -> c_int {
    let mut scratch = MaybeUninit::<Buffer<512>>::uninit();
    let mut state = MaybeUninit::<HeaderState>::uninit();
    let mut action = MaybeUninit::<HeaderAction>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_header_entry_begin(
            mode,
            scratch.as_mut_ptr().cast(),
            512,
            state.as_mut_ptr(),
            action.as_mut_ptr(),
        ) {
            return luaL_error(lua, c"invalid header entry".as_ptr());
        }
        let mut state = state.assume_init();
        let mut action = action.assume_init();
        loop {
            let mut observed = HeaderValue::default();
            match action.kind {
                0 => {
                    let count = action.count as c_int;
                    guard(lua, top, count);
                    return count;
                }
                1 if action.minimum == action.maximum => {
                    lua_check_argc(lua, action.name, action.minimum)
                }
                1 => lua_check_argc_range(lua, action.name, action.minimum, action.maximum),
                3 => {
                    let mut preserve = false;
                    let mut protocol = 0;
                    windows_lua_packet_options::lua_reconstruct_extract_options(
                        lua,
                        action.index,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut preserve,
                        &mut protocol,
                    );
                    observed.preserve = u32::from(preserve);
                    observed.protocol = u32::from(protocol);
                }
                4 => {
                    observed.length = action.length;
                    let success = windows_lua_header_write::write_header(
                        lua,
                        action.index,
                        action.header,
                        action.data,
                        &mut observed.length,
                        state.protocol as u8,
                        state.preserve != 0,
                    );
                    observed.success = u32::from(success);
                }
                6 => lua_pushlstring(lua, action.data, action.length),
                7 => return luaL_error(lua, c"%s".as_ptr(), action.name),
                _ => return luaL_error(lua, c"invalid header action".as_ptr()),
            }
            if !zapret_lua_header_entry_step(&mut state, &observed, &mut action) {
                return luaL_error(lua, c"invalid header state".as_ptr());
            }
        }
    }
}

macro_rules! header_entries {
    ($($entry:ident = $id:literal),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $entry(lua: Lua) -> c_int {
            unsafe { reconstruct_header(lua, $id) }
        }
    )+};
}

header_entries!(
    luacall_reconstruct_tcphdr = 5,
    luacall_reconstruct_udphdr = 6,
    luacall_reconstruct_icmphdr = 7,
    luacall_reconstruct_iphdr = 8,
    luacall_reconstruct_ip6hdr = 9,
);
