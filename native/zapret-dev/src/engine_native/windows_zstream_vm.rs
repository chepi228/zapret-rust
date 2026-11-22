//! Publish streaming codec results on a protected Lua frame.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

type Callback = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;

#[repr(C)]
struct Entry {
    name: *const c_char,
    minimum: c_int,
    maximum: c_int,
    results: c_int,
}

#[repr(C)]
struct Output {
    data: *mut u8,
    length: usize,
    capacity: usize,
    finished: bool,
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Entry>() == 2 * pointer + 8);
    assert!(core::mem::offset_of!(Entry, results) == pointer + 8);
    assert!(size_of::<Output>() == 4 * pointer);
    assert!(core::mem::offset_of!(Output, finished) == 3 * pointer);
};

const ARITY: u32 = 0;
const STREAM: u32 = 1;
const INPUT: u32 = 2;
const COUNT: u32 = 3;
const INPUT_OMITTED: u32 = 4;
const HINT: u32 = 5;
const PROCESS: u32 = 6;
const PROCESS_WITH_HINT: u32 = 7;
const DROP_OUTPUT: u32 = 8;
const NIL_RESULTS: u32 = 9;
const PUBLISH: u32 = 10;
const DONE: u32 = 11;
const STREAM_OFFSET: usize = size_of::<usize>();

unsafe extern "C" {
    fn zapret_lua_zstream_entry(inflating: bool) -> Entry;
    fn zapret_lua_zstream_output_label(finalizer: bool) -> *const c_char;
    fn zapret_lua_zstream_next(action: u32, inflating: bool, argc: c_int, value: i64) -> u32;
    fn zapret_lua_zstream_process(
        stream: *mut c_void,
        inflating: bool,
        input: *const u8,
        length: usize,
        hint: u64,
        hinted: bool,
        output: *mut Output,
        ops: *const c_void,
    ) -> c_int;
    fn zapret_lua_zstream_release(output: *mut Output);
}

unsafe extern "C-unwind" {
    fn lua_check_argc_range(lua: *mut LuaState, name: *const c_char, low: c_int, high: c_int);
    fn lua_uzs(lua: *mut LuaState, index: c_int, inflating: bool) -> *mut c_void;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    fn luaL_checklstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn luaL_checkudata(lua: *mut LuaState, index: c_int, name: *const c_char) -> *mut c_void;
    fn luaL_newmetatable(lua: *mut LuaState, name: *const c_char) -> c_int;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_pushcclosure(lua: *mut LuaState, function: Callback, upvalues: c_int);
    fn lua_setfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_setmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, length: usize);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_remove(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe extern "C-unwind" fn output_gc(lua: *mut LuaState) -> c_int {
    unsafe {
        let output = luaL_checkudata(lua, 1, zapret_lua_zstream_output_label(false));
        zapret_lua_zstream_release(output.cast());
    }
    0
}

unsafe fn output_buffer(lua: *mut LuaState) -> *mut Output {
    unsafe {
        let output = lua_newuserdata(lua, size_of::<Output>()).cast::<Output>();
        output.write_bytes(0, 1);
        if luaL_newmetatable(lua, zapret_lua_zstream_output_label(false)) != 0 {
            lua_pushcclosure(lua, output_gc, 0);
            lua_setfield(lua, -2, zapret_lua_zstream_output_label(true));
        }
        lua_setmetatable(lua, -2);
        output
    }
}

unsafe fn run(lua: *mut LuaState, inflating: bool) -> c_int {
    // The Lua userdata owns the output before processing starts. The same
    // finalizer releases its bytes when string publication raises an error.
    unsafe {
        let entry = zapret_lua_zstream_entry(inflating);
        lua_check_argc_range(lua, entry.name, entry.minimum, entry.maximum);
        let top = lua_gettop(lua);
        let mut stream: *mut c_void = ptr::null_mut();
        let mut output: *mut Output = ptr::null_mut();
        let mut input = ptr::null();
        let mut length = 0;
        let (mut argc, mut value, mut hint) = (0, 0, 0);
        let mut action = zapret_lua_zstream_next(ARITY, inflating, argc, value);
        loop {
            match action {
                STREAM => stream = lua_uzs(lua, 1, inflating),
                INPUT => input = luaL_checklstring(lua, 2, &raw mut length).cast(),
                COUNT => argc = lua_gettop(lua),
                INPUT_OMITTED => value = i64::from(lua_type(lua, 2) == 0),
                HINT => {
                    value = luaL_checkinteger(lua, 3) as i64;
                    hint = value as u64;
                }
                PROCESS | PROCESS_WITH_HINT => {
                    output = output_buffer(lua);
                    value = i64::from(zapret_lua_zstream_process(
                        stream.cast::<u8>().add(STREAM_OFFSET).cast(),
                        inflating,
                        input,
                        length,
                        hint,
                        action == PROCESS_WITH_HINT,
                        output,
                        ptr::null(),
                    ));
                }
                DROP_OUTPUT => lua_settop(lua, -2),
                NIL_RESULTS => {
                    lua_pushnil(lua);
                    lua_pushnil(lua);
                }
                PUBLISH => {
                    let finished = (*output).finished;
                    lua_pushlstring(lua, (*output).data.cast(), (*output).length);
                    zapret_lua_zstream_release(output);
                    lua_remove(lua, -2);
                    lua_pushboolean(lua, c_int::from(finished));
                }
                DONE => {
                    if top.wrapping_add(entry.results) != lua_gettop(lua) {
                        luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                    return entry.results;
                }
                _ => return luaL_error(lua, c"invalid Lua zstream action".as_ptr()),
            }
            action = zapret_lua_zstream_next(action, inflating, argc, value);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_gunzip_inflate(lua: *mut LuaState) -> c_int {
    unsafe { run(lua, true) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_gzip_deflate(lua: *mut LuaState) -> c_int {
    unsafe { run(lua, false) }
}
