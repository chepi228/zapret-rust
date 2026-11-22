//! Argument tables and execution-plan metadata on the pinned Win64 LuaJIT VM.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const PLAN_INVALID: u32 = 6;
const FUNC: u32 = 8;
const FUNC_N: u32 = 9;
const INSTANCE: u32 = 10;
const RANGE: u32 = 11;
const PAYLOAD: u32 = 12;
const FILTER: u32 = 13;
const ARG: u32 = 14;
const FILTER_CAPACITY: usize = 2048;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct LuaContext {
    opaque: [u8; 0],
}

#[repr(C)]
struct ArgumentNode {
    opaque: [u8; 0],
}

#[repr(C)]
struct ArgumentList {
    first: *const ArgumentNode,
}

#[repr(C)]
struct Argument {
    name: *const c_char,
    text: *const c_char,
    kind: u32,
}

#[repr(C)]
struct Rule {
    opaque: [u8; 0],
}

#[repr(C)]
struct PacketRange {
    opaque: [u8; 0],
}

#[repr(C)]
struct Cursor {
    next: *const Rule,
    number: u32,
    completed: u32,
    profile: u32,
    incoming: bool,
}

#[repr(C)]
struct Entry {
    name: *const c_char,
    args: *const ArgumentList,
    range: *const PacketRange,
    payload: u64,
    number: u32,
    index: u32,
    instance: [c_char; 256],
}

const _: () = {
    assert!(size_of::<ArgumentList>() == 8);
    assert!(size_of::<Argument>() == 24 && offset_of!(Argument, kind) == 16);
    assert!(size_of::<Cursor>() == 24 && offset_of!(Cursor, incoming) == 20);
    assert!(size_of::<Entry>() == 296 && offset_of!(Entry, instance) == 40);
};

unsafe extern "C" {
    fn zapret_lua_argument_view_next(
        cursor: *mut *const ArgumentNode,
        substitute: bool,
        argument: *mut Argument,
    ) -> u32;
    fn zapret_lua_context_label(label: u32) -> *const c_char;
    fn zapret_lua_plan_begin_context(context: *const LuaContext, cursor: *mut Cursor) -> bool;
    fn zapret_lua_plan_next(cursor: *mut Cursor, entry: *mut Entry) -> u32;
    fn zapret_lua_plan_payload_next(mask: u64, cursor: *mut u32) -> *const c_char;
    fn l7_payload_str_list(mask: u64, text: *mut c_char, capacity: usize) -> bool;
    fn strlen(text: *const c_char) -> usize;
}

unsafe extern "C-unwind" {
    fn lua_absindex(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_check_argc(lua: *mut LuaState, location: *const c_char, count: c_int);
    fn lua_desync_ctx(lua: *mut LuaState) -> *mut LuaContext;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_pushlstring(lua: *mut LuaState, value: *const c_char, size: usize);
    fn lua_createtable(lua: *mut LuaState, array: c_int, fields: c_int);
    fn lua_pushf_str(lua: *mut LuaState, name: *const c_char, value: *const c_char);
    fn lua_pushf_int(lua: *mut LuaState, name: *const c_char, value: isize);
    fn lua_pushf_nil(lua: *mut LuaState, name: *const c_char);
    fn lua_pushf_range(lua: *mut LuaState, name: *const c_char, range: *const PacketRange);
    fn lua_pushf_blob(
        lua: *mut LuaState,
        index: c_int,
        field: *const c_char,
        blob: *const c_char,
    ) -> bool;
    fn lua_push_blob(lua: *mut LuaState, index: c_int, blob: *const c_char) -> bool;
    fn lua_objlen(lua: *mut LuaState, index: c_int) -> usize;
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_tolstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn push_literal(lua: *mut LuaState, label: u32) {
    unsafe {
        let key = zapret_lua_context_label(label);
        lua_pushlstring(lua, key, strlen(key));
    }
}

unsafe fn check_stack(lua: *mut LuaState, expected: c_int) {
    unsafe {
        if lua_gettop(lua) != expected {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_args(
    lua: *mut LuaState,
    args: *const ArgumentList,
    desync_index: c_int,
    substitute: bool,
) -> bool {
    unsafe {
        let top = lua_gettop(lua);
        let desync_index = lua_absindex(lua, desync_index);
        push_literal(lua, ARG);
        lua_createtable(lua, 0, 0);

        let mut cursor = (&raw const (*args).first).read();
        let mut argument = MaybeUninit::<Argument>::uninit();
        let publish = loop {
            match zapret_lua_argument_view_next(&mut cursor, substitute, argument.as_mut_ptr()) {
                0 => break true,
                1 => {}
                _ => break false,
            }
            let argument = argument.assume_init_ref();
            match argument.kind {
                0 => lua_pushf_str(lua, argument.name, argument.text),
                1 => {
                    if !lua_pushf_blob(lua, desync_index, argument.name, argument.text) {
                        break false;
                    }
                }
                _ => {
                    if !lua_push_blob(lua, desync_index, argument.text) {
                        break false;
                    }
                    let length = lua_objlen(lua, -1) as isize;
                    lua_settop(lua, -2);
                    lua_pushstring(lua, argument.name);
                    lua_pushinteger(lua, length);
                    lua_tolstring(lua, -1, ptr::null_mut());
                    lua_rawset(lua, -3);
                }
            }
        };
        if publish {
            lua_rawset(lua, -3);
        } else {
            lua_settop(lua, -3);
        }
        check_stack(lua, top);
        publish
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_execution_plan(lua: *mut LuaState) -> c_int {
    unsafe {
        lua_check_argc(lua, c"execution_plan".as_ptr(), 1);
        let top = lua_gettop(lua);
        let context = lua_desync_ctx(lua);
        let mut cursor = MaybeUninit::<Cursor>::uninit();
        if !zapret_lua_plan_begin_context(context, cursor.as_mut_ptr()) {
            return luaL_error(lua, zapret_lua_context_label(PLAN_INVALID));
        }
        lua_createtable(lua, 0, 0);
        let mut entry = MaybeUninit::<Entry>::uninit();
        loop {
            match zapret_lua_plan_next(cursor.as_mut_ptr(), entry.as_mut_ptr()) {
                0 => break,
                1 => {}
                _ => return luaL_error(lua, zapret_lua_context_label(PLAN_INVALID)),
            }
            let entry = entry.assume_init_ref();
            lua_pushinteger(lua, entry.index as isize);
            lua_createtable(lua, 0, 7);
            lua_pushf_args(lua, entry.args, -1, false);
            lua_pushf_str(lua, zapret_lua_context_label(FUNC), entry.name);
            lua_pushf_int(lua, zapret_lua_context_label(FUNC_N), entry.number as isize);
            lua_pushf_str(
                lua,
                zapret_lua_context_label(INSTANCE),
                entry.instance.as_ptr(),
            );
            lua_pushf_range(lua, zapret_lua_context_label(RANGE), entry.range);

            push_literal(lua, PAYLOAD);
            lua_createtable(lua, 0, 0);
            let mut payload = 0;
            loop {
                let name = zapret_lua_plan_payload_next(entry.payload, &mut payload);
                if name.is_null() {
                    break;
                }
                lua_pushstring(lua, name);
                lua_pushboolean(lua, 1);
                lua_rawset(lua, -3);
            }
            lua_rawset(lua, -3);

            let mut filter = MaybeUninit::<[c_char; FILTER_CAPACITY]>::uninit();
            let filter_buffer = filter.as_mut_ptr().cast();
            let filter_key = zapret_lua_context_label(FILTER);
            if l7_payload_str_list(entry.payload, filter_buffer, FILTER_CAPACITY) {
                lua_pushf_str(lua, filter_key, filter_buffer);
            } else {
                lua_pushf_nil(lua, filter_key);
            }
            lua_rawset(lua, -3);
        }
        check_stack(lua, top + 1);
        1
    }
}
