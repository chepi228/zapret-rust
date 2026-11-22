//! Publish read-only views on the pinned Win64 LuaJIT stack.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const SERVER_OFFSET: usize = 12_705;
const PARAMS_SIZE: usize = 16_896;
const DONE: u32 = 0;
const QUERY_TRACK: u32 = 1;
const PUSH_NIL: u32 = 2;
const CREATE_TABLE: u32 = 3;
const WRITE_INTEGER: u32 = 4;
const WRITE_BOOLEAN: u32 = 5;
const WRITE_STRING: u32 = 6;
const WRITE_REGISTRY_ENTRY: u32 = 7;
const WRITE_NUMBER: u32 = 8;
const PUSH_LITERAL: u32 = 9;
const RAW_SET: u32 = 10;
const GET_FIELD: u32 = 11;
const PUBLISH_POSITION: u32 = 12;
const RAISE: u32 = 13;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C, align(8))]
struct Params {
    before_server: [MaybeUninit<u8>; SERVER_OFFSET],
    server: bool,
    after_server: [MaybeUninit<u8>; PARAMS_SIZE - SERVER_OFFSET - 1],
}

#[repr(C, align(8))]
struct PositionView {
    fields: [MaybeUninit<u8>; 112],
}

#[repr(C)]
struct TrackView {
    positions: [PositionView; 2],
    metadata: [MaybeUninit<u8>; 48],
}

#[repr(C)]
struct PositionState {
    view: *const PositionView,
    index: u32,
    phase: u32,
}

#[repr(C)]
struct TrackState {
    view: TrackView,
    mode: u32,
    phase: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Action {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    floating: f64,
    kind: u32,
    index: c_int,
}

const _: () = {
    assert!(size_of::<Params>() == PARAMS_SIZE && offset_of!(Params, server) == SERVER_OFFSET);
    assert!(size_of::<PositionView>() == 112 && size_of::<TrackView>() == 272);
    assert!(size_of::<PositionState>() == 16);
    assert!(size_of::<TrackState>() == 280 && offset_of!(TrackState, mode) == 272);
    assert!(size_of::<Action>() == 40 && offset_of!(Action, kind) == 32);
};

unsafe extern "C" {
    static mut params: Params;
    fn zapret_lua_track_position(
        track: *const c_void,
        position: *const c_void,
        view: *mut PositionView,
    ) -> bool;
    fn zapret_lua_track_view(
        track: *const c_void,
        positions: *const c_void,
        incoming: bool,
        server: bool,
        view: *mut TrackView,
    ) -> u32;
    fn zapret_lua_position_publication_begin(
        view: *const PositionView,
        state: *mut PositionState,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_position_publication_step(state: *mut PositionState, action: *mut Action)
    -> bool;
    fn zapret_lua_track_publication_begin(
        mode: u32,
        state: *mut TrackState,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_track_publication_step(
        state: *mut TrackState,
        status: u32,
        action: *mut Action,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_createtable(lua: *mut LuaState, array: c_int, fields: c_int);
    fn lua_pushlstring(lua: *mut LuaState, value: *const c_char, length: usize);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_pushf_lint(lua: *mut LuaState, name: *const c_char, value: i64);
    fn lua_pushf_int(lua: *mut LuaState, name: *const c_char, value: isize);
    fn lua_pushf_bool(lua: *mut LuaState, name: *const c_char, value: bool);
    fn lua_pushf_str(lua: *mut LuaState, name: *const c_char, value: *const c_char);
    fn lua_pushf_reg(lua: *mut LuaState, name: *const c_char, reference: c_int);
    fn lua_pushf_number(lua: *mut LuaState, name: *const c_char, value: f64);
}

unsafe fn check_stack(lua: *mut LuaState, expected: c_int) {
    unsafe {
        if lua_gettop(lua) != expected {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_lua_push_track_position(
    lua: *mut LuaState,
    view: *const PositionView,
) {
    let mut state = MaybeUninit::<PositionState>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_position_publication_begin(view, state.as_mut_ptr(), action.as_mut_ptr()) {
            luaL_error(lua, c"invalid connection position view".as_ptr());
            return;
        }
        loop {
            let operation = action.assume_init_read();
            match operation.kind {
                DONE => {
                    check_stack(lua, top);
                    return;
                }
                CREATE_TABLE => lua_createtable(lua, 0, operation.integer as c_int),
                WRITE_INTEGER => lua_pushf_lint(lua, operation.name, operation.integer),
                WRITE_BOOLEAN => lua_pushf_bool(lua, operation.name, operation.integer != 0),
                PUSH_LITERAL => lua_pushlstring(lua, operation.name, operation.integer as usize),
                RAW_SET => lua_rawset(lua, operation.index),
                _ => {
                    luaL_error(lua, c"invalid connection position action".as_ptr());
                    return;
                }
            }
            if !zapret_lua_position_publication_step(state.as_mut_ptr(), action.as_mut_ptr()) {
                luaL_error(lua, c"invalid connection position state".as_ptr());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_ctrack_pos(
    lua: *mut LuaState,
    track: *const c_void,
    position: *const c_void,
) {
    let mut view = MaybeUninit::<PositionView>::uninit();
    unsafe {
        if !zapret_lua_track_position(track, position, view.as_mut_ptr()) {
            luaL_error(lua, c"invalid connection position view".as_ptr());
            return;
        }
        native_lua_push_track_position(lua, view.as_ptr());
    }
}

unsafe fn publish_track(
    lua: *mut LuaState,
    track: *const c_void,
    positions: *const c_void,
    incoming: bool,
    mode: u32,
) {
    let mut state = MaybeUninit::<TrackState>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_track_publication_begin(mode, state.as_mut_ptr(), action.as_mut_ptr()) {
            luaL_error(lua, c"invalid connection view".as_ptr());
            return;
        }
        let view = &raw mut (*state.as_mut_ptr()).view;
        loop {
            // The preceding VM call can change the inputs to this step.
            let operation = action.assume_init_read();
            let mut status = 0;
            match operation.kind {
                DONE => {
                    check_stack(lua, top.wrapping_add(operation.index));
                    return;
                }
                QUERY_TRACK => {
                    let server = (&raw const params.server).read();
                    status = zapret_lua_track_view(track, positions, incoming, server, view);
                }
                PUSH_NIL => lua_pushnil(lua),
                CREATE_TABLE => lua_createtable(lua, 0, operation.integer as c_int),
                WRITE_INTEGER => lua_pushf_int(lua, operation.name, operation.integer as isize),
                WRITE_BOOLEAN => lua_pushf_bool(lua, operation.name, operation.integer != 0),
                WRITE_STRING => lua_pushf_str(lua, operation.name, operation.data),
                WRITE_REGISTRY_ENTRY => {
                    lua_pushf_reg(lua, operation.name, operation.integer as c_int)
                }
                WRITE_NUMBER => lua_pushf_number(lua, operation.name, operation.floating),
                PUSH_LITERAL => lua_pushlstring(lua, operation.name, operation.integer as usize),
                RAW_SET => lua_rawset(lua, operation.index),
                GET_FIELD => lua_getfield(lua, operation.index, operation.name),
                PUBLISH_POSITION => {
                    // The publication policy only selects one of the two positions.
                    let first = (&raw const (*view).positions).cast::<PositionView>();
                    native_lua_push_track_position(lua, first.add(operation.index as usize));
                }
                RAISE => {
                    luaL_error(lua, c"%s".as_ptr(), operation.name);
                    return;
                }
                _ => {
                    luaL_error(lua, c"invalid connection view action".as_ptr());
                    return;
                }
            }
            if !zapret_lua_track_publication_step(state.as_mut_ptr(), status, action.as_mut_ptr()) {
                luaL_error(lua, c"invalid connection view state".as_ptr());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_push_ctrack(
    lua: *mut LuaState,
    track: *const c_void,
    positions: *const c_void,
    incoming: bool,
) {
    unsafe { publish_track(lua, track, positions, incoming, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushf_ctrack(
    lua: *mut LuaState,
    track: *const c_void,
    positions: *const c_void,
    incoming: bool,
) {
    unsafe { publish_track(lua, track, positions, incoming, 1) }
}
