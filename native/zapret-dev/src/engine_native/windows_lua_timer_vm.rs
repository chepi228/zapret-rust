//! Guest Lua timer entries for the pinned Win64 LuaJIT SEH ABI.
//! Lua owns the registry references. Only plain state and borrowed pointers
//! cross calls that can raise a VM exception.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_ulonglong},
    mem::{MaybeUninit, offset_of},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These callbacks require the Win64 LuaJIT SEH ABI");

const REGISTRY: c_int = -10_000;
const GLOBALS: c_int = -10_002;
const LUA_TFUNCTION: c_int = 6;
const TIMERS_OFFSET: usize = 16_856;
const PARAMS_SIZE: usize = 16_896;

#[repr(C)]
pub struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct TimerPool {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_timers: [MaybeUninit<u8>; TIMERS_OFFSET],
    timers: *mut TimerPool,
    timers_dirty: bool,
    after_dirty: [MaybeUninit<u8>; PARAMS_SIZE - TIMERS_OFFSET - 9],
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

#[repr(C)]
struct State {
    timer: Timer,
    old: Timer,
    name: *const c_char,
    function: *const c_char,
    after: u64,
    index: i64,
    argc: c_int,
    result: c_int,
    mode: u32,
    phase: u32,
}

#[repr(C)]
struct Action {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    kind: u32,
    index: c_int,
}

#[repr(C)]
struct Value {
    data: *const c_char,
    integer: i64,
    code: c_int,
}

const _: () = {
    assert!(size_of::<Params>() == PARAMS_SIZE);
    assert!(offset_of!(Params, timers) == TIMERS_OFFSET);
    assert!(offset_of!(Params, timers_dirty) == 16_864);
    assert!(size_of::<Timer>() == 40 && offset_of!(Timer, oneshot) == 32);
    assert!(size_of::<State>() == 128 && offset_of!(State, mode) == 120);
    assert!(size_of::<Action>() == 32 && size_of::<Value>() == 24);
    assert!(size_of::<isize>() == size_of::<i64>());
};

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_checklstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_pushvalue(lua: *mut LuaState, index: c_int);
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_ref(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushstring(lua: *mut LuaState, text: *const c_char);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_createtable(lua: *mut LuaState, array: c_int, records: c_int);
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, length: usize);
    fn lua_rawgeti(lua: *mut LuaState, table: c_int, index: c_int);
    fn lua_rawset(lua: *mut LuaState, table: c_int);
    fn lua_pushf_lint(lua: *mut LuaState, field: *const c_char, value: i64);
    fn lua_pushf_bool(lua: *mut LuaState, field: *const c_char, value: bool);
    fn lua_rawseti(lua: *mut LuaState, table: c_int, index: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn zapret_timer_unref(timer: *const Timer);
}

unsafe extern "C" {
    static mut params: Params;
    fn zapret_lua_timer_begin(mode: u32, state: *mut State, action: *mut Action) -> bool;
    fn zapret_lua_timer_step(state: *mut State, value: *const Value, action: *mut Action) -> bool;
    fn zapret_lua_arity_error(actual: c_int, min: c_int, max: c_int, ranged: bool)
    -> *const c_char;
    fn boottime_ms() -> u64;
    fn zapret_timer_set(
        pool: *mut *mut TimerPool,
        name: *const c_char,
        timer: *const Timer,
        now: u64,
        old: *mut Timer,
    ) -> c_int;
    fn zapret_timer_get(pool: *const TimerPool, name: *const c_char, timer: *mut Timer) -> c_int;
    fn zapret_timer_remove(pool: *mut *mut TimerPool, id: u64, old: *mut Timer) -> c_int;
    fn zapret_timer_after(pool: *const TimerPool, after: u64, timer: *mut Timer) -> c_int;
    fn DLOG(format: *const c_char, ...) -> c_int;
}

#[inline(never)]
unsafe extern "C-unwind" fn timer_entry(lua: *mut LuaState, mode: u32) -> c_int {
    let mut state = MaybeUninit::<State>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    let mut value = Value {
        data: ptr::null(),
        integer: 0,
        code: 0,
    };
    let mut start = 0;
    let state = state.as_mut_ptr();
    let action = action.as_mut_ptr();

    unsafe {
        if !zapret_lua_timer_begin(mode, state, action) {
            return luaL_error(lua, c"invalid Lua timer entry".as_ptr());
        }
        let timer = &raw mut (*state).timer;
        let old = &raw mut (*state).old;
        let pool = &raw mut params.timers;
        loop {
            let op = action.read();
            match op.kind {
                0 => {
                    let count = op.integer as c_int;
                    if lua_gettop(lua) != start + count {
                        return luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                    return count;
                }
                1 => {
                    let min = op.integer as c_int;
                    let ranged = op.integer != i64::from(op.index);
                    let actual = lua_gettop(lua);
                    let format = zapret_lua_arity_error(actual, min, op.index, ranged);
                    if !format.is_null() {
                        return if ranged {
                            luaL_error(lua, format, op.name, min, op.index, actual)
                        } else {
                            luaL_error(lua, format, op.name, op.index, actual)
                        };
                    }
                    start = lua_gettop(lua);
                    if ranged {
                        value.integer = i64::from(lua_gettop(lua));
                    }
                }
                2 => value.data = luaL_checklstring(lua, op.index, ptr::null_mut()),
                3 => value.integer = luaL_checkinteger(lua, op.index) as i64,
                4 => value.code = lua_type(lua, op.index),
                5 => value.data = lua_tolstring(lua, op.index, ptr::null_mut()),
                6 => lua_getfield(lua, GLOBALS, op.data),
                7 => value.code = c_int::from(lua_type(lua, op.index) == LUA_TFUNCTION),
                8 => lua_pushvalue(lua, op.index),
                9 => value.code = lua_toboolean(lua, op.index),
                10 => value.code = luaL_ref(lua, REGISTRY),
                11 => lua_pushstring(lua, op.data),
                12 => {
                    value.code = zapret_timer_set(pool, (*state).name, timer, boottime_ms(), old);
                }
                13 => zapret_timer_unref(if op.index != 0 { old } else { timer }),
                14 => (&raw mut params.timers_dirty).write(true),
                15 => {
                    DLOG(
                        op.name,
                        (*state).name,
                        op.data,
                        (*timer).period as c_ulonglong,
                        (*timer).oneshot,
                    );
                }
                16 => {
                    return if op.index != 0 {
                        luaL_error(lua, op.name, op.data)
                    } else {
                        luaL_error(lua, c"%s".as_ptr(), op.name)
                    };
                }
                17 => value.code = zapret_timer_get(pool.read(), (*state).name, timer),
                18 => value.code = zapret_timer_remove(pool, (*timer).id, old),
                19 => {
                    DLOG(op.name, (*state).name, op.data);
                }
                20 => lua_pushboolean(lua, c_int::from(op.integer != 0)),
                21 => lua_createtable(lua, 0, 0),
                22 => lua_pushlstring(lua, op.name, op.integer as usize),
                23 => lua_rawgeti(lua, REGISTRY, op.integer as c_int),
                24 => lua_rawset(lua, op.index),
                25 => lua_pushf_lint(lua, op.name, op.integer),
                26 => lua_pushf_bool(lua, op.name, op.integer != 0),
                27 => value.code = zapret_timer_after(pool.read(), (*state).after, timer),
                28 => lua_rawseti(lua, op.index, op.integer as c_int),
                29 => lua_pushnil(lua),
                30 => {
                    // In the pinned build timer_info captures this handle
                    // before checking the name. Other lookups read it later.
                    let current_pool = pool.read();
                    let name = luaL_checklstring(lua, op.index, ptr::null_mut());
                    value.code = zapret_timer_get(current_pool, name, timer);
                }
                _ => return luaL_error(lua, c"invalid Lua timer action".as_ptr()),
            }
            if !zapret_lua_timer_step(state, &value, action) {
                return luaL_error(lua, c"invalid Lua timer state".as_ptr());
            }
        }
    }
}

macro_rules! timer_entries {
    ($($name:ident => $mode:literal),+ $(,)?) => {$(
        /// # Safety
        /// The pinned LuaJIT calls this with a live callback state under SEH.
        #[unsafe(no_mangle)]
        pub unsafe extern "C-unwind" fn $name(lua: *mut LuaState) -> c_int {
            unsafe { timer_entry(lua, $mode) }
        }
    )+};
}

timer_entries! {
    luacall_timer_set => 0,
    luacall_timer_del => 1,
    luacall_timer_info => 2,
    luacall_timer_enum => 3,
}
