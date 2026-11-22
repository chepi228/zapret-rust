//! Scalar and system callbacks entered from a protected Windows Lua frame.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

#[cfg(target_pointer_width = "32")]
#[path = "windows_lua_long_integer.rs"]
mod long_integer;

type NativeBytes<const N: usize> = [MaybeUninit<u8>; N];

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C, align(8))]
struct State(NativeBytes<{ 2 * size_of::<usize>() + 32 }>);

#[repr(C)]
struct Action {
    text: *const c_char,
    data: *const c_void,
    integer: i64,
    length: usize,
    kind: u32,
    index: c_int,
    mode: u32,
    count: c_int,
}

#[derive(Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    pointer: *const c_void,
    integer: i64,
    status: c_int,
    count: c_int,
}

#[repr(C)]
struct SystemName(NativeBytes<516>);

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: c_int,
}

#[repr(C, align(8))]
struct FileInfo(NativeBytes<48>);

#[repr(C, align(4))]
struct Calendar(NativeBytes<36>);

type TimeConvert = unsafe extern "C" fn(*mut Calendar) -> i64;

const CLOCK_REALTIME: c_int = 0;

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 2 * pointer + 32);
    assert!(size_of::<Action>() == 2 * pointer + 32);
    assert!(offset_of!(Action, kind) == 3 * pointer + 8);
    assert!(size_of::<Value>() == 2 * pointer + 24);
    assert!(offset_of!(Value, status) == 2 * pointer + 16);
    assert!(size_of::<SystemName>() == 516 && size_of::<Calendar>() == 36);
    assert!(size_of::<Timespec>() == 16 && offset_of!(Timespec, nanoseconds) == 8);
    assert!(size_of::<FileInfo>() == 48);
};

// Only scalars, native snapshots and Lua-owned pointers cross a throwing call.
unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_checklstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    #[cfg(target_pointer_width = "64")]
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    #[cfg(target_pointer_width = "32")]
    fn luaL_checknumber(lua: *mut LuaState, index: c_int) -> f64;
    fn lua_pushlstring(lua: *mut LuaState, text: *const c_char, size: usize);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushstring(lua: *mut LuaState, text: *const c_char);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn native_lua_system_project(lua: *mut LuaState, mode: u32, view: *const c_void) -> c_int;
    fn lua_get_ifaddrs(lua: *mut LuaState) -> c_int;
    fn lua_timex(lua: *mut LuaState, convert: TimeConvert);
}

unsafe fn check_long(lua: *mut LuaState, index: c_int) -> i64 {
    #[cfg(target_pointer_width = "32")]
    return long_integer::from_number(unsafe { luaL_checknumber(lua, index) });
    #[cfg(target_pointer_width = "64")]
    return unsafe { luaL_checkinteger(lua, index) as i64 };
}

unsafe extern "C" {
    fn zapret_lua_scalar_begin(
        mode: u32,
        argc: c_int,
        state: *mut State,
        output: *mut Action,
    ) -> bool;
    fn zapret_lua_scalar_step(state: *mut State, value: *const Value, output: *mut Action) -> bool;
    fn zapret_lua_arity_error(argc: c_int, min: c_int, max: c_int, range: bool) -> *const c_char;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn getpid() -> c_int;
    fn zapret_lua_source_ip(
        input: *const u8,
        size: usize,
        output: *mut u8,
        ops: *const c_void,
    ) -> u32;
    fn uname(output: *mut SystemName) -> c_int;
    fn clock_gettime(clock: c_int, output: *mut Timespec) -> c_int;
    fn wf_file_stat(path: *const c_char, output: *mut FileInfo) -> c_int;
    fn zapret_localtime_r(seconds: *const i64, output: *mut Calendar) -> *mut Calendar;
    fn zapret_gmtime_r(seconds: *const i64, output: *mut Calendar) -> *mut Calendar;
    fn _mktime64(time: *mut Calendar) -> i64;
    fn _mkgmtime64(time: *mut Calendar) -> i64;
    fn _errno() -> *mut c_int;
    fn strerror(error: c_int) -> *const c_char;
}

unsafe extern "system" {
    fn GetCurrentThreadId() -> u32;
}

unsafe fn scalar(lua: *mut LuaState, mode: u32) -> c_int {
    let mut state = MaybeUninit::<State>::uninit();
    let mut output = MaybeUninit::<Action>::uninit();
    let mut value = Value::default();
    let mut system = MaybeUninit::<SystemName>::uninit();
    let mut clock = MaybeUninit::<Timespec>::uninit();
    let mut file = MaybeUninit::<FileInfo>::uninit();
    let mut calendar = MaybeUninit::<Calendar>::uninit();
    let mut source = MaybeUninit::<[u8; 16]>::uninit();

    unsafe {
        if !zapret_lua_scalar_begin(
            mode,
            lua_gettop(lua),
            state.as_mut_ptr(),
            output.as_mut_ptr(),
        ) {
            return luaL_error(lua, c"invalid Lua scalar entry".as_ptr());
        }
        loop {
            let action = output.assume_init_read();
            match action.kind {
                0 => return action.count,
                1 => {
                    let expected = action.integer as c_int;
                    let format = zapret_lua_arity_error(action.count, expected, expected, false);
                    return luaL_error(lua, format, action.text, expected, action.count);
                }
                2 => {
                    value.span.data = luaL_checklstring(lua, action.index, ptr::null_mut()).cast();
                    value.span.length = 0;
                }
                3 => {
                    value.span.data =
                        lua_reqlstring(lua, action.index, &raw mut value.span.length).cast();
                }
                4 => value.integer = check_long(lua, action.index),
                5 => value.integer = i64::from(lua_gettop(lua)),
                6 => lua_pushlstring(lua, action.data.cast(), action.length),
                7 => lua_pushnil(lua),
                8 => lua_pushinteger(lua, action.integer as isize),
                9 => lua_pushstring(lua, action.data.cast()),
                10 => {
                    let text = action.data.cast::<c_char>();
                    match action.mode {
                        0 => {
                            DLOG(action.text, text);
                        }
                        1 => {
                            DLOG_ERR(action.text, text);
                        }
                        2 => {
                            DLOG_CONDUP(action.text, text);
                        }
                        _ => {}
                    }
                }
                11 => {
                    return match action.mode {
                        0 => luaL_error(lua, action.text, action.length as c_uint),
                        1 => luaL_error(lua, action.text),
                        _ => luaL_error(lua, c"invalid Lua scalar error".as_ptr()),
                    };
                }
                12 => value.count = native_lua_system_project(lua, action.mode, action.data),
                30 => value.integer = i64::from(getpid()),
                31 => value.integer = i64::from(GetCurrentThreadId()),
                32 => {
                    lua_get_ifaddrs(lua);
                }
                33 => {
                    value.status = zapret_lua_source_ip(
                        action.data.cast(),
                        action.length,
                        source.as_mut_ptr().cast(),
                        ptr::null(),
                    ) as c_int;
                    value.pointer = source.as_ptr().cast();
                }
                34 => {
                    value.status = uname(system.as_mut_ptr());
                    value.pointer = system.as_ptr().cast();
                }
                35 => {
                    value.status = clock_gettime(CLOCK_REALTIME, clock.as_mut_ptr());
                    value.pointer = clock.as_ptr().cast();
                }
                36 => {
                    value.status = wf_file_stat(action.data.cast(), file.as_mut_ptr());
                    value.pointer = file.as_ptr().cast();
                }
                37 | 38 => {
                    let seconds = action.integer;
                    let convert = if action.kind == 37 {
                        zapret_localtime_r
                    } else {
                        zapret_gmtime_r
                    };
                    value.pointer = convert(&raw const seconds, calendar.as_mut_ptr()).cast();
                }
                39 => lua_timex(lua, _mktime64),
                40 => lua_timex(lua, _mkgmtime64),
                41 => {
                    value.span.data = strerror(_errno().read()).cast();
                    value.span.length = 0;
                }
                42 => value.integer = i64::from(_errno().read()),
                _ => return luaL_error(lua, c"invalid Lua scalar action".as_ptr()),
            }
            if !zapret_lua_scalar_step(state.as_mut_ptr(), &raw const value, output.as_mut_ptr()) {
                return luaL_error(lua, c"invalid Lua scalar state".as_ptr());
            }
        }
    }
}

macro_rules! scalar_entries {
    ($($entry:ident = $mode:literal),+ $(,)?) => {
        $(
            #[unsafe(no_mangle)]
            unsafe extern "C-unwind" fn $entry(lua: *mut LuaState) -> c_int {
                unsafe { scalar(lua, $mode) }
            }
        )+
    };
}

scalar_entries! {
    luacall_DLOG = 0,
    luacall_DLOG_ERR = 1,
    luacall_DLOG_CONDUP = 2,
    luacall_getpid = 3,
    luacall_gettid = 4,
    luacall_get_ifaddrs = 5,
    luacall_get_source_ip = 6,
    luacall_uname = 7,
    luacall_clock_gettime = 8,
    luacall_clock_getfloattime = 9,
    luacall_stat = 10,
    luacall_localtime = 11,
    luacall_gmtime = 12,
    luacall_timelocal = 13,
    luacall_timegm = 14,
}
