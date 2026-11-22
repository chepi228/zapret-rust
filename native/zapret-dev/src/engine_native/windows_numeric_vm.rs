//! Windows Lua numeric entries. Only plain stack storage and borrowed
//! Lua pointers survive any call that can raise a VM exception.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::MaybeUninit,
    ptr,
};

#[cfg(not(all(windows, any(target_arch = "x86", target_arch = "x86_64"))))]
compile_error!("The Lua numeric entries require the Windows x86 or x64 ABI");

#[cfg(target_pointer_width = "32")]
#[path = "windows_lua_long_integer.rs"]
mod long_integer;

#[repr(C)]
pub struct LuaState {
    opaque: [u8; 0],
}

// The policy owns this layout and publishes some binary results from it.
// Keep the allocation fixed until the final string publication returns.
#[repr(C, align(8))]
struct State {
    opaque: [MaybeUninit<u8>; 2 * size_of::<usize>() + 32],
}

#[repr(C)]
struct Action {
    data: *const u8,
    name: *const c_char,
    integer: i64,
    length: usize,
    kind: u32,
    count: u32,
    minimum: c_int,
    maximum: c_int,
}

#[repr(C)]
struct Value {
    string: *const u8,
    length: usize,
    numbers: *const i64,
    integer: i64,
    count: c_int,
    kind: c_int,
}

const OPERAND_CAPACITY: usize = 100;
const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 2 * pointer + 32 && align_of::<State>() == 8);
    assert!(size_of::<Action>() == 2 * pointer + 32 && size_of::<Value>() == 2 * pointer + 24);
};

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_reqlstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const u8;
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    #[cfg(target_pointer_width = "32")]
    fn luaL_checknumber(lua: *mut LuaState, index: c_int) -> f64;
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    #[cfg(target_pointer_width = "64")]
    fn lua_pushinteger(lua: *mut LuaState, integer: isize);
    #[cfg(target_pointer_width = "32")]
    fn lua_pushnumber(lua: *mut LuaState, number: f64);
    fn lua_pushlstring(lua: *mut LuaState, data: *const u8, length: usize);
    fn lua_pushnil(lua: *mut LuaState);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe fn check_long(lua: *mut LuaState, index: c_int) -> i64 {
    #[cfg(target_pointer_width = "32")]
    return long_integer::from_number(unsafe { luaL_checknumber(lua, index) });
    #[cfg(target_pointer_width = "64")]
    return unsafe { luaL_checkinteger(lua, index) as i64 };
}

unsafe fn push_long(lua: *mut LuaState, integer: i64) {
    #[cfg(target_pointer_width = "32")]
    unsafe {
        lua_pushnumber(lua, integer as f64);
    }
    #[cfg(target_pointer_width = "64")]
    unsafe {
        lua_pushinteger(lua, integer as isize);
    }
}

unsafe extern "C" {
    fn zapret_lua_numeric_entry_begin(
        mode: u32,
        count: c_int,
        state: *mut State,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_numeric_entry_step(
        state: *mut State,
        value: *const Value,
        action: *mut Action,
    ) -> bool;
}

#[inline(never)]
unsafe extern "C-unwind" fn numeric_entry(lua: *mut LuaState, mode: u32) -> c_int {
    let mut state = MaybeUninit::<State>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    let mut operands = MaybeUninit::<[i64; OPERAND_CAPACITY]>::uninit();
    let mut value = Value {
        string: ptr::null(),
        length: 0,
        numbers: ptr::null(),
        integer: 0,
        count: 0,
        kind: 0,
    };
    let state = state.as_mut_ptr();
    let action = action.as_mut_ptr();
    let operands = operands.as_mut_ptr().cast::<i64>();

    unsafe {
        if !zapret_lua_numeric_entry_begin(mode, lua_gettop(lua), state, action) {
            return luaL_error(lua, c"invalid Lua numeric entry".as_ptr());
        }
        loop {
            let current = action.read();
            match current.kind {
                0 => return current.count as c_int,
                1 => {
                    return luaL_error(
                        lua,
                        current.data.cast(),
                        current.name,
                        current.minimum,
                        current.count as c_int,
                    );
                }
                2 => {
                    return luaL_error(
                        lua,
                        current.data.cast(),
                        current.name,
                        current.minimum,
                        current.maximum,
                        current.count as c_int,
                    );
                }
                3 => value.count = lua_gettop(lua),
                4 => value.string = lua_reqlstring(lua, 1, &mut value.length),
                5 => value.integer = check_long(lua, 1),
                6 if current.count as usize <= OPERAND_CAPACITY => {
                    for index in 0..current.count {
                        let operand = check_long(lua, index as c_int + 1);
                        operands.add(index as usize).write(operand);
                    }
                    value.numbers = operands;
                    value.count = current.count as c_int;
                }
                7 => value.kind = lua_type(lua, 2),
                8 => value.integer = luaL_checkinteger(lua, 2) as i64,
                9 => push_long(lua, current.integer),
                10 => lua_pushlstring(lua, current.data, current.length),
                11 => lua_pushnil(lua),
                12 => return luaL_error(lua, current.data.cast()),
                _ => return luaL_error(lua, c"invalid Lua numeric action".as_ptr()),
            }
            if !zapret_lua_numeric_entry_step(state, &value, action) {
                return luaL_error(lua, c"invalid Lua numeric state".as_ptr());
            }
        }
    }
}

macro_rules! numeric_entries {
    ($($name:ident => $mode:literal),+ $(,)?) => {$(
        /// # Safety
        /// The pinned LuaJIT calls this with its live callback state and SEH.
        #[unsafe(no_mangle)]
        pub unsafe extern "C-unwind" fn $name(lua: *mut LuaState) -> c_int {
            unsafe { numeric_entry(lua, $mode) }
        }
    )+};
}

numeric_entries! {
    luacall_bitlshift => 0,
    luacall_bitrshift => 1,
    luacall_bitand => 2,
    luacall_bitor => 3,
    luacall_bitxor => 4,
    luacall_bitnot8 => 5,
    luacall_bitnot16 => 6,
    luacall_bitnot24 => 7,
    luacall_bitnot32 => 8,
    luacall_bitnot48 => 9,
    luacall_bitget => 10,
    luacall_bitset => 11,
    luacall_swap16 => 12,
    luacall_swap24 => 13,
    luacall_swap32 => 14,
    luacall_swap48 => 15,
    luacall_u8add => 16,
    luacall_u16add => 17,
    luacall_u24add => 18,
    luacall_u32add => 19,
    luacall_u48add => 20,
    luacall_divint => 21,
    luacall_u8 => 22,
    luacall_u16 => 23,
    luacall_u24 => 24,
    luacall_u32 => 25,
    luacall_u48 => 26,
    luacall_bu8 => 27,
    luacall_bu16 => 28,
    luacall_bu24 => 29,
    luacall_bu32 => 30,
    luacall_bu48 => 31,
}
