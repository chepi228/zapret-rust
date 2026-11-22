//! Codec lifecycle entries for a protected Windows Lua frame.
//! The VM owns the userdata. Only borrowed pointers and plain stack values
//! cross calls into Lua, and codec natives cannot enter the VM.
#![no_std]

use core::{
    ffi::{CStr, c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

#[cfg(not(all(windows, any(target_arch = "x86", target_arch = "x86_64"))))]
compile_error!("The Lua codec entries require the Windows x86 or x64 ABI");

const STREAM_TYPE: &CStr = c"userdata_zstream";
const LUA_REGISTRYINDEX: c_int = -10000;
const LUA_TNIL: c_int = 0;
const COLLECT: u32 = 2;

#[repr(C)]
pub struct LuaState {
    opaque: [u8; 0],
}

const POINTER: usize = size_of::<usize>();
const STREAM_USERDATA_SIZE: usize = if POINTER == 8 { 96 } else { 60 };

#[repr(C)]
pub struct StreamUserdata {
    opaque: [MaybeUninit<usize>; STREAM_USERDATA_SIZE / POINTER],
}

#[repr(C)]
struct Options {
    opaque: [MaybeUninit<u32>; 6],
}

#[repr(C)]
struct Allocators {
    allocate: unsafe extern "C" fn(*mut c_void, u32, u32) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void, *mut c_void),
}

#[repr(C)]
struct Ops {
    opaque: [u8; 0],
}

const _: () = {
    assert!(size_of::<StreamUserdata>() == STREAM_USERDATA_SIZE);
    assert!(align_of::<StreamUserdata>() == POINTER);
    assert!(size_of::<Options>() == 24 && align_of::<Options>() == 4);
    assert!(size_of::<Allocators>() == 2 * POINTER);
};

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_checkinteger(lua: *mut LuaState, index: c_int) -> isize;
    fn luaL_checkudata(
        lua: *mut LuaState,
        index: c_int,
        name: *const c_char,
    ) -> *mut StreamUserdata;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut StreamUserdata;
    fn lua_getfield(lua: *mut LuaState, index: c_int, key: *const c_char);
    fn luaL_newmetatable(lua: *mut LuaState, name: *const c_char) -> c_int;
    fn lua_setmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushnil(lua: *mut LuaState);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(address: *mut c_void);
    fn zapret_lua_arity_error(
        actual: c_int,
        minimum: c_int,
        maximum: c_int,
        ranged: bool,
    ) -> *const c_char;
    fn zapret_lua_codec_options_begin(role: u32, argc: u32, options: *mut Options) -> bool;
    fn zapret_lua_codec_options_next(options: *const Options, index: *mut c_int) -> u32;
    fn zapret_lua_codec_options_observe(options: *mut Options, absent: u32, number: i64) -> bool;
    fn zapret_lua_codec_validate(stream: *const StreamUserdata, role: u32) -> u32;
    fn zapret_lua_codec_initialize(
        stream: *mut StreamUserdata,
        options: *const Options,
        allocators: *const Allocators,
        ops: *const Ops,
    ) -> c_int;
    fn zapret_lua_codec_finish(stream: *mut StreamUserdata, role: u32, ops: *const Ops) -> c_int;
}

unsafe extern "C" fn codec_allocate(_: *mut c_void, items: u32, size: u32) -> *mut c_void {
    let Some(bytes) = (items as usize).checked_mul(size as usize) else {
        return ptr::null_mut();
    };
    unsafe { malloc(bytes) }
}

unsafe extern "C" fn codec_release(_: *mut c_void, address: *mut c_void) {
    unsafe { free(address) }
}

static ALLOCATORS: Allocators = Allocators {
    allocate: codec_allocate,
    release: codec_release,
};

#[inline]
unsafe extern "C-unwind" fn stack_result(
    lua: *mut LuaState,
    start: c_int,
    results: c_int,
) -> c_int {
    if unsafe { lua_gettop(lua) } != start + results {
        unsafe { luaL_error(lua, c"stack guard failure".as_ptr()) }
    } else {
        results
    }
}

/// # Safety
/// The pinned LuaJIT calls this with a live callback state under SEH.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn lua_cfunc_zstream_gc(lua: *mut LuaState) -> c_int {
    unsafe {
        let stream = luaL_checkudata(lua, 1, STREAM_TYPE.as_ptr());
        zapret_lua_codec_finish(stream, COLLECT, ptr::null());
    }
    0
}

/// # Safety
/// The given index must refer to a live Lua callback stack. On success the
/// returned pointer is valid while its userdata is rooted on that stack.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn lua_uzs(
    lua: *mut LuaState,
    index: c_int,
    inflating: bool,
) -> *mut StreamUserdata {
    unsafe {
        let stream = luaL_checkudata(lua, index, STREAM_TYPE.as_ptr());
        let message = match zapret_lua_codec_validate(stream, u32::from(inflating)) {
            0 => return stream,
            1 => c"gzip stream is not valid",
            2 => c"gzip stream role mismatch",
            _ => c"invalid codec metadata",
        };
        luaL_error(lua, message.as_ptr());
        stream
    }
}

#[inline(never)]
unsafe extern "C-unwind" fn codec_init(lua: *mut LuaState, inflating: bool) -> c_int {
    let (name, maximum) = if inflating {
        (c"gunzip_init", 1)
    } else {
        (c"gzip_init", 3)
    };
    unsafe {
        let actual = lua_gettop(lua);
        let format = zapret_lua_arity_error(actual, 0, maximum, true);
        if !format.is_null() {
            return luaL_error(lua, format, name.as_ptr(), 0, maximum, actual);
        }

        let start = lua_gettop(lua);
        let mut options = MaybeUninit::<Options>::uninit();
        let options = options.as_mut_ptr();
        if !zapret_lua_codec_options_begin(u32::from(inflating), lua_gettop(lua) as u32, options) {
            return luaL_error(lua, c"invalid codec options".as_ptr());
        }

        loop {
            let mut index = MaybeUninit::<c_int>::uninit();
            match zapret_lua_codec_options_next(options, index.as_mut_ptr()) {
                0 => break,
                1 => {
                    let index = index.assume_init();
                    let absent = lua_type(lua, index) == LUA_TNIL;
                    let number = if absent {
                        0
                    } else {
                        luaL_checkinteger(lua, index) as i64
                    };
                    if !zapret_lua_codec_options_observe(options, u32::from(absent), number) {
                        return luaL_error(lua, c"invalid codec option".as_ptr());
                    }
                }
                _ => return luaL_error(lua, c"invalid codec options".as_ptr()),
            }
        }

        let stream = lua_newuserdata(lua, size_of::<StreamUserdata>());
        if zapret_lua_codec_initialize(stream, options, &ALLOCATORS, ptr::null()) == 0 {
            // Engine registration has already created the shared GC metatable.
            // Preserve the inflate lookup and deflate get-or-create API calls.
            if inflating {
                lua_getfield(lua, LUA_REGISTRYINDEX, STREAM_TYPE.as_ptr());
            } else {
                luaL_newmetatable(lua, STREAM_TYPE.as_ptr());
            }
            lua_setmetatable(lua, -2);
        } else {
            lua_settop(lua, -2);
            lua_pushnil(lua);
        }
        stack_result(lua, start, 1)
    }
}

#[inline(never)]
unsafe extern "C-unwind" fn codec_end(lua: *mut LuaState, inflating: bool) -> c_int {
    let name = if inflating {
        c"gunzip_end"
    } else {
        c"gzip_end"
    };
    unsafe {
        let actual = lua_gettop(lua);
        let format = zapret_lua_arity_error(actual, 1, 1, false);
        if !format.is_null() {
            return luaL_error(lua, format, name.as_ptr(), 1, actual);
        }

        let start = lua_gettop(lua);
        let stream = lua_uzs(lua, 1, inflating);
        zapret_lua_codec_finish(stream, u32::from(inflating), ptr::null());
        stack_result(lua, start, 0)
    }
}

/// # Safety
/// The pinned LuaJIT calls this with a live callback state under SEH.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn luacall_gunzip_init(lua: *mut LuaState) -> c_int {
    unsafe { codec_init(lua, true) }
}

/// # Safety
/// The pinned LuaJIT calls this with a live callback state under SEH.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn luacall_gzip_init(lua: *mut LuaState) -> c_int {
    unsafe { codec_init(lua, false) }
}

/// # Safety
/// The pinned LuaJIT calls this with a live callback state under SEH.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn luacall_gunzip_end(lua: *mut LuaState) -> c_int {
    unsafe { codec_end(lua, true) }
}

/// # Safety
/// The pinned LuaJIT calls this with a live callback state under SEH.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn luacall_gzip_end(lua: *mut LuaState) -> c_int {
    unsafe { codec_end(lua, false) }
}
