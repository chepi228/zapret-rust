//! Sandbox removals and blob publication on the pinned Win64 LuaJIT VM.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const GLOBALS: c_int = -10_002;
const LUA_TTABLE: c_int = 5;
const REMOVE: u32 = 2;
const REMOVE_END: u32 = 3;
const BAD_GLOBAL: u32 = 4;
const BAD_FIELD: u32 = 5;
const BLOB_CHANGED: u32 = 6;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct BlobHead {
    opaque: [u8; 0],
}

#[repr(C)]
struct BlobItem {
    opaque: [u8; 0],
}

#[repr(C)]
struct BlobAllocator {
    opaque: [u8; 0],
}

#[repr(C)]
struct Sources {
    lua: *const *mut LuaState,
    blobs: *mut BlobHead,
    allocator: *const BlobAllocator,
}

#[repr(C)]
struct Path {
    global: *const c_char,
    field: *const c_char,
    nested: *const c_char,
}

#[repr(C)]
struct Blob {
    expected: *mut BlobItem,
    name: *const c_char,
    data: *const u8,
    length: usize,
}

const _: () = {
    assert!(size_of::<Sources>() == 24 && size_of::<Path>() == 24);
    assert!(size_of::<Blob>() == 32);
};

unsafe extern "C" {
    static zapret_lua_sandbox_sources: Sources;
    fn zapret_lua_startup_text(label: u32) -> *const c_char;
    fn zapret_lua_harden_next(index: *mut u32, path: *mut Path) -> u32;
    fn zapret_lua_startup_blob(head: *const BlobHead, blob: *mut Blob) -> u32;
    fn zapret_lua_startup_blob_commit(
        head: *mut BlobHead,
        expected: *mut BlobItem,
        allocator: *const BlobAllocator,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushstring(lua: *mut LuaState, text: *const c_char);
    fn lua_pushlstring(lua: *mut LuaState, data: *const c_char, length: usize);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_rawset(lua: *mut LuaState, index: c_int);
    fn lua_setfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn DLOG(format: *const c_char, ...) -> c_int;
}

unsafe fn vm() -> *mut LuaState {
    unsafe { zapret_lua_sandbox_sources.lua.read() }
}

unsafe fn check_stack(top: c_int) {
    unsafe {
        if lua_gettop(vm()) != top {
            luaL_error(vm(), c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_sec_harden() {
    unsafe {
        let top = lua_gettop(vm());
        DLOG(zapret_lua_startup_text(REMOVE));
        let mut index = 0;
        let mut path = MaybeUninit::<Path>::uninit();
        loop {
            match zapret_lua_harden_next(&mut index, path.as_mut_ptr()) {
                0 => break,
                1 => {}
                _ => {
                    luaL_error(vm(), c"invalid Lua sandbox state".as_ptr());
                    return;
                }
            }
            let path = path.assume_init_read();
            if path.field.is_null() {
                lua_pushnil(vm());
                lua_setfield(vm(), GLOBALS, path.global);
                DLOG(c" %s".as_ptr(), path.global);
                continue;
            }
            lua_getfield(vm(), GLOBALS, path.global);
            if lua_type(vm(), -1) != LUA_TTABLE {
                luaL_error(vm(), zapret_lua_startup_text(BAD_GLOBAL), path.global);
                return;
            }
            let pop_index = if path.nested.is_null() {
                lua_pushstring(vm(), path.field);
                DLOG(c" %s.%s".as_ptr(), path.global, path.field);
                -2
            } else {
                lua_getfield(vm(), -1, path.field);
                if lua_type(vm(), -1) != LUA_TTABLE {
                    luaL_error(
                        vm(),
                        zapret_lua_startup_text(BAD_FIELD),
                        path.global,
                        path.field,
                    );
                    return;
                }
                lua_pushstring(vm(), path.nested);
                DLOG(c" %s.%s.%s".as_ptr(), path.global, path.field, path.nested);
                -3
            };
            lua_pushnil(vm());
            lua_rawset(vm(), -3);
            lua_settop(vm(), pop_index);
        }
        DLOG(zapret_lua_startup_text(REMOVE_END));
        check_stack(top);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init_blobs() {
    unsafe {
        let top = lua_gettop(vm());
        let sources = &zapret_lua_sandbox_sources;
        let mut blob = MaybeUninit::<Blob>::uninit();
        loop {
            match zapret_lua_startup_blob(sources.blobs, blob.as_mut_ptr()) {
                0 => break,
                1 => {}
                _ => {
                    luaL_error(vm(), c"invalid startup blob state".as_ptr());
                    return;
                }
            }
            let blob = blob.assume_init_read();
            DLOG(
                c"LUA BLOB: %s (size=%zu)\n".as_ptr(),
                blob.name,
                blob.length,
            );
            // The native list owns the blob through both VM calls.
            lua_pushlstring(vm(), blob.data.cast(), blob.length);
            lua_setfield(vm(), GLOBALS, blob.name);
            if !zapret_lua_startup_blob_commit(sources.blobs, blob.expected, sources.allocator) {
                luaL_error(vm(), zapret_lua_startup_text(BLOB_CHANGED));
                return;
            }
        }
        check_stack(top);
    }
}
