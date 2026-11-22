//! VM lifetime and diagnostic entries for the pinned Win64 LuaJIT SEH ABI.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const REGISTRY: c_int = -10_000;
const INTERRUPT_EVENTS: c_int = 15;
const CONTEXT_OFFSET: usize = 16_880;
const LUA_OFFSET: usize = 16_888;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct LuaDebug {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_context: [MaybeUninit<u8>; CONTEXT_OFFSET],
    context_ref: c_int,
    lua: *mut LuaState,
}

const _: () = {
    assert!(size_of::<Params>() == 16_896);
    assert!(offset_of!(Params, context_ref) == CONTEXT_OFFSET);
    assert!(offset_of!(Params, lua) == LUA_OFFSET);
};

type Hook = unsafe extern "C-unwind" fn(*mut LuaState, *mut LuaDebug);
type Install = unsafe extern "C" fn(*mut c_void);

unsafe extern "C" {
    static mut params: Params;
    fn zapret_lua_vm_publish(address: *mut c_void, install: Install);
    fn zapret_lua_vm_request_quit();
    // The pinned LuaJIT updates the dispatch table without entering the VM.
    fn lua_sethook(lua: *mut LuaState, hook: Option<Hook>, mask: c_int, count: c_int) -> c_int;
    fn exit(status: c_int) -> !;
}

unsafe extern "C-unwind" {
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn luaL_unref(lua: *mut LuaState, table: c_int, reference: c_int);
    fn lua_isstring(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const c_char;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
}

unsafe extern "C-unwind" fn interrupt_hook(lua: *mut LuaState, _: *mut LuaDebug) {
    unsafe {
        lua_sethook(lua, None, 0, 0);
        luaL_error(lua, c"INTERRUPT".as_ptr());
    }
}

unsafe extern "C" fn install_interrupt(address: *mut c_void) {
    unsafe { lua_sethook(address.cast(), Some(interrupt_hook), INTERRUPT_EVENTS, 1) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_publish(lua: *mut LuaState) {
    unsafe { zapret_lua_vm_publish(lua.cast(), install_interrupt) };
}

#[unsafe(no_mangle)]
extern "C" fn lua_req_quit() {
    unsafe { zapret_lua_vm_request_quit() };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_desync_ctx_destroy(lua: *mut LuaState) {
    unsafe {
        let slot = &raw mut params.context_ref;
        let reference = slot.read();
        if reference != 0 {
            // Keep the reference visible during unref and if Lua unwinds.
            luaL_unref(lua, REGISTRY, reference);
            slot.write(0);
        }
    }
}

unsafe fn report_error(slot: *const *mut LuaState) {
    unsafe {
        // Global callers observe the VM again after each operation. The
        // number-to-string conversion can run finalizers and raise an error.
        if lua_isstring(slot.read(), -1) != 0 {
            let message = lua_tolstring(slot.read(), -1, ptr::null_mut());
            DLOG_ERR(c"LUA ERROR: %s\n".as_ptr(), message);
        }
        lua_settop(slot.read(), -2);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_perror(lua: *mut LuaState) {
    unsafe { report_error(&raw const lua) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_panic(lua: *mut LuaState) -> c_int {
    unsafe {
        lua_perror(lua);
        DLOG_ERR(c"LUA PANIC: THIS IS FATAL. DYING.\n".as_ptr());
        exit(100);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_dlog_error() {
    unsafe { report_error(&raw const params.lua) };
}
