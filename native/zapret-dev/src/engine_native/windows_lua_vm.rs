//! VM startup, shutdown, and collection for the pinned Win64 LuaJIT ABI.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem::{offset_of, size_of},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const REGISTRY: c_int = -10_000;
const MULTRET: c_int = -1;
const LUA_TTABLE: c_int = 5;
const LUA_TFUNCTION: c_int = 6;
const LUA_GCCOLLECT: c_int = 2;
const LUA_GCCOUNT: c_int = 3;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct ConntrackPool {
    opaque: [u8; 0],
}

#[repr(C)]
struct TimerPool {
    opaque: [u8; 0],
}

#[repr(C)]
struct Sources {
    lua: *mut *mut LuaState,
    conntrack: *mut ConntrackPool,
    timers: *mut *mut TimerPool,
    gc_interval: *const u64,
    gc_time: *mut u64,
    jit_version: *const c_char,
    jit_edition: *const c_char,
    lua_version: c_uint,
}

const _: () = {
    assert!(size_of::<Sources>() == 64);
    assert!(offset_of!(Sources, jit_version) == 40);
    assert!(offset_of!(Sources, lua_version) == 56);
};

type Callback = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;

unsafe extern "C" {
    static zapret_lua_vm_sources: Sources;
    fn zapret_lua_vm_detach(address: *mut c_void) -> bool;
    fn zapret_cleanup_closed_params(params: *mut c_void);
}

unsafe extern "C-unwind" {
    fn luaL_newstate() -> *mut LuaState;
    fn lua_close(lua: *mut LuaState);
    fn lua_atpanic(lua: *mut LuaState, callback: Option<Callback>) -> Option<Callback>;
    fn luaL_openlibs(lua: *mut LuaState);
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_call(lua: *mut LuaState, arguments: c_int, results: c_int);
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    fn lua_gc(lua: *mut LuaState, action: c_int, size: c_int) -> c_int;

    fn lua_panic(lua: *mut LuaState) -> c_int;
    fn lua_desync_ctx_destroy(lua: *mut LuaState);
    fn rust_ring_register(lua: *mut LuaState) -> c_int;
    #[cfg(zapret_engine_production)]
    fn zapret_register_native_modules(lua: *mut LuaState);
    fn ConntrackPoolDestroy(pool: *mut ConntrackPool);
    fn TimerPoolDestroy(pool: *mut *mut TimerPool);
    fn boottime_ms() -> u64;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
}

unsafe fn vm() -> *mut LuaState {
    // A VM operation or a native callback can update this slot.
    unsafe { zapret_lua_vm_sources.lua.read() }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_cleanup(lua: *mut LuaState) {
    unsafe {
        lua_desync_ctx_destroy(lua);
        ConntrackPoolDestroy(zapret_lua_vm_sources.conntrack);
        TimerPoolDestroy(zapret_lua_vm_sources.timers);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_shutdown() {
    unsafe {
        if vm().is_null() {
            return;
        }
        DLOG(c"LUA SHUTDOWN\n".as_ptr());
        zapret_lua_vm_detach(vm().cast());
        lua_cleanup(vm());
        lua_close(vm());
        zapret_lua_vm_sources.lua.write(ptr::null_mut());
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn cleanup_params(params: *mut c_void) {
    unsafe {
        lua_shutdown();
        zapret_cleanup_closed_params(params);
    }
}

unsafe fn report_jit() -> bool {
    unsafe {
        lua_getfield(vm(), REGISTRY, c"_LOADED".as_ptr());
        if lua_type(vm(), -1) != LUA_TTABLE {
            return true;
        }
        lua_getfield(vm(), -1, c"jit".as_ptr());
        if lua_type(vm(), -1) != LUA_TTABLE {
            return true;
        }
        lua_getfield(vm(), -1, c"status".as_ptr());
        let status_type = lua_type(vm(), -1);
        let mut index = lua_gettop(vm());
        if status_type != LUA_TFUNCTION || index < 1 {
            return true;
        }

        lua_call(vm(), 0, MULTRET);
        let status = if lua_toboolean(vm(), index) != 0 {
            c"JIT: ON"
        } else {
            c"JIT: OFF"
        };
        DLOG_CONDUP(status.as_ptr());
        loop {
            let Some(next) = index.checked_add(1) else {
                DLOG_ERR(c"invalid Lua VM initialization plan\n".as_ptr());
                return false;
            };
            let text = lua_tolstring(vm(), next, ptr::null_mut());
            if text.is_null() {
                break;
            }
            DLOG_CONDUP(c" %s".as_ptr(), text);
            index = next;
        }
        DLOG_CONDUP(c"\n".as_ptr());
        true
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_basic_init() -> bool {
    unsafe {
        lua_shutdown();
        let created = luaL_newstate();
        zapret_lua_vm_sources.lua.write(created);
        if created.is_null() {
            DLOG_ERR(c"LUA INIT ERROR\n".as_ptr());
            return false;
        }
        let sources = &zapret_lua_vm_sources;
        DLOG_CONDUP(
            c"LUA v%u.%u %s%s\n".as_ptr(),
            sources.lua_version / 100,
            sources.lua_version % 100,
            sources.jit_version,
            sources.jit_edition,
        );
        lua_atpanic(vm(), Some(lua_panic));
        luaL_openlibs(vm());
        if rust_ring_register(vm()) == 0 {
            lua_close(vm());
            sources.lua.write(ptr::null_mut());
            return false;
        }
        #[cfg(zapret_engine_production)]
        zapret_register_native_modules(vm());
        if !report_jit() {
            return false;
        }
        lua_settop(vm(), 0);
        true
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_do_gc() {
    unsafe {
        let sources = &zapret_lua_vm_sources;
        if sources.gc_interval.read() == 0 {
            return;
        }
        let now = boottime_ms();
        if now.wrapping_sub(sources.gc_time.read()) < sources.gc_interval.read() {
            return;
        }
        let before = lua_gc(vm(), LUA_GCCOUNT, 0);
        lua_gc(vm(), LUA_GCCOLLECT, 0);
        let after = lua_gc(vm(), LUA_GCCOUNT, 0);
        DLOG(
            c"\nLUA GARBAGE COLLECT: %dK => %dK\n".as_ptr(),
            before,
            after,
        );
        sources.gc_time.write(now);
    }
}
