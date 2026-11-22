//! Initialization order and stack ownership for the pinned Win64 LuaJIT.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("This entry requires the Win64 LuaJIT SEH ABI");

const VM_OFFSET: usize = 16_888;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_vm: [MaybeUninit<u8>; VM_OFFSET],
    lua: *mut LuaState,
}

const _: () = {
    assert!(offset_of!(Params, lua) == VM_OFFSET);
    assert!(size_of::<Params>() == 16_896);
};

unsafe extern "C" {
    static mut params: Params;
    fn zapret_lua_startup_step(state: *mut u32, previous_ok: bool) -> u32;
    fn zapret_lua_startup_text(message: u32) -> *const c_char;
    fn zapret_lua_publish(lua: *mut LuaState);
}

unsafe extern "C-unwind" {
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_basic_init() -> bool;
    fn lua_sec_harden();
    fn lua_init_blobs();
    fn lua_init_const();
    fn lua_init_functions();
    fn lua_init_mt();
    fn lua_init_scripts() -> bool;
    fn lua_desync_functions_exist() -> bool;
    fn lua_shutdown();
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init() -> bool {
    unsafe {
        DLOG(zapret_lua_startup_text(0));
        if !lua_basic_init() {
            return false;
        }

        let stack = lua_gettop((&raw const params.lua).read());
        let mut state = 0;
        let mut previous_ok = true;
        let initialized = loop {
            match zapret_lua_startup_step(&mut state, previous_ok) {
                1 => lua_sec_harden(),
                2 => lua_init_blobs(),
                3 => lua_init_const(),
                4 => lua_init_functions(),
                5 => lua_init_mt(),
                6 => zapret_lua_publish((&raw const params.lua).read()),
                7 => previous_ok = lua_init_scripts(),
                8 => previous_ok = lua_desync_functions_exist(),
                9 => break true,
                _ => break false,
            }
        };
        if lua_gettop((&raw const params.lua).read()) != stack {
            luaL_error(
                (&raw const params.lua).read(),
                c"stack guard failure".as_ptr(),
            );
        }
        if initialized {
            DLOG(zapret_lua_startup_text(1));
        } else {
            lua_shutdown();
        }
        initialized
    }
}
