//! Run initialization scripts on the current pinned Win64 LuaJIT VM.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    sync::atomic::{AtomicI32, Ordering},
};

#[cfg(zapret_engine_production)]
#[path = "windows_builtin_init_option.rs"]
mod builtin_init;

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const LUA_MULTRET: c_int = -1;
const LUA_GLOBALS: c_int = -10_002;
const LUA_TFUNCTION: c_int = 6;
const DEBUG_OFFSET: usize = 4_252;
const PROFILES_OFFSET: usize = 4_272;
const SCRIPTS_OFFSET: usize = 12_744;
const LUA_OFFSET: usize = 16_888;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Probe = unsafe extern "C" fn(*const c_char, *mut bool, *mut c_char) -> bool;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct ScriptNode {
    opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    before_debug: [MaybeUninit<u8>; DEBUG_OFFSET],
    debug: bool,
    before_profiles: [MaybeUninit<u8>; PROFILES_OFFSET - DEBUG_OFFSET - size_of::<bool>()],
    profiles: *const c_void,
    before_scripts:
        [MaybeUninit<u8>; SCRIPTS_OFFSET - PROFILES_OFFSET - size_of::<*const c_void>()],
    scripts: *const ScriptNode,
    before_lua: [MaybeUninit<u8>; LUA_OFFSET - SCRIPTS_OFFSET - size_of::<*const ScriptNode>()],
    lua: *mut LuaState,
}

#[repr(C)]
struct Scripts {
    current: *const ScriptNode,
    yielded: bool,
}

#[repr(C)]
struct Script {
    text: *const c_char,
    file: bool,
    preview: [c_char; 128],
}

#[repr(C)]
struct Functions {
    profile: *const c_void,
    rule: *const c_void,
    yielded: bool,
    started: bool,
}

const _: () = {
    assert!(offset_of!(Params, debug) == DEBUG_OFFSET);
    assert!(offset_of!(Params, profiles) == PROFILES_OFFSET);
    assert!(offset_of!(Params, scripts) == SCRIPTS_OFFSET);
    assert!(offset_of!(Params, lua) == LUA_OFFSET);
    assert!(size_of::<Params>() == 16_896);
    assert!(size_of::<Scripts>() == 16 && size_of::<Script>() == 144);
    assert!(size_of::<Functions>() == 24);
};

unsafe extern "C" {
    static mut params: Params;
    static bQuit: AtomicI32;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn lua_file_open_test(path: *const c_char, gzip: *mut bool, resolved: *mut c_char) -> bool;
    fn zapret_lua_script_next(
        scripts: *mut Scripts,
        quit: bool,
        debug: bool,
        output: *mut Script,
    ) -> u32;
    fn zapret_lua_script_report(script: *const Script, log: Log);
    fn zapret_lua_test_init_scripts(first: *const ScriptNode, probe: Probe, log: Log) -> bool;
    fn zapret_lua_function_next(cursor: *mut Functions, output: *mut *const c_char) -> u32;
    fn zapret_lua_report_missing_function(name: *const c_char, log: Log);
}

#[cfg(zapret_engine_production)]
#[unsafe(no_mangle)]
unsafe extern "C" fn desync_instance(
    function: *const c_char,
    profile: u32,
    number: u32,
    output: *mut c_char,
    capacity: usize,
) {
    unsafe extern "C" {
        fn zapret_desync_instance(
            function: *const c_char,
            profile: u32,
            number: u32,
            output: *mut c_char,
            capacity: usize,
        );
    }
    unsafe { zapret_desync_instance(function, profile, number, output, capacity) };
}

unsafe extern "C-unwind" {
    fn luaL_doZfile(lua: *mut LuaState, path: *const c_char) -> c_int;
    fn luaL_loadstring(lua: *mut LuaState, text: *const c_char) -> c_int;
    fn lua_pcall(lua: *mut LuaState, args: c_int, results: c_int, handler: c_int) -> c_int;
    fn lua_perror(lua: *mut LuaState);
    fn lua_getfield(lua: *mut LuaState, index: c_int, key: *const c_char);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    #[cfg(zapret_engine_production)]
    fn lua_pushcclosure(
        lua: *mut LuaState,
        callback: unsafe extern "C-unwind" fn(*mut LuaState) -> c_int,
        upvalues: c_int,
    );
    #[cfg(zapret_engine_production)]
    fn zapret_initialize_builtin_rules(lua: *mut LuaState) -> c_int;
}

unsafe fn initialize(script: &Script) -> bool {
    unsafe {
        if script.file {
            return luaL_doZfile((&raw const params.lua).read(), script.text) == 0;
        }
        #[cfg(zapret_engine_production)]
        if core::ffi::CStr::from_ptr(script.text) == builtin_init::BUILTIN_SCRIPT {
            let lua = (&raw const params.lua).read();
            lua_pushcclosure(lua, zapret_initialize_builtin_rules, 0);
            return lua_pcall(lua, 0, 0, 0) == 0;
        }
        luaL_loadstring((&raw const params.lua).read(), script.text) == 0
            && lua_pcall((&raw const params.lua).read(), 0, LUA_MULTRET, 0) == 0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn lua_test_init_script_files() -> bool {
    unsafe {
        zapret_lua_test_init_scripts(
            (&raw const params.scripts).read(),
            lua_file_open_test,
            DLOG_ERR,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init_scripts() -> bool {
    let mut scripts = Scripts {
        current: unsafe { (&raw const params.scripts).read() },
        yielded: false,
    };
    let mut output = MaybeUninit::<Script>::uninit();
    loop {
        let status = unsafe {
            zapret_lua_script_next(
                &mut scripts,
                bQuit.load(Ordering::SeqCst) != 0,
                (&raw const params.debug).read(),
                output.as_mut_ptr(),
            )
        };
        if status != 1 {
            return status == 0;
        }
        let script = unsafe { output.assume_init_ref() };
        unsafe {
            if (&raw const params.debug).read() {
                zapret_lua_script_report(script, DLOG);
            }
            // The diagnostic and each VM operation may change the current VM.
            if !initialize(script) {
                lua_perror((&raw const params.lua).read());
                return false;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_desync_functions_exist() -> bool {
    let mut cursor = Functions {
        profile: unsafe { (&raw const params.profiles).read() },
        rule: core::ptr::null(),
        yielded: false,
        started: false,
    };
    let mut output = MaybeUninit::uninit();
    loop {
        let status = unsafe { zapret_lua_function_next(&mut cursor, output.as_mut_ptr()) };
        if status != 1 {
            return status == 0;
        }
        let name = unsafe { output.assume_init() };
        unsafe {
            lua_getfield((&raw const params.lua).read(), LUA_GLOBALS, name);
            // A global lookup may invoke a metamethod before the stack is read again.
            let found = lua_type((&raw const params.lua).read(), -1) == LUA_TFUNCTION;
            lua_settop((&raw const params.lua).read(), -2);
            if !found {
                zapret_lua_report_missing_function(name, DLOG_ERR);
                return false;
            }
        }
    }
}
