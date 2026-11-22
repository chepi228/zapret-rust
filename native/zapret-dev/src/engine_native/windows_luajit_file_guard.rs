//! Protected script loading for the pinned Win64 LuaJIT runtime.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64", target_env = "gnu")))]
compile_error!("The LuaJIT file guard requires the pinned MinGW Win64 layout");

// Checked against lj_obj.h and lj_frame.h by the direct LuaJIT file oracle.
const STATE_CFRAME: usize = 80;
const CFRAME_ERRFUNC: usize = 84;

#[repr(C)]
pub struct LuaState {
    opaque: [u8; 0],
}

type LuaFunction = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;
type Protected =
    unsafe extern "C-unwind" fn(*mut LuaState, Option<LuaFunction>, *mut c_void) -> *mut c_void;
type Load =
    unsafe extern "C-unwind" fn(*mut LuaState, *const c_char, usize, *const c_char) -> c_int;
type Release = unsafe extern "C" fn(*mut c_void);

unsafe extern "C-unwind" {
    fn lj_vm_cpcall(
        lua: *mut LuaState,
        function: Option<LuaFunction>,
        context: *mut c_void,
        protected: Protected,
    ) -> c_int;
    fn lj_err_throw(lua: *mut LuaState, status: c_int) -> !;
}

struct ScriptLoad {
    bytes: *const c_char,
    length: usize,
    source: *const c_char,
    load: Load,
    status: c_int,
}

unsafe extern "C-unwind" fn load_script(
    lua: *mut LuaState,
    _function: Option<LuaFunction>,
    context: *mut c_void,
) -> *mut c_void {
    let script = unsafe { &mut *context.cast::<ScriptLoad>() };
    unsafe {
        // Use the parser's frameless protected call convention. The caller's
        // error handler stays visible and the chunk or error stays on its stack.
        let cframe = lua.cast::<u8>().add(STATE_CFRAME).cast::<*mut u8>().read();
        cframe.add(CFRAME_ERRFUNC).cast::<i32>().write(-1);
        script.status = (script.load)(lua, script.bytes, script.length, script.source);
    }
    ptr::null_mut()
}

/// # Safety
/// The arguments describe a LuaJIT state and an owned buffer on its thread.
/// The release callback matches the buffer's allocation and cannot unwind.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn zapret_lua_load_owned_buffer(
    lua: *mut LuaState,
    bytes: *mut c_char,
    length: usize,
    source: *const c_char,
    load: Load,
    release: Release,
) -> c_int {
    let mut context = ScriptLoad {
        bytes,
        length,
        source,
        load,
        status: 0,
    };
    let thrown = unsafe { lj_vm_cpcall(lua, None, (&raw mut context).cast(), load_script) };
    unsafe { release(bytes.cast()) };
    if thrown != 0 {
        // The original error object is already on the stack and the error
        // handler has run. Preserve the status without invoking it again.
        unsafe { lj_err_throw(lua, thrown) };
    }
    context.status
}
