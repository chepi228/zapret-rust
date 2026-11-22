//! Execution context cutoff and cancellation on the pinned Win64 LuaJIT VM.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_uint},
    mem::{MaybeUninit, offset_of, size_of},
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("These entries require the Win64 LuaJIT SEH ABI");

const REGISTRY: c_int = -10_000;
const BOOLEAN: c_int = 1;

const IS_NIL: u32 = 0;
const HAS_DIRECTION: u32 = 1;
const DIRECTION_PROVIDED: u32 = 2;
const SCRIPT_DIRECTION: u32 = 3;
const NATIVE_DIRECTION: u32 = 4;
const TABLE_NEEDED: u32 = 5;

const CUTOFF_INVALID: u32 = 3;
const EXECUTION_INVALID: u32 = 4;
const INSTANCE_CUTOFF: u32 = 15;
const LUA_CUTOFF: u32 = 16;
const CANCEL: u32 = 17;

const REPORT_MISSING: u32 = 0;
const REPORT_INSTANCE_CUTOFF: u32 = 1;
const REPORT_LUA_CUTOFF: u32 = 2;
const REPORT_CANCEL: u32 = 3;

#[repr(C)]
struct LuaState {
    opaque: [u8; 0],
}

#[repr(C)]
struct LuaContext {
    opaque: [u8; 0],
}

#[repr(C)]
struct Scope {
    instance: *const c_char,
    profile: u32,
    registry: c_int,
    incoming: bool,
    outgoing: bool,
    tracked: bool,
}

const _: () = {
    assert!(size_of::<Scope>() == 24);
    assert!(offset_of!(Scope, profile) == 8 && offset_of!(Scope, registry) == 12);
    assert!(offset_of!(Scope, incoming) == 16 && offset_of!(Scope, tracked) == 18);
};

unsafe extern "C" {
    fn zapret_lua_context_vm(operation: u32, value: c_int) -> u32;
    fn zapret_lua_context_label(label: u32) -> *const c_char;
    fn zapret_lua_context_report(report: u32, tracked: bool) -> *const c_char;
    fn zapret_lua_context_scope(
        context: *const LuaContext,
        direction: u32,
        by_instance: bool,
        output: *mut Scope,
    ) -> bool;
    fn zapret_lua_context_cutoff(context: *const LuaContext, direction: u32) -> bool;
    fn zapret_lua_context_cancel(context: *mut LuaContext) -> bool;
    fn DLOG(format: *const c_char, ...) -> c_int;
}

unsafe extern "C-unwind" {
    fn lua_desync_ctx(lua: *mut LuaState) -> *mut LuaContext;
    fn lua_check_argc(lua: *mut LuaState, location: *const c_char, count: c_int);
    fn lua_check_argc_range(lua: *mut LuaState, location: *const c_char, min: c_int, max: c_int);
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_getfield(lua: *mut LuaState, index: c_int, field: *const c_char);
    fn lua_rawgeti(lua: *mut LuaState, index: c_int, key: c_int);
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn luaL_checktype(lua: *mut LuaState, index: c_int, kind: c_int);
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_pushf_table(lua: *mut LuaState, name: *const c_char);
    fn lua_pushi_table(lua: *mut LuaState, index: isize);
    fn lua_pushi_bool(lua: *mut LuaState, index: isize, value: bool);
}

unsafe fn read_scope(
    context: *const LuaContext,
    direction: u32,
    by_instance: bool,
) -> Option<Scope> {
    let mut scope = MaybeUninit::uninit();
    unsafe {
        if zapret_lua_context_scope(context, direction, by_instance, scope.as_mut_ptr()) {
            Some(scope.assume_init())
        } else {
            None
        }
    }
}

unsafe fn cutoff_direction(lua: *mut LuaState) -> u32 {
    unsafe {
        if zapret_lua_context_vm(HAS_DIRECTION, lua_gettop(lua)) != 0
            && zapret_lua_context_vm(DIRECTION_PROVIDED, lua_type(lua, 2)) != 0
        {
            luaL_checktype(lua, 2, BOOLEAN);
            zapret_lua_context_vm(SCRIPT_DIRECTION, lua_toboolean(lua, 2))
        } else {
            0
        }
    }
}

unsafe fn report_cutoff(report: u32, scope: &Scope) {
    unsafe {
        DLOG(
            zapret_lua_context_report(report, scope.tracked),
            scope.instance,
            c_uint::from(scope.incoming),
            c_uint::from(scope.outgoing),
        );
    }
}

unsafe fn check_stack(lua: *mut LuaState, top: c_int) {
    unsafe {
        if lua_gettop(lua) != top {
            luaL_error(lua, c"stack guard failure".as_ptr());
        }
    }
}

unsafe fn table_needed(lua: *mut LuaState) -> bool {
    unsafe { zapret_lua_context_vm(TABLE_NEEDED, lua_type(lua, -1)) != 0 }
}

unsafe fn publish_instance(lua: *mut LuaState, scope: &Scope) {
    unsafe {
        // A field lookup can call Lua again. Keep the original scope snapshot
        // and the pointer to the instance name, as the C caller does.
        lua_rawgeti(lua, REGISTRY, scope.registry);
        lua_getfield(lua, -1, scope.instance);
        if table_needed(lua) {
            lua_settop(lua, -2);
            lua_pushf_table(lua, scope.instance);
            lua_getfield(lua, -1, scope.instance);
        }
        lua_rawgeti(lua, -1, scope.profile as c_int);
        if table_needed(lua) {
            lua_settop(lua, -2);
            lua_pushi_table(lua, scope.profile as isize);
            lua_rawgeti(lua, -1, scope.profile as c_int);
        }
        if scope.outgoing {
            lua_pushi_bool(lua, 0, true);
        }
        if scope.incoming {
            lua_pushi_bool(lua, 1, true);
        }
        lua_settop(lua, -4);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_instance_cutoff(lua: *mut LuaState) -> c_int {
    unsafe {
        lua_check_argc_range(lua, zapret_lua_context_label(INSTANCE_CUTOFF), 1, 2);
        let top = lua_gettop(lua);
        if zapret_lua_context_vm(IS_NIL, lua_type(lua, 1)) != 0 {
            DLOG(zapret_lua_context_report(REPORT_MISSING, false));
        } else {
            let context = lua_desync_ctx(lua);
            let direction = cutoff_direction(lua);
            let Some(scope) = read_scope(context, direction, true) else {
                return luaL_error(lua, zapret_lua_context_label(CUTOFF_INVALID));
            };
            report_cutoff(REPORT_INSTANCE_CUTOFF, &scope);
            if scope.tracked {
                publish_instance(lua, &scope);
            }
        }
        check_stack(lua, top);
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_instance_cutoff_check(
    lua: *mut LuaState,
    context: *const LuaContext,
    incoming: bool,
) -> bool {
    unsafe {
        let direction = zapret_lua_context_vm(NATIVE_DIRECTION, c_int::from(incoming));
        let Some(scope) = read_scope(context, direction, true) else {
            return false;
        };
        if !scope.tracked {
            return false;
        }
        lua_rawgeti(lua, REGISTRY, scope.registry);
        lua_getfield(lua, -1, scope.instance);
        if table_needed(lua) {
            lua_settop(lua, -3);
            return false;
        }
        lua_rawgeti(lua, -1, scope.profile as c_int);
        if table_needed(lua) {
            lua_settop(lua, -4);
            return false;
        }
        lua_rawgeti(lua, -1, c_int::from(incoming));
        let result = lua_toboolean(lua, -1) != 0;
        lua_settop(lua, -5);
        result
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_lua_cutoff(lua: *mut LuaState) -> c_int {
    unsafe {
        lua_check_argc_range(lua, zapret_lua_context_label(LUA_CUTOFF), 1, 2);
        let top = lua_gettop(lua);
        let context = lua_desync_ctx(lua);
        let direction = cutoff_direction(lua);
        let Some(scope) = read_scope(context, direction, false) else {
            return luaL_error(lua, zapret_lua_context_label(CUTOFF_INVALID));
        };
        report_cutoff(REPORT_LUA_CUTOFF, &scope);
        if scope.tracked && !zapret_lua_context_cutoff(context, direction) {
            return luaL_error(lua, zapret_lua_context_label(CUTOFF_INVALID));
        }
        check_stack(lua, top);
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_execution_plan_cancel(lua: *mut LuaState) -> c_int {
    unsafe {
        lua_check_argc(lua, zapret_lua_context_label(CANCEL), 1);
        let context = lua_desync_ctx(lua);
        let Some(scope) = read_scope(context, 0, false) else {
            return luaL_error(lua, zapret_lua_context_label(EXECUTION_INVALID));
        };
        DLOG(
            zapret_lua_context_report(REPORT_CANCEL, scope.tracked),
            scope.instance,
        );
        if !zapret_lua_context_cancel(context) {
            return luaL_error(lua, zapret_lua_context_label(EXECUTION_INVALID));
        }
        0
    }
}
