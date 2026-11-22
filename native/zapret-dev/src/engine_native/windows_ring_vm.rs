//! LuaJIT entries compiled separately with Windows SEH unwinding enabled.
#![no_std]

#[path = "../../../zapret-ring-ffi/src/api.rs"]
mod api;
#[path = "../../../zapret-wincompat/src/ring_bridge_policy/abi.rs"]
mod policy;
#[path = "../../../zapret-ring-ffi/src/request.rs"]
mod request;
#[cfg(zapret_engine_production)]
mod windows_lua_modules;

use api::{Api, Response};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};
use policy::{Feedback, Flow, Registration, RegistrationView};
use request::{ARGUMENT_SLOTS, Request, STORE_HANDLE_PRESENT, STORE_HANDLE_SLOT};

#[repr(C)]
pub struct LuaState {
    opaque: [u8; 0],
}

type Callback = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;
const REGISTRY: c_int = -10000;
const GLOBALS: c_int = -10002;
const OPERATION: c_int = GLOBALS - 1;

const _: () = {
    assert!(size_of::<Request>() == 400);
    assert!(size_of::<Response>() == 272 && size_of::<Api>() == 32);
    assert!(size_of::<Flow>() == 40 && size_of::<Feedback>() == 48);
    assert!(size_of::<Registration>() == 12 && size_of::<RegistrationView>() == 80);
    assert!(STORE_HANDLE_SLOT == 2 && STORE_HANDLE_PRESENT == (1 << 18));
};

// The pinned Win64 LuaJIT raises a native SEH exception. These entry frames own
// only scalars and Lua-owned pointers when an API call can raise.
unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_type(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_toboolean(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_tonumber(lua: *mut LuaState, index: c_int) -> f64;
    fn lua_tointeger(lua: *mut LuaState, index: c_int) -> isize;
    fn lua_tolstring(lua: *mut LuaState, index: c_int, length: *mut usize) -> *const u8;
    fn lua_touserdata(lua: *mut LuaState, index: c_int) -> *mut c_void;
    fn lua_newuserdata(lua: *mut LuaState, size: usize) -> *mut c_void;
    fn lua_createtable(lua: *mut LuaState, array_slots: c_int, record_slots: c_int);
    fn lua_getfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_setfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_setmetatable(lua: *mut LuaState, index: c_int) -> c_int;
    fn lua_pushcclosure(lua: *mut LuaState, callback: Callback, upvalues: c_int);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushnumber(lua: *mut LuaState, value: f64);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_pushnil(lua: *mut LuaState);
    fn lua_pushlstring(lua: *mut LuaState, text: *const u8, length: usize);
    fn luaL_checkudata(lua: *mut LuaState, index: c_int, name: *const c_char) -> *mut c_void;
    fn luaL_newmetatable(lua: *mut LuaState, name: *const c_char) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

unsafe extern "C" {
    fn zapret_ring_vm_load() -> bool;
    fn zapret_ring_vm_backend() -> *const Api;
    fn zapret_ring_entry_step(flow: &mut Flow, feedback: &Feedback) -> u32;
    fn zapret_ring_entry_error(action: u32) -> *const c_char;
    fn zapret_ring_request_number(request: &mut Request, index: i32, value: f64);
    fn zapret_ring_request_text(request: &mut Request, index: i32, data: *const u8, length: usize);
    fn zapret_ring_request_store(request: &mut Request, object: *mut c_void);
    fn zapret_ring_class_name(class: u32) -> *const c_char;
    fn zapret_ring_registration_step(flow: &mut Registration, view: &mut RegistrationView) -> u32;
    fn zapret_ring_release_object(
        object: *mut *mut c_void,
        release: unsafe extern "C" fn(*mut c_void) -> bool,
    );
}

unsafe extern "C" fn release(object: *mut c_void) -> bool {
    let Some(api) = (unsafe { zapret_ring_vm_backend().as_ref() }) else {
        return false;
    };
    unsafe { (api.drop_object)(object) };
    true
}

unsafe extern "C-unwind" fn finalize(lua: *mut LuaState) -> c_int {
    unsafe { zapret_ring_release_object(lua_touserdata(lua, 1).cast(), release) };
    0
}

unsafe extern "C-unwind" fn call(lua: *mut LuaState) -> c_int {
    let mut flow = Flow::default();
    let mut view = Feedback::default();
    let mut request = Request {
        numbers: [0.0; ARGUMENT_SLOTS],
        present: 0,
        strings: [ptr::null(); ARGUMENT_SLOTS],
        lengths: [0; ARGUMENT_SLOTS],
        text_present: 0,
    };
    let mut response = Response::default();
    let mut handle = ptr::null_mut();
    let mut created: *mut *mut c_void = ptr::null_mut();
    let mut inline = MaybeUninit::<[u8; 512]>::uninit();
    let mut bytes = inline.as_mut_ptr().cast::<u8>();
    // The Rust policy validates slots, buffer bounds and result arity before
    // issuing the corresponding VM action.
    unsafe {
        loop {
            let action = zapret_ring_entry_step(&mut flow, &view);
            match action {
                1 => view.operation = lua_tointeger(lua, OPERATION) as u32,
                2 => view.arguments = lua_gettop(lua),
                3 => {}
                4 => {
                    let slot = luaL_checkudata(lua, 1, zapret_ring_class_name(flow.object_class));
                    handle = slot.cast::<*mut c_void>().read();
                    view.available = !handle.is_null();
                }
                5 => view.kind = lua_type(lua, flow.index + 1),
                6 => {
                    let value = f64::from(lua_toboolean(lua, flow.index + 1) != 0);
                    zapret_ring_request_number(&mut request, flow.index, value);
                }
                7 => view.number = lua_tonumber(lua, flow.index + 1),
                8 => {
                    let mut length = 0;
                    let text = lua_tolstring(lua, flow.index + 1, &mut length);
                    zapret_ring_request_text(&mut request, flow.index, text, length);
                }
                9 => zapret_ring_request_number(&mut request, flow.index, view.number),
                10 => {
                    created = lua_newuserdata(lua, size_of::<*mut c_void>()).cast();
                    created.write(ptr::null_mut());
                    lua_getfield(
                        lua,
                        REGISTRY,
                        zapret_ring_class_name(flow.constructor_class),
                    );
                    lua_setmetatable(lua, -2);
                }
                11 => bytes = lua_newuserdata(lua, flow.capacity).cast(),
                12 => bytes = inline.as_mut_ptr().cast(),
                13 => {
                    view.backend = ((*zapret_ring_vm_backend()).invoke)(
                        flow.operation,
                        handle,
                        &request,
                        &mut response,
                        bytes,
                        flow.capacity,
                    );
                }
                14 => {
                    return luaL_error(
                        lua,
                        zapret_ring_entry_error(flow.phase),
                        flow.operation,
                        view.backend,
                    );
                }
                15 => {
                    created.write(response.object);
                    view.available = !response.object.is_null();
                }
                17 | 19 => view.results = response.count,
                20 | 22..=24 => {
                    let item = response
                        .values
                        .as_ptr()
                        .add(flow.output_index as usize)
                        .read();
                    match action {
                        20 => view.kind = item.kind as i32,
                        22 => lua_pushnumber(lua, item.number),
                        23 => lua_pushboolean(lua, c_int::from(item.number != 0.0)),
                        _ => {
                            view.offset = item.offset;
                            view.length = item.length;
                        }
                    }
                }
                21 => lua_pushnil(lua),
                26 => lua_pushlstring(lua, bytes.add(view.offset), view.length),
                27 => return flow.return_count,
                34 => {
                    let slot = luaL_checkudata(lua, flow.index + 1, zapret_ring_class_name(1));
                    let store = slot.cast::<*mut c_void>().read();
                    view.available = !store.is_null();
                    if view.available {
                        zapret_ring_request_store(&mut request, store);
                    }
                }
                _ => return luaL_error(lua, c"%s".as_ptr(), zapret_ring_entry_error(flow.phase)),
            }
        }
    }
}

/// # Safety
/// The engine passes a live state on a thread with LuaJIT SEH enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn rust_ring_register(lua: *mut LuaState) -> c_int {
    if !unsafe { zapret_ring_vm_load() } {
        return 0;
    }
    let mut flow = Registration::default();
    let mut view = RegistrationView {
        integer: 0,
        name: [0; 64],
        name_length: 0,
    };
    unsafe {
        loop {
            let action = zapret_ring_registration_step(&mut flow, &mut view);
            let name = view.name.as_ptr();
            match action {
                1 => {
                    luaL_newmetatable(lua, name.cast());
                }
                2 => lua_pushcclosure(lua, finalize, 0),
                3 | 5 | 10 | 12 | 14 => lua_setfield(lua, -2, name.cast()),
                4 | 13 => lua_pushlstring(lua, name, view.name_length),
                6 => lua_settop(lua, -2),
                7 => lua_createtable(lua, 0, 0),
                8 | 11 => lua_pushinteger(lua, view.integer as isize),
                9 => lua_pushcclosure(lua, call, 1),
                15 => lua_setfield(lua, GLOBALS, name.cast()),
                16 => return 1,
                _ => return 0,
            }
        }
    }
}

#[cfg(zapret_engine_production)]
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_register_native_modules(lua: *mut LuaState) {
    unsafe { windows_lua_modules::register(lua) };
}

#[cfg(zapret_engine_production)]
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_initialize_builtin_rules(lua: *mut LuaState) -> c_int {
    unsafe { windows_lua_modules::initialize_builtins(lua) }
}
