//! LuaJIT entries for the native checksum implementations.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
};

type Lua = *mut c_void;

#[repr(C)]
struct Plan {
    ip: *const u8,
    header: *const u8,
    payload: *const u8,
    header_length: usize,
    payload_length: usize,
    total_length: usize,
    kind: u32,
    family: u8,
    stage: u8,
}

#[repr(C)]
struct Api {
    name: *const c_char,
    header_error: *const c_char,
}

const _: () = {
    assert!(size_of::<Plan>() == 56 && offset_of!(Plan, kind) == 48);
    assert!(offset_of!(Plan, stage) == 53 && size_of::<Api>() == 16);
};

unsafe extern "C" {
    fn zapret_lua_checksum_entry(kind: u32) -> Api;
    fn zapret_lua_checksum_error(kind: u32) -> *const c_char;
    fn zapret_lua_checksum_ipv4(
        data: *const u8,
        length: usize,
        output: *mut u8,
        capacity: usize,
    ) -> bool;
    fn zapret_lua_checksum_begin(
        kind: u32,
        ip: *const u8,
        length: usize,
        output: *mut Plan,
    ) -> bool;
    fn zapret_lua_checksum_header(plan: *mut Plan, data: *const u8, length: usize) -> bool;
    fn zapret_lua_checksum_payload(plan: *mut Plan, data: *const u8, length: usize) -> bool;
    fn zapret_lua_checksum_finish(plan: *const Plan, output: *mut u8, capacity: usize) -> bool;
    fn zapret_lua_tls_text(label: u32) -> *const c_char;
    fn zapret_lua_tls_payload(argc: c_int, known_tag: bool, tag: c_int) -> bool;
    fn zapret_lua_tls_prepare(
        text: *const c_char,
        length: usize,
        workspace: *mut TlsWorkspace,
    ) -> u32;
    fn zapret_lua_tls_apply(
        workspace: *const TlsWorkspace,
        data: *const u8,
        payload: *const u8,
        payload_length: usize,
        output: *mut u8,
        written: *mut usize,
        report: extern "C" fn(*const c_char),
    ) -> bool;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
}

unsafe extern "C-unwind" {
    fn lua_check_argc(lua: Lua, name: *const c_char, count: c_int);
    fn lua_check_argc_range(lua: Lua, name: *const c_char, min: c_int, max: c_int);
    fn lua_gettop(lua: Lua) -> c_int;
    fn lua_type(lua: Lua, index: c_int) -> c_int;
    fn lua_reqlstring(lua: Lua, index: c_int, size: *mut usize) -> *const u8;
    fn lua_reqstring(lua: Lua, index: c_int) -> *const c_char;
    fn lua_newuserdata(lua: Lua, size: usize) -> *mut u8;
    fn lua_pushlstring(lua: Lua, data: *const u8, size: usize);
    fn lua_pushnil(lua: Lua);
    fn lua_remove(lua: Lua, index: c_int);
    fn luaL_error(lua: Lua, format: *const c_char, ...) -> c_int;
}

#[repr(C)]
struct TlsWorkspace {
    sni: [u8; 256],
    flags: u32,
    mode: u32,
    length: usize,
    capacity: usize,
}

const _: () = assert!(size_of::<TlsWorkspace>() == 280 && offset_of!(TlsWorkspace, length) == 264);

extern "C" fn tls_report(message: *const c_char) {
    unsafe { DLOG_ERR(c"%s".as_ptr(), message) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_tls_mod(lua: Lua) -> c_int {
    unsafe {
        lua_check_argc_range(lua, zapret_lua_tls_text(0), 2, 3);
        let top = lua_gettop(lua);
        let argc = lua_gettop(lua);
        let mut length = 0;
        let mut payload_length = 0;
        let data = lua_reqlstring(lua, 1, &mut length);
        let options = lua_reqstring(lua, 2);
        let payload = if zapret_lua_tls_payload(argc, false, 0)
            && zapret_lua_tls_payload(argc, true, lua_type(lua, 3))
        {
            lua_reqlstring(lua, 3, &mut payload_length)
        } else {
            core::ptr::null()
        };
        let mut workspace = MaybeUninit::<TlsWorkspace>::uninit();
        match zapret_lua_tls_prepare(options, length, workspace.as_mut_ptr()) {
            0 => lua_pushlstring(lua, data, length),
            1 => {
                let workspace = workspace.assume_init();
                let output = lua_newuserdata(lua, workspace.capacity);
                let mut written = 0;
                if zapret_lua_tls_apply(
                    &workspace,
                    data,
                    payload,
                    payload_length,
                    output,
                    &mut written,
                    tls_report,
                ) {
                    DLOG(zapret_lua_tls_text(1), workspace.flags);
                    lua_pushlstring(lua, output, written);
                } else {
                    lua_pushnil(lua);
                }
                lua_remove(lua, -2);
            }
            2 => return luaL_error(lua, zapret_lua_tls_text(2), options),
            _ => return luaL_error(lua, zapret_lua_tls_text(3)),
        }
        result(lua, top)
    }
}

unsafe fn result(lua: Lua, top: c_int) -> c_int {
    if unsafe { lua_gettop(lua) } != top.wrapping_add(1) {
        return unsafe { luaL_error(lua, c"stack guard failure".as_ptr()) };
    }
    1
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_csum_ip4_fix(lua: Lua) -> c_int {
    unsafe {
        let api = zapret_lua_checksum_entry(3);
        lua_check_argc(lua, api.name, 1);
        let top = lua_gettop(lua);
        let mut length = 0;
        let data = lua_reqlstring(lua, 1, &mut length);
        let mut output = MaybeUninit::<[u8; 60]>::uninit();
        if !zapret_lua_checksum_ipv4(data, length, output.as_mut_ptr().cast(), 60) {
            return luaL_error(lua, api.header_error);
        }
        lua_pushlstring(lua, output.as_ptr().cast(), length);
        result(lua, top)
    }
}

unsafe fn transport(lua: Lua, kind: u32) -> c_int {
    unsafe {
        let api = zapret_lua_checksum_entry(kind);
        lua_check_argc(lua, api.name, 3);
        let top = lua_gettop(lua);
        let mut length = 0;
        let ip = lua_reqlstring(lua, 1, &mut length);
        let mut plan = MaybeUninit::<Plan>::uninit();
        if !zapret_lua_checksum_begin(kind, ip, length, plan.as_mut_ptr()) {
            return luaL_error(lua, zapret_lua_checksum_error(0));
        }
        let mut plan = plan.assume_init();
        let header = lua_reqlstring(lua, 2, &mut length);
        if !zapret_lua_checksum_header(&mut plan, header, length) {
            return luaL_error(lua, c"%s".as_ptr(), api.header_error);
        }
        let payload = lua_reqlstring(lua, 3, &mut length);
        if !zapret_lua_checksum_payload(&mut plan, payload, length) {
            return luaL_error(lua, zapret_lua_checksum_error(1));
        }
        let out = lua_newuserdata(lua, plan.total_length);
        if !zapret_lua_checksum_finish(&plan, out, plan.total_length) {
            return luaL_error(lua, zapret_lua_checksum_error(2));
        }
        lua_pushlstring(lua, out, plan.header_length);
        lua_remove(lua, -2);
        result(lua, top)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_csum_tcp_fix(lua: Lua) -> c_int {
    unsafe { transport(lua, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_csum_udp_fix(lua: Lua) -> c_int {
    unsafe { transport(lua, 1) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luacall_csum_icmp_fix(lua: Lua) -> c_int {
    unsafe { transport(lua, 2) }
}
