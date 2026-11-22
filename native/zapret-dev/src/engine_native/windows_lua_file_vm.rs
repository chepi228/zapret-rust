//! Gzip and plain-file loading shared by the Windows Lua runtimes.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

#[cfg(not(all(windows, any(target_arch = "x86", target_arch = "x86_64"))))]
compile_error!("The Lua file entry requires the Windows x86 or x64 ABI");

const PATH_CAPACITY: usize = 4096;
const LUA_MULTRET: c_int = -1;
const LUA_ERRFILE: c_int = 6;

const DONE: u32 = 0;
const PROBE: u32 = 1;
const PLAIN: u32 = 2;
const READ: u32 = 3;
const LOAD_BUFFER: u32 = 4;
const RELEASE: u32 = 5;
const EXECUTE: u32 = 6;
const MISSING: u32 = 7;
const REOPEN_FAILED: u32 = 8;
const UNZIP_FAILED: u32 = 9;

#[repr(C)]
pub struct LuaState {
    _opaque: [u8; 0],
}

type File = *mut c_void;
type Free = unsafe extern "C" fn(*mut c_void);
type LoadBuffer =
    unsafe extern "C-unwind" fn(*mut LuaState, *const c_char, usize, *const c_char) -> c_int;

#[repr(C)]
struct NativeIo {
    open: unsafe extern "C" fn(*const c_char, *const c_char) -> File,
    close: unsafe extern "C" fn(File) -> c_int,
    probe: unsafe extern "C" fn(File) -> bool,
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: Free,
    read: unsafe extern "C" fn(File, *mut *mut c_char, *mut usize, usize) -> c_int,
}

#[repr(C)]
struct FileOps {
    io: NativeIo,
    load_file: unsafe extern "C-unwind" fn(*mut LuaState, *const c_char) -> c_int,
    load_buffer: LoadBuffer,
}

#[derive(Default)]
#[repr(C)]
struct Flow {
    phase: u32,
    status: c_int,
}

#[derive(Default)]
#[repr(C)]
struct Feedback {
    status: c_int,
    found: u32,
    gzip: u32,
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<NativeIo>() == 6 * pointer);
    assert!(size_of::<FileOps>() == 8 * pointer);
    assert!(core::mem::offset_of!(FileOps, load_file) == 6 * pointer);
    assert!(core::mem::offset_of!(FileOps, load_buffer) == 7 * pointer);
    assert!(size_of::<Flow>() == 8 && size_of::<Feedback>() == 12);
};

unsafe extern "C" {
    static zapret_lua_file_vm_native_ops: FileOps;
    fn zapret_lua_file_probe(
        filename: *const c_char,
        gzip: *mut bool,
        output: *mut c_char,
        capacity: usize,
        io: &NativeIo,
    ) -> bool;
    fn zapret_lua_file_read(
        filename: *const c_char,
        bytes: *mut *mut c_char,
        length: *mut usize,
        io: &NativeIo,
    ) -> u32;
    fn zapret_lua_file_step(flow: &mut Flow, feedback: &Feedback) -> u32;
}

unsafe extern "C-unwind" {
    fn zapret_lua_load_owned_buffer(
        lua: *mut LuaState,
        bytes: *mut c_char,
        length: usize,
        source: *const c_char,
        load: LoadBuffer,
        release: Free,
    ) -> c_int;
    fn lua_pcall(lua: *mut LuaState, nargs: c_int, results: c_int, error: c_int) -> c_int;
    fn lua_pushfstring(lua: *mut LuaState, format: *const c_char, ...) -> *const c_char;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
}

/// # Safety
/// The path is terminated and the optional resolved path buffer has PATH_MAX bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_file_open_test(
    filename: *const c_char,
    gzip: *mut bool,
    resolved: *mut c_char,
) -> bool {
    let capacity = if resolved.is_null() { 0 } else { PATH_CAPACITY };
    unsafe {
        zapret_lua_file_probe(
            filename,
            gzip,
            resolved,
            capacity,
            &zapret_lua_file_vm_native_ops.io,
        )
    }
}

/// # Safety
/// The live Lua state is used from its owning thread and the path is terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn luaL_doZfile(lua: *mut LuaState, filename: *const c_char) -> c_int {
    let mut state = Flow::default();
    let mut feedback = Feedback::default();
    let mut gzip = false;
    let mut resolved = MaybeUninit::<[c_char; PATH_CAPACITY]>::uninit();
    let path = resolved.as_mut_ptr().cast::<c_char>();
    let mut length = 0;
    let mut data = ptr::null_mut();
    let ops = unsafe { &zapret_lua_file_vm_native_ops };

    loop {
        match unsafe { zapret_lua_file_step(&mut state, &feedback) } {
            DONE => return state.status,
            PROBE => {
                feedback.found =
                    u32::from(unsafe { lua_file_open_test(filename, &mut gzip, path) });
                feedback.gzip = u32::from(gzip);
            }
            PLAIN => {
                // The pinned luaL_dofile macro normalizes statuses to 0 or 1.
                feedback.status = c_int::from(unsafe {
                    (ops.load_file)(lua, path) != 0 || lua_pcall(lua, 0, LUA_MULTRET, 0) != 0
                });
            }
            READ => {
                feedback.status =
                    unsafe { zapret_lua_file_read(path, &mut data, &mut length, &ops.io) } as c_int;
            }
            LOAD_BUFFER => {
                feedback.status = unsafe {
                    zapret_lua_load_owned_buffer(
                        lua,
                        data,
                        length,
                        path,
                        ops.load_buffer,
                        ops.io.release,
                    )
                };
            }
            RELEASE => data = ptr::null_mut(),
            EXECUTE => feedback.status = unsafe { lua_pcall(lua, 0, LUA_MULTRET, 0) },
            MISSING => {
                unsafe {
                    lua_pushfstring(
                        lua,
                        c"could not open lua file '%s' or '%s.gz'".as_ptr(),
                        filename,
                        filename,
                    );
                }
                return LUA_ERRFILE;
            }
            action @ (REOPEN_FAILED | UNZIP_FAILED) => {
                let format = if action == REOPEN_FAILED {
                    c"could not open lua file '%s'"
                } else {
                    c"could not unzip lua file '%s'"
                };
                unsafe { lua_pushfstring(lua, format.as_ptr(), path) };
                return LUA_ERRFILE;
            }
            _ => return unsafe { luaL_error(lua, c"invalid Lua file plan".as_ptr()) },
        }
    }
}
