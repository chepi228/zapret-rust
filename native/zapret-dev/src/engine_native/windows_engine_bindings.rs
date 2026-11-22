//! Windows engine metadata shared with the existing entry ABIs.
#![no_std]

use core::ffi::{c_char, c_int, c_void};
use core::mem::offset_of;

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

unsafe extern "C" {
    static mut params: [u8; PARAMS.size];

    fn wf_fopen(name: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(file: *mut c_void) -> c_int;
    fn zapret_crt_is_gzip(file: *mut c_void) -> bool;
    fn zapret_crt_z_readfile(
        file: *mut c_void,
        bytes: *mut *mut c_char,
        length: *mut usize,
        extra: usize,
    ) -> c_int;
    fn malloc(size: usize) -> *mut c_void;
    fn free(address: *mut c_void);
}

unsafe extern "C-unwind" {
    fn luaL_loadfile(lua: *mut c_void, name: *const c_char) -> c_int;
    fn luaL_loadbuffer(
        lua: *mut c_void,
        bytes: *const c_char,
        length: usize,
        source: *const c_char,
    ) -> c_int;
    fn lua_desync_ctx_create(lua: *mut c_void);
}

// These offsets are checked against the pinned Windows headers by the C
// conformance build. Use raw pointers because callbacks mutate live parameters.
const fn param<T>(offset: usize) -> *mut T {
    unsafe { (&raw mut params).cast::<u8>().add(offset).cast() }
}

#[repr(C)]
struct Banner {
    version: *const c_char,
    revision: *const c_char,
    lua_compat: u32,
    pinned: bool,
}

// These metadata records are immutable. Pointee access is managed by the engine.
unsafe impl Sync for Banner {}

#[unsafe(export_name = "zapret_engine_banner")]
static BANNER: Banner = Banner {
    version: concat!(env!("ZAPRET_ENGINE_VERSION"), "\0").as_ptr().cast(),
    revision: concat!(env!("ZAPRET_ENGINE_REVISION"), "\0")
        .as_ptr()
        .cast(),
    lua_compat: 6,
    pinned: true,
};

#[repr(C)]
struct Vm {
    lua: *mut *mut c_void,
    conntrack: *mut c_void,
    timers: *mut *mut c_void,
    gc_interval: *const u64,
    gc_time: *mut u64,
    jit_version: *const c_char,
    jit_edition: *const c_char,
    lua_version: u32,
}

unsafe impl Sync for Vm {}

static mut LUA_GC_TIME: u64 = 0;

#[cfg(zapret_luajit_compatibility)]
const VM_VERSION: (&core::ffi::CStr, &core::ffi::CStr, u32) =
    (c"LuaJIT 2.1.1756211046", c" OpenResty", 501);
#[cfg(not(zapret_luajit_compatibility))]
const VM_VERSION: (&core::ffi::CStr, &core::ffi::CStr, u32) = (c"Luna (Rust) 4.0.2", c"", 502);

#[unsafe(export_name = "zapret_lua_vm_sources")]
static VM: Vm = Vm {
    lua: param(PARAMS.lua),
    conntrack: param(PARAMS.conntrack),
    timers: param(PARAMS.timers),
    gc_interval: param(PARAMS.lua_gc),
    gc_time: &raw mut LUA_GC_TIME,
    jit_version: VM_VERSION.0.as_ptr(),
    jit_edition: VM_VERSION.1.as_ptr(),
    lua_version: VM_VERSION.2,
};

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}

static BLOB_ALLOCATOR: Allocator = Allocator {
    allocate: malloc,
    release: free,
};

#[repr(C)]
struct Sandbox {
    lua: *const *mut c_void,
    blobs: *mut c_void,
    allocator: *const Allocator,
}

unsafe impl Sync for Sandbox {}

#[unsafe(export_name = "zapret_lua_sandbox_sources")]
static SANDBOX: Sandbox = Sandbox {
    lua: param(PARAMS.lua),
    blobs: param(PARAMS.blobs),
    allocator: &BLOB_ALLOCATOR,
};

#[repr(C)]
struct LuaFile {
    open: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    close: unsafe extern "C" fn(*mut c_void) -> c_int,
    probe: unsafe extern "C" fn(*mut c_void) -> bool,
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    read: unsafe extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, usize) -> c_int,
    load_file: unsafe extern "C-unwind" fn(*mut c_void, *const c_char) -> c_int,
    load_buffer:
        unsafe extern "C-unwind" fn(*mut c_void, *const c_char, usize, *const c_char) -> c_int,
}

#[unsafe(export_name = "zapret_lua_file_vm_native_ops")]
static LUA_FILE: LuaFile = LuaFile {
    open: wf_fopen,
    close: fclose,
    probe: zapret_crt_is_gzip,
    allocate: malloc,
    release: free,
    read: zapret_crt_z_readfile,
    load_file: luaL_loadfile,
    load_buffer: luaL_loadbuffer,
};

type Callback = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;

macro_rules! registry_callbacks {
    ($($name:ident),+ $(,)?) => {
        const CALLBACKS: [Callback; 101] = [$(const {
            unsafe extern "C-unwind" {
                fn $name(lua: *mut c_void) -> c_int;
            }
            $name
        }),+];
    };
}

include!("windows_lua_registry_bindings.inc.rs");

#[repr(C)]
struct Registry {
    lua: *const *mut c_void,
    version: *const c_char,
    mark: *const u32,
    debug: *const bool,
    daemon: *const bool,
    server: *const bool,
    cache_hostname: *const bool,
    ctrack_disable: *const bool,
    callbacks: *const Callback,
    count: usize,
    create_context: unsafe extern "C-unwind" fn(*mut c_void),
}

unsafe impl Sync for Registry {}

#[unsafe(export_name = "zapret_lua_registry_sources")]
static REGISTRY: Registry = Registry {
    lua: param(PARAMS.lua),
    version: param(PARAMS.version),
    mark: param(PARAMS.mark),
    debug: param(PARAMS.debug),
    daemon: param(PARAMS.daemon),
    server: param(PARAMS.server),
    cache_hostname: param(PARAMS.cache_hostname),
    ctrack_disable: param(PARAMS.ctrack_disable),
    callbacks: CALLBACKS.as_ptr(),
    count: CALLBACKS.len(),
    create_context: lua_desync_ctx_create,
};

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Banner>() == if pointer == 8 { 24 } else { 16 });
    assert!(offset_of!(Banner, lua_compat) == 2 * pointer);
    assert!(size_of::<Vm>() == 8 * pointer && offset_of!(Vm, jit_version) == 5 * pointer);
    assert!(offset_of!(Vm, lua_version) == 7 * pointer);
    assert!(size_of::<Sandbox>() == 3 * pointer && offset_of!(Sandbox, allocator) == 2 * pointer);
    assert!(size_of::<LuaFile>() == 8 * pointer && offset_of!(LuaFile, load_file) == 6 * pointer);
    assert!(offset_of!(LuaFile, load_buffer) == 7 * pointer);
    assert!(
        size_of::<Registry>() == 11 * pointer && offset_of!(Registry, callbacks) == 8 * pointer
    );
};
