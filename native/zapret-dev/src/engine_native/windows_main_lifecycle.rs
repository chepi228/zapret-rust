//! Windows bindings for main preparation and mutex ownership.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
};

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Handle = *mut c_void;

#[repr(C, align(8))]
struct Conntrack([MaybeUninit<u8>; 40]);

#[repr(C)]
struct Params {
    before_timeouts: [MaybeUninit<u8>; PARAMS.timeouts],
    timeouts: [u32; 4],
    conntrack: Conntrack,
    disabled: bool,
    before_lifetime: [MaybeUninit<u8>; 3],
    lifetime: u32,
}

#[repr(C)]
struct Input {
    pool: *mut c_void,
    timeouts: [u32; 4],
    lifetime: u32,
    dry: bool,
    disabled: bool,
}

#[repr(C)]
struct MainOps {
    init: unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32),
    debug: Log,
    console: Log,
}

#[repr(C)]
struct MutexOps {
    release: unsafe extern "C" fn(Handle) -> bool,
    close: unsafe extern "C" fn(Handle),
}

const _: () = {
    assert!(offset_of!(Params, timeouts) == PARAMS.timeouts);
    assert!(offset_of!(Params, conntrack) == PARAMS.conntrack);
    assert!(offset_of!(Params, disabled) == PARAMS.ctrack_disable);
    assert!(offset_of!(Params, lifetime) == PARAMS.ipcache_lifetime);
    let pointer = size_of::<usize>();
    assert!(size_of::<Input>() == pointer + 24);
    assert!(size_of::<MainOps>() == 3 * pointer && size_of::<MutexOps>() == 2 * pointer);
};

unsafe extern "C" {
    fn ConntrackPoolInit(
        pool: *mut c_void,
        interval: i64,
        syn: u32,
        established: u32,
        fin: u32,
        udp: u32,
    );
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn abort() -> !;
    fn zapret_lifecycle_prepare(input: *const Input, ops: *const MainOps) -> u32;
    fn zapret_lifecycle_release_mutex(slot: *mut Handle, ops: *const MutexOps) -> bool;
}

unsafe extern "system" {
    fn ReleaseMutex(handle: Handle) -> c_int;
    fn CloseHandle(handle: Handle) -> c_int;
}

unsafe extern "C" fn init(
    pool: *mut c_void,
    interval: u32,
    syn: u32,
    est: u32,
    fin: u32,
    udp: u32,
) {
    unsafe { ConntrackPoolInit(pool, i64::from(interval), syn, est, fin, udp) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_lifecycle_prepare(params: *mut Params, dry: bool) -> u32 {
    let input = unsafe {
        Input {
            pool: (&raw mut (*params).conntrack).cast(),
            timeouts: (*params).timeouts,
            lifetime: (*params).lifetime,
            dry,
            disabled: (*params).disabled,
        }
    };
    let ops = MainOps {
        init,
        debug: DLOG,
        console: DLOG_CONDUP,
    };
    let status = unsafe { zapret_lifecycle_prepare(&input, &ops) };
    if status == 1 {
        unsafe { DLOG_ERR(c"invalid main lifecycle state\n".as_ptr()) };
    }
    status
}

unsafe extern "C" fn release(handle: Handle) -> bool {
    unsafe { ReleaseMutex(handle) != 0 }
}

unsafe extern "C" fn close(handle: Handle) {
    unsafe { CloseHandle(handle) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_lifecycle_release_mutex(slot: *mut Handle) {
    let ops = MutexOps { release, close };
    if !unsafe { zapret_lifecycle_release_mutex(slot, &ops) } {
        unsafe { abort() };
    }
}
