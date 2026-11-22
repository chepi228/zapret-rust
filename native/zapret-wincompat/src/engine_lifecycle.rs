//! Native main preparation and cleanup after the C VM boundary has closed Lua.
use crate::logging::LogSink;
use std::ffi::c_void;
fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
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
    init: Option<unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32)>,
    debug: Option<LogSink>,
    console: Option<LogSink>,
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lifecycle_prepare(input: *const Input, ops: *const MainOps) -> u32 {
    if !valid(input) || !valid(ops) {
        return 1;
    }
    let input = unsafe { &*input };
    let ops = unsafe { &*ops };
    if input.pool.is_null() {
        return 1;
    }
    let (Some(init), Some(debug), Some(console)) = (ops.init, ops.debug, ops.console) else {
        return 1;
    };
    if input.dry {
        unsafe { console(c"command line parameters verified\n".as_ptr()) };
        return 8;
    }
    unsafe {
        if input.disabled {
            console(c"conntrack disabled ! some functions will not work. make sure it's what you want.\n".as_ptr());
        } else {
            let [syn, established, fin, udp] = input.timeouts;
            debug(
                c"initializing conntrack with timeouts tcp=%u:%u:%u udp=%u\n".as_ptr(),
                syn,
                established,
                fin,
                udp,
            );
            init(input.pool, 10, syn, established, fin, udp);
        }
        debug(c"ipcache lifetime %us\n".as_ptr(), input.lifetime);
    }
    0
}
#[repr(C)]
struct State {
    context: *mut c_void,
    conntrack: *mut c_void,
    profiles: *mut c_void,
    templates: *mut c_void,
    hosts: *mut c_void,
    ips: *mut c_void,
    cache: *mut c_void,
    blobs: *mut c_void,
    scripts: *mut c_void,
    timers: *mut c_void,
    ssid: *mut c_void,
    networks: *mut c_void,
    parts: *mut c_void,
    capture: *mut *mut c_void,
}
#[repr(C)]
struct DropOps {
    arguments: Option<DropSlot>,
    conntrack: Option<DropSlot>,
    profiles: Option<DropSlot>,
    registry: Option<DropSlot>,
    cache: Option<DropSlot>,
    blobs: Option<DropSlot>,
    strings: Option<DropSlot>,
    timers: Option<DropSlot>,
    filters: Option<DropSlot>,
    release: Option<DropSlot>,
}
type DropSlot = unsafe extern "C" fn(*mut c_void);
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lifecycle_cleanup(state: *const State, ops: *const DropOps) -> bool {
    if !valid(state) || !valid(ops) {
        return false;
    }
    let state = unsafe { &*state };
    let ops = unsafe { &*ops };
    let Some(release) = ops.release else {
        return false;
    };
    let order = [
        (ops.arguments, state.context),
        (ops.conntrack, state.conntrack),
        (ops.profiles, state.profiles),
        (ops.profiles, state.templates),
        (ops.registry, state.hosts),
        (ops.registry, state.ips),
        (ops.cache, state.cache),
        (ops.blobs, state.blobs),
        (ops.strings, state.scripts),
        (ops.timers, state.timers),
        (ops.strings, state.ssid),
        (ops.strings, state.networks),
        (ops.strings, state.parts),
        (ops.filters, state.context),
    ];
    if !valid(state.capture)
        || order
            .iter()
            .any(|(drop, slot)| drop.is_none() || slot.is_null())
    {
        return false;
    }
    for (drop, slot) in order {
        unsafe { drop.expect("validated drop binding")(slot) };
    }
    // Detach before the allocator callback; a later cleanup sees an empty slot.
    let capture = unsafe { state.capture.replace(std::ptr::null_mut()) };
    if !capture.is_null() {
        unsafe { release(capture) };
    }
    true
}
#[repr(C)]
struct MutexOps {
    release: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    close: Option<unsafe extern "C" fn(*mut c_void)>,
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lifecycle_release_mutex(
    slot: *mut *mut c_void,
    ops: *const MutexOps,
) -> bool {
    if !valid(slot) || !valid(ops) {
        return false;
    }
    let ops = unsafe { &*ops };
    let (Some(release), Some(close)) = (ops.release, ops.close) else {
        return false;
    };
    let owned = unsafe { slot.replace(std::ptr::null_mut()) };
    if !owned.is_null() {
        unsafe {
            release(owned);
            close(owned)
        };
    }
    true
}
#[cfg(windows)]
const _: () = {
    let pointer = size_of::<*mut c_void>();
    assert!(size_of::<Input>() == pointer + 24);
    assert!(size_of::<MainOps>() == 3 * pointer);
    assert!(size_of::<State>() == 14 * pointer);
    assert!(size_of::<DropOps>() == 10 * pointer);
    assert!(size_of::<MutexOps>() == 2 * pointer);
};
