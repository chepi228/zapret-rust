//! Release the engine's remaining records after the Lua VM has closed.
use super::config::{cleanup_args, cleanup_windivert_portfilters};
use super::startup_params::PARAMS;
use core::ffi::c_void;

type Slot = *mut c_void;
type DropSlot = unsafe extern "C" fn(Slot);

#[repr(C)]
struct State {
    context: Slot,
    conntrack: Slot,
    profiles: Slot,
    templates: Slot,
    hosts: Slot,
    ips: Slot,
    cache: Slot,
    blobs: Slot,
    scripts: Slot,
    timers: Slot,
    ssid: Slot,
    networks: Slot,
    parts: Slot,
    capture: *mut Slot,
}

#[repr(C)]
struct DropOps {
    arguments: DropSlot,
    conntrack: DropSlot,
    profiles: DropSlot,
    registry: DropSlot,
    cache: DropSlot,
    blobs: DropSlot,
    strings: DropSlot,
    timers: DropSlot,
    filters: DropSlot,
    release: DropSlot,
}

const _: () = {
    assert!(size_of::<State>() == 14 * size_of::<Slot>());
    assert!(size_of::<DropOps>() == 10 * size_of::<Slot>());
};

unsafe extern "C" {
    fn ConntrackPoolDestroy(pool: Slot);
    fn TimerPoolDestroy(pool: Slot);
    fn dp_list_destroy(head: *mut Slot);
    fn zapret_list_files_destroy(head: *mut Slot);
    fn ipcacheDestroy(head: *mut Slot);
    fn blob_collection_destroy(head: *mut Slot);
    fn strlist_destroy(head: *mut Slot);
    fn free(pointer: Slot);
    fn abort() -> !;
    fn zapret_lifecycle_cleanup(state: *const State, ops: *const DropOps) -> bool;
}

unsafe extern "C" fn drop_arguments(slot: Slot) {
    unsafe { cleanup_args(slot.cast()) };
}

unsafe extern "C" fn drop_profiles(slot: Slot) {
    unsafe { dp_list_destroy(slot.cast()) };
}

unsafe extern "C" fn drop_registry(slot: Slot) {
    unsafe { zapret_list_files_destroy(slot.cast()) };
}

unsafe extern "C" fn drop_cache(slot: Slot) {
    unsafe { ipcacheDestroy(slot.cast()) };
}

unsafe extern "C" fn drop_blobs(slot: Slot) {
    unsafe { blob_collection_destroy(slot.cast()) };
}

unsafe extern "C" fn drop_strings(slot: Slot) {
    unsafe { strlist_destroy(slot.cast()) };
}

unsafe extern "C" fn drop_filters(slot: Slot) {
    unsafe { cleanup_windivert_portfilters(slot.cast()) };
}

const DROP_OPS: DropOps = DropOps {
    arguments: drop_arguments,
    conntrack: ConntrackPoolDestroy,
    profiles: drop_profiles,
    registry: drop_registry,
    cache: drop_cache,
    blobs: drop_blobs,
    strings: drop_strings,
    timers: TimerPoolDestroy,
    filters: drop_filters,
    release: free,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cleanup_closed_params(params: *mut u8) {
    let field = |offset| unsafe { params.add(offset).cast() };
    let state = State {
        context: params.cast(),
        conntrack: field(PARAMS.conntrack),
        profiles: field(PARAMS.profile_head),
        templates: field(PARAMS.template_head),
        hosts: field(PARAMS.hostlists),
        ips: field(PARAMS.ipsets),
        cache: field(PARAMS.ipcache),
        blobs: field(PARAMS.blobs),
        scripts: field(PARAMS.lua_scripts),
        timers: field(PARAMS.timers),
        ssid: field(PARAMS.ssid_filter),
        networks: field(PARAMS.network_filter),
        parts: field(PARAMS.raw_filter_parts),
        capture: field(PARAMS.capture_filter).cast(),
    };
    if !unsafe { zapret_lifecycle_cleanup(&state, &DROP_OPS) } {
        unsafe { abort() };
    }
}
