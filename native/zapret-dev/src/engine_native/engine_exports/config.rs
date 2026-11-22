//! Native engine records checked by engine_config_exports_abi.h.
use super::startup_params::PARAMS;
use core::{
    ffi::{c_char, c_void},
    mem::size_of,
};

#[repr(C)]
struct Layout {
    size: usize,
    offsets: [usize; 10],
}

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}

const PARAMS_LAYOUT: Layout = Layout {
    size: PARAMS.size,
    offsets: [
        PARAMS.intercept,
        PARAMS.mark,
        PARAMS.timeouts,
        PARAMS.timeouts + 4,
        PARAMS.timeouts + 8,
        PARAMS.timeouts + 12,
        PARAMS.ipcache_lifetime,
        PARAMS.lua_gc,
        PARAMS.reassembly_disabled,
        PARAMS.payload_disabled,
    ],
};
const FILTER_SLOTS: usize = 13;
const ALLOCATOR: Allocator = Allocator {
    allocate: malloc,
    release: free,
};

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
    fn abort() -> !;
    fn wordfree(words: *mut c_void);
    fn strlist_destroy(head: *mut *mut c_void);
    fn zapret_engine_config_init(params: *mut u8, capacity: usize, layout: *const Layout) -> bool;
    fn zapret_engine_filter_buffers(
        slots: *const *mut *mut c_char,
        count: usize,
        allocator: *const Allocator,
    ) -> bool;
    fn zapret_engine_filter_clear(
        slots: *const *mut *mut c_char,
        count: usize,
        allocator: *const Allocator,
    ) -> bool;
}

unsafe fn filter_slots(params: *mut u8) -> [*mut *mut c_char; FILTER_SLOTS] {
    core::array::from_fn(|index| unsafe {
        params
            .add(PARAMS.first_filter_buffer + index * size_of::<*mut c_char>())
            .cast()
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn init_params(params: *mut u8) {
    if !unsafe { zapret_engine_config_init(params, PARAMS_LAYOUT.size, &PARAMS_LAYOUT) } {
        unsafe { abort() };
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn cleanup_args(params: *mut u8) {
    // wexp is the first member of the engine record.
    unsafe { wordfree(params.cast()) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn alloc_windivert_portfilters(params: *mut u8) -> bool {
    let slots = unsafe { filter_slots(params) };
    unsafe { zapret_engine_filter_buffers(slots.as_ptr(), slots.len(), &ALLOCATOR) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn cleanup_windivert_portfilters(params: *mut u8) {
    let slots = unsafe { filter_slots(params) };
    unsafe {
        zapret_engine_filter_clear(slots.as_ptr(), slots.len(), &ALLOCATOR);
        strlist_destroy(params.add(PARAMS.raw_filter_parts).cast());
    }
}
