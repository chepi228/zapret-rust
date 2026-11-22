use core::ffi::{c_char, c_int, c_void};

pub(super) const HASH_COUNT: usize = 16;

#[repr(C)]
pub(super) struct PrefixCursor {
    pub(super) phase: u32,
    pub(super) available: bool,
    pub(super) first: u8,
}

#[repr(C)]
pub(super) struct ProfileFlow {
    pub(super) profiles: *mut c_void,
    pub(super) templates: *mut c_void,
    pub(super) current: *mut c_void,
    pub(super) count: u32,
    pub(super) template_count: u32,
    pub(super) skip: bool,
    pub(super) template: bool,
}

#[repr(C)]
pub(super) struct PrefixSlots {
    pub(super) argc: *mut c_int,
    pub(super) argv: *mut *mut *mut c_char,
    pub(super) hashes: *mut u32,
    pub(super) profiles: *mut ProfileFlow,
    pub(super) entry: *mut *mut c_void,
    pub(super) profile: *mut *mut c_void,
}

const _: () = {
    use core::mem::{offset_of, size_of};

    let pointer = size_of::<*const c_void>();
    assert!(size_of::<PrefixCursor>() == 8 && offset_of!(PrefixCursor, first) == 5);
    assert!(size_of::<PrefixSlots>() == 6 * pointer);
    assert!(offset_of!(PrefixSlots, profiles) == 3 * pointer);
    assert!(size_of::<ProfileFlow>() == if pointer == 4 { 24 } else { 40 });
    assert!(offset_of!(ProfileFlow, template) == 3 * pointer + 9);
};
