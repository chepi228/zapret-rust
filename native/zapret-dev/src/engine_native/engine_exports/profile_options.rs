//! Local CLI profile controls, defaults and filter-list ownership.
use core::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct Profile {
    _opaque: [u8; 0],
}

#[repr(C)]
struct ProfileEntry {
    _opaque: [u8; 0],
}

#[repr(C)]
struct ListFile {
    _opaque: [u8; 0],
}

#[repr(C)]
struct PacketRange {
    _opaque: [u8; 0],
}

type ProfileHead = *mut *mut ProfileEntry;
type ListSlot = *mut *mut ListFile;
type FilterHead = *mut *mut c_void;
type DenyEmpty = unsafe extern "C" fn(u32, FilterHead) -> bool;
type FilterAdd = unsafe extern "C" fn(FilterHead, *const c_void) -> bool;
type ListOperation = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize) -> usize;
type PublishProfile = unsafe extern "C" fn(*const ProfileFlow, ProfileHead, *mut *mut Profile);

#[repr(C)]
struct ProfileFlow {
    profiles: ProfileHead,
    templates: ProfileHead,
    current: *mut ProfileEntry,
    count: u32,
    template_count: u32,
    skip: bool,
    template: bool,
}

#[repr(C)]
struct ControlTarget {
    flow: *mut ProfileFlow,
    profile: *mut Profile,
    skip: *mut bool,
    template: *mut bool,
    caches: [ListSlot; 4],
    payload: *mut u64,
    incoming: *mut PacketRange,
    outgoing: *mut PacketRange,
    dry: *mut bool,
}

#[repr(C)]
struct ControlOps {
    next: unsafe extern "C" fn(*mut ProfileFlow, *const c_char) -> u32,
    label: unsafe extern "C" fn(*mut Profile, bool, *const c_char) -> u32,
    import: unsafe extern "C" fn(*const ProfileFlow, *const c_char) -> u32,
}

const _: () = {
    let pointer = size_of::<*mut c_void>();
    assert!(size_of::<ProfileFlow>() == if pointer == 4 { 24 } else { 40 });
    assert!(core::mem::offset_of!(ProfileFlow, current) == 2 * pointer);
    assert!(core::mem::offset_of!(ProfileFlow, skip) == 3 * pointer + 8);
    assert!(core::mem::offset_of!(ProfileFlow, template) == 3 * pointer + 9);
    assert!(size_of::<ControlTarget>() == 12 * pointer && size_of::<ControlOps>() == 3 * pointer);
};

unsafe extern "C" {
    fn zapret_native_cli_kind(index: c_int, category: u32) -> c_int;
    fn zapret_cli_control_apply(
        kind: u32,
        text: *const c_char,
        target: &ControlTarget,
        ops: &ControlOps,
        entry: ProfileHead,
        profile: *mut *mut Profile,
        publish: PublishProfile,
    ) -> c_int;
    fn native_profile_next(flow: *mut ProfileFlow, text: *const c_char) -> u32;
    fn native_profile_label(profile: *mut Profile, cookie: bool, text: *const c_char) -> u32;
    fn native_profile_import(flow: *const ProfileFlow, text: *const c_char) -> u32;
    fn zapret_profile_filter_defaults(profile: *mut Profile, deny_empty: DenyEmpty) -> bool;
    fn port_filters_deny_if_empty(head: FilterHead) -> bool;
    fn icmp_filters_deny_if_empty(head: FilterHead) -> bool;
    fn ipp_filters_deny_if_empty(head: FilterHead) -> bool;
    fn zapret_parse_port_list(text: *const c_char, head: FilterHead, add: FilterAdd) -> bool;
    fn zapret_parse_icmp_list(text: *const c_char, head: FilterHead, add: FilterAdd) -> bool;
    fn zapret_parse_ip_list(text: *const c_char, head: FilterHead, add: FilterAdd) -> bool;
    fn port_filter_add(head: FilterHead, filter: *const c_void) -> bool;
    fn icmp_filter_add(head: FilterHead, filter: *const c_void) -> bool;
    fn ipp_filter_add(head: FilterHead, filter: *const c_void) -> bool;
    fn zapret_list_lifecycle(
        operation: u32,
        kind: usize,
        head: usize,
        text: usize,
        next_offset: usize,
        unused: usize,
        native: ListOperation,
    ) -> usize;
    fn free(pointer: *mut c_void);
}

const CONTROL_CATEGORY: u32 = 5;
const CONTROL_OPS: ControlOps = ControlOps {
    next: native_profile_next,
    label: native_profile_label,
    import: native_profile_import,
};

unsafe extern "C" fn publish_profile(
    flow: *const ProfileFlow,
    entry: ProfileHead,
    profile: *mut *mut Profile,
) {
    let current = unsafe { (*flow).current };
    // The C layout check pins the embedded profile to the start of the entry.
    unsafe {
        entry.write(current);
        profile.write(current.cast());
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn engine_control_option(
    index: c_int,
    text: *const c_char,
    flow: *mut ProfileFlow,
    entry: ProfileHead,
    profile: *mut *mut Profile,
    host: ListSlot,
    host_exclude: ListSlot,
    ip: ListSlot,
    ip_exclude: ListSlot,
    payload: *mut u64,
    incoming: *mut PacketRange,
    outgoing: *mut PacketRange,
    dry: *mut bool,
) -> c_int {
    let kind = unsafe { zapret_native_cli_kind(index, CONTROL_CATEGORY) };
    if kind < 0 {
        return 0;
    }
    let target = unsafe {
        ControlTarget {
            flow,
            profile: profile.read(),
            skip: &raw mut (*flow).skip,
            template: &raw mut (*flow).template,
            caches: [host, host_exclude, ip, ip_exclude],
            payload,
            incoming,
            outgoing,
            dry,
        }
    };
    unsafe {
        zapret_cli_control_apply(
            kind as u32,
            text,
            &target,
            &CONTROL_OPS,
            entry,
            profile,
            publish_profile,
        )
    }
}

unsafe extern "C" fn deny_empty(kind: u32, head: FilterHead) -> bool {
    unsafe {
        match kind {
            4 | 5 => port_filters_deny_if_empty(head),
            6 => icmp_filters_deny_if_empty(head),
            _ => ipp_filters_deny_if_empty(head),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn filter_defaults(profile: *mut Profile) -> bool {
    unsafe { zapret_profile_filter_defaults(profile, deny_empty) }
}

unsafe extern "C" fn filter_list_operation(
    operation: u32,
    a: usize,
    b: usize,
    _c: usize,
    _d: usize,
    _e: usize,
) -> usize {
    unsafe {
        match operation {
            1 => zapret_parse_port_list(a as _, b as _, port_filter_add) as usize,
            2 => zapret_parse_icmp_list(a as _, b as _, icmp_filter_add) as usize,
            3 => zapret_parse_ip_list(a as _, b as _, ipp_filter_add) as usize,
            4 => {
                free(a as *mut c_void);
                0
            }
            _ => 0,
        }
    }
}

unsafe fn parse_filter_list(
    kind: usize,
    text: *const c_char,
    head: FilterHead,
    links_offset: usize,
) -> bool {
    const PARSE_AND_ROLL_BACK: u32 = 1;
    unsafe {
        zapret_list_lifecycle(
            PARSE_AND_ROLL_BACK,
            kind,
            head as usize,
            text as usize,
            links_offset,
            0,
            filter_list_operation,
        ) != 0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_pf_list(text: *const c_char, head: FilterHead) -> bool {
    unsafe { parse_filter_list(0, text, head, 8) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_icf_list(text: *const c_char, head: FilterHead) -> bool {
    unsafe { parse_filter_list(1, text, head, size_of::<*mut c_void>()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_ipp_list(text: *const c_char, head: FilterHead) -> bool {
    unsafe { parse_filter_list(2, text, head, size_of::<*mut c_void>()) }
}
