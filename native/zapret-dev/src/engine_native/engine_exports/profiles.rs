//! Native profile entry points over the shared Rust configuration owner.
use super::{DLOG_ERR, Log};
use core::ffi::{c_char, c_void};

type Record = *mut c_void;
type Head = *mut Record;
type ProfileHead = *mut *mut ProfileEntry;

#[repr(C)]
struct Profile {
    _opaque: [u8; 0],
}

#[repr(C)]
struct ProfileEntry {
    _opaque: [u8; 0],
}

#[repr(C)]
struct ProfileFlow {
    _opaque: [u8; 0],
}

#[repr(C)]
struct ProfileOps {
    allocate: unsafe extern "C" fn(usize) -> Record,
    release: unsafe extern "C" fn(Record),
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    copy: unsafe extern "C" fn(u32, Head, *const Record) -> bool,
    destroy: unsafe extern "C" fn(u32, Head),
    failures: unsafe extern "C" fn(Head),
    error: Log,
}

const _: () = {
    let pointer = size_of::<Record>();
    assert!(size_of::<ProfileOps>() == 7 * pointer);
    assert!(core::mem::offset_of!(ProfileOps, error) == 6 * pointer);
};

unsafe extern "C" {
    fn calloc(count: usize, size: usize) -> Record;
    fn free(pointer: Record);
    fn strdup(text: *const c_char) -> *mut c_char;
    fn zapret_list_collection_copy(to: Head, from: *const c_void) -> bool;
    fn zapret_list_collection_destroy(head: Head);
    fn port_filters_copy(to: Head, from: *const Record) -> bool;
    fn port_filters_destroy(head: Head);
    fn icmp_filters_copy(to: Head, from: *const Record) -> bool;
    fn icmp_filters_destroy(head: Head);
    fn ipp_filters_copy(to: Head, from: *const Record) -> bool;
    fn ipp_filters_destroy(head: Head);
    fn funclist_copy(to: Head, from: *const Record) -> bool;
    fn funclist_destroy(head: Head);
    fn HostFailPoolDestroy(head: Head);

    fn zapret_profile_init_dynamic(profile: *mut Profile);
    fn zapret_profile_init(profile: *mut Profile);
    fn zapret_profile_clear(profile: *mut Profile, ops: &ProfileOps);
    fn zapret_profile_entry_destroy(entry: *mut ProfileEntry, ops: &ProfileOps);
    fn zapret_profile_list_destroy(head: ProfileHead, ops: &ProfileOps);
    fn zapret_profile_add(head: ProfileHead, ops: &ProfileOps) -> *mut ProfileEntry;
    fn zapret_profile_move(head: ProfileHead, entry: *mut ProfileEntry);
    fn zapret_profile_search(entry: *mut ProfileEntry, name: *const c_char) -> *mut ProfileEntry;
    fn zapret_profile_has_automatic(entry: *const ProfileEntry) -> bool;
    fn zapret_profile_import(to: *mut Profile, from: *const Profile, ops: &ProfileOps) -> bool;
    fn zapret_profile_next(flow: *mut ProfileFlow, name: *const c_char, ops: &ProfileOps) -> u32;
    fn zapret_profile_finish(flow: *mut ProfileFlow, ops: &ProfileOps) -> u32;
    fn zapret_profile_label(
        profile: *mut Profile,
        cookie: bool,
        name: *const c_char,
        ops: &ProfileOps,
    ) -> u32;
    fn zapret_profile_import_named(
        flow: *const ProfileFlow,
        name: *const c_char,
        ops: &ProfileOps,
    ) -> u32;
    fn zapret_profile_add_default(head: ProfileHead, ops: &ProfileOps) -> bool;
}

unsafe extern "C" fn allocate(size: usize) -> Record {
    unsafe { calloc(1, size) }
}

unsafe extern "C" fn copy_collection(kind: u32, to: Head, from: *const Record) -> bool {
    unsafe {
        match kind {
            // The registry takes the collection pointer. The embedded BSD list
            // routines take the address of the head.
            0..=3 => zapret_list_collection_copy(to, from.read()),
            4 | 5 => port_filters_copy(to, from),
            6 => icmp_filters_copy(to, from),
            7 => ipp_filters_copy(to, from),
            _ => funclist_copy(to, from),
        }
    }
}

unsafe extern "C" fn destroy_collection(kind: u32, head: Head) {
    unsafe {
        match kind {
            0..=3 => zapret_list_collection_destroy(head),
            4 | 5 => port_filters_destroy(head),
            6 => icmp_filters_destroy(head),
            7 => ipp_filters_destroy(head),
            _ => funclist_destroy(head),
        }
    }
}

const OPS: ProfileOps = ProfileOps {
    allocate,
    release: free,
    duplicate: strdup,
    copy: copy_collection,
    destroy: destroy_collection,
    failures: HostFailPoolDestroy,
    error: DLOG_ERR,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_init_dynamic(profile: *mut Profile) {
    unsafe { zapret_profile_init_dynamic(profile) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_init(profile: *mut Profile) {
    unsafe { zapret_profile_init(profile) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_clear(profile: *mut Profile) {
    unsafe { zapret_profile_clear(profile, &OPS) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_entry_destroy(entry: *mut ProfileEntry) {
    unsafe { zapret_profile_entry_destroy(entry, &OPS) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_list_destroy(head: ProfileHead) {
    unsafe { zapret_profile_list_destroy(head, &OPS) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_list_add(head: ProfileHead) -> *mut ProfileEntry {
    unsafe { zapret_profile_add(head, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_list_move(head: ProfileHead, entry: *mut ProfileEntry) {
    unsafe { zapret_profile_move(head, entry) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_list_search_name(
    head: ProfileHead,
    name: *const c_char,
) -> *mut ProfileEntry {
    unsafe { zapret_profile_search(head.read(), name) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_list_have_autohostlist(head: ProfileHead) -> bool {
    unsafe { zapret_profile_has_automatic(head.read()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dp_copy(to: *mut Profile, from: *const Profile) -> bool {
    unsafe { zapret_profile_import(to, from, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_profile_next(flow: *mut ProfileFlow, name: *const c_char) -> u32 {
    unsafe { zapret_profile_next(flow, name, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_profile_finish(flow: *mut ProfileFlow) -> u32 {
    unsafe { zapret_profile_finish(flow, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_profile_label(
    profile: *mut Profile,
    cookie: bool,
    name: *const c_char,
) -> u32 {
    unsafe { zapret_profile_label(profile, cookie, name, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_profile_import(flow: *const ProfileFlow, name: *const c_char) -> u32 {
    unsafe { zapret_profile_import_named(flow, name, &OPS) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_profile_add_default(head: ProfileHead) -> bool {
    unsafe { zapret_profile_add_default(head, &OPS) }
}
