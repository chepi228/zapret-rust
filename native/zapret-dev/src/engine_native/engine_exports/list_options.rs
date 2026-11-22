//! Local list option routing and comma-list native entry points.
use super::{
    DLOG_ERR, Log,
    lists::{IpPools, ListFile},
    profile_layout as profile,
};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

type Record = *mut c_void;
type ListSlot = *mut *mut ListFile;
type Insert = unsafe extern "C" fn(Record, *mut c_char) -> bool;
type Open = unsafe extern "C" fn(*const c_char, *const c_char) -> Record;
type FileResult = unsafe extern "C" fn(Record) -> c_int;

#[repr(C)]
struct Profile {
    before_automatic: [MaybeUninit<u8>; profile::AUTO_HOSTLIST],
    automatic: *mut ListFile,
}

#[repr(C)]
struct StringList {
    first: Record,
}

#[repr(C)]
struct Target {
    profile: *mut Profile,
    cached: ListSlot,
    automatic: ListSlot,
    skip: bool,
}

#[repr(C)]
struct Backend {
    register: unsafe extern "C" fn(*mut Profile, bool, *const c_char) -> *mut ListFile,
    parse: unsafe extern "C" fn(*mut ListFile, *const c_char) -> bool,
}

#[repr(C)]
struct Ops {
    hosts: Backend,
    ips: Backend,
    probe_auto: unsafe extern "C" fn(*const c_char) -> u32,
}

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> Record,
    release: unsafe extern "C" fn(Record),
}

const _: () = {
    let pointer = profile::POINTER;
    assert!(offset_of!(Profile, automatic) == profile::AUTO_HOSTLIST);
    assert!(size_of::<StringList>() == pointer && offset_of!(StringList, first) == 0);
    assert!(size_of::<Target>() == 4 * pointer && offset_of!(Target, skip) == 3 * pointer);
    assert!(size_of::<Ops>() == 5 * pointer && offset_of!(Ops, probe_auto) == 4 * pointer);
    assert!(size_of::<Allocator>() == 2 * pointer);
};

unsafe extern "C" {
    fn RegisterHostlist(profile: *mut Profile, exclude: bool, name: *const c_char)
    -> *mut ListFile;
    fn RegisterIpset(profile: *mut Profile, exclude: bool, name: *const c_char) -> *mut ListFile;
    fn AppendHostlistItem(pool: Record, text: *mut c_char) -> bool;
    fn AppendIpsetItem(pool: Record, text: *mut c_char) -> bool;

    fn wf_fopen(path: *const c_char, mode: *const c_char) -> Record;
    fn zapret_crt_is_gzip(file: Record) -> bool;
    fn ferror(file: Record) -> c_int;
    fn fclose(file: Record) -> c_int;
    fn malloc(size: usize) -> Record;
    fn free(value: Record);

    fn zapret_config_list(text: *const c_char, pool: Record, insert: Insert) -> bool;
    fn zapret_collection_parse_strings(
        list: *mut StringList,
        text: *const c_char,
        allocator: *const Allocator,
    ) -> bool;
    fn zapret_cli_auto_probe(
        path: *const c_char,
        open: Open,
        is_gzip: unsafe extern "C" fn(Record) -> bool,
        read_error: FileResult,
        close: FileResult,
    ) -> u32;
    fn zapret_cli_list_option(kind: u32, text: *const c_char, target: &Target, ops: &Ops) -> u32;
    fn zapret_cli_list_report(kind: u32, status: u32, text: *const c_char, error: Log) -> c_int;
}

const ALLOCATOR: Allocator = Allocator {
    allocate: malloc,
    release: free,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_domain_list(text: *mut c_char, pool: *mut Record) -> bool {
    unsafe { zapret_config_list(text, pool.cast(), AppendHostlistItem) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_ip_list(text: *mut c_char, pool: *mut IpPools) -> bool {
    unsafe { zapret_config_list(text, pool.cast(), AppendIpsetItem) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn parse_strlist(text: *mut c_char, list: *mut StringList) -> bool {
    unsafe { zapret_collection_parse_strings(list, text, &ALLOCATOR) }
}

unsafe extern "C" fn parse_host_file(file: *mut ListFile, text: *const c_char) -> bool {
    unsafe { parse_domain_list(text.cast_mut(), &raw mut (*file).hosts) }
}

unsafe extern "C" fn parse_ip_file(file: *mut ListFile, text: *const c_char) -> bool {
    unsafe { parse_ip_list(text.cast_mut(), &raw mut (*file).ips) }
}

unsafe extern "C" fn probe_auto(path: *const c_char) -> u32 {
    unsafe { zapret_cli_auto_probe(path, wf_fopen, zapret_crt_is_gzip, ferror, fclose) }
}

const OPS: Ops = Ops {
    hosts: Backend {
        register: RegisterHostlist,
        parse: parse_host_file,
    },
    ips: Backend {
        register: RegisterIpset,
        parse: parse_ip_file,
    },
    probe_auto,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn engine_list_option(
    index: c_int,
    text: *const c_char,
    profile: *mut Profile,
    skip: bool,
    host: ListSlot,
    host_exclude: ListSlot,
    ip: ListSlot,
    ip_exclude: ListSlot,
) -> c_int {
    let (kind, cached) = match index {
        20 => (0, ptr::null_mut()),
        21 => (1, host),
        22 => (2, ptr::null_mut()),
        23 => (3, host_exclude),
        24 => (4, ptr::null_mut()),
        46 => (5, ptr::null_mut()),
        47 => (6, ip),
        48 => (7, ptr::null_mut()),
        49 => (8, ip_exclude),
        _ => return 0,
    };
    let automatic = if kind == 4 && !skip && !profile.is_null() {
        unsafe { &raw mut (*profile).automatic }
    } else {
        ptr::null_mut()
    };
    let target = Target {
        profile,
        cached,
        automatic,
        skip,
    };
    unsafe {
        let status = zapret_cli_list_option(kind, text, &target, &OPS);
        zapret_cli_list_report(kind, status, text, DLOG_ERR)
    }
}
