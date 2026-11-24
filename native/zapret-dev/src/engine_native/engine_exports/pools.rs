//! Engine collection entry points with UCRT allocation and the existing Rust stores.
use super::{
    DLOG_ERR, Log,
    helpers::{FileStamp, boottime, file_mod_signature, file_open_test},
};
use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

type Record = *mut c_void;
type Head = *mut Record;
type Native = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize) -> usize;

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> Record,
    release: unsafe extern "C" fn(Record),
}

const ALLOCATOR: Allocator = Allocator {
    allocate: malloc,
    release: free,
};

#[repr(C)]
struct AddressPools {
    ipv4: Record,
    ipv6: Record,
}

unsafe extern "C" {
    fn malloc(size: usize) -> Record;
    fn free(pointer: Record);
    fn strlen(text: *const c_char) -> usize;
    fn DLOG_PERROR(text: *const c_char) -> c_int;
    fn wf_realpath(path: *const c_char, output: *mut c_char) -> *mut c_char;

    fn zapret_host_add(pool: Head, name: *const c_char, length: usize, flags: u32) -> c_int;
    fn zapret_host_has(pool: Record, name: *const c_char) -> c_int;
    fn zapret_host_destroy(pool: Head);
    fn zapret_ip_add(pool: Head, address: *const u8, width: u8, bits: u8) -> c_int;
    fn zapret_ip_check(pool: *const c_void, address: *const u8, bits: u8) -> c_int;
    fn zapret_ip_destroy(pool: Head);

    fn zapret_collection_add(
        kind: u32,
        head: Head,
        name: *const c_char,
        tail: bool,
        allocator: &Allocator,
    ) -> Record;
    fn zapret_collection_copy(
        kind: u32,
        target: Head,
        source: *const Record,
        allocator: &Allocator,
    ) -> bool;
    fn zapret_collection_destroy(kind: u32, head: Head, allocator: &Allocator);
    fn zapret_collection_search(head: *const Record, text: *const c_char) -> bool;
    fn zapret_filter_collection_add(
        kind: u32,
        head: Head,
        value: *const c_void,
        allocator: &Allocator,
    ) -> bool;
    fn zapret_filter_collection_copy(
        kind: u32,
        target: Head,
        source: *const Record,
        allocator: &Allocator,
    ) -> bool;
    fn zapret_filter_collection_destroy(kind: u32, head: Head, allocator: &Allocator);
    fn zapret_filter_collection_matches(kind: u32, head: *const Record, key: u16, code: u8)
    -> bool;
    fn zapret_filter_collection_deny_empty(kind: u32, head: Head, allocator: &Allocator) -> bool;
    fn zapret_blob_add(
        head: Head,
        allocator: &Allocator,
        data: *const c_void,
        size: usize,
        reserve: usize,
    ) -> Record;
    fn zapret_blob_destroy(blob: Record, allocator: &Allocator);
    fn zapret_blob_destroy_list(head: Head, allocator: &Allocator);
    fn zapret_blob_find(head: Head, name: *const c_char) -> Record;

    fn zapret_hostfail_add(pool: Head, name: *const c_char, timeout: c_int, now: i64) -> Record;
    fn zapret_hostfail_find(pool: *const c_void, name: *const c_char) -> Record;
    fn zapret_hostfail_next_expired(pool: *const c_void, cursor: *mut u64, now: i64) -> Record;
    fn zapret_hostfail_remove(pool: Head, entry: *const c_void);
    fn zapret_hostfail_destroy(pool: Head);
    fn zapret_ipcache_after(
        pool: *const c_void,
        cursor: *mut u64,
        address: *mut u8,
        interface: *mut u8,
    ) -> Record;
    fn zapret_ipcache_next_expired(
        pool: *const c_void,
        cursor: *mut u64,
        lifetime: i64,
        now: i64,
    ) -> Record;
    fn zapret_ipcache_remove(pool: Head, entry: *const c_void);
    fn zapret_ipcache_find(
        pool: *const c_void,
        address: *const u8,
        width: usize,
        interface: *const c_char,
    ) -> Record;
    fn zapret_ipcache_add(
        pool: Head,
        address: *const u8,
        width: usize,
        interface: *const c_char,
        now: i64,
    ) -> Record;
    fn zapret_ipcache_touch(entry: Record, now: i64);
    fn zapret_ipcache_hostname(entry: *const c_void) -> *mut c_char;
    fn zapret_cache_purge_due(previous: i64, now: i64) -> c_int;
    fn zapret_cache_lifecycle(
        entry: u32,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        native: Native,
    ) -> usize;

    fn zapret_list_register(registry: Head, collection: Head, path: *const c_char) -> Record;
    fn zapret_list_lifecycle(
        entry: u32,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        native: Native,
    ) -> usize;
    fn zapret_list_stamp_checked(
        filename: *const c_char,
        output: *mut FileStamp,
        kind: *const c_char,
        stat: unsafe extern "C" fn(*const c_char, *mut FileStamp) -> bool,
        perror: unsafe extern "C" fn(*const c_char) -> c_int,
        log: Log,
    ) -> bool;
    fn zapret_list_read_checked(
        filename: *const c_char,
        kind: *const c_char,
        flags: c_int,
        probe: unsafe extern "C" fn(*const c_char, c_int) -> bool,
        perror: unsafe extern "C" fn(*const c_char) -> c_int,
        log: Log,
    ) -> bool;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistPoolAddStrLen(
    pool: Head,
    name: *const c_char,
    length: usize,
    flags: u32,
) -> bool {
    unsafe { zapret_host_add(pool, name, length, flags) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistPoolAddStr(pool: Head, name: *const c_char, flags: u32) -> bool {
    unsafe { HostlistPoolAddStrLen(pool, name, strlen(name), flags) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistPoolCheckStr(pool: Record, name: *const c_char) -> bool {
    unsafe { zapret_host_has(pool, name) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistPoolDestroy(pool: Head) {
    unsafe { zapret_host_destroy(pool) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset4Add(pool: Head, address: *const u8, bits: u8) -> bool {
    unsafe { zapret_ip_add(pool, address, 32, bits) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset6Add(pool: Head, address: *const u8, bits: u8) -> bool {
    unsafe { zapret_ip_add(pool, address, 128, bits) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset4AddCidr(pool: Head, cidr: *const u8) -> bool {
    unsafe { ipset4Add(pool, cidr, cidr.add(4).read()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset6AddCidr(pool: Head, cidr: *const u8) -> bool {
    unsafe { ipset6Add(pool, cidr, cidr.add(16).read()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset4Check(pool: *const c_void, address: *const u8, bits: u8) -> bool {
    unsafe { zapret_ip_check(pool, address, bits) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipset6Check(pool: *const c_void, address: *const u8, bits: u8) -> bool {
    unsafe { zapret_ip_check(pool, address, bits) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipsetDestroy(pools: *mut AddressPools) {
    unsafe {
        zapret_ip_destroy(&raw mut (*pools).ipv4);
        zapret_ip_destroy(&raw mut (*pools).ipv6);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn strlist_add(head: Head, value: *const c_char) -> bool {
    !unsafe { zapret_collection_add(0, head, value, false, &ALLOCATOR) }.is_null()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn strlist_add_tail(head: Head, value: *const c_char) -> bool {
    !unsafe { zapret_collection_add(0, head, value, true, &ALLOCATOR) }.is_null()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn strlist_search(head: *const Record, text: *const c_char) -> bool {
    unsafe { zapret_collection_search(head, text) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn str2list_add(head: Head) -> Record {
    unsafe { zapret_collection_add(1, head, ptr::null(), false, &ALLOCATOR) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn funclist_add_tail(head: Head, value: *const c_char) -> Record {
    unsafe { zapret_collection_add(2, head, value, true, &ALLOCATOR) }
}

macro_rules! collection_lifecycle {
    ($kind:literal, $copy:ident, $destroy:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $copy(target: Head, source: *const Record) -> bool {
            unsafe { zapret_collection_copy($kind, target, source, &ALLOCATOR) }
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $destroy(head: Head) {
            unsafe { zapret_collection_destroy($kind, head, &ALLOCATOR) }
        }
    };
}

collection_lifecycle!(0, strlist_copy, strlist_destroy);
collection_lifecycle!(1, str2list_copy, str2list_destroy);
collection_lifecycle!(2, funclist_copy, funclist_destroy);

macro_rules! filter_collection {
    ($kind:literal, $add:ident, $copy:ident, $destroy:ident, $deny_empty:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $add(head: Head, value: *const c_void) -> bool {
            unsafe { zapret_filter_collection_add($kind, head, value, &ALLOCATOR) }
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $copy(target: Head, source: *const Record) -> bool {
            unsafe { zapret_filter_collection_copy($kind, target, source, &ALLOCATOR) }
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $destroy(head: Head) {
            unsafe { zapret_filter_collection_destroy($kind, head, &ALLOCATOR) }
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $deny_empty(head: Head) -> bool {
            unsafe { zapret_filter_collection_deny_empty($kind, head, &ALLOCATOR) }
        }
    };
}

filter_collection!(
    0,
    port_filter_add,
    port_filters_copy,
    port_filters_destroy,
    port_filters_deny_if_empty
);
filter_collection!(
    1,
    icmp_filter_add,
    icmp_filters_copy,
    icmp_filters_destroy,
    icmp_filters_deny_if_empty
);
filter_collection!(
    2,
    ipp_filter_add,
    ipp_filters_copy,
    ipp_filters_destroy,
    ipp_filters_deny_if_empty
);

#[unsafe(no_mangle)]
unsafe extern "C" fn port_filters_match(head: *const Record, port: u16) -> bool {
    unsafe { zapret_filter_collection_matches(0, head, port, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn icmp_filters_match(head: *const Record, kind: u8, code: u8) -> bool {
    unsafe { zapret_filter_collection_matches(1, head, u16::from(kind), code) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipp_filters_match(head: *const Record, protocol: u8) -> bool {
    unsafe { zapret_filter_collection_matches(2, head, u16::from(protocol), 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_collection_add(head: Head) -> Record {
    unsafe { zapret_blob_add(head, &ALLOCATOR, ptr::null(), 0, 0) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_collection_add_blob(
    head: Head,
    data: *const c_void,
    size: usize,
    reserve: usize,
) -> Record {
    unsafe { zapret_blob_add(head, &ALLOCATOR, data, size, reserve) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_destroy(blob: Record) {
    unsafe { zapret_blob_destroy(blob, &ALLOCATOR) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_collection_destroy(head: Head) {
    unsafe { zapret_blob_destroy_list(head, &ALLOCATOR) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_collection_empty(head: *const Record) -> bool {
    unsafe { head.read().is_null() }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn blob_collection_search_name(head: Head, name: *const c_char) -> Record {
    unsafe { zapret_blob_find(head, name) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolDestroy(pool: Head) {
    unsafe { zapret_hostfail_destroy(pool) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolAdd(pool: Head, name: *const c_char, timeout: c_int) -> Record {
    unsafe { zapret_hostfail_add(pool, name, timeout, boottime()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolFind(pool: Record, name: *const c_char) -> Record {
    unsafe { zapret_hostfail_find(pool, name) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolDel(pool: Head, entry: Record) {
    unsafe { zapret_hostfail_remove(pool, entry) }
}

unsafe extern "C" fn cache_native(
    op: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
) -> usize {
    unsafe {
        match op {
            1 => boottime() as usize,
            4 => {
                zapret_hostfail_remove(a as Head, b as *const c_void);
                0
            }
            5 => zapret_ipcache_after(
                a as *const c_void,
                b as *mut u64,
                ptr::null_mut(),
                ptr::null_mut(),
            ) as usize,
            7 => {
                zapret_ipcache_remove(a as Head, b as *const c_void);
                0
            }
            8 => zapret_ipcache_hostname(a as *const c_void) as usize,
            9 => {
                free(a as Record);
                0
            }
            10 => zapret_ipcache_find(a as *const c_void, b as *const u8, c, d as *const c_char)
                as usize,
            11 => zapret_ipcache_add(a as Head, b as *const u8, c, d as *const c_char, e as i64)
                as usize,
            12 => {
                zapret_ipcache_touch(a as Record, b as i64);
                0
            }
            13 => zapret_cache_purge_due(a as i64, b as i64) as usize,
            14 => {
                zapret_hostfail_next_expired(a as *const c_void, b as *mut u64, c as i64) as usize
            }
            15 => {
                zapret_ipcache_next_expired(a as *const c_void, b as *mut u64, c as i64, d as i64)
                    as usize
            }
            _ => 0,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolPurge(pool: Head) {
    unsafe { zapret_cache_lifecycle(1, pool as usize, 0, 0, 0, 0, cache_native) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostFailPoolPurgeRateLimited(pool: Head, previous: *mut i64) {
    unsafe { zapret_cache_lifecycle(2, pool as usize, previous as usize, 0, 0, 0, cache_native) };
}

unsafe fn ip_cache(
    operation: u32,
    cache: *mut AddressPools,
    a: usize,
    b: usize,
    c: usize,
) -> Record {
    unsafe {
        zapret_cache_lifecycle(
            operation,
            (&raw mut (*cache).ipv4) as usize,
            (&raw mut (*cache).ipv6) as usize,
            a,
            b,
            c,
            cache_native,
        ) as Record
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipcacheDestroy(cache: *mut AddressPools) {
    unsafe { ip_cache(3, cache, 0, 0, 0) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipcacheFind(
    cache: *mut AddressPools,
    v4: *const u8,
    v6: *const u8,
    interface: *const c_char,
) -> Record {
    unsafe { ip_cache(4, cache, v4 as usize, v6 as usize, interface as usize) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ipcacheTouch(
    cache: *mut AddressPools,
    v4: *const u8,
    v6: *const u8,
    interface: *const c_char,
) -> Record {
    unsafe { ip_cache(5, cache, v4 as usize, v6 as usize, interface as usize) }
}

// The dispatch loop checks the previous purge time on the engine thread.
static mut IPCACHE_PURGE_PREVIOUS: i64 = 0;

#[unsafe(no_mangle)]
unsafe extern "C" fn ipcachePurgeRateLimited(cache: *mut AddressPools, lifetime: i64) {
    unsafe {
        ip_cache(
            6,
            cache,
            lifetime as usize,
            (&raw mut IPCACHE_PURGE_PREVIOUS) as usize,
            0,
        )
    };
}

unsafe extern "C" fn register_native(
    op: u32,
    a: usize,
    b: usize,
    c: usize,
    _d: usize,
    _e: usize,
) -> usize {
    unsafe {
        match op {
            13 => wf_realpath(a as *const c_char, b as *mut c_char) as usize,
            14 => zapret_list_register(a as Head, b as Head, c as *const c_char) as usize,
            _ => 0,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_register_path(
    registry: Head,
    collection: Head,
    path: *const c_char,
) -> Record {
    unsafe {
        zapret_list_lifecycle(
            4,
            registry as usize,
            collection as usize,
            path as usize,
            0,
            0,
            register_native,
        ) as Record
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_read_stamp(
    filename: *const c_char,
    output: *mut FileStamp,
    kind: *const c_char,
) -> bool {
    unsafe {
        zapret_list_stamp_checked(
            filename,
            output,
            kind,
            file_mod_signature,
            DLOG_PERROR,
            DLOG_ERR,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_probe_read(filename: *const c_char, kind: *const c_char) -> bool {
    const O_RDONLY: c_int = 0;
    unsafe {
        zapret_list_read_checked(
            filename,
            kind,
            O_RDONLY,
            file_open_test,
            DLOG_PERROR,
            DLOG_ERR,
        )
    }
}
