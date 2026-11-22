//! Engine list entries over the existing Rust registries, loaders and presenters.
use super::{
    DLOG, DLOG_ERR, Log,
    helpers::{FileStamp, file_open_test},
    profile_layout as profile,
    startup_params::PARAMS,
    state::params_address,
};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

type Record = *mut c_void;
type Head = *mut Record;
type Insert = unsafe extern "C" fn(Record, *const u8, usize, u32) -> c_int;
type Native = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize) -> usize;

#[repr(C)]
struct ParamsPrefix {
    before_debug: [MaybeUninit<u8>; PARAMS.debug],
    debug: bool,
    before_profiles: [MaybeUninit<u8>; PARAMS.profile_head - PARAMS.debug - 1],
    profiles: Record,
    templates: Record,
    before_lists: [MaybeUninit<u8>; PARAMS.hostlists - PARAMS.template_head - profile::POINTER],
    hosts: Record,
    ips: Record,
    blobs: Record,
}

fn list_params() -> *mut ParamsPrefix {
    params_address().cast()
}

#[repr(C)]
struct ProfileLists {
    before_lists: [MaybeUninit<u8>; profile::FIRST_COLLECTION],
    ips: Record,
    excluded_ips: Record,
    hosts: Record,
    excluded_hosts: Record,
}

#[repr(C)]
pub(super) struct IpPools {
    ipv4: Record,
    ipv6: Record,
}

#[repr(C)]
pub(super) struct ListFile {
    filename: *const c_char,
    stamp: FileStamp,
    pub(super) hosts: Record,
    pub(super) ips: IpPools,
}

#[derive(Default)]
#[repr(C, align(4))]
struct Cidr4 {
    address: [u8; 4],
    prefix: u8,
}

#[derive(Default)]
#[repr(C, align(2))]
struct Cidr6 {
    address: [u8; 16],
    prefix: u8,
}

struct IpInsertion {
    pool: *mut IpPools,
    ipv4: Cidr4,
    ipv6: Cidr6,
}

#[repr(C)]
struct LoadInfo {
    count: u64,
    decompressed_size: u64,
    compressed: u32,
    error: u32,
}

#[repr(C)]
struct AppendOps {
    load: unsafe extern "C" fn(*const c_char, c_int, Insert, Record, *mut LoadInfo) -> c_int,
    message: Log,
    error: Log,
    perror: unsafe extern "C" fn(*const c_char) -> c_int,
    set_error: unsafe extern "C" fn(u32),
}

#[repr(C)]
struct HostOps {
    reload: unsafe extern "C" fn(*mut ListFile, *mut bool) -> bool,
    automatic: unsafe extern "C" fn(),
    log: Option<Log>,
}

#[repr(C)]
struct IpOps {
    reload: unsafe extern "C" fn(*mut ListFile) -> bool,
    log: Option<Log>,
    format_address: unsafe extern "C" fn(*const u8, usize, *mut c_char, usize) -> usize,
}

#[repr(C)]
struct DebugSources {
    debug: *const bool,
    registry: *const Record,
    profiles: *const Record,
    templates: *const Record,
}

const _: () = {
    use core::mem::offset_of;
    let pointer = profile::POINTER;
    assert!(offset_of!(ParamsPrefix, debug) == PARAMS.debug);
    assert!(offset_of!(ParamsPrefix, profiles) == PARAMS.profile_head);
    assert!(offset_of!(ParamsPrefix, templates) == PARAMS.template_head);
    assert!(offset_of!(ParamsPrefix, hosts) == PARAMS.hostlists);
    assert!(offset_of!(ParamsPrefix, ips) == PARAMS.ipsets);
    assert!(offset_of!(ParamsPrefix, blobs) == PARAMS.blobs);
    assert!(offset_of!(ProfileLists, ips) == profile::FIRST_COLLECTION);
    assert!(offset_of!(ProfileLists, excluded_ips) == profile::FIRST_COLLECTION + pointer);
    assert!(offset_of!(ProfileLists, hosts) == profile::FIRST_COLLECTION + 2 * pointer);
    assert!(offset_of!(ProfileLists, excluded_hosts) == profile::FIRST_COLLECTION + 3 * pointer);
    assert!(size_of::<ListFile>() == if pointer == 4 { 48 } else { 56 });
    assert!(offset_of!(ListFile, stamp) == 8 && size_of::<IpPools>() == 2 * pointer);
    assert!(offset_of!(ListFile, hosts) == 32);
    assert!(offset_of!(ListFile, ips) == 32 + pointer);
    assert!(size_of::<Cidr4>() == 8 && offset_of!(Cidr4, prefix) == 4);
    assert!(size_of::<Cidr6>() == 18 && offset_of!(Cidr6, prefix) == 16);
    assert!(size_of::<LoadInfo>() == 24 && size_of::<AppendOps>() == 5 * pointer);
    assert!(size_of::<HostOps>() == 3 * pointer && size_of::<IpOps>() == 3 * pointer);
    assert!(size_of::<DebugSources>() == 4 * pointer);
};

unsafe extern "C" {
    fn strlen(text: *const c_char) -> usize;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn DLOG_PERROR(text: *const c_char) -> c_int;
    fn wf_error(error: u32);
    fn file_size(filename: *const c_char, bytes: *mut i64) -> bool;
    fn HostlistPoolAddStrLen(pool: Head, text: *const c_char, length: usize, flags: u32) -> bool;
    fn HostlistPoolDestroy(pool: Head);
    fn ipset4Add(pool: Head, address: *const u8, prefix: u8) -> bool;
    fn ipset6Add(pool: Head, address: *const u8, prefix: u8) -> bool;
    fn ipsetDestroy(pool: *mut IpPools);
    fn zapret_parse_cidr4(text: *mut c_char, cidr: *mut Cidr4) -> bool;
    fn zapret_parse_cidr6(text: *mut c_char, cidr: *mut Cidr6) -> bool;
    fn zapret_lua_ntop(
        address: *const u8,
        width: usize,
        text: *mut c_char,
        capacity: usize,
    ) -> usize;

    fn zapret_list_lifecycle(
        entry: u32,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        native: Native,
    ) -> usize;
    fn zapret_list_item(
        text: *mut u8,
        len: usize,
        hosts: c_int,
        insert: Insert,
        ctx: Record,
    ) -> c_int;
    fn zapret_list_load(
        filename: *const c_char,
        hosts: c_int,
        insert: Insert,
        context: Record,
        result: *mut LoadInfo,
    ) -> c_int;
    fn zapret_list_append_file(
        filename: *const c_char,
        hosts: c_int,
        insert: Insert,
        context: Record,
        ops: &AppendOps,
    ) -> bool;
    fn zapret_list_reload(
        file: *mut ListFile,
        changed: *mut bool,
        kind: *const c_char,
        stamp: unsafe extern "C" fn(*const c_char, *mut FileStamp, *const c_char) -> bool,
        probe: unsafe extern "C" fn(*const c_char, *const c_char) -> bool,
        append: unsafe extern "C" fn(*mut ListFile) -> bool,
    ) -> bool;
    fn zapret_list_read_stamp(
        filename: *const c_char,
        output: *mut FileStamp,
        kind: *const c_char,
    ) -> bool;
    fn zapret_list_probe_read(filename: *const c_char, kind: *const c_char) -> bool;
    fn zapret_list_collection_at(collection: Record, index: usize) -> *mut ListFile;
    fn zapret_list_register_path(registry: Head, collection: Head, name: *const c_char) -> Record;
    fn zapret_list_register_checked(
        profile: *mut ProfileLists,
        exclude: bool,
        kind: u32,
        name: *const c_char,
        size: unsafe extern "C" fn(*const c_char) -> bool,
        error: unsafe extern "C" fn(u32, *const c_char),
        register: unsafe extern "C" fn(*mut ProfileLists, u32, *const c_char) -> *mut ListFile,
    ) -> *mut ListFile;
    fn zapret_list_startup_error(kind: u32) -> *const c_char;
    fn zapret_list_startup_probe(
        hosts: *const Record,
        ips: *const Record,
        probe: unsafe extern "C" fn(*const c_char) -> bool,
        report: unsafe extern "C" fn(u32, *const ListFile),
    ) -> bool;
    fn zapret_list_startup_report(
        kind: u32,
        file: *const ListFile,
        perror: unsafe extern "C" fn(*const c_char) -> c_int,
        report: Log,
    );
    fn zapret_list_host_nonempty(
        pool: Head,
        insert: unsafe extern "C" fn(Head, *const c_char, usize, u32) -> bool,
    ) -> bool;
    fn zapret_profile_ensure_automatic_hosts(
        entry: Record,
        prepare: unsafe extern "C" fn(*mut ListFile),
    );

    fn zapret_hostlists_load_all(registry: Record, ops: &HostOps) -> bool;
    fn zapret_ipsets_load_all(registry: Record, ops: &IpOps) -> bool;
    fn zapret_hostlists_reload_pair(include: Record, exclude: Record, ops: &HostOps) -> bool;
    fn zapret_ipsets_reload_pair(include: Record, exclude: Record, ops: &IpOps) -> bool;
    fn zapret_hostlists_check(
        include: Record,
        exclude: Record,
        host: *const c_char,
        no_subdomains: bool,
        excluded: *mut bool,
        skip_reload: bool,
        ops: &HostOps,
    ) -> bool;
    fn zapret_ipsets_check(
        include: Record,
        exclude: Record,
        ipv4: *const u8,
        ipv6: *const u8,
        reverse4: *const u8,
        reverse6: *const u8,
        ops: &IpOps,
    ) -> bool;
    fn zapret_list_report_profile(profile: *const ProfileLists, ips: bool, log: Log);
    fn zapret_native_list_debug(sources: &DebugSources, ip: bool, log: Log);
    fn zapret_native_blob_debug(head: *const Record, log: Log);
    fn zapret_native_lua_debug(
        profile: *const c_void,
        entity: *const c_char,
        enabled: bool,
        payload_name: unsafe extern "C" fn(u32) -> *const c_char,
        log: Log,
    );
    fn l7payload_str(payload: u32) -> *const c_char;
    fn zapret_native_list_profile_debug(
        profile: *const ProfileLists,
        entity: *const c_char,
        ip: bool,
        log: Log,
    );
}

const APPEND: AppendOps = AppendOps {
    load: zapret_list_load,
    message: DLOG_CONDUP,
    error: DLOG_ERR,
    perror: DLOG_PERROR,
    set_error: wf_error,
};

unsafe extern "C" fn host_insert_native(
    op: u32,
    pool: usize,
    text: usize,
    len: usize,
    flags: usize,
    _unused: usize,
) -> usize {
    unsafe {
        match op {
            5 => usize::from(HostlistPoolAddStrLen(
                pool as Head,
                text as *const c_char,
                len,
                flags as u32,
            )),
            6 => {
                HostlistPoolDestroy(pool as Head);
                0
            }
            _ => 0,
        }
    }
}

unsafe extern "C" fn insert_host(pool: Record, text: *const u8, len: usize, flags: u32) -> c_int {
    unsafe {
        zapret_list_lifecycle(
            2,
            pool as usize,
            text as usize,
            len,
            flags as usize,
            0,
            host_insert_native,
        ) as c_int
    }
}

unsafe extern "C" fn ip_insert_native(
    op: u32,
    context: usize,
    text: usize,
    format: usize,
    _d: usize,
    _e: usize,
) -> usize {
    let context = context as *mut IpInsertion;
    let text = text as *mut c_char;
    unsafe {
        match op {
            7 => usize::from(zapret_parse_cidr4(text, &raw mut (*context).ipv4)),
            8 => usize::from(ipset4Add(
                &raw mut (*(*context).pool).ipv4,
                (*context).ipv4.address.as_ptr(),
                (*context).ipv4.prefix,
            )),
            9 => usize::from(zapret_parse_cidr6(text, &raw mut (*context).ipv6)),
            10 => usize::from(ipset6Add(
                &raw mut (*(*context).pool).ipv6,
                (*context).ipv6.address.as_ptr(),
                (*context).ipv6.prefix,
            )),
            11 => {
                DLOG_ERR(format as *const c_char, text.cast_const());
                0
            }
            12 => {
                ipsetDestroy((*context).pool);
                0
            }
            _ => 0,
        }
    }
}

unsafe extern "C" fn insert_ip(pool: Record, text: *const u8, len: usize, _flags: u32) -> c_int {
    let mut context = IpInsertion {
        pool: pool.cast(),
        ipv4: Cidr4::default(),
        ipv6: Cidr6::default(),
    };
    unsafe {
        zapret_list_lifecycle(
            3,
            (&raw mut context) as usize,
            text as usize,
            len,
            0,
            0,
            ip_insert_native,
        ) as c_int
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AppendHostlistItem(pool: Head, text: *mut c_char) -> bool {
    unsafe { zapret_list_item(text.cast(), strlen(text), 1, insert_host, pool.cast()) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AppendIpsetItem(pool: *mut IpPools, text: *mut c_char) -> bool {
    unsafe { zapret_list_item(text.cast(), strlen(text), 0, insert_ip, pool.cast()) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn AppendHostList(pool: Head, filename: *const c_char) -> bool {
    unsafe { zapret_list_append_file(filename, 1, insert_host, pool.cast(), &APPEND) }
}

unsafe extern "C" fn append_registered_hosts(file: *mut ListFile) -> bool {
    unsafe { AppendHostList(&raw mut (*file).hosts, (*file).filename) }
}

unsafe extern "C" fn append_registered_ips(file: *mut ListFile) -> bool {
    unsafe {
        zapret_list_append_file(
            (*file).filename,
            0,
            insert_ip,
            (&raw mut (*file).ips).cast(),
            &APPEND,
        )
    }
}

unsafe extern "C" fn reload_hosts(file: *mut ListFile, changed: *mut bool) -> bool {
    unsafe {
        zapret_list_reload(
            file,
            changed,
            c"hostlist".as_ptr(),
            zapret_list_read_stamp,
            zapret_list_probe_read,
            append_registered_hosts,
        )
    }
}

unsafe extern "C" fn reload_ips(file: *mut ListFile) -> bool {
    unsafe {
        zapret_list_reload(
            file,
            ptr::null_mut(),
            c"ipset".as_ptr(),
            zapret_list_read_stamp,
            zapret_list_probe_read,
            append_registered_ips,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn NonEmptyHostlist(pool: Head) -> bool {
    unsafe { zapret_list_host_nonempty(pool, HostlistPoolAddStrLen) }
}

unsafe extern "C" fn ensure_automatic(file: *mut ListFile) {
    unsafe { NonEmptyHostlist(&raw mut (*file).hosts) };
}

unsafe extern "C" fn make_automatic_nonempty() {
    unsafe { zapret_profile_ensure_automatic_hosts((*list_params()).profiles, ensure_automatic) };
}

fn debug_sink() -> Option<Log> {
    unsafe { (*list_params()).debug }.then_some(DLOG as Log)
}

fn host_ops() -> HostOps {
    HostOps {
        reload: reload_hosts,
        automatic: make_automatic_nonempty,
        log: debug_sink(),
    }
}

fn ip_ops() -> IpOps {
    IpOps {
        reload: reload_ips,
        log: debug_sink(),
        format_address: zapret_lua_ntop,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn LoadAllHostLists() -> bool {
    let ops = host_ops();
    unsafe { zapret_hostlists_load_all((*list_params()).hosts, &ops) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn LoadAllIpsets() -> bool {
    let ops = ip_ops();
    unsafe { zapret_ipsets_load_all((*list_params()).ips, &ops) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistsReloadCheckForProfile(profile: *const ProfileLists) -> bool {
    let ops = host_ops();
    unsafe { zapret_hostlists_reload_pair((*profile).hosts, (*profile).excluded_hosts, &ops) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IpsetsReloadCheckForProfile(profile: *const ProfileLists) -> bool {
    let ops = ip_ops();
    unsafe { zapret_ipsets_reload_pair((*profile).ips, (*profile).excluded_ips, &ops) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn HostlistCheck(
    profile: *const ProfileLists,
    host: *const c_char,
    no_subdomains: bool,
    excluded: *mut bool,
    skip_reload: bool,
) -> bool {
    unsafe { zapret_list_report_profile(profile, false, DLOG) };
    let ops = host_ops();
    unsafe {
        zapret_hostlists_check(
            (*profile).hosts,
            (*profile).excluded_hosts,
            host,
            no_subdomains,
            excluded,
            skip_reload,
            &ops,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IpsetCheck(
    profile: *const ProfileLists,
    ipv4: *const u8,
    ipv6: *const u8,
    reverse4: *const u8,
    reverse6: *const u8,
) -> bool {
    unsafe {
        if zapret_list_collection_at((*profile).ips, 0).is_null()
            && zapret_list_collection_at((*profile).excluded_ips, 0).is_null()
        {
            return true;
        }
        zapret_list_report_profile(profile, true, DLOG);
    }
    let ops = ip_ops();
    unsafe {
        zapret_ipsets_check(
            (*profile).ips,
            (*profile).excluded_ips,
            ipv4,
            ipv6,
            reverse4,
            reverse6,
            &ops,
        )
    }
}

unsafe extern "C" fn startup_size(filename: *const c_char) -> bool {
    unsafe { file_size(filename, ptr::null_mut()) }
}

unsafe extern "C" fn startup_open(filename: *const c_char) -> bool {
    const O_RDONLY: c_int = 0;
    unsafe { file_open_test(filename, O_RDONLY) }
}

unsafe extern "C" fn startup_open_error(kind: u32, file: *const ListFile) {
    unsafe { zapret_list_startup_report(kind, file, DLOG_PERROR, DLOG_ERR) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn test_list_files() -> bool {
    unsafe {
        let params = list_params();
        zapret_list_startup_probe(
            &raw const (*params).hosts,
            &raw const (*params).ips,
            startup_open,
            startup_open_error,
        )
    }
}

unsafe extern "C" fn startup_size_error(kind: u32, filename: *const c_char) {
    unsafe { DLOG_ERR(zapret_list_startup_error(kind), filename) };
}

unsafe extern "C" fn register_slot(
    profile: *mut ProfileLists,
    slot: u32,
    filename: *const c_char,
) -> *mut ListFile {
    unsafe {
        let params = list_params();
        let (registry, collection) = match slot {
            0 => (&raw mut (*params).hosts, &raw mut (*profile).hosts),
            1 => (&raw mut (*params).hosts, &raw mut (*profile).excluded_hosts),
            2 => (&raw mut (*params).ips, &raw mut (*profile).ips),
            3 => (&raw mut (*params).ips, &raw mut (*profile).excluded_ips),
            _ => return ptr::null_mut(),
        };
        zapret_list_register_path(registry, collection, filename).cast()
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn RegisterHostlist(
    profile: *mut ProfileLists,
    exclude: bool,
    filename: *const c_char,
) -> *mut ListFile {
    unsafe {
        zapret_list_register_checked(
            profile,
            exclude,
            0,
            filename,
            startup_size,
            startup_size_error,
            register_slot,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn RegisterIpset(
    profile: *mut ProfileLists,
    exclude: bool,
    filename: *const c_char,
) -> *mut ListFile {
    unsafe {
        zapret_list_register_checked(
            profile,
            exclude,
            1,
            filename,
            startup_size,
            startup_size_error,
            register_slot,
        )
    }
}

fn debug_lists(ips: bool) {
    unsafe {
        let params = list_params();
        let sources = DebugSources {
            debug: &raw const (*params).debug,
            registry: if ips {
                &raw const (*params).ips
            } else {
                &raw const (*params).hosts
            },
            profiles: &raw const (*params).profiles,
            templates: &raw const (*params).templates,
        };
        zapret_native_list_debug(&sources, ips, DLOG);
    }
}

#[unsafe(no_mangle)]
extern "C" fn HostlistsDebug() {
    debug_lists(false);
}

#[unsafe(no_mangle)]
extern "C" fn IpsetsDebug() {
    debug_lists(true);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn BlobDebug() {
    unsafe { zapret_native_blob_debug(&raw const (*list_params()).blobs, DLOG) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn LuaDesyncDebug(profile: *const c_void, entity: *const c_char) {
    unsafe {
        zapret_native_lua_debug(profile, entity, (*list_params()).debug, l7payload_str, DLOG)
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn IpsetsDebugProfile(profile: *const ProfileLists, entity: *const c_char) {
    unsafe { zapret_native_list_profile_debug(profile, entity, true, DLOG) };
}
