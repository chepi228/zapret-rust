//! Native storage and platform bindings for the existing Rust CLI policies.
use super::{
    DLOG, DLOG_ERR, Log, profile_layout as profile, startup_params::PARAMS, state::params_address,
};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
    ptr,
};

#[path = "../windows_builtin_init_option.rs"]
mod builtin_init;

const PATH_CAPACITY: usize = 4096;
type Reserved<const N: usize> = [MaybeUninit<u8>; N];
type Path = [c_char; PATH_CAPACITY];

// Checked against the pinned C records in engine_cli_options_abi.h. Project
// individual fields with raw pointers so platform callbacks can observe them.
#[repr(C)]
struct Params {
    before_debug: Reserved<{ PARAMS.debug_target }>,
    debug_target: c_int,
    debug_logfile: Path,
    debug: bool,
    daemon: bool,
    intercept: bool,
    fuzz: u32,
    before_filters: Reserved<{ PARAMS.ssid_filter_neg - PARAMS.fuzz - 4 }>,
    ssid_filter_neg: bool,
    nlm_filter_neg: bool,
    before_pidfile: Reserved<{ PARAMS.pidfile - PARAMS.ssid_filter_neg - 2 }>,
    pidfile: Path,
    hostlist_auto_debuglog: Path,
    before_timeouts: Reserved<{ PARAMS.timeouts - PARAMS.auto_hostlist_log - PATH_CAPACITY }>,
    ctrack_t_syn: u32,
    ctrack_t_est: u32,
    ctrack_t_fin: u32,
    ctrack_t_udp: u32,
    before_flags: Reserved<{ PARAMS.ctrack_disable - PARAMS.timeouts - 16 }>,
    ctrack_disable: bool,
    server: bool,
    cache_hostname: bool,
    ipcache_lifetime: u32,
    before_scripts: Reserved<{ PARAMS.lua_scripts - PARAMS.ipcache_lifetime - 4 }>,
    lua_init_scripts: *mut c_void,
    writable_dir_enable: bool,
    writable_dir: Path,
    before_gc: Reserved<{ PARAMS.lua_gc - PARAMS.writable_dir - PATH_CAPACITY }>,
    lua_gc: u64,
    after_gc: Reserved<{ PARAMS.size - PARAMS.lua_gc - 8 }>,
}

#[repr(C, align(8))]
struct Profile {
    before_auto_hostlist: Reserved<{ profile::FIRST_HOSTLIST_LIMIT }>,
    hostlist_auto_fail_threshold: c_int,
    hostlist_auto_fail_time: c_int,
    hostlist_auto_retrans_threshold: c_int,
    hostlist_auto_udp_in: c_int,
    hostlist_auto_udp_out: c_int,
    hostlist_auto_retrans_maxseq: u32,
    hostlist_auto_incoming_maxseq: u32,
    hostlist_auto_retrans_reset: bool,
    before_explicit: Reserved<{ profile::FIRST_EXPLICIT - profile::FIRST_HOSTLIST_LIMIT - 29 }>,
    b_hostlist_auto_fail_threshold: bool,
    b_hostlist_auto_fail_time: bool,
    b_hostlist_auto_retrans_threshold: bool,
    b_hostlist_auto_retrans_maxseq: bool,
    b_hostlist_auto_incoming_maxseq: bool,
    b_hostlist_auto_retrans_reset: bool,
    b_hostlist_auto_udp_out: bool,
    b_hostlist_auto_udp_in: bool,
    after_explicit: Reserved<2>,
}

#[derive(Default)]
#[repr(C)]
struct StartupTarget {
    path: *mut c_char,
    capacity: usize,
    enabled: *mut bool,
    debug: *mut bool,
    log_target: *mut c_int,
    scripts: *mut c_void,
}

type Perror = unsafe extern "C" fn(*const c_char) -> c_int;
type FileOpen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FileClose = unsafe extern "C" fn(*mut c_void) -> c_int;

#[repr(C)]
struct StartupOps {
    resolve: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> u32,
    touch: unsafe extern "C" fn(*const c_char, bool) -> u32,
    cwd: unsafe extern "C" fn(*const c_char) -> u32,
    environment: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    syslog: unsafe extern "C" fn(c_int, c_int),
    trace_directory: Log,
    append: unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
}

#[derive(Default)]
#[repr(C)]
struct StartupDetail {
    error: u32,
    argument_offset: u32,
}

#[repr(C)]
struct NumericTarget {
    value: *mut c_void,
    explicit: *mut bool,
    intercept: *mut bool,
    timeouts: [*mut u32; 4],
}

#[repr(C)]
struct NumericOption {
    value: *mut c_void,
    explicit: *mut bool,
    lower: i64,
    upper: i64,
    scale: u32,
    kind: u32,
    disable: *mut bool,
}

#[repr(C)]
struct NumericOps {
    number: unsafe extern "C" fn(*const c_char, *const NumericOption) -> bool,
    timeouts: unsafe extern "C" fn(*const c_char, *mut u32, *mut u32, *mut u32, *mut u32) -> bool,
}

const _: () = {
    let pointer = profile::POINTER;
    assert!(size_of::<Params>() == PARAMS.size && align_of::<Params>() == 8);
    assert!(offset_of!(Params, debug_logfile) == PARAMS.debug_logfile);
    assert!(
        offset_of!(Params, debug) == PARAMS.debug && offset_of!(Params, daemon) == PARAMS.daemon
    );
    assert!(offset_of!(Params, fuzz) == PARAMS.fuzz);
    assert!(offset_of!(Params, ssid_filter_neg) == PARAMS.ssid_filter_neg);
    assert!(offset_of!(Params, pidfile) == PARAMS.pidfile);
    assert!(offset_of!(Params, hostlist_auto_debuglog) == PARAMS.auto_hostlist_log);
    assert!(offset_of!(Params, ctrack_t_syn) == PARAMS.timeouts);
    assert!(offset_of!(Params, ctrack_disable) == PARAMS.ctrack_disable);
    assert!(offset_of!(Params, ipcache_lifetime) == PARAMS.ipcache_lifetime);
    assert!(offset_of!(Params, lua_init_scripts) == PARAMS.lua_scripts);
    assert!(offset_of!(Params, writable_dir) == PARAMS.writable_dir);
    assert!(offset_of!(Params, lua_gc) == PARAMS.lua_gc);
    assert!(size_of::<Profile>() == profile::SIZE && align_of::<Profile>() == 8);
    assert!(offset_of!(Profile, hostlist_auto_fail_threshold) == profile::FIRST_HOSTLIST_LIMIT);
    assert!(offset_of!(Profile, hostlist_auto_retrans_reset) == profile::FIRST_HOSTLIST_LIMIT + 28);
    assert!(offset_of!(Profile, b_hostlist_auto_fail_threshold) == profile::FIRST_EXPLICIT);
    assert!(offset_of!(Profile, b_hostlist_auto_udp_in) == profile::FIRST_EXPLICIT + 7);
    assert!(size_of::<StartupTarget>() == 6 * pointer && size_of::<StartupOps>() == 7 * pointer);
    assert!(size_of::<StartupDetail>() == 8);
    assert!(size_of::<NumericTarget>() == 7 * pointer && size_of::<NumericOps>() == 2 * pointer);
    assert!(size_of::<NumericOption>() == if pointer == 4 { 40 } else { 48 });
    assert!(offset_of!(NumericOption, kind) == 2 * pointer + 20);
};

unsafe extern "C" {
    static mut progname: *const c_char;
    fn DLOG_PERROR(text: *const c_char) -> c_int;
    fn openlog(name: *const c_char, options: c_int, facility: c_int);
    fn strlist_add_tail(head: *mut c_void, text: *const c_char) -> bool;
    fn wf_getenv(name: *const c_char) -> *mut c_char;
    fn wf_chdir(path: *const c_char) -> c_int;
    fn wf_fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(file: *mut c_void) -> c_int;
    fn zapret_engine_realpath(text: *const c_char, path: *mut c_char, capacity: usize) -> u32;
    fn zapret_native_cli_kind(index: c_int, category: u32) -> c_int;
    fn zapret_cli_startup_touch(
        path: *const c_char,
        truncate: bool,
        open: FileOpen,
        close: FileClose,
    ) -> u32;
    fn zapret_cli_startup_cwd(path: *const c_char, chdir: Perror) -> u32;
    fn zapret_cli_startup_option(
        kind: u32,
        text: *const c_char,
        target: *const StartupTarget,
        ops: *const StartupOps,
        detail: *mut StartupDetail,
    ) -> u32;
    fn zapret_cli_startup_report(
        kind: u32,
        status: u32,
        text: *const c_char,
        argument_offset: u32,
        error: Log,
        stderr: Option<Log>,
        perror: Perror,
    ) -> c_int;
    fn zapret_cli_set_number(text: *const c_char, option: *const NumericOption) -> bool;
    fn zapret_cli_timeouts(
        text: *const c_char,
        syn: *mut u32,
        est: *mut u32,
        fin: *mut u32,
        udp: *mut u32,
    ) -> bool;
    fn zapret_native_cli_apply_numeric(
        index: c_int,
        text: *const c_char,
        target: *const NumericTarget,
        ops: *const NumericOps,
    ) -> c_int;
}

unsafe extern "C" fn startup_touch(path: *const c_char, truncate: bool) -> u32 {
    unsafe { zapret_cli_startup_touch(path, truncate, wf_fopen, fclose) }
}

unsafe extern "C" fn startup_cwd(path: *const c_char) -> u32 {
    unsafe { zapret_cli_startup_cwd(path, wf_chdir) }
}

unsafe extern "C" fn startup_syslog(options: c_int, facility: c_int) {
    // The active program name is read at the callback after mode publication.
    unsafe { openlog(progname, options, facility) }
}

const STARTUP_OPS: StartupOps = StartupOps {
    resolve: zapret_engine_realpath,
    touch: startup_touch,
    cwd: startup_cwd,
    environment: wf_getenv,
    syslog: startup_syslog,
    trace_directory: DLOG,
    append: strlist_add_tail,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn engine_startup_option(index: c_int, text: *const c_char) -> c_int {
    let selected = unsafe { zapret_native_cli_kind(index, 1) };
    if selected < 0 {
        return 0;
    }
    let kind = selected as u32;
    let text = if index == IDX_BUILTIN_RULES {
        builtin_init::BUILTIN_SCRIPT.as_ptr()
    } else {
        text
    };
    let params = params_address().cast::<Params>();
    let mut target = StartupTarget::default();
    unsafe {
        let path = match kind {
            0 => {
                target.debug = &raw mut (*params).debug;
                target.log_target = &raw mut (*params).debug_target;
                &raw mut (*params).debug_logfile
            }
            2 => &raw mut (*params).pidfile,
            3 => {
                target.enabled = &raw mut (*params).writable_dir_enable;
                &raw mut (*params).writable_dir
            }
            4 => {
                target.scripts = (&raw mut (*params).lua_init_scripts).cast();
                ptr::null_mut()
            }
            5 => &raw mut (*params).hostlist_auto_debuglog,
            _ => ptr::null_mut(),
        };
        if !path.is_null() {
            target.path = path.cast();
            target.capacity = PATH_CAPACITY;
        }
        let mut detail = StartupDetail::default();
        let status = zapret_cli_startup_option(kind, text, &target, &STARTUP_OPS, &mut detail);
        zapret_cli_startup_report(
            kind,
            status,
            text,
            detail.argument_offset,
            DLOG_ERR,
            None,
            DLOG_PERROR,
        )
    }
}

const IDX_INTERCEPT: c_int = 2;
const IDX_FUZZ: c_int = 3;
const IDX_DAEMON: c_int = 6;
const IDX_CTRACK_DISABLE: c_int = 10;
const IDX_SERVER: c_int = 12;
const IDX_IPCACHE_LIFETIME: c_int = 13;
const IDX_IPCACHE_HOSTNAME: c_int = 14;
const IDX_LUA_GC: c_int = 19;
const IDX_HOSTLIST_AUTO_FAIL_THRESHOLD: c_int = 25;
const IDX_HOSTLIST_AUTO_FAIL_TIME: c_int = 26;
const IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD: c_int = 27;
const IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ: c_int = 28;
const IDX_HOSTLIST_AUTO_RETRANS_RESET: c_int = 29;
const IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ: c_int = 30;
const IDX_HOSTLIST_AUTO_UDP_IN: c_int = 31;
const IDX_HOSTLIST_AUTO_UDP_OUT: c_int = 32;
const IDX_SSID_FILTER_NEG: c_int = 73;
const IDX_NLM_FILTER_NEG: c_int = 75;
const IDX_BUILTIN_RULES: c_int = 77;

const NUMERIC_OPS: NumericOps = NumericOps {
    number: zapret_cli_set_number,
    timeouts: zapret_cli_timeouts,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn engine_numeric_option(
    index: c_int,
    text: *const c_char,
    profile: *mut Profile,
) -> c_int {
    let params = params_address().cast::<Params>();
    unsafe {
        let mut target = NumericTarget {
            value: ptr::null_mut(),
            explicit: ptr::null_mut(),
            intercept: &raw mut (*params).intercept,
            timeouts: [
                &raw mut (*params).ctrack_t_syn,
                &raw mut (*params).ctrack_t_est,
                &raw mut (*params).ctrack_t_fin,
                &raw mut (*params).ctrack_t_udp,
            ],
        };
        target.value = match index {
            IDX_INTERCEPT => (&raw mut (*params).intercept).cast(),
            IDX_FUZZ => (&raw mut (*params).fuzz).cast(),
            IDX_DAEMON => (&raw mut (*params).daemon).cast(),
            IDX_CTRACK_DISABLE => (&raw mut (*params).ctrack_disable).cast(),
            IDX_SERVER => (&raw mut (*params).server).cast(),
            IDX_IPCACHE_HOSTNAME => (&raw mut (*params).cache_hostname).cast(),
            IDX_IPCACHE_LIFETIME => (&raw mut (*params).ipcache_lifetime).cast(),
            IDX_LUA_GC => (&raw mut (*params).lua_gc).cast(),
            IDX_HOSTLIST_AUTO_FAIL_THRESHOLD => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_fail_threshold;
                (&raw mut (*profile).hostlist_auto_fail_threshold).cast()
            }
            IDX_HOSTLIST_AUTO_FAIL_TIME => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_fail_time;
                (&raw mut (*profile).hostlist_auto_fail_time).cast()
            }
            IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_retrans_threshold;
                (&raw mut (*profile).hostlist_auto_retrans_threshold).cast()
            }
            IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_retrans_maxseq;
                (&raw mut (*profile).hostlist_auto_retrans_maxseq).cast()
            }
            IDX_HOSTLIST_AUTO_RETRANS_RESET => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_retrans_reset;
                (&raw mut (*profile).hostlist_auto_retrans_reset).cast()
            }
            IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_incoming_maxseq;
                (&raw mut (*profile).hostlist_auto_incoming_maxseq).cast()
            }
            IDX_HOSTLIST_AUTO_UDP_IN => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_udp_in;
                (&raw mut (*profile).hostlist_auto_udp_in).cast()
            }
            IDX_HOSTLIST_AUTO_UDP_OUT => {
                target.explicit = &raw mut (*profile).b_hostlist_auto_udp_out;
                (&raw mut (*profile).hostlist_auto_udp_out).cast()
            }
            IDX_SSID_FILTER_NEG => (&raw mut (*params).ssid_filter_neg).cast(),
            IDX_NLM_FILTER_NEG => (&raw mut (*params).nlm_filter_neg).cast(),
            _ => ptr::null_mut(),
        };
        zapret_native_cli_apply_numeric(index, text, &target, &NUMERIC_OPS)
    }
}
