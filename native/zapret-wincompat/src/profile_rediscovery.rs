//! Profile reselection after a connection reveals its hostname or L7 protocol.
use crate::{
    logging::LogSink,
    play_prolog::PlayState,
    profile_config::{profile_has_automatic_hosts, profile_hosts_empty},
    protocol::{l7payload_str, l7proto_str},
};

use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

const UNKNOWN_L7: u32 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct HostCheck {
    done: bool,
    result: bool,
    excluded: bool,
}

// Contiguous fields beginning at t_ctrack.dp. Only named fields are accessed.
// The C adapter checks offsets and owns the record and hostname allocation.
#[repr(C)]
pub(super) struct Connection {
    pub(super) profile: *mut c_void,
    pub(super) search_complete: bool,
    pub(super) retransmissions: u8,
    pub(super) failure_finalized: bool,
    pub(super) incoming_ttl: u8,
    cutoff: bool,
    pub(super) lua_in_cutoff: bool,
    pub(super) lua_out_cutoff: bool,
    pub(super) l7: u32,
    l7_discovered: bool,
    pub(super) hostname: *mut c_char,
    pub(super) hostname_is_ip: bool,
    hostname_discovered: bool,
    pub(super) auto_check: bool,
    pub(super) lua_state: i32,
    pub(super) instance_cutoff: i32,
}

#[repr(C)]
struct Session {
    context: *mut c_void,
    profile: *mut *mut c_void,
    connection: *mut Connection,
    checks: *mut HostCheck,
    host: *mut c_char,
    l7: u32,
    protocol: u8,
    have_host: bool,
}

enum Event {
    Hostname,
    DiscoveredL7,
    DiscoveredHostname,
    AllocationFailed,
    ClearIncomingCutoff,
    ClearOutgoingCutoff,
    ProfileChanged,
    NegativeHostCheck,
}

unsafe fn report_endpoints(state: *const PlayState, ops: &Ops) {
    let mut source = [0; 48];
    let mut destination = [0; 48];
    let direction = |reverse| {
        if reverse {
            c"in".as_ptr()
        } else {
            c"out".as_ptr()
        }
    };
    unsafe {
        (ops.format_endpoint)(
            ptr::addr_of!((*state).source).cast(),
            source.as_mut_ptr(),
            source.len(),
        );
        (ops.format_endpoint)(
            ptr::addr_of!((*state).destination).cast(),
            destination.as_mut_ptr(),
            destination.len(),
        );
        (ops.log)(
            c"dpi desync src=%s dst=%s track_direction=%s fixed_direction=%s connection_proto=%s payload_type=%s\n".as_ptr(),
            source.as_ptr(), destination.as_ptr(), direction((*state).reverse), direction((*state).reverse_fixed),
            l7proto_str((*state).l7), l7payload_str((*state).payload_kind),
        );
    }
}

#[repr(C)]
struct Ops {
    normalize: unsafe extern "C" fn(*mut c_char) -> bool,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_void),
    cache: unsafe extern "C" fn(*mut c_void, *const c_char, bool) -> bool,
    find: unsafe extern "C" fn(*mut c_void, *const c_char, bool, *mut HostCheck) -> *mut c_void,
    check_host: unsafe extern "C" fn(*const c_void, *const c_char, bool, *mut bool, bool) -> bool,
    udp_failure: unsafe extern "C" fn(*mut c_void),
    log: LogSink,
    error: LogSink,
    format_endpoint: unsafe extern "C" fn(*const c_void, *mut c_char, usize),
    debug_enabled: *const bool,
}

impl Session {
    unsafe fn report(&self, ops: &Ops, event: Event) {
        let log = ops.log;
        unsafe {
            match event {
                Event::Hostname => log(c"hostname: %s\n".as_ptr(), self.host.cast_const()),
                Event::DiscoveredL7 => log(c"discovered l7 protocol\n".as_ptr()),
                Event::DiscoveredHostname => log(c"discovered hostname\n".as_ptr()),
                Event::AllocationFailed => (ops.error)(c"hostname dup : out of memory".as_ptr()),
                Event::ClearIncomingCutoff => {
                    log(c"clearing lua in cutoff because of profile change\n".as_ptr())
                }
                Event::ClearOutgoingCutoff => {
                    log(c"clearing lua out cutoff because of profile change\n".as_ptr())
                }
                Event::ProfileChanged => {
                    log(c"desync profile changed by revealed l7 protocol or hostname !\n".as_ptr())
                }
                Event::NegativeHostCheck => log(
                    c"not applying tampering because of previous negative hostlist check\n"
                        .as_ptr(),
                ),
            };
        }
    }

    unsafe fn store_checks(&self, checks: HostCheck) {
        if !self.connection.is_null() {
            unsafe { self.checks.write(checks) };
        }
    }

    unsafe fn discover_hostname(&self, ops: &Ops, is_ip: bool) -> bool {
        let connection = self.connection;
        let previous = unsafe { (*connection).hostname };
        let same =
            !previous.is_null() && unsafe { CStr::from_ptr(previous) == CStr::from_ptr(self.host) };
        let hostname = if same {
            previous
        } else {
            unsafe { (ops.duplicate)(self.host) }
        };
        if hostname.is_null() {
            unsafe { self.report(ops, Event::AllocationFailed) };
            return false;
        }
        if !unsafe { (ops.cache)(self.context, self.host, is_ip) } {
            if !same {
                unsafe { (ops.release)(hostname.cast()) };
            }
            return false;
        }
        // Commit after both fallible operations. A later packet can retry
        // discovery without losing the hostname previously obtained from cache.
        unsafe {
            (*connection).hostname = hostname;
            (*connection).hostname_is_ip = is_ip;
            (*connection).hostname_discovered = true;
            if !same {
                (ops.release)(previous.cast());
            }
        }
        true
    }

    unsafe fn profile_changed(&self, ops: &Ops) {
        let connection = self.connection;
        if !connection.is_null() {
            unsafe {
                if (*connection).lua_in_cutoff {
                    self.report(ops, Event::ClearIncomingCutoff);
                    (*connection).lua_in_cutoff = false;
                }
                if (*connection).lua_out_cutoff {
                    self.report(ops, Event::ClearOutgoingCutoff);
                    (*connection).lua_out_cutoff = false;
                }
            }
        }
        unsafe { self.report(ops, Event::ProfileChanged) };
    }
}

// C owns a live play_state and optional connection throughout this call.
// Callbacks run with no Rust borrow of those records or their hostname storage.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_rediscover(session: &Session, ops: &Ops) -> bool {
    let connection = session.connection;
    let is_ip = if session.have_host {
        let is_ip = unsafe { (ops.normalize)(session.host) };
        unsafe { session.report(ops, Event::Hostname) };
        is_ip
    } else {
        false
    };
    let discovered_l7 = if connection.is_null() {
        session.l7 != UNKNOWN_L7
    } else {
        unsafe { !(*connection).l7_discovered && (*connection).l7 != UNKNOWN_L7 }
    };
    if discovered_l7 {
        unsafe { session.report(ops, Event::DiscoveredL7) };
    }
    let discovered_hostname = session.have_host
        && (connection.is_null() || unsafe { !(*connection).hostname_discovered });
    if discovered_hostname {
        unsafe { session.report(ops, Event::DiscoveredHostname) };
        if !connection.is_null() && !unsafe { session.discover_hostname(ops, is_ip) } {
            return false;
        }
    }
    if discovered_l7 && !connection.is_null() {
        unsafe { (*connection).l7_discovered = true };
    }
    let mut checks = if connection.is_null() {
        HostCheck::default()
    } else {
        unsafe { session.checks.read() }
    };
    if discovered_l7 || discovered_hostname {
        let (hostname, hostname_is_ip) = if !connection.is_null() {
            unsafe {
                (
                    (*connection).hostname.cast_const(),
                    (*connection).hostname_is_ip,
                )
            }
        } else if session.have_host {
            (session.host.cast_const(), is_ip)
        } else {
            (ptr::null(), is_ip)
        };
        let previous = unsafe { session.profile.read() };
        let profile = unsafe { (ops.find)(session.context, hostname, hostname_is_ip, &mut checks) };
        unsafe {
            session.profile.write(profile);
            if !connection.is_null() {
                (*connection).profile = profile;
                (*connection).search_complete = true;
            }
            session.store_checks(checks);
        }
        if profile.is_null() {
            return false;
        }
        if profile != previous {
            unsafe { session.profile_changed(ops) };
        }
    }
    if session.have_host {
        let profile = unsafe { session.profile.read() };
        let hosts_empty = unsafe { profile_hosts_empty(profile) };
        let automatic = unsafe { profile_has_automatic_hosts(profile) };
        if !hosts_empty {
            if !checks.done {
                checks.result = unsafe {
                    (ops.check_host)(profile, session.host, is_ip, &mut checks.excluded, false)
                };
                checks.done = true;
                unsafe { session.store_checks(checks) };
            }
            if !connection.is_null() {
                unsafe {
                    if !checks.result {
                        (*connection).auto_check = automatic && !checks.excluded;
                    } else if session.protocol == TCP && (*connection).auto_check {
                        (*connection).retransmissions = u8::MAX;
                    }
                }
            }
        }
    }
    if !connection.is_null() && session.protocol == UDP {
        unsafe { (ops.udp_failure)(session.context) };
    }
    if checks.done && !checks.result {
        unsafe { session.report(ops, Event::NegativeHostCheck) };
        return false;
    }
    if unsafe { ops.debug_enabled.read() } {
        unsafe { report_endpoints(session.context.cast(), ops) };
    }
    true
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{offset_of, size_of};

    assert!(size_of::<HostCheck>() == 3);
    assert!(offset_of!(Connection, search_complete) == 8);
    assert!(offset_of!(Connection, retransmissions) == 9);
    assert!(offset_of!(Connection, lua_in_cutoff) == 13);
    assert!(offset_of!(Connection, lua_out_cutoff) == 14);
    assert!(offset_of!(Connection, l7) == 16);
    assert!(offset_of!(Connection, l7_discovered) == 20);
    assert!(offset_of!(Connection, hostname) == 24);
    assert!(offset_of!(Connection, hostname_is_ip) == 32);
    assert!(offset_of!(Connection, hostname_discovered) == 33);
    assert!(offset_of!(Connection, auto_check) == 34);
    assert!(size_of::<Session>() == 48);
    assert!(offset_of!(Session, l7) == 40);
    assert!(offset_of!(Session, protocol) == 44);
    assert!(size_of::<Ops>() == 88 && offset_of!(Ops, format_endpoint) == 72);
};
