//! Hostname and incoming-TTL policy on top of the existing Rust IP indexes.
use crate::caches::IpItem;
#[cfg(windows)]
use crate::{address::zapret_address_ntopa46, native_logging_entry::LogSink};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::INET6_ADDRSTRLEN;

#[repr(C)]
struct Ops {
    find: unsafe extern "C" fn(*mut c_void) -> *mut IpItem,
    touch: unsafe extern "C" fn(*mut c_void) -> *mut IpItem,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_void),
    report: unsafe extern "C" fn(*mut c_void, u32, *const IpItem),
}

#[repr(C)]
struct Session {
    context: *mut c_void,
    ops: *const Ops,
    enabled: bool,
    server: bool,
}

#[repr(u32)]
enum Event {
    HostnameAllocationFailed,
    StoredHostname,
    SearchHostname,
    FoundHostname,
    TtlAllocationFailed,
    UpdatedTtl,
    FoundTtl,
}

#[cfg(windows)]
#[repr(C)]
struct Addresses {
    ipv4: *const u8,
    ipv6: *const u8,
}

#[cfg(windows)]
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_packet_cache_report(
    addresses: *const Addresses,
    event: u32,
    item: *const IpItem,
    debug_enabled: bool,
    debug: LogSink,
    error: LogSink,
) {
    if event > Event::FoundTtl as u32 {
        return;
    }
    // The native cache uses these consecutive Event discriminants.
    let event = unsafe { std::mem::transmute::<u32, Event>(event) };
    unsafe {
        match event {
            Event::HostnameAllocationFailed => {
                error(c"ipcache_put_hostname: out of memory\n".as_ptr());
            }
            Event::StoredHostname => {
                debug(
                    c"hostname cached (is_ip=%u): %s\n".as_ptr(),
                    u32::from((*item).hostname_is_ip),
                    (*item).hostname,
                );
            }
            Event::SearchHostname | Event::FoundHostname => {
                if !debug_enabled {
                    return;
                }
                let mut address = [0; INET6_ADDRSTRLEN as usize];
                zapret_address_ntopa46(
                    (*addresses).ipv4,
                    (*addresses).ipv6,
                    address.as_mut_ptr(),
                    address.len(),
                );
                if matches!(event, Event::FoundHostname) {
                    debug(
                        c"got cached hostname for %s : %s (is_ip=%u)\n".as_ptr(),
                        address.as_ptr(),
                        (*item).hostname,
                        u32::from((*item).hostname_is_ip),
                    );
                } else {
                    debug(
                        c"ipcache hostname search for %s\n".as_ptr(),
                        address.as_ptr(),
                    );
                }
            }
            Event::TtlAllocationFailed => {
                error(c"ipcache: out of memory\n".as_ptr());
            }
            Event::UpdatedTtl => {
                debug(c"updated ttl cache\n".as_ptr());
            }
            Event::FoundTtl => {
                debug(c"got cached ttl %u\n".as_ptr(), u32::from((*item).ttl));
            }
        }
    }
}

impl Session {
    unsafe fn report(&self, event: Event, item: *const IpItem) {
        unsafe { ((*self.ops).report)(self.context, event as u32, item) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cache_put_hostname(
    session: &Session,
    hostname: *const c_char,
    is_ip: bool,
) -> bool {
    if !session.enabled {
        return true;
    }
    let ops = unsafe { &*session.ops };
    let item = unsafe { (ops.touch)(session.context) };
    if item.is_null() {
        unsafe { session.report(Event::HostnameAllocationFailed, item) };
        return false;
    }
    let previous = unsafe { (*item).hostname };
    if previous.is_null() || unsafe { libc::strcmp(previous, hostname) != 0 } {
        // Both strings belong to the C runtime. Duplicate before releasing
        // the old value, keeping a previously usable entry on allocation failure.
        let replacement = unsafe { (ops.duplicate)(hostname) };
        if replacement.is_null() {
            unsafe { session.report(Event::HostnameAllocationFailed, item) };
            return false;
        }
        unsafe {
            (*item).hostname = replacement;
            (*item).hostname_is_ip = u8::from(is_ip);
            (ops.release)(previous.cast());
            session.report(Event::StoredHostname, item);
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cache_get_hostname(
    session: &Session,
    output: *mut c_char,
    capacity: usize,
    is_ip: *mut bool,
) -> bool {
    if capacity == 0 {
        return false;
    }
    if !session.enabled {
        unsafe { output.write(0) };
        return false;
    }
    unsafe { session.report(Event::SearchHostname, ptr::null()) };
    let item = unsafe { ((*session.ops).find)(session.context) };
    if item.is_null() || unsafe { (*item).hostname.is_null() } {
        unsafe { output.write(0) };
        return false;
    }
    unsafe { session.report(Event::FoundHostname, item) };
    let source = unsafe { (*item).hostname };
    let length = unsafe { CStr::from_ptr(source) }
        .to_bytes()
        .len()
        .min(capacity - 1);
    unsafe {
        ptr::copy(source, output, length);
        output.add(length).write(0);
        if !is_ip.is_null() {
            is_ip.write((*item).hostname_is_ip != 0);
        }
        output.read() != 0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cache_ttl(session: &Session, incoming: *mut u8, update: bool) {
    if incoming.is_null() || session.server {
        return;
    }
    let value = unsafe { incoming.read() };
    let ops = unsafe { &*session.ops };
    if update && value != 0 {
        let item = unsafe { (ops.touch)(session.context) };
        if item.is_null() {
            unsafe { session.report(Event::TtlAllocationFailed, item) };
        } else if unsafe { (*item).ttl } != value {
            unsafe {
                session.report(Event::UpdatedTtl, item);
                (*item).ttl = value;
            }
        }
    } else if value == 0 {
        let item = unsafe { (ops.find)(session.context) };
        if !item.is_null() && unsafe { (*item).ttl } != 0 {
            unsafe {
                session.report(Event::FoundTtl, item);
                incoming.write((*item).ttl);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_and_inactive_sessions_do_not_access_callbacks() {
        let inactive = Session {
            context: ptr::null_mut(),
            ops: ptr::null(),
            enabled: false,
            server: true,
        };
        let mut flag = true;
        unsafe {
            assert!(zapret_cache_put_hostname(&inactive, ptr::null(), false));
            assert!(!zapret_cache_get_hostname(
                &inactive,
                ptr::null_mut(),
                0,
                &mut flag
            ));
            let mut output = b'x' as c_char;
            assert!(!zapret_cache_get_hostname(
                &inactive,
                &mut output,
                1,
                &mut flag
            ));
            assert_eq!(output, 0);
            assert!(flag);
            zapret_cache_ttl(&inactive, ptr::null_mut(), true);
            zapret_cache_ttl(&inactive, ptr::dangling_mut(), true);
        }
    }
}
