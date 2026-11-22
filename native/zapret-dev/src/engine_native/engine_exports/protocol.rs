//! Keep the existing protocol entry and native logger.
use super::{DLOG, DLOG_ERR, Log};
use core::ffi::{c_char, c_void};
use core::ptr;

type Reporter = extern "C" fn(*const c_char);

unsafe extern "C" {
    fn zapret_tls_mod(
        options: *const c_void,
        payload: *const u8,
        payload_length: usize,
        output: *mut u8,
        length: *mut usize,
        capacity: usize,
        report: Option<Reporter>,
    ) -> bool;
    fn zapret_tls_report_applied(options: *const c_void, applied: bool, log: Log);
    fn zapret_ipv6_extension(data: *const u8, length: usize, protocol: u8) -> usize;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn proto_find_ip6_exthdr(data: *mut u8, length: usize, protocol: u8) -> *mut u8 {
    let offset = unsafe { zapret_ipv6_extension(data, length, protocol) };
    if offset == 0 {
        ptr::null_mut()
    } else {
        unsafe { data.add(offset) }
    }
}

extern "C" fn report(message: *const c_char) {
    unsafe { DLOG_ERR(c"%s".as_ptr(), message) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TLSMod(
    options: *const c_void,
    payload: *const u8,
    payload_length: usize,
    output: *mut u8,
    length: *mut usize,
    capacity: usize,
) -> bool {
    let applied = unsafe {
        zapret_tls_mod(
            options,
            payload,
            payload_length,
            output,
            length,
            capacity,
            Some(report),
        )
    };
    unsafe { zapret_tls_report_applied(options, applied, DLOG) };
    applied
}
