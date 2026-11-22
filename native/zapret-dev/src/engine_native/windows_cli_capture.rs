//! Bind the Windows capture option catalog to the engine's CLI storage.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
};

type Head = *mut *mut c_void;
type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Perror = unsafe extern "C" fn(*const c_char) -> c_int;
type Render = unsafe extern "C" fn(
    *const c_char,
    u32,
    *const c_char,
    *const c_char,
    *mut c_char,
    usize,
) -> bool;
type Numeric = unsafe extern "C" fn(*const c_char, *const c_void) -> bool;

#[cfg(zapret_engine_production)]
mod windows_capture_preflight;
mod windows_startup_params;
use windows_startup_params::PARAMS as LAYOUT;

const CAPTURE_CATEGORY: u32 = 4;
const WF_TCP_IN: usize = 0;
const WF_UDP_IN: usize = 1;
const WF_TCP_OUT: usize = 2;
const WF_UDP_OUT: usize = 3;
const WF_ICMP_IN: usize = 4;
const WF_ICMP_OUT: usize = 5;
const WF_IPP_IN: usize = 6;
const WF_IPP_OUT: usize = 7;
const WF_RAWF_PART: usize = 9;
const WF_RAWF_FILTER: usize = 10;
const GLOBAL_SSID_FILTER: usize = 11;
const GLOBAL_SSID_FILTER_NEG: usize = 12;
const GLOBAL_NLM_FILTER: usize = 13;
const GLOBAL_NLM_FILTER_NEG: usize = 14;
const WF_RAWF: usize = 15;

#[repr(C)]
pub struct CaptureCli {
    save: *mut c_char,
    save_capacity: usize,
    ipv4: *mut bool,
    ipv6: *mut bool,
    lan: *mut bool,
    loopback: *mut bool,
    empty: *mut bool,
    duplicate: *mut bool,
    index: *mut u32,
    sub_index: *mut u32,
    hashes: *mut u32,
}

#[repr(C)]
struct Params {
    _prefix: [MaybeUninit<u8>; LAYOUT.intercept],
    intercept: bool,
    _before_ssid: [MaybeUninit<u8>; LAYOUT.ssid_filter - LAYOUT.intercept - 1],
    ssid_filter: *mut c_void,
    nlm_filter: *mut c_void,
    ssid_filter_neg: bool,
    nlm_filter_neg: bool,
    wf_raw_part: *mut c_void,
    windivert_filter: *mut c_char,
    wf_pf_tcp_src_in: *mut c_char,
    wf_pf_tcp_dst_in: *mut c_char,
    wf_pf_udp_src_in: *mut c_char,
    wf_pf_udp_dst_in: *mut c_char,
    wf_pf_tcp_src_out: *mut c_char,
    wf_pf_tcp_dst_out: *mut c_char,
    wf_pf_udp_src_out: *mut c_char,
    wf_pf_udp_dst_out: *mut c_char,
    wf_icf_in: *mut c_char,
    wf_icf_out: *mut c_char,
    wf_ipf_in: *mut c_char,
    wf_ipf_out: *mut c_char,
    wf_raw_filter: *mut c_char,
    _before_server: [MaybeUninit<u8>; LAYOUT.server - LAYOUT.pidfile],
    server: bool,
}

#[derive(Default)]
#[repr(C)]
struct Target {
    first: *mut c_void,
    second: *mut c_void,
    capacity: usize,
    hash: *mut u32,
    secondary_hash: *mut u32,
    collection: Head,
}

#[repr(C)]
struct Ops {
    render: Render,
    versions: unsafe extern "C" fn(*const c_char, *mut bool, *mut bool) -> bool,
    read: unsafe extern "C" fn(*const c_char, i64, *mut c_void, *mut usize) -> u32,
    append: unsafe extern "C" fn(Head, *const c_char) -> bool,
    strings: unsafe extern "C" fn(*const c_char, Head) -> bool,
    number: unsafe extern "C" fn(*const c_char, *mut bool) -> bool,
    networks: unsafe extern "C" fn(bool) -> bool,
}

#[repr(C)]
struct CaptureResult {
    status: u32,
    error: u32,
}

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(
        size_of::<CaptureCli>() == 11 * pointer && offset_of!(CaptureCli, hashes) == 10 * pointer
    );
    assert!(offset_of!(CaptureCli, index) == 8 * pointer);
    assert!(offset_of!(CaptureCli, save_capacity) == pointer);
    assert!(offset_of!(Params, ssid_filter) == LAYOUT.ssid_filter);
    assert!(offset_of!(Params, nlm_filter) == LAYOUT.network_filter);
    assert!(offset_of!(Params, ssid_filter_neg) == LAYOUT.ssid_filter_neg);
    assert!(offset_of!(Params, nlm_filter_neg) == LAYOUT.ssid_filter_neg + 1);
    assert!(offset_of!(Params, wf_raw_part) == LAYOUT.raw_filter_parts);
    assert!(offset_of!(Params, windivert_filter) == LAYOUT.capture_filter);
    assert!(
        offset_of!(Params, wf_pf_tcp_src_in) == LAYOUT.first_filter_buffer
            && offset_of!(Params, wf_raw_filter) == LAYOUT.first_filter_buffer + 12 * pointer
    );
    assert!(
        offset_of!(Params, intercept) == LAYOUT.intercept
            && offset_of!(Params, server) == LAYOUT.server
    );
    assert!(size_of::<Target>() == 6 * pointer && size_of::<Ops>() == 7 * pointer);
    assert!(size_of::<CaptureResult>() == 8);
};

unsafe extern "C" {
    static mut params: Params;
    fn zapret_native_cli_kind(index: c_int, category: u32) -> c_int;
    fn zapret_native_cli_option_name(index: c_int) -> *const c_char;
    fn zapret_native_cli_capacity(index: c_int) -> usize;

    fn zapret_filter_clauses(
        text: *const c_char,
        kind: u32,
        protocol: *const c_char,
        field: *const c_char,
        output: *mut c_char,
        capacity: usize,
    ) -> bool;
    fn zapret_filter_ip_versions(text: *const c_char, ipv4: *mut bool, ipv6: *mut bool) -> bool;
    fn zapret_engine_load_file(
        path: *const c_char,
        offset: i64,
        output: *mut c_void,
        length: *mut usize,
    ) -> u32;
    fn strlist_add(head: Head, text: *const c_char) -> bool;
    fn parse_strlist(text: *mut c_char, head: Head) -> bool;
    fn zapret_cli_set_number(text: *const c_char, option: *const c_void) -> bool;
    fn zapret_cli_set_boolean(text: *const c_char, slot: *mut bool, parse: Numeric) -> bool;
    fn nlm_list(all: bool) -> bool;
    fn wf_error(error: u32);
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn DLOG_PERROR(text: *const c_char) -> c_int;

    fn zapret_cli_capture_option(
        kind: u32,
        text: *const c_char,
        target: &Target,
        ops: &Ops,
    ) -> CaptureResult;
    fn zapret_cli_capture_report(
        result: CaptureResult,
        name: *const c_char,
        publish: unsafe extern "C" fn(u32),
        log: Log,
        perror: Perror,
    ) -> c_int;
}

unsafe extern "C" fn capture_strings(text: *const c_char, head: Head) -> bool {
    unsafe { parse_strlist(text.cast_mut(), head) }
}

unsafe extern "C" fn capture_boolean(text: *const c_char, value: *mut bool) -> bool {
    unsafe { zapret_cli_set_boolean(text, value, zapret_cli_set_number) }
}

const OPS: Ops = Ops {
    render: zapret_filter_clauses,
    versions: zapret_filter_ip_versions,
    read: zapret_engine_load_file,
    append: strlist_add,
    strings: capture_strings,
    number: capture_boolean,
    networks: nlm_list,
};

unsafe fn hash_slot(state: *mut CaptureCli, index: usize) -> *mut u32 {
    unsafe { (*state).hashes.add(index) }
}

/// # Safety
/// The option text and parser state use the engine's live Windows CLI storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn engine_capture_option(
    index: c_int,
    text: *const c_char,
    state: *mut CaptureCli,
) -> c_int {
    let kind = unsafe { zapret_native_cli_kind(index, CAPTURE_CATEGORY) };
    if kind < 0 {
        return 0;
    }
    unsafe {
        let name = zapret_native_cli_option_name(index);
        let mut target = Target {
            capacity: zapret_native_cli_capacity(index),
            ..Target::default()
        };
        match kind {
            0 => {
                target.first = (*state).index.cast();
                target.second = (*state).sub_index.cast();
            }
            1 => {
                target.first = (*state).ipv4.cast();
                target.second = (*state).ipv6.cast();
            }
            2 => {
                target.first = params.wf_pf_tcp_src_in.cast();
                target.second = params.wf_pf_tcp_dst_in.cast();
                target.hash = hash_slot(state, WF_TCP_IN);
            }
            3 => {
                target.first = params.wf_pf_tcp_src_out.cast();
                target.second = params.wf_pf_tcp_dst_out.cast();
                target.hash = hash_slot(state, WF_TCP_OUT);
            }
            4 => {
                target.first = params.wf_pf_udp_src_in.cast();
                target.second = params.wf_pf_udp_dst_in.cast();
                target.hash = hash_slot(state, WF_UDP_IN);
            }
            5 => {
                target.first = params.wf_pf_udp_src_out.cast();
                target.second = params.wf_pf_udp_dst_out.cast();
                target.hash = hash_slot(state, WF_UDP_OUT);
            }
            6 => {
                target.first = params.wf_icf_in.cast();
                target.hash = hash_slot(state, WF_ICMP_IN);
            }
            7 => {
                target.first = params.wf_icf_out.cast();
                target.hash = hash_slot(state, WF_ICMP_OUT);
            }
            8 => {
                target.first = params.wf_ipf_in.cast();
                target.hash = hash_slot(state, WF_IPP_IN);
            }
            9 => {
                target.first = params.wf_ipf_out.cast();
                target.hash = hash_slot(state, WF_IPP_OUT);
            }
            10 => {
                target.first = params.windivert_filter.cast();
                target.hash = hash_slot(state, WF_RAWF);
            }
            11 => {
                target.collection = &raw mut params.wf_raw_part;
                target.hash = hash_slot(state, WF_RAWF_PART);
            }
            12 => {
                target.first = params.wf_raw_filter.cast();
                target.hash = hash_slot(state, WF_RAWF_FILTER);
                target.secondary_hash = hash_slot(state, WF_RAWF);
            }
            13 => target.first = (*state).empty.cast(),
            14 => target.first = (*state).lan.cast(),
            15 => target.first = (*state).loopback.cast(),
            16 => {
                target.first = (*state).save.cast();
                target.capacity = (*state).save_capacity;
            }
            17 => target.first = (*state).duplicate.cast(),
            18 => {
                target.collection = &raw mut params.ssid_filter;
                target.hash = hash_slot(state, GLOBAL_SSID_FILTER);
            }
            19 => {
                target.first = (&raw mut params.ssid_filter_neg).cast();
                target.hash = hash_slot(state, GLOBAL_SSID_FILTER_NEG);
            }
            20 => {
                target.collection = &raw mut params.nlm_filter;
                target.hash = hash_slot(state, GLOBAL_NLM_FILTER);
            }
            21 => {
                target.first = (&raw mut params.nlm_filter_neg).cast();
                target.hash = hash_slot(state, GLOBAL_NLM_FILTER_NEG);
            }
            22 => (),
            _ => return 0,
        }
        let result = zapret_cli_capture_option(kind as u32, text, &target, &OPS);
        zapret_cli_capture_report(result, name, wf_error, DLOG_ERR, DLOG_PERROR)
    }
}
