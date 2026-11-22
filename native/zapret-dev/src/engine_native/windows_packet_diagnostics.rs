//! Bind the packet and TLS reporters to the Windows engine's live debug setting.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::{MaybeUninit, align_of, offset_of},
};

const DEBUG_OFFSET: usize = 4_252;
const PARAMS_SIZE: usize = 16_896;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Dump = unsafe extern "C" fn(*const u8, usize, usize);
type FindExtension =
    unsafe extern "C" fn(*const u8, usize, u16, *mut *const u8, *mut usize, bool) -> bool;

#[repr(C)]
struct Packet {
    _opaque: [u8; 0],
}

#[repr(C, align(8))]
struct Params {
    _before_debug: [MaybeUninit<u8>; DEBUG_OFFSET],
    debug: bool,
    _after_debug: [MaybeUninit<u8>; PARAMS_SIZE - DEBUG_OFFSET - size_of::<bool>()],
}

#[repr(C)]
struct TlsDebugOps {
    server_hello: unsafe extern "C" fn(*const u8, usize, bool) -> bool,
    find_extension: FindExtension,
    debug: Log,
    error: Log,
}

const _: () = {
    assert!(size_of::<Params>() == PARAMS_SIZE && align_of::<Params>() == 8);
    assert!(offset_of!(Params, debug) == DEBUG_OFFSET && size_of::<bool>() == 1);
    assert!(size_of::<TlsDebugOps>() == 32 && align_of::<TlsDebugOps>() == 8);
    assert!(offset_of!(TlsDebugOps, find_extension) == 8);
    assert!(offset_of!(TlsDebugOps, debug) == 16 && offset_of!(TlsDebugOps, error) == 24);
};

unsafe extern "C" {
    static mut params: Params;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn hexdump_limited_dlog(data: *const u8, length: usize, limit: usize);
    fn IsTLSHandshakeServerHello(data: *const u8, length: usize, partial: bool) -> bool;
    fn TLSFindExtInHandshake(
        data: *const u8,
        length: usize,
        kind: u16,
        extension: *mut *const u8,
        extension_length: *mut usize,
        partial: bool,
    ) -> bool;
    fn zapret_packet_debug_report(
        packet: *const Packet,
        replay: bool,
        enabled: bool,
        log: Log,
        dump: Dump,
    );
    fn zapret_tls_debug(
        record: bool,
        data: *const u8,
        length: usize,
        enabled: *const bool,
        ops: &TlsDebugOps,
    );
}

static TLS_DEBUG_OPS: TlsDebugOps = TlsDebugOps {
    server_hello: IsTLSHandshakeServerHello,
    find_extension: TLSFindExtInHandshake,
    debug: DLOG,
    error: DLOG_ERR,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn packet_debug(replay: bool, packet: *const Packet) {
    unsafe {
        zapret_packet_debug_report(
            packet,
            replay,
            (&raw const params.debug).read(),
            DLOG,
            hexdump_limited_dlog,
        );
    }
}

#[unsafe(export_name = "TLSDebugHandshake")]
unsafe extern "C" fn tls_debug_handshake(data: *const u8, length: usize) {
    unsafe { zapret_tls_debug(false, data, length, &raw const params.debug, &TLS_DEBUG_OPS) };
}

#[unsafe(export_name = "TLSDebug")]
unsafe extern "C" fn tls_debug(data: *const u8, length: usize) {
    // The record log can change the setting before the handshake starts.
    unsafe { zapret_tls_debug(true, data, length, &raw const params.debug, &TLS_DEBUG_OPS) };
}
