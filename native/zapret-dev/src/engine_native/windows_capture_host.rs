//! WinDivert observations and capture callbacks on Windows.
#![no_std]

mod windows_engine_fuzz;
mod windows_startup_params;
use windows_startup_params::PARAMS as LAYOUT;

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
};

const ADDRESS_COUNT: usize = 128;
const CAPTURE_IFNAME_CAPACITY: usize = 44;
const PASS: u8 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;

const OUTBOUND: u32 = 1 << 17;
const IMPOSTOR: u32 = 1 << 19;
const IPV6: u32 = 1 << 20;
const IP_CHECKSUM: u32 = 1 << 21;
const TCP_CHECKSUM: u32 = 1 << 22;
const UDP_CHECKSUM: u32 = 1 << 23;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

#[repr(C)]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    interface: u32,
    sub_interface: u32,
    data: [MaybeUninit<u8>; 56],
}

#[repr(C)]
struct Interface {
    index: u32,
    subindex: u32,
    outbound: bool,
}

#[repr(C)]
struct Observation {
    interface: Interface,
    ipv6: bool,
    ip_checksum: bool,
    tcp_checksum: bool,
    udp_checksum: bool,
}

#[repr(C)]
struct Plan {
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
}

#[repr(C)]
struct PacketOps {
    impostor: unsafe extern "C" fn(*const Address) -> bool,
    interface: unsafe extern "C" fn(*const Address, *mut Interface),
    debug: Log,
}

#[repr(C)]
struct ActivateOps {
    open: unsafe extern "C" fn(*const c_char) -> bool,
    sandbox: unsafe extern "C" fn() -> bool,
    console: Log,
    error: Log,
}

#[repr(C)]
struct Batch {
    length: usize,
    count: u32,
    error: u32,
}

#[repr(C)]
struct CaptureOps {
    register_signals: unsafe extern "C" fn(),
    network_ready: unsafe extern "C" fn() -> bool,
    quitting: unsafe extern "C" fn() -> bool,
    sleep_ms: unsafe extern "C" fn(u64),
    activate: unsafe extern "C-unwind" fn(*mut u32) -> bool,
    deactivate: unsafe extern "C" fn(),
    idle: unsafe extern "C-unwind" fn(),
    prepare: unsafe extern "C-unwind" fn(),
    receive: unsafe extern "C-unwind" fn(*mut Address, *mut u8, *mut Batch, *mut u64) -> u32,
    ipv6: unsafe extern "C" fn(*const Address, u32) -> bool,
    process: unsafe extern "C-unwind" fn(
        *const Address,
        u32,
        u32,
        *const u8,
        usize,
        *mut u8,
        *mut usize,
    ) -> u8,
    send: unsafe extern "C" fn(*const Address, u32, *const u8, usize) -> bool,
    report: unsafe extern "C" fn(u32, u32, usize, usize),
}

#[repr(C, align(8))]
struct Params {
    before_intercept: [MaybeUninit<u8>; LAYOUT.intercept],
    intercept: bool,
    before_fuzz: MaybeUninit<u8>,
    fuzz: u32,
    before_ssid: [MaybeUninit<u8>; LAYOUT.ssid_filter - LAYOUT.fuzz - 4],
    ssid: *const c_void,
    networks: *const c_void,
    ssid_negated: bool,
    networks_negated: bool,
    before_filter: [MaybeUninit<u8>; LAYOUT.capture_filter - LAYOUT.ssid_filter_neg - 2],
    filter: *const c_char,
    before_lua: [MaybeUninit<u8>; LAYOUT.lua - LAYOUT.capture_filter - size_of::<*const c_char>()],
    lua: *const c_void,
}

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<Address>() == 80 && align_of::<Address>() == 8);
    assert!(offset_of!(Address, interface) == 16 && offset_of!(Address, sub_interface) == 20);
    assert!(size_of::<Interface>() == 12 && size_of::<Observation>() == 16);
    assert!(size_of::<Plan>() == 3 * pointer && size_of::<PacketOps>() == 3 * pointer);
    assert!(size_of::<Batch>() == pointer + 8 && size_of::<CaptureOps>() == 13 * pointer);
    assert!(size_of::<ActivateOps>() == 4 * pointer && size_of::<Params>() == LAYOUT.size);
    assert!(
        offset_of!(Params, intercept) == LAYOUT.intercept
            && offset_of!(Params, fuzz) == LAYOUT.fuzz
    );
    assert!(
        offset_of!(Params, ssid) == LAYOUT.ssid_filter
            && offset_of!(Params, networks) == LAYOUT.network_filter
    );
    assert!(offset_of!(Params, ssid_negated) == LAYOUT.ssid_filter_neg);
    assert!(
        offset_of!(Params, filter) == LAYOUT.capture_filter
            && offset_of!(Params, lua) == LAYOUT.lua
    );
};

unsafe extern "C" {
    static mut params: Params;
    static w_win32_error: u32;
    fn catch_signals();
    fn logical_net_filter_match() -> bool;
    fn loop_quitting() -> bool;
    fn loop_sleep_ms(delay: u64);
    fn rawsend_cleanup();
    fn loop_report(event: u32, id: u32, length: usize, other: usize);
    fn windivert_init(filter: *const c_char) -> bool;
    fn win_sandbox() -> bool;
    fn windivert_send(packet: *const u8, length: usize, address: *const Address) -> bool;
    fn win_dark_init(
        wlan: *const *const c_void,
        wlan_negated: bool,
        network: *const *const c_void,
        network_negated: bool,
    ) -> bool;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn zapret_engine_activate_native(
        filter: *const c_char,
        intercept: *const bool,
        status: *const u32,
        error: *mut u32,
        ops: &ActivateOps,
    ) -> bool;
    fn zapret_engine_activate_next(phase: u32, succeeded: bool) -> u32;
    fn zapret_prepare_capture_packet(
        id: u32,
        length: usize,
        observation: &Observation,
        address: *const Address,
        ops: &PacketOps,
        name: *mut u8,
        capacity: usize,
        input: *mut Plan,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn zapret_capture_receive(
        addresses: *mut Address,
        packet: *mut u8,
        batch: *mut Batch,
        deadline: *mut u64,
    ) -> u32;
    fn NoInterceptLoop();
    fn loop_prepare();
    fn lua_init() -> bool;
    fn zapret_capture_loop(ops: &CaptureOps, addresses: *mut Address, intercept: bool) -> u32;
    fn dpi_desync_packet(
        mark: u32,
        inbound: *const c_char,
        outbound: *const c_char,
        packet: *const u8,
        length: usize,
        modified: *mut u8,
        modified_length: *mut usize,
    ) -> u8;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_boot_network() -> bool {
    unsafe {
        win_dark_init(
            &raw const params.ssid,
            params.ssid_negated,
            &raw const params.networks,
            params.networks_negated,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn native_boot_capture() -> c_int {
    let mut addresses = MaybeUninit::<[Address; ADDRESS_COUNT]>::uninit();
    unsafe { zapret_capture_loop(&OPS, addresses.as_mut_ptr().cast(), params.intercept) as c_int }
}

unsafe extern "C-unwind" fn activate(error: *mut u32) -> bool {
    const OPS: ActivateOps = ActivateOps {
        open: windivert_init,
        sandbox: win_sandbox,
        console: DLOG_CONDUP,
        error: DLOG_ERR,
    };
    unsafe {
        if !zapret_engine_activate_native(
            params.filter,
            &raw const params.intercept,
            &raw const w_win32_error,
            error,
            &OPS,
        ) {
            return false;
        }
        let mut phase = 0;
        let mut succeeded = false;
        loop {
            phase = zapret_engine_activate_next(phase, succeeded);
            match phase {
                1 => succeeded = !params.lua.is_null(),
                2 => succeeded = lua_init(),
                3 => {
                    error.write(ERROR_INVALID_PARAMETER);
                    return false;
                }
                4 => windows_engine_fuzz::run(),
                5 => return true,
                _ => return false,
            }
        }
    }
}

unsafe fn flag(address: *const Address, mask: u32) -> bool {
    unsafe { (*address).flags & mask != 0 }
}

unsafe fn interface(address: *const Address) -> Interface {
    unsafe {
        Interface {
            index: (*address).interface,
            subindex: (*address).sub_interface,
            outbound: flag(address, OUTBOUND),
        }
    }
}

unsafe extern "C" fn observe_impostor(address: *const Address) -> bool {
    unsafe { flag(address, IMPOSTOR) }
}

unsafe extern "C" fn observe_interface(address: *const Address, output: *mut Interface) {
    unsafe { output.write(interface(address)) };
}

unsafe extern "C" fn ipv6(addresses: *const Address, index: u32) -> bool {
    unsafe { flag(addresses.add(index as usize), IPV6) }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_native_capture_process(
    addresses: *const Address,
    index: u32,
    id: u32,
    packet: *const u8,
    length: usize,
    modified: *mut u8,
    modified_length: *mut usize,
) -> u8 {
    const PACKET_OPS: PacketOps = PacketOps {
        impostor: observe_impostor,
        interface: observe_interface,
        debug: DLOG,
    };
    let mut name = MaybeUninit::<[u8; CAPTURE_IFNAME_CAPACITY]>::uninit();
    let mut plan = MaybeUninit::<Plan>::uninit();
    unsafe {
        let address = addresses.add(index as usize);
        let observation = Observation {
            interface: interface(address),
            ipv6: flag(address, IPV6),
            ip_checksum: flag(address, IP_CHECKSUM),
            tcp_checksum: flag(address, TCP_CHECKSUM),
            udp_checksum: flag(address, UDP_CHECKSUM),
        };
        if !zapret_prepare_capture_packet(
            id,
            length,
            &observation,
            address,
            &PACKET_OPS,
            name.as_mut_ptr().cast(),
            CAPTURE_IFNAME_CAPACITY,
            plan.as_mut_ptr(),
        ) {
            return PASS;
        }
        let plan = plan.assume_init();
        dpi_desync_packet(
            plan.mark,
            plan.inbound,
            plan.outbound,
            packet,
            length,
            modified,
            modified_length,
        )
    }
}

unsafe extern "C" fn send(
    addresses: *const Address,
    index: u32,
    packet: *const u8,
    length: usize,
) -> bool {
    unsafe { windivert_send(packet, length, addresses.add(index as usize)) }
}

const OPS: CaptureOps = CaptureOps {
    register_signals: catch_signals,
    network_ready: logical_net_filter_match,
    quitting: loop_quitting,
    sleep_ms: loop_sleep_ms,
    activate,
    deactivate: rawsend_cleanup,
    idle: NoInterceptLoop,
    prepare: loop_prepare,
    receive: zapret_capture_receive,
    ipv6,
    process: zapret_native_capture_process,
    send,
    report: loop_report,
};
