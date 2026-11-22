//! Bind the Win32 network observations to the capture loop.
#![no_std]

use core::{
    ffi::{c_int, c_void},
    ptr,
    sync::atomic::{AtomicI32, Ordering},
};

type Environment = *mut c_void;
type List = *const *const c_void;

#[repr(C)]
struct Binding {
    environment: *mut Environment,
    wlan: *mut List,
    network: *mut List,
    wlan_negated: *mut bool,
    network_negated: *mut bool,
    error: *mut u32,
    reset: extern "C" fn(),
}

#[repr(C)]
struct Snapshot {
    second: u64,
    error: u32,
    checked: bool,
    allowed: bool,
}

#[repr(C)]
struct Queries {
    wlan: extern "C" fn() -> u32,
    network: extern "C" fn() -> u32,
}

#[derive(Default)]
#[repr(C)]
struct Poll {
    phase: u32,
    status: u32,
}

#[derive(Default)]
#[repr(C)]
struct Feedback {
    quitting: bool,
    network: bool,
}

const _: () = {
    let pointer = size_of::<Environment>();
    assert!(size_of::<Binding>() == 7 * pointer && size_of::<Queries>() == 2 * pointer);
    assert!(size_of::<Snapshot>() == 16 && core::mem::offset_of!(Snapshot, checked) == 12);
    assert!(size_of::<Poll>() == 8 && size_of::<Feedback>() == 2);
};

unsafe extern "C" {
    static mut w_win32_error: u32;
    static bQuit: AtomicI32;
    fn zapret_network_unbind(binding: &Binding);
    fn zapret_network_bind(
        binding: &Binding,
        wlan: List,
        wlan_negated: bool,
        network: List,
        network_negated: bool,
    ) -> bool;
    fn zapret_network_bind_present(binding: &Binding) -> bool;
    fn zapret_network_environment_wlan(
        environment: Environment,
        list: List,
        error: *mut u32,
    ) -> bool;
    fn zapret_network_environment_nlm(
        environment: Environment,
        list: List,
        error: *mut u32,
    ) -> bool;
    fn zapret_network_observation(is_hresult: bool, matched: bool, status: u32) -> u32;
    fn zapret_network_gate(
        snapshot: *mut Snapshot,
        ticks: u64,
        refresh: bool,
        wlan_negated: bool,
        network_negated: bool,
        error: *mut u32,
        queries: &Queries,
    ) -> bool;
    fn zapret_capture_poll_step(flow: &mut Poll, feedback: &Feedback) -> u32;
    fn usleep(delay: u32) -> c_int;
}

unsafe extern "system" {
    fn GetTickCount64() -> u64;
}

const EMPTY: Snapshot = Snapshot {
    second: 0,
    error: 0,
    checked: false,
    allowed: false,
};

static mut ENVIRONMENT: Environment = ptr::null_mut();
static mut WLAN: List = ptr::null();
static mut NETWORK: List = ptr::null();
static mut WLAN_NEGATED: bool = false;
static mut NETWORK_NEGATED: bool = false;
static mut SNAPSHOT: Snapshot = EMPTY;

const BINDING: Binding = Binding {
    environment: &raw mut ENVIRONMENT,
    wlan: &raw mut WLAN,
    network: &raw mut NETWORK,
    wlan_negated: &raw mut WLAN_NEGATED,
    network_negated: &raw mut NETWORK_NEGATED,
    error: &raw mut w_win32_error,
    reset,
};

extern "C" fn reset() {
    unsafe { (&raw mut SNAPSHOT).write(EMPTY) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn win_dark_init(
    wlan: List,
    wlan_negated: bool,
    network: List,
    network_negated: bool,
) -> bool {
    unsafe { zapret_network_bind(&BINDING, wlan, wlan_negated, network, network_negated) }
}

#[unsafe(no_mangle)]
extern "C" fn win_dark_deinit() {
    unsafe { zapret_network_unbind(&BINDING) };
}

#[unsafe(no_mangle)]
extern "C" fn logical_net_filter_present() -> bool {
    unsafe { zapret_network_bind_present(&BINDING) }
}

extern "C" fn observe_wlan() -> u32 {
    unsafe {
        let matched = zapret_network_environment_wlan(ENVIRONMENT, WLAN, &raw mut w_win32_error);
        zapret_network_observation(false, matched, w_win32_error)
    }
}

extern "C" fn observe_network() -> u32 {
    unsafe {
        let matched = zapret_network_environment_nlm(ENVIRONMENT, NETWORK, &raw mut w_win32_error);
        zapret_network_observation(true, matched, w_win32_error)
    }
}

fn check_network(refresh: bool) -> bool {
    const QUERIES: Queries = Queries {
        wlan: observe_wlan,
        network: observe_network,
    };
    unsafe {
        zapret_network_gate(
            &raw mut SNAPSHOT,
            GetTickCount64(),
            refresh,
            WLAN_NEGATED,
            NETWORK_NEGATED,
            &raw mut w_win32_error,
            &QUERIES,
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn logical_net_filter_match() -> bool {
    check_network(true)
}

#[unsafe(no_mangle)]
extern "C" fn receive_poll() -> u32 {
    let mut flow = Poll::default();
    let mut value = Feedback::default();
    loop {
        match unsafe { zapret_capture_poll_step(&mut flow, &value) } {
            1 => {
                unsafe { usleep(0) };
            }
            2 => value.quitting = unsafe { bQuit.load(Ordering::SeqCst) != 0 },
            3 => value.network = check_network(false),
            4 => return flow.status,
            _ => return 3, // ZAPRET_QUIT
        }
    }
}
