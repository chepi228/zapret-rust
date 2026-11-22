//! WinDivert imports and live engine handle slots.
#![no_std]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

type Handle = *mut c_void;
type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Close = unsafe extern "C" fn(Handle);
type Submit = unsafe extern "C" fn(Handle, *const u8, u32, *const c_void) -> c_int;
type SubmitReceive =
    unsafe extern "C" fn(Handle, *mut u8, u32, *mut u32, *mut c_void, *mut u32, *mut c_void) -> u32;
type RawSend = unsafe extern "C" fn(*const u16, u32, *const c_char, *const c_void, usize) -> bool;

const ERROR_SUCCESS: u32 = 0;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const WSAESHUTDOWN: c_int = 10_058;
const LAYER_NETWORK: c_int = 0;
const SYSTEM_MESSAGE: u32 = 0x100 | 0x200 | 0x1000;
const AMERICAN_ENGLISH: u32 = 0x0409;

#[repr(C)]
struct Handles {
    open: unsafe extern "C" fn(*const c_char) -> Handle,
    close: Close,
    event: unsafe extern "C" fn() -> Handle,
}

#[repr(C)]
struct Diagnostics {
    message: unsafe extern "C" fn(u32) -> *mut c_char,
    log: Log,
    release: unsafe extern "C" fn(*mut c_char),
}

#[repr(C)]
struct Receive {
    timers: *const TimerOps,
    poll: unsafe extern "C" fn() -> u32,
    submit: SubmitReceive,
}

#[repr(C)]
struct TimerOps {
    opaque: [u8; 0],
}

#[repr(C)]
struct Batch {
    length: usize,
    count: u32,
    error: u32,
}

#[repr(C)]
struct Send {
    submit: Submit,
    invalid_interface: unsafe extern "C" fn(),
    error: Log,
}

const _: () = {
    let pointer = size_of::<Handle>();
    assert!(size_of::<Batch>() == pointer + 8);
    assert!(size_of::<Handles>() == 3 * pointer && size_of::<Diagnostics>() == 3 * pointer);
    assert!(size_of::<Receive>() == 3 * pointer && size_of::<Send>() == 3 * pointer);
};

static mut FILTER: Handle = ptr::null_mut();
static mut RECEIVE_EVENT: Handle = ptr::null_mut();

unsafe extern "C" {
    static mut w_win32_error: u32;
    static zapret_capture_timers: TimerOps;
    fn receive_poll() -> u32;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn _errno() -> *mut c_int;
    fn WinDivertOpen(filter: *const c_char, layer: c_int, priority: i16, flags: u64) -> Handle;
    fn WinDivertClose(handle: Handle) -> c_int;
    fn WinDivertRecvEx(
        handle: Handle,
        packet: *mut u8,
        capacity: u32,
        received: *mut u32,
        flags: u64,
        addresses: *mut c_void,
        address_bytes: *mut u32,
        overlapped: *mut c_void,
    ) -> c_int;
    fn WinDivertSend(
        handle: Handle,
        packet: *const u8,
        length: u32,
        sent: *mut u32,
        address: *const c_void,
    ) -> c_int;
    fn zapret_divert_activate(
        filter: *mut Handle,
        event: *mut Handle,
        error: *mut u32,
        condition: *const c_char,
        mutex: *const c_char,
        ops: &Handles,
    ) -> u32;
    fn zapret_divert_deactivate(filter: *mut Handle, event: *mut Handle, close: Close);
    fn zapret_divert_open_report(status: u32, error: *const u32, ops: &Diagnostics) -> bool;
    fn zapret_win_receive_report(
        status: u32,
        io_error: c_int,
        shutdown_error: c_int,
        log: Log,
    ) -> u32;
    fn zapret_divert_send(
        handle: Handle,
        packet: *const u8,
        length: usize,
        address: *const c_void,
        error: *mut u32,
        submit: Submit,
    ) -> bool;
    fn zapret_divert_rawsend(
        family: u16,
        interface: *const c_char,
        packet: *const c_void,
        length: usize,
        handle: *const Handle,
        error: *mut u32,
        ops: &Send,
    ) -> bool;
    fn zapret_rawsend_repeat(
        repeats: c_int,
        destination: *const u16,
        mark: u32,
        interface: *const c_char,
        packet: *const c_void,
        length: usize,
        send: RawSend,
    ) -> bool;
}

unsafe extern "C-unwind" {
    fn zapret_win_receive(
        ops: &Receive,
        filter: Handle,
        event: Handle,
        packet: *mut u8,
        addresses: *mut c_void,
        batch: *mut Batch,
        deadline: *mut u64,
    ) -> u32;
}

unsafe extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual: c_int,
        initial: c_int,
        name: *const u16,
    ) -> Handle;
    fn GetLastError() -> u32;
    fn FormatMessageA(
        flags: u32,
        source: *const c_void,
        error: u32,
        language: u32,
        output: *mut c_char,
        size: u32,
        arguments: *const c_void,
    ) -> u32;
    fn LocalFree(pointer: Handle) -> Handle;
}

unsafe extern "C" fn open_driver(filter: *const c_char) -> Handle {
    unsafe { WinDivertOpen(filter, LAYER_NETWORK, 0, 0) }
}

unsafe extern "C" fn close_driver(handle: Handle) {
    unsafe { WinDivertClose(handle) };
}

unsafe extern "C" fn create_event() -> Handle {
    unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) }
}

unsafe extern "C" fn error_message(error: u32) -> *mut c_char {
    let mut message: *mut c_char = ptr::null_mut();
    unsafe {
        FormatMessageA(
            SYSTEM_MESSAGE,
            ptr::null(),
            error,
            AMERICAN_ENGLISH,
            (&raw mut message).cast(),
            0,
            ptr::null(),
        )
    };
    message
}

unsafe extern "C" fn release_message(message: *mut c_char) {
    unsafe { LocalFree(message.cast()) };
}

#[unsafe(no_mangle)]
extern "C" fn rawsend_cleanup() {
    unsafe { zapret_divert_deactivate(&raw mut FILTER, &raw mut RECEIVE_EVENT, close_driver) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn windivert_init(filter: *const c_char) -> bool {
    const HANDLES: Handles = Handles {
        open: open_driver,
        close: close_driver,
        event: create_event,
    };
    const DIAGNOSTICS: Diagnostics = Diagnostics {
        message: error_message,
        log: DLOG_ERR,
        release: release_message,
    };
    unsafe {
        let status = zapret_divert_activate(
            &raw mut FILTER,
            &raw mut RECEIVE_EVENT,
            &raw mut w_win32_error,
            filter,
            c"Global\\winws_windivert_mutex".as_ptr(),
            &HANDLES,
        );
        zapret_divert_open_report(status, &raw const w_win32_error, &DIAGNOSTICS)
    }
}

unsafe extern "C" fn submit_receive(
    filter: Handle,
    packet: *mut u8,
    capacity: u32,
    received: *mut u32,
    addresses: *mut c_void,
    address_bytes: *mut u32,
    overlapped: *mut c_void,
) -> u32 {
    unsafe {
        if WinDivertRecvEx(
            filter,
            packet,
            capacity,
            received,
            0,
            addresses,
            address_bytes,
            overlapped,
        ) != 0
        {
            ERROR_SUCCESS
        } else {
            GetLastError()
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_capture_receive(
    addresses: *mut c_void,
    packet: *mut u8,
    batch: *mut Batch,
    deadline: *mut u64,
) -> u32 {
    const RECEIVE: Receive = Receive {
        timers: &raw const zapret_capture_timers,
        poll: receive_poll,
        submit: submit_receive,
    };
    unsafe {
        let status = zapret_win_receive(
            &RECEIVE,
            FILTER,
            RECEIVE_EVENT,
            packet,
            addresses,
            batch,
            deadline,
        );
        zapret_win_receive_report(status, EIO, WSAESHUTDOWN, DLOG_ERR)
    }
}

unsafe extern "C" fn submit_send(
    handle: Handle,
    data: *const u8,
    length: u32,
    address: *const c_void,
) -> c_int {
    unsafe { WinDivertSend(handle, data, length, ptr::null_mut(), address) }
}

unsafe extern "C" fn invalid_interface() {
    unsafe { _errno().write(EINVAL) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn windivert_send(
    data: *const u8,
    length: usize,
    address: *const c_void,
) -> bool {
    unsafe {
        zapret_divert_send(
            FILTER,
            data,
            length,
            address,
            &raw mut w_win32_error,
            submit_send,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawsend(
    destination: *const u16,
    _mark: u32,
    interface: *const c_char,
    data: *const c_void,
    length: usize,
) -> bool {
    const SEND: Send = Send {
        submit: submit_send,
        invalid_interface,
        error: DLOG_ERR,
    };
    unsafe {
        zapret_divert_rawsend(
            destination.read(),
            interface,
            data,
            length,
            &raw const FILTER,
            &raw mut w_win32_error,
            &SEND,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rawsend_rep(
    repeats: c_int,
    destination: *const u16,
    mark: u32,
    interface: *const c_char,
    data: *const c_void,
    length: usize,
) -> bool {
    unsafe { zapret_rawsend_repeat(repeats, destination, mark, interface, data, length, rawsend) }
}
