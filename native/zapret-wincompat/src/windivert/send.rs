//! Validate and submit outgoing packets for the Windows capture engine.
use crate::{filters::decimal_prefix, logging::LogSink, packet_queue::RawSend};
use std::{
    ffi::{CStr, c_char, c_void},
    mem::MaybeUninit,
};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError, HANDLE, SetLastError};

const IPV6: u16 = 23;
const OUTBOUND: u32 = 1 << 17;
const ADDRESS_IPV6: u32 = 1 << 20;
const CHECKSUM_FLAGS: u32 = (1 << 21) | (1 << 22) | (1 << 23);

#[repr(C)]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    interface: u32,
    sub_interface: u32,
    network_reserved: [u8; 56],
}

fn interface_id(text: &[u8]) -> Option<(u32, u32)> {
    if text.is_empty() {
        return Some((1, 0));
    }
    let (index, tail) = decimal_prefix(text)?;
    let (sub_interface, _) = decimal_prefix(tail.strip_prefix(b".")?)?;
    // Preserve the scanf prefix grammar used by the legacy pseudo-interface
    // text. Both numeric values have already been checked for overflow.
    Some((index, sub_interface))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_address(
    family: u16,
    interface: *const c_char,
    output: *mut Address,
) -> bool {
    let interface = if interface.is_null() {
        &[]
    } else {
        unsafe { CStr::from_ptr(interface) }.to_bytes()
    };
    let Some((interface, sub_interface)) = interface_id(interface) else {
        return false;
    };
    let flags = OUTBOUND | CHECKSUM_FLAGS | if family == IPV6 { ADDRESS_IPV6 } else { 0 };
    unsafe {
        output.write(Address {
            timestamp: 0,
            flags,
            reserved: 0,
            interface,
            sub_interface,
            network_reserved: [0; 56],
        });
    }
    true
}

type Submit = unsafe extern "C" fn(HANDLE, *const u8, u32, *const c_void) -> i32;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_send(
    handle: HANDLE,
    packet: *const u8,
    length: usize,
    address: *const c_void,
    error: *mut u32,
    submit: Submit,
) -> bool {
    let Ok(length) = u32::try_from(length) else {
        unsafe {
            SetLastError(ERROR_INVALID_PARAMETER);
            error.write(ERROR_INVALID_PARAMETER);
        }
        return false;
    };
    let success = unsafe { submit(handle, packet, length, address) } != 0;
    unsafe { error.write(GetLastError()) };
    success
}

#[repr(C)]
struct RawSendOps {
    submit: Submit,
    invalid_interface: unsafe extern "C" fn(),
    error: LogSink,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_rawsend(
    family: u16,
    interface: *const c_char,
    data: *const u8,
    length: usize,
    handle: *const HANDLE,
    error: *mut u32,
    ops: &RawSendOps,
) -> bool {
    let mut address = MaybeUninit::<Address>::uninit();
    if !unsafe { zapret_divert_address(family, interface, address.as_mut_ptr()) } {
        unsafe { (ops.invalid_interface)() };
        return false;
    }
    let sent = unsafe {
        zapret_divert_send(
            handle.read(),
            data,
            length,
            address.as_ptr().cast(),
            error,
            ops.submit,
        )
    };
    if !sent {
        unsafe {
            (ops.error)(
                c"windivert send error. win32 code %u\n".as_ptr(),
                error.read(),
            );
        }
    }
    sent
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_rawsend_repeat(
    repeats: i32,
    destination: *const c_void,
    mark: u32,
    interface: *const c_char,
    data: *const c_void,
    length: usize,
    send: RawSend,
) -> bool {
    (0..repeats).all(|_| unsafe { send(destination, mark, interface, data, length) })
}
