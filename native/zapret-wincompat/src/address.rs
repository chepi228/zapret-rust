//! Address helpers and Lua conversion with aligned, bounded Win32 buffers.
use crate::text_buffer::TextBuffer;
use std::{
    ffi::{CStr, c_char, c_void},
    fmt::Write,
    mem::offset_of,
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, inet_ntop, inet_pton};

#[repr(align(4))]
struct Address([u8; 16]);

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_lua_ntop(
    input: *const u8,
    length: usize,
    output: *mut c_char,
    capacity: usize,
) -> usize {
    let family = match length {
        4 => AF_INET,
        16 => AF_INET6,
        _ => return 0,
    };
    if capacity == 0 {
        return 0;
    }
    let mut address = Address([0; 16]);
    unsafe { ptr::copy_nonoverlapping(input, address.0.as_mut_ptr(), length) };
    if unsafe {
        inet_ntop(
            i32::from(family),
            address.0.as_ptr().cast(),
            output.cast(),
            capacity,
        )
    }
    .is_null()
    {
        return 0;
    }
    unsafe { CStr::from_ptr(output) }.to_bytes().len()
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_lua_pton(
    input: *const c_char,
    output: *mut u8,
    capacity: usize,
) -> usize {
    let mut address = Address([0; 16]);
    let length = if unsafe {
        inet_pton(
            i32::from(AF_INET),
            input.cast(),
            address.0.as_mut_ptr().cast(),
        )
    } == 1
    {
        4
    } else if unsafe {
        inet_pton(
            i32::from(AF_INET6),
            input.cast(),
            address.0.as_mut_ptr().cast(),
        )
    } == 1
    {
        16
    } else {
        return 0;
    };
    if capacity < length {
        return 0;
    }
    unsafe { ptr::copy_nonoverlapping(address.0.as_ptr(), output, length) };
    length
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_address_ntopa46(
    ipv4: *const u8,
    ipv6: *const u8,
    output: *mut c_char,
    capacity: usize,
) {
    if capacity == 0 {
        return;
    }
    unsafe { output.write(0) };
    if !ipv4.is_null() {
        unsafe { zapret_lua_ntop(ipv4, 4, output, capacity) };
    } else if !ipv6.is_null() {
        unsafe { zapret_lua_ntop(ipv6, 16, output, capacity) };
    } else {
        let Some(mut output) = (unsafe { TextBuffer::new(output, capacity) }) else {
            return;
        };
        let _ = output.write_str("UNKNOWN_FAMILY");
    }
}

unsafe fn family(address: *const c_void) -> u16 {
    unsafe { ptr::read_unaligned(address.cast::<u16>()) }
}

unsafe fn ip(address: *const c_void) -> Option<(*const u8, usize)> {
    use windows_sys::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6};
    match unsafe { family(address) } {
        AF_INET => Some((
            unsafe { address.byte_add(offset_of!(SOCKADDR_IN, sin_addr)).cast() },
            4,
        )),
        AF_INET6 => Some((
            unsafe { address.byte_add(offset_of!(SOCKADDR_IN6, sin6_addr)).cast() },
            16,
        )),
        _ => None,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_address_ntop46(
    address: *const c_void,
    output: *mut c_char,
    capacity: usize,
) {
    if capacity == 0 {
        return;
    }
    if let Some((data, length)) = unsafe { ip(address) } {
        unsafe {
            output.write(0);
            zapret_lua_ntop(data, length, output, capacity);
        }
    } else {
        unsafe { zapret_address_ntopa46(ptr::null(), ptr::null(), output, capacity) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_address_port(address: *const c_void) -> u16 {
    if matches!(unsafe { family(address) }, AF_INET | AF_INET6) {
        u16::from_be(unsafe { ptr::read_unaligned(address.byte_add(2).cast::<u16>()) })
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_address_has_ip(address: *const c_void) -> bool {
    unsafe { ip(address) }.is_some_and(|(data, length)| {
        (0..length).any(|index| unsafe { data.add(index).read() } != 0)
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_address_ntop_port(
    address: *const c_void,
    output: *mut c_char,
    capacity: usize,
) {
    if capacity == 0 {
        return;
    }
    let mut bytes = [0u8; 46];
    unsafe { zapret_address_ntop46(address, bytes.as_mut_ptr().cast(), bytes.len()) };
    let text = unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }
        .to_str()
        .unwrap_or("UNKNOWN_FAMILY");
    let Some(mut output) = (unsafe { TextBuffer::new(output, capacity) }) else {
        return;
    };
    match unsafe { family(address) } {
        AF_INET => {
            let _ = write!(output, "{text}:{}", unsafe { zapret_address_port(address) });
        }
        AF_INET6 => {
            let _ = write!(output, "[{text}]:{}", unsafe {
                zapret_address_port(address)
            });
        }
        _ => {
            let _ = output.write_str(text);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_address_strip_host(host: *mut c_char) -> bool {
    let mut address = Address([0; 16]);
    // Finish inspecting the immutable input before editing the caller's buffer.
    let (start, length, family) = {
        let bytes = unsafe { CStr::from_ptr(host) }.to_bytes();
        let start = bytes
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        if bytes.len() < 2 {
            return false;
        }
        if bytes[0] == b'[' {
            let Some(end) = bytes.iter().position(|&byte| byte == b']') else {
                return false;
            };
            (start + 1, end - 1, Some(AF_INET6))
        } else if unsafe {
            inet_pton(
                i32::from(AF_INET6),
                host.add(start).cast(),
                address.0.as_mut_ptr().cast(),
            )
        } == 1
        {
            (start, bytes.len(), None)
        } else {
            let length = bytes
                .iter()
                .position(|&byte| byte == b':')
                .unwrap_or(bytes.len());
            (start, length, Some(AF_INET))
        }
    };
    unsafe {
        ptr::copy(host.add(start), host, length);
        host.add(length).write(0);
    }
    family.is_none_or(|family| unsafe { inet_pton(i32::from(family), host.cast(), address.0.as_mut_ptr().cast()) } == 1)
}
