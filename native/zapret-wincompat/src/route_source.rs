//! Bounded source-address selection with a socket owned entirely inside Rust.
use std::{ffi::c_void, ptr};
use windows_sys::Win32::Networking::WinSock;
#[repr(C)]
struct Ops {
    socket: unsafe extern "C" fn(i32, i32, i32) -> usize,
    connect: unsafe extern "C" fn(usize, *const c_void, i32) -> i32,
    name: unsafe extern "C" fn(usize, *mut c_void, *mut i32) -> i32,
    close: unsafe extern "C" fn(usize) -> i32,
}
unsafe extern "C" fn system_socket(family: i32, kind: i32, protocol: i32) -> usize {
    unsafe { WinSock::socket(family, kind, protocol) }
}
unsafe extern "C" fn system_connect(socket: usize, address: *const c_void, length: i32) -> i32 {
    unsafe { WinSock::connect(socket, address.cast(), length) }
}
unsafe extern "C" fn system_name(socket: usize, address: *mut c_void, length: *mut i32) -> i32 {
    unsafe { WinSock::getsockname(socket, address.cast(), length) }
}
unsafe extern "C" fn system_close(socket: usize) -> i32 {
    unsafe { WinSock::closesocket(socket) }
}
static SYSTEM: Ops = Ops {
    socket: system_socket,
    connect: system_connect,
    name: system_name,
    close: system_close,
};
struct Socket<'a> {
    handle: usize,
    ops: &'a Ops,
}
impl Drop for Socket<'_> {
    fn drop(&mut self) {
        unsafe { (self.ops.close)(self.handle) };
    }
}
const _: () = {
    assert!(size_of::<Ops>() == 4 * size_of::<usize>());
    assert!(std::mem::offset_of!(Ops, close) == 3 * size_of::<usize>());
    assert!(size_of::<WinSock::SOCKADDR_IN>() == 16);
    assert!(size_of::<WinSock::SOCKADDR_IN6>() == 28);
};
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_route_source(
    version: u32,
    target: *const u8,
    source: *mut u8,
    ops: *const Ops,
) -> bool {
    let (family, length, offset, width) = match version {
        4 => (2u16, 16, 4, 4),
        6 => (23u16, 28, 8, 16),
        _ => return false,
    };
    if target.is_null() || source.is_null() || !ops.is_null() && !ops.is_aligned() {
        return false;
    }
    let ops = if ops.is_null() {
        &SYSTEM
    } else {
        unsafe { &*ops }
    };
    let handle = unsafe { (ops.socket)(family as i32, 2, 0) };
    if handle == usize::MAX {
        return false;
    }
    let socket = Socket { handle, ops };
    // Copy the target after opening, matching the C helper's observation order.
    // Byte arrays also accept Lua strings with unaligned address contents.
    let mut destination = [0u8; 28];
    destination[..2].copy_from_slice(&family.to_ne_bytes());
    destination[2..4].fill(255);
    unsafe { ptr::copy_nonoverlapping(target, destination.as_mut_ptr().add(offset), width) };
    if unsafe { (ops.connect)(handle, destination.as_ptr().cast(), length) } != 0 {
        return false;
    }
    let mut local = [0u8; 28];
    let mut received = length;
    if unsafe { (ops.name)(handle, local.as_mut_ptr().cast(), &mut received) } != 0 {
        return false;
    }
    // The C helper closes before publishing. No owned handle can survive this
    // return or the Lua allocation/error in the outer adapter.
    drop(socket);
    unsafe { ptr::copy_nonoverlapping(local.as_ptr().add(offset), source, width) };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_source_ip(
    target: *const u8,
    length: usize,
    output: *mut u8,
    ops: *const Ops,
) -> u32 {
    let version = match length {
        4 => 4,
        16 => 6,
        _ => return 2,
    };
    u32::from(unsafe { zapret_route_source(version, target, output, ops) })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Calls {
        failure: u32,
        trace: Vec<u32>,
        expected: Vec<u8>,
    }
    thread_local! {static CALLS:RefCell<Calls>=RefCell::new(Calls::default());}
    unsafe extern "C" fn open(family: i32, kind: i32, protocol: i32) -> usize {
        CALLS.with_borrow_mut(|c| {
            c.trace.push(1);
            assert!(family == 2 || family == 23);
            assert_eq!((kind, protocol), (2, 0));
            if c.failure == 1 { usize::MAX } else { 42 }
        })
    }
    unsafe extern "C" fn connect(socket: usize, data: *const c_void, length: i32) -> i32 {
        CALLS.with_borrow_mut(|c| {
            c.trace.push(2);
            assert_eq!(socket, 42);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length as usize) },
                &c.expected
            );
            if c.failure == 2 { -1 } else { 0 }
        })
    }
    unsafe extern "C" fn name(socket: usize, data: *mut c_void, length: *mut i32) -> i32 {
        CALLS.with_borrow_mut(|c| {
            c.trace.push(3);
            assert_eq!(socket, 42);
            assert_eq!(unsafe { *length }, c.expected.len() as i32);
            unsafe { ptr::copy_nonoverlapping(c.expected.as_ptr(), data.cast(), c.expected.len()) };
            if c.failure == 3 { -1 } else { 0 }
        })
    }
    unsafe extern "C" fn close(socket: usize) -> i32 {
        CALLS.with_borrow_mut(|c| {
            c.trace.push(4);
            assert_eq!(socket, 42);
            -1
        })
    }
    fn ops() -> Ops {
        Ops {
            socket: open,
            connect,
            name,
            close,
        }
    }
    fn setup(version: u32, failure: u32) -> Vec<u8> {
        let (family, length, offset, width) = if version == 4 {
            (2u16, 16, 4, 4)
        } else {
            (23u16, 28, 8, 16)
        };
        let mut expected = vec![0; length];
        expected[..2].copy_from_slice(&family.to_ne_bytes());
        expected[2..4].fill(255);
        let target: Vec<_> = (0..width as u8).collect();
        expected[offset..offset + width].copy_from_slice(&target);
        CALLS.set(
            RefCell::new(Calls {
                failure,
                expected,
                trace: Vec::new(),
            })
            .into_inner(),
        );
        target
    }
    #[test]
    fn source_address_uses_zeroed_route_lookup_and_closes_before_publishing() {
        let target = setup(6, 0);
        let mut output = [0xa5; 16];
        assert!(unsafe { zapret_route_source(6, target.as_ptr(), output.as_mut_ptr(), &ops()) });
        assert_eq!(&output, target.as_slice());
        CALLS.with_borrow(|c| assert_eq!(&c.trace, &[1, 2, 3, 4]));
    }
    #[test]
    fn every_failure_closes_only_an_opened_socket_and_keeps_output_unmodified() {
        for failure in 1..=3 {
            let target = setup(4, failure);
            let mut output = [0xa5; 4];
            assert!(!unsafe {
                zapret_route_source(4, target.as_ptr(), output.as_mut_ptr(), &ops())
            });
            assert_eq!(output, [0xa5; 4]);
            CALLS.with_borrow(|c| {
                assert_eq!(
                    c.trace,
                    match failure {
                        1 => vec![1],
                        2 => vec![1, 2, 4],
                        _ => vec![1, 2, 3, 4],
                    }
                )
            });
        }
    }
    #[test]
    fn close_failure_does_not_discard_a_successfully_selected_address() {
        let target = setup(4, 0);
        let mut output = [0; 4];
        assert!(unsafe { zapret_route_source(4, target.as_ptr(), output.as_mut_ptr(), &ops()) });
        assert_eq!(&output, target.as_slice());
    }
    #[test]
    fn lua_width_classification_rejects_before_touching_the_socket_api() {
        let target = setup(4, 0);
        for length in [0, 1, 3, 5, 15, 17, usize::MAX] {
            let mut output = [0xa5; 16];
            assert_eq!(
                unsafe {
                    zapret_lua_source_ip(target.as_ptr(), length, output.as_mut_ptr(), &ops())
                },
                2
            );
            assert_eq!(output, [0xa5; 16]);
        }
        CALLS.with_borrow(|c| assert!(c.trace.is_empty()));
    }
    #[test]
    fn lua_socket_failure_returns_nil_without_publishing_scratch_output() {
        let target = setup(6, 2);
        let mut output = [0xa5; 16];
        assert_eq!(
            unsafe { zapret_lua_source_ip(target.as_ptr(), 16, output.as_mut_ptr(), &ops()) },
            0
        );
        assert_eq!(output, [0xa5; 16]);
        CALLS.with_borrow(|c| assert_eq!(c.trace, vec![1, 2, 4]));
    }
    #[test]
    fn null_or_invalid_metadata_cannot_open_a_socket() {
        let target = setup(4, 0);
        let mut output = [0xa5; 16];
        for (version, data, out) in [
            (0, target.as_ptr(), output.as_mut_ptr()),
            (4, ptr::null(), output.as_mut_ptr()),
            (4, target.as_ptr(), ptr::null_mut()),
        ] {
            assert!(!unsafe { zapret_route_source(version, data, out, &ops()) });
        }
        CALLS.with_borrow(|c| assert!(c.trace.is_empty()));
    }
}
