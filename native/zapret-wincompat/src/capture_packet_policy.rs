//! Per-packet input projection and receive polling between native C observations.
use crate::logging::LogSink;
use std::{
    ffi::{c_char, c_void},
    mem::MaybeUninit,
};

#[repr(C)]
struct PacketInput {
    mark: u32,
    interface_in: *const c_char,
    interface_out: *const c_char,
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
struct PacketOps {
    impostor: unsafe extern "C" fn(*const c_void) -> bool,
    interface: unsafe extern "C" fn(*const c_void, *mut Interface),
    debug: LogSink,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_prepare_capture_packet(
    id: u32,
    length: usize,
    observation: &Observation,
    native_address: *const c_void,
    ops: &PacketOps,
    text: *mut u8,
    capacity: usize,
    output: *mut PacketInput,
) -> bool {
    let initial = &observation.interface;
    let direction = if initial.outbound {
        c"outbound"
    } else {
        c"inbound"
    };
    unsafe {
        (ops.debug)(
            c"\npacket: id=%u len=%zu %s IPv6=%u IPChecksum=%u TCPChecksum=%u UDPChecksum=%u IfIdx=%u.%u\n".as_ptr(),
            id, length, direction.as_ptr(), u32::from(observation.ipv6), u32::from(observation.ip_checksum),
            u32::from(observation.tcp_checksum), u32::from(observation.udp_checksum), initial.index, initial.subindex,
        );
        // The logger may update the native address. Only inspect the current
        // interface after admitting the packet using the current impostor flag.
        if (ops.impostor)(native_address) {
            (ops.debug)(c"windivert: passing impostor packet\n".as_ptr());
            return false;
        }
        let mut interface = MaybeUninit::<Interface>::uninit();
        (ops.interface)(native_address, interface.as_mut_ptr());
        let interface = interface.assume_init();
        capture_packet_input(
            interface.index,
            interface.subindex,
            interface.outbound,
            text,
            capacity,
            output,
        )
    }
}

fn decimal(mut value: u32, target: &mut [u8]) -> usize {
    let mut digits = [0; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let count = digits.len() - start;
    target[..count].copy_from_slice(&digits[start..]);
    count
}
unsafe fn capture_packet_input(
    index: u32,
    subindex: u32,
    outbound: bool,
    text: *mut u8,
    capacity: usize,
    output: *mut PacketInput,
) -> bool {
    let mut buffer = [0; 22];
    let mut count = decimal(index, &mut buffer);
    buffer[count] = b'.';
    count += 1;
    count += decimal(subindex, &mut buffer[count..]);
    if text.is_null() || capacity <= count {
        return false;
    }
    unsafe { std::ptr::copy_nonoverlapping(buffer.as_ptr(), text, count + 1) };
    let empty = c"".as_ptr();
    let name = text.cast();
    let input = PacketInput {
        mark: 0,
        interface_in: if outbound { empty } else { name },
        interface_out: if outbound { name } else { empty },
    };
    unsafe { output.write(input) };
    true
}

const _: () = {
    assert!(size_of::<Interface>() == 12 && std::mem::offset_of!(Interface, outbound) == 8);
    assert!(size_of::<Observation>() == 16 && std::mem::offset_of!(Observation, ipv6) == 12);
    let pointer = size_of::<usize>();
    assert!(size_of::<PacketOps>() == 3 * pointer && size_of::<PacketInput>() == 3 * pointer);
    assert!(std::mem::offset_of!(PacketInput, interface_in) == pointer);
};

#[repr(C)]
struct Poll {
    phase: u32,
    status: u32,
}
#[repr(C)]
struct PollFeedback {
    quitting: bool,
    network: bool,
}
#[unsafe(no_mangle)]
extern "C" fn zapret_capture_poll_step(flow: &mut Poll, value: &PollFeedback) -> u32 {
    let next = match flow.phase {
        0 => 1,
        1 => 2,
        2 => {
            if value.quitting {
                flow.status = 3;
                4
            } else {
                3
            }
        }
        3 => {
            flow.status = if value.network { 0 } else { 2 };
            4
        }
        4 => 4,
        _ => 5,
    };
    flow.phase = next;
    next
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interfaces_are_native_decimal_and_borrow_the_callers_buffer() {
        let mut text = [0xa5; 44];
        let mut out = PacketInput {
            mark: 99,
            interface_in: std::ptr::null(),
            interface_out: std::ptr::null(),
        };
        assert!(unsafe {
            capture_packet_input(u32::MAX, 0, true, text.as_mut_ptr(), text.len(), &mut out)
        });
        assert_eq!(&text[..13], b"4294967295.0\0");
        assert_eq!(out.mark, 0);
        assert_eq!(out.interface_out, text.as_ptr().cast());
        assert_eq!(unsafe { *out.interface_in }, 0);
    }
    #[test]
    fn quit_is_observed_after_yield_and_skips_network_lookup() {
        let mut flow = Poll {
            phase: 0,
            status: 99,
        };
        let value = PollFeedback {
            quitting: true,
            network: false,
        };
        let trace = [
            zapret_capture_poll_step(&mut flow, &value),
            zapret_capture_poll_step(&mut flow, &value),
            zapret_capture_poll_step(&mut flow, &value),
        ];
        assert_eq!(trace, [1, 2, 4]);
        assert_eq!(flow.status, 3);
    }
    #[test]
    fn no_quit_requests_native_network_observation_then_selects_reconnect_or_batch() {
        for (network, status) in [(false, 2), (true, 0)] {
            let mut flow = Poll {
                phase: 0,
                status: 99,
            };
            let value = PollFeedback {
                quitting: false,
                network,
            };
            for want in [1, 2, 3, 4] {
                assert_eq!(zapret_capture_poll_step(&mut flow, &value), want)
            }
            assert_eq!(flow.status, status);
        }
    }
    #[test]
    fn decimal_names_are_bounded_and_failed_capacity_does_not_publish() {
        let mut text = [0xa5; 44];
        let mut out = PacketInput {
            mark: 99,
            interface_in: std::ptr::null(),
            interface_out: std::ptr::null(),
        };
        for (index, sub) in [(0, 0), (1, 10), (100, 999), (u32::MAX, u32::MAX)] {
            let expected = format!("{index}.{sub}\0");
            assert!(!unsafe {
                capture_packet_input(
                    index,
                    sub,
                    false,
                    text.as_mut_ptr(),
                    expected.len() - 1,
                    &mut out,
                )
            });
            assert!(unsafe {
                capture_packet_input(index, sub, false, text.as_mut_ptr(), text.len(), &mut out)
            });
            assert_eq!(&text[..expected.len()], expected.as_bytes());
            assert_eq!(out.interface_in, text.as_ptr().cast());
            assert_eq!(unsafe { *out.interface_out }, 0);
        }
    }
}
