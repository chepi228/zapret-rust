//! Packet assembly decisions between Lua calls. The state owns no VM resources.
use std::{ffi::c_char, ptr, slice};

const IP: u32 = 2;
const IP6: u32 = 4;
const TCP: u32 = 6;
const UDP: u32 = 8;
const ICMP: u32 = 10;
const PAYLOAD: u32 = 11;
const DONE: u32 = 12;
const ERROR: u32 = 13;
const NO_NEXT_HEADER: u8 = 59;

// C reads the command and bounded output span after each transition. It performs
// VM calls with no active Rust frame, then supplies the resulting scalar values.
#[repr(C)]
struct State {
    buffer: *mut u8,
    capacity: usize,
    used: usize,
    network: usize,
    problem: usize,
    output: *mut u8,
    available: usize,
    phase: u32,
    error: u32,
    version: u8,
    transport: u8,
    last_protocol: u8,
    fragmented: bool,
    keep_sum: bool,
    bad_sum: bool,
    preserve_next: bool,
    serialize: bool,
}
#[repr(C)]
struct Observation {
    data: *const u8,
    length: usize,
    present: bool,
    success: bool,
}
#[repr(C)]
struct Probe {
    next: u32,
    protocol: u8,
    done: bool,
}
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
impl State {
    fn valid(&self) -> bool {
        !self.buffer.is_null()
            && self.capacity <= isize::MAX as usize
            && self.used <= self.capacity
            && self.network <= self.used
            && self.output == self.buffer.wrapping_add(self.used)
            && self.available == self.capacity - self.used
            && matches!(
                self.phase,
                IP | IP6 | TCP | UDP | ICMP | PAYLOAD | DONE | ERROR
            )
    }
    fn fail(&mut self, error: u32, problem: usize) {
        self.phase = ERROR;
        self.error = error;
        self.problem = problem;
    }
    fn publish_span(&mut self) {
        self.output = self.buffer.wrapping_add(self.used);
        self.available = self.capacity - self.used;
        self.serialize = !matches!(self.phase, UDP | ICMP) || self.available >= 8;
    }
}

// The caller owns the complete buffer and state. Bits: keep, bad, preserve, fragment.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_begin(
    buffer: *mut u8,
    capacity: usize,
    flags: u8,
    last_protocol: u8,
    state: *mut State,
) -> bool {
    if !valid(state) || buffer.is_null() || capacity > isize::MAX as usize || flags & !15 != 0 {
        return false;
    }
    unsafe {
        state.write(State {
            buffer,
            capacity,
            used: 0,
            network: 0,
            problem: 0,
            output: buffer,
            available: capacity,
            phase: IP,
            error: 0,
            version: 0,
            transport: 0,
            last_protocol,
            fragmented: flags & 8 != 0,
            keep_sum: flags & 1 != 0,
            bad_sum: flags & 2 != 0,
            preserve_next: flags & 12 != 0,
            serialize: true,
        });
    }
    true
}

// No call reachable here invokes Lua. Payload bytes stay rooted on the C VM stack.
unsafe fn transition(state: &mut State, value: &Observation) {
    let remaining = state.available;
    match state.phase {
        IP | IP6 | TCP | UDP | ICMP => {
            let phase = state.phase;
            if !value.present {
                state.phase = match phase {
                    IP => IP6,
                    IP6 => {
                        state.fail(0, 0);
                        return;
                    }
                    TCP => UDP,
                    UDP => ICMP,
                    _ => PAYLOAD,
                };
                return;
            }
            if matches!(phase, UDP | ICMP) && remaining < 8 {
                state.fail(if phase == UDP { 4 } else { 6 }, 0);
                return;
            }
            if !value.success {
                state.fail(
                    match phase {
                        IP => 1,
                        IP6 => 2,
                        TCP => 3,
                        UDP => 5,
                        _ => 7,
                    },
                    0,
                );
                return;
            }
            let minimum = match phase {
                IP | TCP => 20,
                IP6 => 40,
                _ => 8,
            };
            if value.length < minimum || value.length > remaining {
                state.fail(11, value.length);
                return;
            }
            state.used += value.length;
            if matches!(phase, IP | IP6) {
                state.version = if phase == IP { 4 } else { 6 };
                state.network = state.used;
                state.phase = if state.fragmented { PAYLOAD } else { TCP };
            } else {
                state.transport = match phase {
                    TCP => 6,
                    UDP => 17,
                    _ => 1,
                };
                state.phase = PAYLOAD;
            }
        }
        PAYLOAD => {
            let length = if value.data.is_null() {
                0
            } else {
                value.length
            };
            if length > 65535 {
                state.fail(8, length);
                return;
            }
            if length > remaining {
                state.fail(9, length);
                return;
            }
            if length != 0 {
                unsafe { ptr::copy(value.data, state.output, length) };
            }
            state.used += length;
            if !state.fragmented {
                let mut checksum_xor = 0;
                if !state.keep_sum && state.transport != 0 {
                    // Preserve the old RNG sequence on invalid UDP lengths.
                    if state.transport == 17 && state.used - state.network > 65535 {
                        state.fail(12, 0);
                        return;
                    }
                    if state.bad_sum {
                        checksum_xor = (1 + (crate::system::zapret_random() as u32 % 65535)) as u16;
                    }
                }
                let packet = unsafe { slice::from_raw_parts_mut(state.buffer, state.used) };
                let written = match crate::packet_write::finish_assembly(
                    packet,
                    state.network,
                    state.version,
                    state.transport,
                    state.keep_sum,
                    checksum_xor,
                ) {
                    Ok(written) => written,
                    Err(error) => {
                        state.fail(
                            match error {
                                2 => 12,
                                3 => 13,
                                4 => 14,
                                5 => 15,
                                6 => 16,
                                _ => 17,
                            },
                            0,
                        );
                        return;
                    }
                };
                if written < state.network || written > state.used {
                    state.fail(11, written);
                    return;
                }
                state.used = written;
            }
            state.phase = DONE;
        }
        _ => unreachable!(),
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_observe(
    state: *mut State,
    observation: *const Observation,
) -> bool {
    if !valid(state) || !valid(observation) {
        return false;
    }
    let state = unsafe { &mut *state };
    if !state.valid() || state.phase >= DONE {
        return false;
    }
    unsafe { transition(state, &*observation) };
    state.publish_span();
    true
}
#[unsafe(no_mangle)]
extern "C" fn zapret_lua_packet_probe_protocol(last_protocol: u8) -> bool {
    last_protocol == NO_NEXT_HEADER
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_packet_protocol_step(step: u32, present: bool) -> Probe {
    let (next, protocol, done) = match (step, present) {
        (0, true) => (0, 6, true),
        (0, false) => (1, 0, false),
        (1, true) => (0, 17, true),
        (1, false) => (2, 0, false),
        (2, true) => (3, 0, false),
        (3, true) => (0, 1, true),
        (3, false) => (4, 0, false),
        (4, true) => (0, 58, true),
        _ => (0, NO_NEXT_HEADER, true),
    };
    Probe {
        next,
        protocol,
        done,
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_protocol_label(step: u32) -> *const c_char {
    match step {
        0 => c"tcp".as_ptr(),
        1 => c"udp".as_ptr(),
        2 => c"icmp".as_ptr(),
        3 => c"ip".as_ptr(),
        4 => c"ip6".as_ptr(),
        _ => ptr::null(),
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_assembly_label(phase: u32) -> *const c_char {
    match phase {
        0 => c"frag_off".as_ptr(),
        IP => c"ip".as_ptr(),
        IP6 => c"ip6".as_ptr(),
        TCP => c"tcp".as_ptr(),
        UDP => c"udp".as_ptr(),
        ICMP => c"icmp".as_ptr(),
        PAYLOAD => c"payload".as_ptr(),
        _ => ptr::null(),
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_assembly_error_format(error: u32) -> *const c_char {
    match error {
        1 => c"reconstruct_dissect: bad ip\n",
        2 => c"reconstruct_dissect: bad ip6\n",
        3 => c"reconstruct_dissect: bad tcp\n",
        4 => c"reconstruct_dissect: no space for udp header\n",
        5 => c"reconstruct_dissect: bad udp\n",
        6 => c"reconstruct_dissect: no space for icmp header\n",
        7 => c"reconstruct_dissect: bad icmp\n",
        8 => c"reconstruct_dissect: payload too large : %zu\n",
        9 => c"reconstruct_dissect: payload does not fit into the buffer : payload %zu buffer_left %zu\n",
        11 => c"reconstruct_dissect: invalid assembly state\n",
        12 => c"reconstruct_dissect: invalid payload length\n",
        13 => c"ipv4 frag : invalid ip_len\n",
        14 => c"ipv4 frag : fragment end is outside of the packet\n",
        15 => c"ipv6 frag : invalid ip6_plen\n",
        16 => c"ipv6 frag : fragmentable part is outside of the packet\n",
        17 => c"reconstruct_dissect: invalid packet layout\n",
        _ => return ptr::null(),
    }
    .as_ptr()
}
#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<State>() == 72);
    assert!(size_of::<Observation>() == 24);
    assert!(size_of::<Probe>() == 8);
};
