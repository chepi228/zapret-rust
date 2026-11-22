//! Connection lookup and TCP/UDP accounting for the native engine.
//!
//! C owns each stable connection record and its Lua references. Rust calls
//! finish before C creates or releases Lua objects.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::c_void,
    ops::Bound::{Excluded, Unbounded},
    ptr, slice,
    sync::atomic::{AtomicU64, Ordering},
};

#[repr(C, align(4))]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
struct Key {
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    l3: u8,
    l4: u8,
    reserved: [u8; 2],
}

impl Key {
    fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            reserved: [0; 2],
            ..self
        }
    }
}

unsafe fn read_key(key: *const Key) -> Key {
    // The last two bytes are padding in t_conn. C structure assignment need
    // not preserve them, so never read them or use them as part of identity.
    let mut value = Key::default();
    unsafe { ptr::copy_nonoverlapping(key.cast::<u8>(), ptr::from_mut(&mut value).cast(), 38) };
    value
}

struct Entry {
    value: *mut c_void,
    order: u64,
}

#[derive(Default)]
struct Index {
    entries: HashMap<Key, Entry>,
    order: BTreeMap<u64, Key>,
}

static NEXT_ORDER: AtomicU64 = AtomicU64::new(1);

impl Index {
    fn insert(&mut self, key: Key, value: *mut c_void) -> bool {
        if self.entries.contains_key(&key) || self.entries.try_reserve(1).is_err() {
            return false;
        }
        let order = NEXT_ORDER.fetch_add(1, Ordering::Relaxed);
        self.entries.insert(key, Entry { value, order });
        self.order.insert(order, key);
        true
    }

    fn find(&self, key: Key) -> Option<(*mut c_void, bool)> {
        self.entries
            .get(&key)
            .map(|entry| (entry.value, false))
            .or_else(|| {
                self.entries
                    .get(&key.reversed())
                    .map(|entry| (entry.value, true))
            })
    }

    fn remove(&mut self, key: &Key) -> Option<*mut c_void> {
        let entry = self.entries.remove(key)?;
        self.order.remove(&entry.order);
        Some(entry.value)
    }
}

// Private C ABI. Packet headers and keys are readable for their C layouts.
// Output slots are writable and each pool is confined to the engine thread.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_key(
    out: *mut Key,
    ipv4: *const u8,
    ipv6: *const u8,
    tcp: *const u8,
    udp: *const u8,
    reverse: i32,
) -> i32 {
    let mut key = Key::default();
    if !ipv4.is_null() {
        let bytes = unsafe { slice::from_raw_parts(ipv4, 20) };
        key.source[..4].copy_from_slice(&bytes[12..16]);
        key.destination[..4].copy_from_slice(&bytes[16..20]);
    } else if !ipv6.is_null() {
        let bytes = unsafe { slice::from_raw_parts(ipv6, 40) };
        key.source.copy_from_slice(&bytes[8..24]);
        key.destination.copy_from_slice(&bytes[24..40]);
        key.l3 = 41;
    } else {
        unsafe { out.write(key) };
        return 0;
    }
    let ports = if !tcp.is_null() {
        key.l4 = 6;
        tcp
    } else if !udp.is_null() {
        key.l4 = 17;
        udp
    } else {
        key.l4 = 59;
        ptr::null()
    };
    if !ports.is_null() {
        let bytes = unsafe { slice::from_raw_parts(ports, 4) };
        key.source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        key.destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    }
    if reverse != 0 {
        key = key.reversed();
    }
    unsafe { out.write(key) };
    i32::from(key.l4 != 59)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_insert(
    slot: *mut *mut Index,
    key: *const Key,
    value: *mut c_void,
) -> i32 {
    let key = unsafe { read_key(key) };
    let slot = unsafe { &mut *slot };
    if slot.is_null() {
        let mut index = Box::new(Index::default());
        if !index.insert(key, value) {
            return 0;
        }
        *slot = Box::into_raw(index);
        1
    } else {
        i32::from(unsafe { &mut **slot }.insert(key, value))
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_find(
    index: *const Index,
    key: *const Key,
    reverse: *mut i32,
) -> *mut c_void {
    let result = unsafe { index.as_ref() }.and_then(|index| index.find(unsafe { read_key(key) }));
    match result {
        Some((value, direction)) => {
            if !reverse.is_null() {
                unsafe { reverse.write(i32::from(direction)) };
            }
            value
        }
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_after(index: *const Index, cursor: *mut u64) -> *mut c_void {
    let Some(index) = (unsafe { index.as_ref() }) else {
        return ptr::null_mut();
    };
    let after = unsafe { cursor.read() };
    let Some((&order, key)) = index.order.range((Excluded(after), Unbounded)).next() else {
        return ptr::null_mut();
    };
    unsafe { cursor.write(order) };
    index.entries[key].value
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_remove(
    slot: *mut *mut Index,
    key: *const Key,
) -> *mut c_void {
    let slot = unsafe { &mut *slot };
    let Some(index) = (unsafe { slot.as_mut() }) else {
        return ptr::null_mut();
    };
    let removed = index
        .remove(&unsafe { read_key(key) })
        .unwrap_or(ptr::null_mut());
    if index.entries.is_empty() {
        let index = std::mem::replace(slot, ptr::null_mut());
        drop(unsafe { Box::from_raw(index) });
    }
    removed
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Timestamp {
    pub(super) seconds: i64,
    pub(super) nanoseconds: i32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Position {
    pub(super) packets: u64,
    pub(super) data_packets: u64,
    pub(super) bytes: u64,
    pub(super) ipv6_flow: u32,
    pub(super) position: u32,
    pub(super) upper: u32,
    pub(super) previous_upper: u32,
    pub(super) sequence: u32,
    pub(super) initial_sequence: u32,
    pub(super) window: u16,
    pub(super) mss: u16,
    pub(super) calculated_window: u32,
    pub(super) scale: u8,
    pub(super) over_2g: u8,
    reserved: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Positions {
    pub(super) last: Timestamp,
    pub(super) state: i32,
    reserved: u32,
    pub(super) client: Position,
    pub(super) server: Position,
    pub(super) protocol: u8,
    tail: [u8; 7],
}

/// Read the TCP sequence from a live C position snapshot without reading padding.
pub(super) unsafe fn replay_tcp_sequence(
    snapshot: *const c_void,
    server_side: bool,
) -> Option<u32> {
    let positions = snapshot.cast::<Positions>();
    if unsafe { (*positions).protocol } != 6 {
        return None;
    }
    let direction = if server_side {
        unsafe { ptr::addr_of!((*positions).server) }
    } else {
        unsafe { ptr::addr_of!((*positions).client) }
    };
    Some(unsafe { (*direction).sequence })
}

pub(super) unsafe fn reassembly_client_sequence(snapshot: *const c_void) -> u32 {
    unsafe { (*snapshot.cast::<Positions>()).client.sequence }
}

/// Only a connection that has seen a server packet has a known TCP window.
pub(super) unsafe fn reassembly_tcp_window(snapshot: *const c_void) -> Option<u32> {
    let positions = snapshot.cast::<Positions>();
    let observed = unsafe { (*positions).server.packets } != 0;
    observed.then(|| unsafe { (*positions).server.calculated_window })
}

#[repr(C)]
struct Packet {
    tcp: *const u8,
    tcp_size: usize,
    payload_size: usize,
    ipv6_flow: u32,
    ipv6: u32,
}

#[repr(C)]
struct Timeouts {
    syn: u32,
    established: u32,
    fin: u32,
    udp: u32,
}

fn syn(flags: u8) -> bool {
    flags & 0x3f == 2
}
fn syn_ack(flags: u8) -> bool {
    flags & 0x3f == 0x12
}

fn option(mut bytes: &[u8], kind: u8) -> Option<&[u8]> {
    while let Some(&first) = bytes.first() {
        match first {
            0 => return None,
            1 => bytes = &bytes[1..],
            _ => {
                let length = usize::from(*bytes.get(1)?);
                if length < 2 || length > bytes.len() {
                    return None;
                }
                if first == kind {
                    return Some(&bytes[..length]);
                }
                bytes = &bytes[length..];
            }
        }
    }
    None
}

fn update(
    positions: &mut Positions,
    tcp: Option<&[u8]>,
    payload: usize,
    ipv6_flow: Option<u32>,
    incoming: bool,
    after_reset: bool,
) -> bool {
    let reset = tcp.is_some_and(|tcp| {
        let flags = tcp[13];
        let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        (syn(flags) && positions.state != 0)
            || (syn_ack(flags)
                && positions.state != 0
                && positions.client.initial_sequence != acknowledgement.wrapping_sub(1))
    });
    if !after_reset {
        let direct = if incoming {
            &mut positions.server
        } else {
            &mut positions.client
        };
        direct.packets = direct.packets.wrapping_add(1);
        direct.data_packets = direct.data_packets.wrapping_add(u64::from(payload != 0));
        direct.bytes = direct.bytes.wrapping_add(payload as u64);
        if reset {
            // C releases the old Lua state and initializes the record between
            // calls. The second call observes any work done by Lua finalizers.
            return true;
        }
    }
    if let Some(tcp) = tcp {
        let flags = tcp[13];
        let sequence = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        if syn(flags) {
            positions.client.initial_sequence = sequence;
        } else if syn_ack(flags) {
            if positions.client.initial_sequence == 0 {
                positions.client.initial_sequence = acknowledgement.wrapping_sub(1);
            }
            positions.server.initial_sequence = sequence;
        } else if flags & 5 != 0 {
            positions.state = 2;
        } else if positions.state == 0 {
            positions.state = 1;
            if !incoming && positions.server.initial_sequence == 0 {
                positions.server.initial_sequence = acknowledgement.wrapping_sub(1);
            }
        }

        let (direct, reverse) = if incoming {
            (&mut positions.server, &mut positions.client)
        } else {
            (&mut positions.client, &mut positions.server)
        };
        if let Some(flow) = ipv6_flow {
            direct.ipv6_flow = flow;
        }
        direct.window = u16::from_be_bytes([tcp[14], tcp[15]]);
        direct.calculated_window = u32::from(direct.window);
        if positions.state == 0 {
            if let Some(scale) =
                option(&tcp[20..], 3).filter(|option| option.len() == 3 && option[2] != 255)
            {
                direct.scale = scale[2].min(14);
            }
            direct.mss = option(&tcp[20..], 2)
                .filter(|option| option.len() == 4)
                .map_or(0, |mss| u16::from_be_bytes([mss[2], mss[3]]));
        } else {
            direct.calculated_window = direct
                .calculated_window
                .wrapping_shl(u32::from(direct.scale));
        }
        direct.sequence = sequence;
        direct.position = sequence.wrapping_add(payload as u32);
        reverse.position = acknowledgement;
        reverse.sequence = acknowledgement;
        if positions.state == 0 {
            direct.previous_upper = direct.position;
            direct.upper = direct.position;
        } else if payload != 0 {
            direct.previous_upper = direct.upper;
            if direct.position.wrapping_sub(direct.upper) & 0x8000_0000 == 0 {
                direct.upper = direct.position;
            }
        }
        if direct.sequence.wrapping_sub(direct.initial_sequence) & 0x8000_0000 != 0 {
            direct.over_2g = 1;
        }
        if reverse.sequence.wrapping_sub(reverse.initial_sequence) & 0x8000_0000 != 0 {
            reverse.over_2g = 1;
        }
    }
    false
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_start(tcp: *const u8, udp: i32) -> i32 {
    if !tcp.is_null() {
        let flags = unsafe { *tcp.add(13) };
        if syn_ack(flags) {
            return 2;
        }
        if syn(flags) {
            return 1;
        }
    }
    i32::from(udp != 0)
}

/// TCP slices are prevalidated by the packet parser and cover tcp_size bytes.
/// The packet size includes the TCP header only. UDP uses a null TCP pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_update(
    positions: *mut Positions,
    packet: *const Packet,
    reverse: i32,
    after_reset: i32,
) -> i32 {
    let packet = unsafe { &*packet };
    let tcp = if packet.tcp.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(packet.tcp, packet.tcp_size) })
    };
    let positions = unsafe { &mut *positions };
    let reset = update(
        positions,
        tcp,
        packet.payload_size,
        (packet.ipv6 != 0).then_some(packet.ipv6_flow),
        reverse != 0,
        after_reset != 0,
    );
    i32::from(reset)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_conntrack_expired(
    limits: *const Timeouts,
    positions: *const Positions,
    protocol: u8,
    cutoff: i32,
    now: i64,
) -> i32 {
    let limits = unsafe { &*limits };
    let positions = unsafe { &*positions };
    let idle = now.wrapping_sub(positions.last.seconds);
    let timeout = match (protocol, positions.state) {
        (6, 0) => Some(limits.syn),
        (6, 1) => Some(limits.established),
        (6, 2) => Some(limits.fin),
        (17, _) => Some(limits.udp),
        _ => None,
    };
    i32::from(cutoff != 0 || timeout.is_some_and(|limit| idle >= i64::from(limit)))
}

const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<Key>() == 40);
    assert!(size_of::<Timestamp>() == 16);
    assert!(size_of::<Position>() == 64);
    assert!(offset_of!(Position, sequence) == 40);
    assert!(offset_of!(Position, calculated_window) == 52);
    assert!(size_of::<Positions>() == 160);
    assert!(offset_of!(Positions, client) == 24);
    assert!(offset_of!(Positions, server) == 88);
    assert!(offset_of!(Positions, protocol) == 152);
    assert!(size_of::<Packet>() == 3 * size_of::<usize>() + 8);
    assert!(offset_of!(Packet, ipv6_flow) == 3 * size_of::<usize>());
};

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u8, seq: u32, ack: u32) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[4..8].copy_from_slice(&seq.to_be_bytes());
        bytes[8..12].copy_from_slice(&ack.to_be_bytes());
        bytes[12] = 0x80;
        bytes[13] = flags;
        bytes[14..16].copy_from_slice(&4096u16.to_be_bytes());
        bytes[20..29].copy_from_slice(&[2, 4, 5, 180, 1, 3, 3, 20, 0]);
        bytes
    }

    #[test]
    fn reverse_direction_preserves_logical_client_and_server_state() {
        let mut positions = Positions::default();
        assert!(!update(
            &mut positions,
            Some(&header(2, 100, 0)),
            0,
            None,
            false,
            false
        ));
        assert_eq!(positions.client.initial_sequence, 100);
        assert_eq!(positions.client.scale, 14);
        assert_eq!(positions.client.mss, 1460);
        assert!(!update(
            &mut positions,
            Some(&header(0x12, 900, 101)),
            0,
            None,
            true,
            false
        ));
        assert_eq!(positions.client.initial_sequence, 100);
        assert_eq!(positions.server.initial_sequence, 900);
        assert_eq!(positions.server.packets, 1);
        assert!(!update(
            &mut positions,
            Some(&header(0x10, 101, 901)),
            5,
            None,
            false,
            false
        ));
        assert_eq!(positions.state, 1);
        assert_eq!(positions.client.position, 106);
        assert_eq!(positions.client.calculated_window, 4096 << 14);
        assert_eq!(positions.client.packets, 2);
    }

    #[test]
    fn scale_none_byte_keeps_the_existing_scale() {
        let mut positions = Positions {
            client: Position {
                scale: 8,
                ..Position::default()
            },
            ..Positions::default()
        };
        let mut tcp = header(2, 100, 0);
        tcp[27] = 255;
        assert!(!update(&mut positions, Some(&tcp), 0, None, false, false));
        assert_eq!(positions.client.scale, 8);
    }

    #[test]
    fn tuple_reuse_releases_lua_between_accounting_and_the_new_syn() {
        let mut positions = Positions {
            state: 2,
            client: Position {
                packets: 6,
                ..Position::default()
            },
            ..Positions::default()
        };
        assert!(update(
            &mut positions,
            Some(&header(2, 500, 0)),
            2,
            None,
            false,
            false
        ));
        assert_eq!(positions.client.packets, 7);
        positions = Positions::default(); // C cleanup and Lua initialization.
        assert!(!update(
            &mut positions,
            Some(&header(2, 500, 0)),
            2,
            None,
            false,
            true
        ));
        assert_eq!(positions.client.packets, 0);
        assert_eq!(positions.client.initial_sequence, 500);
        assert_eq!(positions.client.position, 502);
    }

    #[test]
    fn c_key_padding_does_not_participate_in_identity() {
        let mut key = Key {
            source_port: 80,
            destination_port: 40000,
            reserved: [0xa5; 2],
            ..Key::default()
        };
        let first = unsafe { read_key(&key) };
        key.reserved = [0x5a; 2];
        assert!(first == unsafe { read_key(&key) });
        assert_eq!(first.reserved, [0; 2]);
    }

    #[test]
    fn index_payloads_remain_stable_and_removed_keys_do_not_affect_enumeration() {
        let mut first = 1u8;
        let mut second = 2u8;
        let first_ptr = ptr::from_mut(&mut first).cast();
        let second_ptr = ptr::from_mut(&mut second).cast();
        let key = Key {
            source_port: 10,
            destination_port: 20,
            l4: 6,
            ..Key::default()
        };
        let mut index = Index::default();
        assert!(index.insert(key, first_ptr));
        assert_eq!(index.find(key.reversed()), Some((first_ptr, true)));
        assert!(!index.insert(key, second_ptr));
        let other = Key {
            source_port: 30,
            ..key
        };
        assert!(index.insert(other, second_ptr));
        assert_eq!(index.remove(&key), Some(first_ptr));
        assert_eq!(index.find(other), Some((second_ptr, false)));
        assert_eq!(index.order.len(), 1);
        assert!(index.find(key).is_none());
    }
}
