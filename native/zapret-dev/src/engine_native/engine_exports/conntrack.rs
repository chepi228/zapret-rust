//! Engine conntrack storage and native operations between protected VM calls.
use super::helpers::{Timespec, boottime, clock_gettime};
use super::{startup_params::PARAMS, state::params_address};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
};

type Bytes<const N: usize> = [MaybeUninit<u8>; N];
const POINTER: usize = size_of::<usize>();
const CLOCK_BOOT_OR_UPTIME: c_int = 1;
const LUA_NOREF: c_int = -2;
const L7_UNKNOWN: u32 = 1;
const L7P_UNKNOWN: u32 = 1;

#[repr(C)]
struct Packet {
    before_ip: Bytes<{ 2 * POINTER }>,
    ipv4: *const u8,
    ipv6: *const u8,
    before_tcp: Bytes<{ 2 * POINTER }>,
    tcp: *const u8,
    udp: *const u8,
    before_transport_size: Bytes<POINTER>,
    transport_size: usize,
    before_payload_size: Bytes<{ 2 * POINTER }>,
    payload_size: usize,
    tail: Bytes<POINTER>,
}

#[repr(C, align(4))]
struct Key {
    before_protocol: Bytes<37>,
    protocol: u8,
    tail: Bytes<2>,
}

#[repr(C)]
struct PacketInput {
    tcp: *const u8,
    tcp_size: usize,
    payload_size: usize,
    ipv6_flow: u32,
    ipv6: u32,
}

#[repr(C)]
struct Positions {
    last: Timespec,
    before_protocol: Bytes<136>,
    protocol: u8,
    tail: Bytes<7>,
}

#[repr(C)]
struct Reassembly([MaybeUninit<usize>; 4]);

#[repr(C)]
struct Queue([MaybeUninit<usize>; 2]);

#[repr(C)]
struct Track {
    before_start: Bytes<8>,
    start: Timespec,
    positions: Positions,
    before_cutoff: Bytes<{ 4 + POINTER }>,
    cutoff: bool,
    before_l7: Bytes<3>,
    l7: u32,
    before_hostname: Bytes<1>,
    hostname: *mut c_char,
    hostname_is_ip: bool,
    before_refs: Bytes<3>,
    lua_state: c_int,
    lua_instance_cutoff: c_int,
    reassembly_payload: u32,
    reassembly: Reassembly,
    delayed: Queue,
}

#[repr(C)]
struct Entry {
    track: Track,
    key: Key,
}

#[repr(C)]
struct Table {
    syn: u32,
    established: u32,
    fin: u32,
    udp: u32,
    interval: i64,
    last_purge: i64,
    pool: *mut c_void,
}

#[repr(C)]
struct Lifecycle {
    entry: u32,
    stage: u32,
    status: u32,
    reverse: u32,
    reset: u32,
    find_direction: u32,
    protocol: u32,
    queue_limit: u32,
    after_clear: u32,
    after_init: u32,
    after_new: u32,
    after_feed: u32,
    incoming: c_int,
    tcp: u32,
    udp: u32,
    padding: u32,
    track: *mut Track,
    element: *mut Entry,
    out_track: *mut *mut Track,
    out_reverse: *mut bool,
    cursor: u64,
    now: i64,
    last: i64,
    interval: i64,
    result: usize,
}

#[repr(C)]
struct Context {
    table: *mut Table,
    packet: *const Packet,
    key: Key,
    input: PacketInput,
}

const _: () = {
    assert!(size_of::<Packet>() == 14 * POINTER && offset_of!(Packet, ipv4) == 2 * POINTER);
    assert!(offset_of!(Packet, ipv6) == 3 * POINTER && offset_of!(Packet, tcp) == 6 * POINTER);
    assert!(
        offset_of!(Packet, udp) == 7 * POINTER && offset_of!(Packet, transport_size) == 9 * POINTER
    );
    assert!(offset_of!(Packet, payload_size) == 12 * POINTER);
    assert!(size_of::<Key>() == 40 && offset_of!(Key, protocol) == 37);
    assert!(size_of::<PacketInput>() == 3 * POINTER + 8);
    assert!(offset_of!(PacketInput, ipv6_flow) == 3 * POINTER);
    assert!(size_of::<Positions>() == 160 && offset_of!(Positions, protocol) == 152);
    assert!(size_of::<Timespec>() == 16);
    let track_size = 216 + 8 * POINTER;
    let reassembly = 216 + 2 * POINTER;
    assert!(size_of::<Track>() == track_size && align_of::<Track>() == 8);
    assert!(offset_of!(Track, start) == 8 && offset_of!(Track, positions) == 24);
    assert!(offset_of!(Track, cutoff) == 188 + POINTER && offset_of!(Track, l7) == 192 + POINTER);
    assert!(offset_of!(Track, hostname) == 200 + POINTER);
    assert!(offset_of!(Track, hostname_is_ip) == reassembly - 16);
    assert!(offset_of!(Track, lua_state) == reassembly - 12);
    assert!(offset_of!(Track, lua_instance_cutoff) == reassembly - 8);
    assert!(offset_of!(Track, reassembly_payload) == reassembly - 4);
    assert!(offset_of!(Track, reassembly) == reassembly);
    assert!(offset_of!(Track, delayed) == reassembly + 4 * POINTER);
    assert!(size_of::<Entry>() == track_size + 40 && offset_of!(Entry, key) == track_size);
    assert!(size_of::<Table>() == 40 && offset_of!(Table, interval) == 16);
    assert!(offset_of!(Table, last_purge) == 24 && offset_of!(Table, pool) == 32);
    assert!(size_of::<Lifecycle>() == 104 + 4 * POINTER && offset_of!(Lifecycle, track) == 64);
    assert!(offset_of!(Lifecycle, element) == 64 + POINTER);
    assert!(offset_of!(Lifecycle, cursor) == 64 + 4 * POINTER);
    assert!(offset_of!(Lifecycle, result) == 96 + 4 * POINTER);
    assert!(size_of::<Context>() == 48 + 5 * POINTER);
    assert!(offset_of!(Context, input) == 40 + 2 * POINTER);
};

unsafe extern "C" {
    fn abort() -> !;
    fn malloc(size: usize) -> *mut c_void;
    fn free(value: *mut c_void);
    fn ReasmClear(reassembly: *mut Reassembly);
    fn rawpacket_queue_destroy(queue: *mut Queue);
    fn rawpacket_queue_init(queue: *mut Queue, limit: u32);
    fn zapret_conntrack_lifecycle_step(state: &mut Lifecycle) -> u32;
    fn zapret_conntrack_key(
        key: *mut Key,
        ipv4: *const u8,
        ipv6: *const u8,
        tcp: *const u8,
        udp: *const u8,
        reverse: c_int,
    ) -> c_int;
    fn zapret_conntrack_insert(
        pool: *mut *mut c_void,
        key: *const Key,
        element: *mut Entry,
    ) -> c_int;
    fn zapret_conntrack_after(pool: *const c_void, cursor: *mut u64) -> *mut Entry;
    fn zapret_conntrack_find(
        pool: *const c_void,
        key: *const Key,
        incoming: *mut c_int,
    ) -> *mut Entry;
    fn zapret_conntrack_remove(pool: *mut *mut c_void, key: *const Key) -> *mut Entry;
    fn zapret_conntrack_start(tcp: *const u8, udp: c_int) -> c_int;
    fn zapret_conntrack_update(
        positions: *mut Positions,
        packet: *const PacketInput,
        reverse: c_int,
        reset: c_int,
    ) -> c_int;
    fn zapret_conntrack_expired(
        table: *const Table,
        positions: *const Positions,
        protocol: u8,
        cutoff: c_int,
        now: i64,
    ) -> c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ConntrackPoolInit(
    table: *mut Table,
    interval: i64,
    syn: u32,
    established: u32,
    fin: u32,
    udp: u32,
) {
    unsafe {
        (*table).syn = syn;
        (*table).established = established;
        (*table).fin = fin;
        (*table).udp = udp;
        (*table).interval = interval;
        (*table).last_purge = boottime();
        (*table).pool = ptr::null_mut();
    }
}

unsafe fn release_hostname(track: *mut Track) {
    unsafe { free((*track).hostname.cast()) };
}

unsafe fn reset_hostname(track: *mut Track) {
    unsafe {
        (*track).hostname = ptr::null_mut();
        (*track).hostname_is_ip = false;
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ConntrackClearHostname(track: *mut Track) {
    unsafe {
        release_hostname(track);
        reset_hostname(track);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ConntrackExtractConn(
    key: *mut Key,
    reverse: bool,
    packet: *const Packet,
) -> bool {
    unsafe {
        zapret_conntrack_key(
            key,
            (*packet).ipv4,
            (*packet).ipv6,
            (*packet).tcp,
            (*packet).udp,
            c_int::from(reverse),
        ) != 0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ConntrackPoolDoubleSearch(
    table: *mut Table,
    packet: *const Packet,
    track: *mut *mut Track,
    reverse: *mut bool,
) -> bool {
    let mut key = MaybeUninit::<Key>::uninit();
    if !unsafe { ConntrackExtractConn(key.as_mut_ptr(), false, packet) } {
        return false;
    }
    let mut incoming = 0;
    let entry = unsafe { zapret_conntrack_find((*table).pool, key.as_ptr(), &mut incoming) };
    if entry.is_null() {
        return false;
    }
    unsafe {
        if !track.is_null() {
            track.write(&raw mut (*entry).track);
        }
        if !reverse.is_null() {
            reverse.write(incoming != 0);
        }
    }
    true
}

unsafe fn packet_input(packet: *const Packet) -> PacketInput {
    unsafe {
        let ipv6 = (*packet).ipv6;
        PacketInput {
            tcp: (*packet).tcp,
            tcp_size: (*packet).transport_size,
            payload_size: (*packet).payload_size,
            // The native IPv6 header can be unaligned within the packet buffer.
            ipv6_flow: if ipv6.is_null() {
                0
            } else {
                u32::from_be(ipv6.cast::<u32>().read_unaligned())
            },
            ipv6: u32::from(!ipv6.is_null()),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_conntrack_until_vm(
    state: &mut Lifecycle,
    context: &mut Context,
) -> u32 {
    loop {
        let operation = unsafe { zapret_conntrack_lifecycle_step(state) };
        let track = state.track;
        let entry = state.element;
        let table = context.table;
        let packet = context.packet;
        unsafe {
            match operation {
                0 | 5 | 6 | 11 | 12 | 14 => return operation,
                1 => release_hostname(track),
                2 => reset_hostname(track),
                3 => ReasmClear(&raw mut (*track).reassembly),
                4 => rawpacket_queue_destroy(&raw mut (*track).delayed),
                7 => free(entry.cast()),
                8 => track.write_bytes(0, 1),
                9 => {
                    (*track).lua_instance_cutoff = LUA_NOREF;
                    (*track).lua_state = LUA_NOREF;
                    (*track).l7 = L7_UNKNOWN;
                    (*track).reassembly_payload = L7P_UNKNOWN;
                }
                10 => rawpacket_queue_init(&raw mut (*track).delayed, state.queue_limit),
                16 => state.now = boottime(),
                18 => state.element = malloc(size_of::<Entry>()).cast(),
                19 => ptr::copy_nonoverlapping(&raw const context.key, &raw mut (*entry).key, 1),
                20 => {
                    state.status =
                        zapret_conntrack_insert(&raw mut (*table).pool, &context.key, entry) as u32
                }
                21 => state.track = &raw mut (*entry).track,
                22 => state.element = zapret_conntrack_after((*table).pool, &mut state.cursor),
                23 => {
                    zapret_conntrack_remove(&raw mut (*table).pool, &raw const (*entry).key);
                }
                24 => {
                    state.status = u32::from(ConntrackExtractConn(
                        &raw mut context.key,
                        state.reverse != 0,
                        packet,
                    ))
                }
                25 => {
                    let incoming = if state.find_direction == 0 {
                        ptr::null_mut()
                    } else {
                        &raw mut state.incoming
                    };
                    state.element = zapret_conntrack_find((*table).pool, &context.key, incoming);
                }
                26 => {
                    state.status =
                        zapret_conntrack_start((*packet).tcp, c_int::from(!(*packet).udp.is_null()))
                            as u32
                }
                27 => context.input = packet_input(packet),
                28 => {
                    state.status = zapret_conntrack_update(
                        &raw mut (*track).positions,
                        &context.input,
                        state.reverse as c_int,
                        state.reset as c_int,
                    ) as u32
                }
                29 => {
                    clock_gettime(CLOCK_BOOT_OR_UPTIME, &raw mut (*track).positions.last);
                }
                30 => {
                    // The native timespec starts with its signed seconds field.
                    let seconds = (&raw const (*track).start).cast::<i64>().read();
                    state.status = u32::from(seconds == 0);
                }
                31 => ptr::copy_nonoverlapping(
                    &raw const (*track).positions.last,
                    &raw mut (*track).start,
                    1,
                ),
                32 => state.out_track.write(track),
                33 => state.out_reverse.write(state.reverse != 0),
                34 => {
                    state.tcp = u32::from(!(*packet).tcp.is_null());
                    state.udp = u32::from(!(*packet).udp.is_null());
                }
                35 => (*track).positions.protocol = state.protocol as u8,
                36 => {
                    state.last = (*table).last_purge;
                    state.interval = (*table).interval;
                }
                37 => {
                    state.status = zapret_conntrack_expired(
                        table,
                        &raw const (*entry).track.positions,
                        (*entry).key.protocol,
                        c_int::from((*entry).track.cutoff),
                        state.now,
                    ) as u32
                }
                38 => (*table).last_purge = state.now,
                // The old init action is handled by the complete Rust export.
                _ => return operation,
            }
        }
    }
}

const LUA_REGISTRYINDEX: c_int = -10_000;

unsafe extern "C-unwind" {
    fn luaL_unref(lua: *mut c_void, table: c_int, reference: c_int);
    fn lua_createtable(lua: *mut c_void, array: c_int, records: c_int);
    fn luaL_ref(lua: *mut c_void, table: c_int) -> c_int;
}

unsafe fn conntrack_entry(
    opcode: u32,
    table: *mut Table,
    packet: *const Packet,
    out_track: *mut *mut Track,
    out_reverse: *mut bool,
) -> usize {
    // The C entry initializes its scalar and nullable fields to zero.
    let mut state: Lifecycle = unsafe { core::mem::zeroed() };
    let mut context: Context = unsafe { core::mem::zeroed() };
    state.entry = opcode;
    state.out_track = out_track;
    state.out_reverse = out_reverse;
    context.table = table;
    context.packet = packet;
    // The live VM may change during any registry operation.
    let lua_slot = unsafe { params_address().add(PARAMS.lua).cast::<*mut c_void>() };
    unsafe {
        loop {
            let operation = zapret_engine_conntrack_until_vm(&mut state, &mut context);
            if operation == 0 {
                return state.result;
            }
            let lua = lua_slot.read();
            let track = state.track;
            match operation {
                5 => luaL_unref(lua, LUA_REGISTRYINDEX, (*track).lua_state),
                6 => luaL_unref(lua, LUA_REGISTRYINDEX, (*track).lua_instance_cutoff),
                11 => lua_createtable(lua, 0, 0),
                12 => (&raw mut (*track).lua_state).write(luaL_ref(lua, LUA_REGISTRYINDEX)),
                14 => {
                    (&raw mut (*track).lua_instance_cutoff).write(luaL_ref(lua, LUA_REGISTRYINDEX))
                }
                _ => abort(),
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn ConntrackPoolDestroy(table: *mut Table) {
    unsafe { conntrack_entry(5, table, ptr::null(), ptr::null_mut(), ptr::null_mut()) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn ConntrackPoolFeed(
    table: *mut Table,
    packet: *const Packet,
    track: *mut *mut Track,
    reverse: *mut bool,
) -> bool {
    unsafe { conntrack_entry(10, table, packet, track, reverse) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn ConntrackPoolDrop(table: *mut Table, packet: *const Packet) -> bool {
    unsafe { conntrack_entry(11, table, packet, ptr::null_mut(), ptr::null_mut()) != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn ConntrackPoolPurge(table: *mut Table) {
    unsafe { conntrack_entry(12, table, ptr::null(), ptr::null_mut(), ptr::null_mut()) };
}
