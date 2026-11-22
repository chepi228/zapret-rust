//! Connection snapshots for C-owned Lua table construction. Never invokes Lua.
mod publication;
use crate::{
    conntrack::{Position, Positions, Timestamp},
    play_prolog::connection,
    protocol::l7proto_str,
};
use std::{
    ffi::{c_char, c_void},
    ptr,
};

// Read named fields only: C does not promise initialized structure padding.
#[repr(C)]
struct TrackHead {
    checks: [u8; 3],
    started: Timestamp,
    positions: Positions,
}

#[repr(C)]
#[derive(Default)]
struct PositionView {
    counters: [i64; 3],
    tcp: [i64; 10],
    ipv6_flow: u32,
    is_tcp: bool,
    over_2g: bool,
}

#[repr(C)]
#[derive(Default)]
struct TrackView {
    positions: [PositionView; 2],
    hostname: *const c_char,
    protocol: *const c_char,
    started: f64,
    elapsed: f64,
    lua_state: i32,
    incoming_ttl: u8,
    hostname_is_ip: bool,
    incoming_cutoff: bool,
    outgoing_cutoff: bool,
    direct_is_server: bool,
}

fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}

unsafe fn position_view(position: *const Position, tcp: bool) -> PositionView {
    let mut view = PositionView {
        counters: unsafe {
            [
                (*position).packets as i64,
                (*position).data_packets as i64,
                (*position).bytes as i64,
            ]
        },
        tcp: [0; 10],
        ipv6_flow: unsafe { (*position).ipv6_flow },
        is_tcp: tcp,
        over_2g: false,
    };
    if tcp {
        // C performs these subtractions as uint32_t, then widens to Lua's
        // signed 64-bit integer. Do not sign-extend the relative positions.
        let initial = unsafe { (*position).initial_sequence };
        view.tcp = unsafe {
            [
                i64::from(initial),
                i64::from((*position).sequence),
                i64::from((*position).sequence.wrapping_sub(initial)),
                i64::from((*position).position.wrapping_sub(initial)),
                i64::from((*position).upper.wrapping_sub(initial)),
                i64::from((*position).previous_upper.wrapping_sub(initial)),
                i64::from((*position).window),
                i64::from((*position).calculated_window),
                i64::from((*position).scale),
                i64::from((*position).mss),
            ]
        };
        view.over_2g = unsafe { (*position).over_2g != 0 };
    }
    view
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_track_position(
    track: *const c_void,
    position: *const Position,
    output: *mut PositionView,
) -> bool {
    let head = track.cast::<TrackHead>();
    if !valid(head) || !valid(position) || !valid(output) {
        return false;
    }
    let tcp = unsafe { (*head).positions.protocol == 6 };
    let view = unsafe { position_view(position, tcp) };
    unsafe { output.write(view) };
    true
}

// 0 is the ordinary nil connection, 1 publishes a view, 2 rejects an invalid
// pointer without modifying output. All borrowed strings remain owned by C.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_track_view(
    track: *const c_void,
    mut positions: *const Positions,
    incoming: bool,
    server: bool,
    output: *mut TrackView,
) -> u32 {
    if !valid(output) {
        return 2;
    }
    if track.is_null() {
        return 0;
    }
    let head = track.cast::<TrackHead>();
    if !valid(head) {
        return 2;
    }
    if positions.is_null() {
        positions = unsafe { ptr::addr_of!((*head).positions) };
    }
    if !valid(positions) {
        return 2;
    }
    let metadata = unsafe { connection(track.cast_mut()) };
    let tcp = unsafe { (*head).positions.protocol == 6 };
    // Cast seconds separately before subtracting, matching Lua/C rounding
    // even for clocks outside f64's exact integer range.
    let started = unsafe {
        (*head).started.seconds as f64 + f64::from((*head).started.nanoseconds) / 1_000_000_000.0
    };
    let elapsed = unsafe {
        (*positions).last.seconds as f64 - (*head).started.seconds as f64
            + f64::from(
                (*positions)
                    .last
                    .nanoseconds
                    .wrapping_sub((*head).started.nanoseconds),
            ) / 1_000_000_000.0
    };
    let hostname = unsafe { (*metadata).hostname };
    let view = TrackView {
        positions: unsafe {
            [
                position_view(ptr::addr_of!((*positions).client), tcp),
                position_view(ptr::addr_of!((*positions).server), tcp),
            ]
        },
        hostname,
        protocol: l7proto_str(unsafe { (*metadata).l7 }),
        started,
        elapsed,
        lua_state: unsafe { (*metadata).lua_state },
        incoming_ttl: unsafe { (*metadata).incoming_ttl },
        // This optional flag is not read by the C view without a hostname.
        hostname_is_ip: !hostname.is_null() && unsafe { (*metadata).hostname_is_ip },
        incoming_cutoff: unsafe { (*metadata).lua_in_cutoff },
        outgoing_cutoff: unsafe { (*metadata).lua_out_cutoff },
        direct_is_server: incoming ^ server,
    };
    unsafe { output.write(view) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn tcp_view_preserves_unsigned_wrap_and_signed_counter_conversion() {
        // The native C ABI places the live positions at byte 24 and its
        // protocol at byte 152. The full C oracle verifies these offsets.
        let mut track = [0u64; 28];
        unsafe { track.as_mut_ptr().cast::<u8>().add(24 + 152).write(6) };
        let mut position = Position::default();
        position.packets = u64::MAX;
        position.data_packets = 1 << 63;
        position.bytes = 42;
        position.ipv6_flow = 0x12345678;
        position.sequence = 2;
        position.initial_sequence = u32::MAX;
        position.position = 0;
        position.previous_upper = u32::MAX - 1;
        position.over_2g = 1;
        let mut out = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_track_position(track.as_ptr().cast(), &position, out.as_mut_ptr())
        });
        let out = unsafe { out.assume_init() };
        assert_eq!(out.counters, [-1, i64::MIN, 42]);
        assert_eq!(out.tcp[..4], [i64::from(u32::MAX), 2, 3, 1]);
        assert_eq!(out.tcp[5], i64::from(u32::MAX));
        assert!(out.is_tcp && out.over_2g);
        assert_eq!(out.ipv6_flow, 0x12345678);
    }

    #[test]
    fn non_tcp_does_not_read_uninitialized_tcp_fields() {
        let mut track = [0u64; 28];
        unsafe { track.as_mut_ptr().cast::<u8>().add(24 + 152).write(17) };
        let mut input = MaybeUninit::<Position>::uninit();
        let position = input.as_mut_ptr();
        unsafe {
            ptr::addr_of_mut!((*position).packets).write(3);
            ptr::addr_of_mut!((*position).data_packets).write(2);
            ptr::addr_of_mut!((*position).bytes).write(1);
            ptr::addr_of_mut!((*position).ipv6_flow).write(0);
        }
        let mut output = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_track_position(track.as_ptr().cast(), position, output.as_mut_ptr())
        });
        let output = unsafe { output.assume_init() };
        assert_eq!(output.counters, [3, 2, 1]);
        assert!(!output.is_tcp && !output.over_2g);
        assert_eq!(output.tcp, [0; 10]);
    }

    #[test]
    fn null_connection_ignores_snapshot_and_preserves_output() {
        let mut output = MaybeUninit::<TrackView>::uninit();
        unsafe {
            output
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0xa5, size_of::<TrackView>())
        };
        assert_eq!(
            unsafe {
                zapret_lua_track_view(
                    ptr::null(),
                    ptr::dangling(),
                    true,
                    false,
                    output.as_mut_ptr(),
                )
            },
            0
        );
        let bytes = unsafe {
            std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), size_of::<TrackView>())
        };
        assert!(bytes.iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn native_record_layout_matches_the_shared_connection_types() {
        use crate::profile_rediscovery::Connection;
        let pointer = size_of::<usize>();
        assert_eq!(std::mem::offset_of!(TrackHead, positions), 24);
        assert_eq!(size_of::<TrackHead>(), 184);
        assert_eq!(
            std::mem::offset_of!(Connection, lua_state),
            20 + 2 * pointer
        );
        assert_eq!(size_of::<PositionView>(), 112);
        assert_eq!(size_of::<TrackView>(), 256 + 2 * pointer);
    }
}
