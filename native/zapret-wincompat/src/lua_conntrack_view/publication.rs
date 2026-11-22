//! Metadata and publication steps; VM calls stay on the C side of the boundary.
use super::*;

const COUNTERS: [&std::ffi::CStr; 3] = [c"pcounter", c"pdcounter", c"pbcounter"];
const TCP: [&std::ffi::CStr; 10] = [
    c"seq0",
    c"seq",
    c"rseq",
    c"pos",
    c"uppos",
    c"uppos_prev",
    c"winsize",
    c"winsize_calc",
    c"scale",
    c"mss",
];
fn position_capacity() -> i64 {
    11
}
#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    floating: f64,
    kind: u32,
    index: i32,
}
fn named(kind: u32, name: &std::ffi::CStr) -> Action {
    Action {
        name: name.as_ptr(),
        kind,
        ..Action::default()
    }
}
fn literal(name: &std::ffi::CStr) -> Action {
    Action {
        integer: name.to_bytes().len() as i64,
        ..named(9, name)
    }
}
fn integer(name: &std::ffi::CStr, value: i64) -> Action {
    Action {
        integer: value,
        ..named(4, name)
    }
}
fn boolean(name: &std::ffi::CStr, value: bool) -> Action {
    Action {
        integer: i64::from(value),
        ..named(5, name)
    }
}
fn number(name: &std::ffi::CStr, value: f64) -> Action {
    Action {
        floating: value,
        ..named(8, name)
    }
}
fn string(name: &std::ffi::CStr, value: *const c_char) -> Action {
    Action {
        data: value,
        ..named(6, name)
    }
}
fn rawset() -> Action {
    Action {
        kind: 10,
        index: -3,
        ..Action::default()
    }
}

#[repr(C)]
struct PositionState {
    view: *const PositionView,
    index: u32,
    phase: u32,
}
unsafe fn position_next(state: &mut PositionState) -> Option<Action> {
    if !valid(state.view) || state.index > 10 {
        return None;
    }
    loop {
        // SAFETY: only the current view field is read, at its original VM
        // boundary. The caller keeps the view alive and initializes it in time.
        unsafe {
            match state.phase {
                0 if state.index < 3 => {
                    let index = state.index as usize;
                    state.index += 1;
                    return Some(integer(COUNTERS[index], (*state.view).counters[index]));
                }
                0 => state.phase = 1,
                1 => {
                    state.phase = 2;
                    let value = (*state.view).ipv6_flow;
                    if value != 0 {
                        return Some(integer(c"ip6_flow", i64::from(value)));
                    }
                }
                2 => {
                    if (*state.view).is_tcp {
                        state.phase = 3;
                        state.index = 0;
                        return Some(literal(c"tcp"));
                    }
                    state.phase = 8;
                    return Some(Action::default());
                }
                3 => {
                    state.phase = 4;
                    return Some(Action {
                        kind: 3,
                        integer: position_capacity(),
                        ..Action::default()
                    });
                }
                4 if state.index < 10 => {
                    let index = state.index as usize;
                    state.index += 1;
                    if index == 2 {
                        state.phase = 5;
                    }
                    return Some(integer(TCP[index], (*state.view).tcp[index]));
                }
                4 => state.phase = 6,
                5 => {
                    state.phase = 4;
                    return Some(boolean(c"rseq_over_2G", (*state.view).over_2g));
                }
                6 => {
                    state.phase = 7;
                    return Some(rawset());
                }
                7 => {
                    state.phase = 8;
                    return Some(Action::default());
                }
                _ => return None,
            }
        }
    }
}
#[repr(C)]
struct TrackState {
    view: TrackView,
    mode: u32,
    phase: u32,
}
fn track_begin(mode: u32) -> Option<(TrackState, Action)> {
    if mode > 1 {
        return None;
    }
    Some((
        TrackState {
            view: TrackView::default(),
            mode,
            phase: if mode == 1 { 1 } else { 0 },
        },
        if mode == 1 {
            literal(c"track")
        } else {
            Action {
                kind: 1,
                ..Action::default()
            }
        },
    ))
}
fn track_next(state: &mut TrackState, status: u32) -> Option<Action> {
    if state.mode > 1 {
        return None;
    }
    loop {
        let output = match state.phase {
            0 => {
                if status == 0 {
                    state.phase = 30;
                    Action {
                        kind: 2,
                        ..Action::default()
                    }
                } else if status == 1 {
                    state.phase = 2;
                    Action {
                        kind: 3,
                        integer: 9,
                        ..Action::default()
                    }
                } else {
                    state.phase = 32;
                    named(13, c"invalid connection view")
                }
            }
            1 => {
                state.phase = 0;
                Action {
                    kind: 1,
                    ..Action::default()
                }
            }
            2 => {
                state.phase = 3;
                if state.view.incoming_ttl == 0 {
                    continue;
                }
                integer(c"incoming_ttl", i64::from(state.view.incoming_ttl))
            }
            3 => {
                state.phase = 4;
                string(c"l7proto", state.view.protocol)
            }
            4 => {
                state.phase = 5;
                string(c"hostname", state.view.hostname)
            }
            5 => {
                state.phase = 6;
                if state.view.hostname.is_null() {
                    continue;
                }
                boolean(c"hostname_is_ip", state.view.hostname_is_ip)
            }
            6 => {
                state.phase = 7;
                Action {
                    integer: i64::from(state.view.lua_state),
                    ..named(7, c"lua_state")
                }
            }
            7 => {
                state.phase = 8;
                boolean(c"lua_in_cutoff", state.view.incoming_cutoff)
            }
            8 => {
                state.phase = 9;
                boolean(c"lua_out_cutoff", state.view.outgoing_cutoff)
            }
            9 => {
                state.phase = 10;
                number(c"t_start", state.view.started)
            }
            10 => {
                state.phase = 11;
                literal(c"pos")
            }
            11 => {
                state.phase = 12;
                Action {
                    kind: 3,
                    integer: 5,
                    ..Action::default()
                }
            }
            12 => {
                state.phase = 13;
                number(c"dt", state.view.elapsed)
            }
            13 => {
                state.phase = 14;
                literal(c"client")
            }
            14 => {
                state.phase = 15;
                Action {
                    kind: 3,
                    ..Action::default()
                }
            }
            15 => {
                state.phase = 16;
                Action {
                    kind: 12,
                    index: 0,
                    ..Action::default()
                }
            }
            16 => {
                state.phase = 17;
                rawset()
            }
            17 => {
                state.phase = 18;
                literal(c"server")
            }
            18 => {
                state.phase = 19;
                Action {
                    kind: 3,
                    ..Action::default()
                }
            }
            19 => {
                state.phase = 20;
                Action {
                    kind: 12,
                    index: 1,
                    ..Action::default()
                }
            }
            20 => {
                state.phase = 21;
                rawset()
            }
            21 => {
                state.phase = 22;
                literal(c"direct")
            }
            22 => {
                state.phase = 23;
                Action {
                    index: -2,
                    ..named(
                        11,
                        if state.view.direct_is_server {
                            c"server"
                        } else {
                            c"client"
                        },
                    )
                }
            }
            23 => {
                state.phase = 24;
                rawset()
            }
            24 => {
                state.phase = 25;
                literal(c"reverse")
            }
            25 => {
                state.phase = 26;
                Action {
                    index: -2,
                    ..named(
                        11,
                        if state.view.direct_is_server {
                            c"client"
                        } else {
                            c"server"
                        },
                    )
                }
            }
            26 => {
                state.phase = 27;
                rawset()
            }
            27 => {
                state.phase = 30;
                rawset()
            }
            30 if state.mode == 1 => {
                state.phase = 31;
                rawset()
            }
            30 => {
                state.phase = 32;
                Action {
                    index: 1,
                    ..Action::default()
                }
            }
            31 => {
                state.phase = 32;
                Action::default()
            }
            _ => return None,
        };
        return Some(output);
    }
}

/// # Safety
/// View points to live native view storage. State/action outputs are aligned,
/// writable and disjoint. Only the first counter is read before C's next call.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_position_publication_begin(
    view: *const PositionView,
    state: *mut PositionState,
    output: *mut Action,
) -> bool {
    if !valid(view) || !valid(state) || !valid(output) {
        return false;
    }
    let mut initial = PositionState {
        view,
        index: 0,
        phase: 0,
    };
    let Some(action) = (unsafe { position_next(&mut initial) }) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned metadata is initialized; the borrowed view remains live.
/// Each selected field must be initialized before its corresponding read step.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_position_publication_step(
    state: *mut PositionState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some(action) = (unsafe { position_next(&mut *state) }) else {
        return false;
    };
    unsafe {
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned outputs are writable. C fills the view using the existing
/// native query when requested, after any named-field prefix has been published.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_track_publication_begin(
    mode: u32,
    state: *mut TrackState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some((initial, action)) = track_begin(mode) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned metadata is initialized. Supply native query status only
/// for a query command. All view CStrings stay borrowed through VM publication.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_track_publication_step(
    state: *mut TrackState,
    status: u32,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some(action) = track_next(unsafe { &mut *state }, status) else {
        return false;
    };
    unsafe {
        output.write(action);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_position_capacity_includes_the_over_2g_flag() {
        assert_eq!(position_capacity(), 11);
    }

    #[test]
    fn field_prefix_precedes_query_and_nil_keeps_its_stack_delta() {
        for mode in 0..2 {
            let (mut state, first) = track_begin(mode).unwrap();
            assert_eq!(first.kind, if mode == 1 { 9 } else { 1 });
            if mode == 1 {
                assert_eq!(track_next(&mut state, 0).unwrap().kind, 1);
            }
            assert_eq!(track_next(&mut state, 0).unwrap().kind, 2);
            if mode == 1 {
                assert_eq!(track_next(&mut state, 0).unwrap().kind, 10);
            }
            assert_eq!(
                track_next(&mut state, 0).unwrap().index,
                if mode == 0 { 1 } else { 0 }
            );
        }
    }
    #[test]
    fn optional_flags_are_read_after_the_prior_vm_publication() {
        let (mut state, _) = track_begin(0).unwrap();
        assert_eq!(track_next(&mut state, 1).unwrap().integer, 9);
        state.view.incoming_ttl = 0;
        let protocol = track_next(&mut state, 0).unwrap();
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(protocol.name) }.to_bytes(),
            b"l7proto"
        );
        let hostname = track_next(&mut state, 0).unwrap();
        assert_eq!(hostname.kind, 6);
        state.view.hostname = c"".as_ptr();
        state.view.hostname_is_ip = true;
        assert_eq!(track_next(&mut state, 0).unwrap().integer, 1);
        state.view.lua_state = -2;
        assert_eq!(track_next(&mut state, 0).unwrap().integer, -2);
    }
    #[test]
    fn view_counters_and_tcp_flags_remain_deferred() {
        let mut view = std::mem::MaybeUninit::<PositionView>::uninit();
        let view = view.as_mut_ptr();
        let mut state = PositionState {
            view,
            index: 0,
            phase: 0,
        };
        unsafe {
            ptr::addr_of_mut!((*view).counters[0]).write(-1);
            assert_eq!(position_next(&mut state).unwrap().integer, -1);
            ptr::addr_of_mut!((*view).counters[1]).write(i64::MIN);
            assert_eq!(position_next(&mut state).unwrap().integer, i64::MIN);
            ptr::addr_of_mut!((*view).counters[2]).write(17);
            assert_eq!(position_next(&mut state).unwrap().integer, 17);
            ptr::addr_of_mut!((*view).ipv6_flow).write(0);
            ptr::addr_of_mut!((*view).is_tcp).write(true);
            assert_eq!(position_next(&mut state).unwrap().kind, 9);
            assert_eq!(position_next(&mut state).unwrap().integer, 11);
            for i in 0..3 {
                ptr::addr_of_mut!((*view).tcp[i]).write(i as i64);
                assert_eq!(position_next(&mut state).unwrap().integer, i as i64);
            }
            ptr::addr_of_mut!((*view).over_2g).write(true);
            let flag = position_next(&mut state).unwrap();
            assert_eq!((flag.kind, flag.integer), (5, 1));
        }
    }
    #[test]
    fn aliases_read_direction_after_the_key_and_reuse_getfield_targets() {
        let (mut state, _) = track_begin(0).unwrap();
        state.phase = 21;
        state.view.direct_is_server = false;
        assert_eq!(track_next(&mut state, 0).unwrap().kind, 9);
        state.view.direct_is_server = true;
        let alias = track_next(&mut state, 0).unwrap();
        assert_eq!((alias.kind, alias.index), (11, -2));
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(alias.name) }.to_bytes(),
            b"server"
        );
        state.phase = 24;
        track_next(&mut state, 0).unwrap();
        state.view.direct_is_server = false;
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(track_next(&mut state, 0).unwrap().name) }.to_bytes(),
            b"server"
        );
    }
    #[test]
    fn no_tcp_or_flow_skips_fields_without_removing_existing_parent_values() {
        let view = PositionView::default();
        let mut state = PositionState {
            view: &view,
            index: 3,
            phase: 0,
        };
        assert_eq!(unsafe { position_next(&mut state) }.unwrap().kind, 0);
        assert!(unsafe { position_next(&mut state) }.is_none());
    }
    #[test]
    fn invalid_abi_leaves_actions_unchanged() {
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<PositionState>(), pointer + 8);
        assert_eq!(size_of::<TrackState>(), 264 + 2 * pointer);
        assert_eq!(size_of::<Action>(), 2 * pointer + 24);
        let mut action = Action {
            kind: 91,
            ..Action::default()
        };
        let mut state = std::mem::MaybeUninit::<TrackState>::uninit();
        assert!(!unsafe { zapret_lua_track_publication_begin(2, state.as_mut_ptr(), &mut action) });
        assert_eq!(action.kind, 91);
        assert!(!unsafe { zapret_lua_position_publication_step(ptr::null_mut(), &mut action) });
        assert_eq!(action.kind, 91);
    }
}
