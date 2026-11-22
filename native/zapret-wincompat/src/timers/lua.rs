//! Complete timer entry policies. All Lua and native callbacks remain in C.
use super::TimerInfo;
use std::ffi::c_char;
#[cfg(test)]
use std::ptr;

#[repr(C)]
struct Report {
    format: *const c_char,
    reason: *const c_char,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_timer_report(removed: bool, succeeded: bool) -> Report {
    if removed {
        Report {
            format: c"timer: '%s' deleted because of %s\n".as_ptr(),
            reason: if succeeded { c"oneshot" } else { c"error" }.as_ptr(),
        }
    } else {
        Report {
            format: c"\ntimer: '%s' period %llu oneshot %u fires=%u\n".as_ptr(),
            reason: std::ptr::null(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct State {
    timer: TimerInfo,
    old: TimerInfo,
    name: *const c_char,
    function: *const c_char,
    after: u64,
    index: i64,
    argc: i32,
    result: i32,
    mode: u32,
    phase: u32,
}
#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    kind: u32,
    index: i32,
}
#[repr(C)]
#[derive(Default)]
struct Value {
    data: *const c_char,
    integer: i64,
    code: i32,
}
fn action(kind: u32, index: i32) -> Action {
    Action {
        kind,
        index,
        ..Action::default()
    }
}
fn named(kind: u32, name: &std::ffi::CStr, integer: i64) -> Action {
    Action {
        name: name.as_ptr(),
        integer,
        ..action(kind, 0)
    }
}
fn done(state: &mut State) -> Action {
    state.phase = 99;
    Action {
        integer: i64::from(state.mode != 0),
        ..Action::default()
    }
}
fn error(state: &mut State, message: &std::ffi::CStr, callback: bool) -> Action {
    state.phase = 99;
    Action {
        name: message.as_ptr(),
        data: state.function,
        ..action(16, i32::from(callback))
    }
}
fn begin(mode: u32) -> Option<(State, Action)> {
    let (name, min, max) = match mode {
        0 => (c"timer_set", 3, 5),
        1 => (c"timer_del", 1, 1),
        2 => (c"timer_info", 1, 1),
        3 => (c"timer_enum", 0, 0),
        _ => return None,
    };
    Some((
        State {
            mode,
            index: 1,
            timer: TimerInfo {
                data_ref: -2,
                ..TimerInfo::default()
            },
            ..State::default()
        },
        Action {
            index: max,
            ..named(1, name, min)
        },
    ))
}
fn set_flags(state: &mut State) -> Action {
    if state.argc >= 4 {
        state.phase = 8;
        action(9, 4)
    } else {
        state.timer.oneshot = 0;
        state.phase = 9;
        action(10, 0)
    }
}
fn set_native(state: &mut State) -> Action {
    state.phase = 14;
    action(12, 0)
}
fn set_next(state: &mut State, value: &Value) -> Option<Action> {
    let next = match state.phase {
        0 => {
            state.argc = i32::try_from(value.integer).ok()?;
            state.phase = 1;
            action(2, 1)
        }
        1 => {
            if value.data.is_null() {
                return None;
            }
            state.name = value.data;
            state.phase = 2;
            action(3, 3)
        }
        2 => {
            if value.integer < 10 {
                return Some(error(
                    state,
                    c"invalid timer period. must be >=10 ms",
                    false,
                ));
            }
            state.timer.period = value.integer as u64;
            state.phase = 3;
            action(4, 2)
        }
        3 => match value.code {
            4 => {
                state.phase = 4;
                action(5, 2)
            }
            6 => {
                state.phase = 7;
                action(8, 2)
            }
            _ => error(state, c"invalid timer function type", false),
        },
        4 => {
            if value.data.is_null() {
                return None;
            }
            state.function = value.data;
            state.phase = 5;
            Action {
                data: state.function,
                ..action(6, 0)
            }
        }
        5 => {
            state.phase = 6;
            action(7, -1)
        }
        6 => {
            if value.code == 0 {
                error(state, c"timer function '%s' does not exist", true)
            } else {
                set_flags(state)
            }
        }
        7 => set_flags(state),
        8 => {
            state.timer.oneshot = u32::from(value.code != 0);
            state.phase = 9;
            action(10, 0)
        }
        9 => {
            state.timer.func_ref = value.code;
            state.phase = 10;
            Action {
                data: state.name,
                ..action(11, 0)
            }
        }
        10 => {
            state.phase = 11;
            action(10, 0)
        }
        11 => {
            state.timer.name_ref = value.code;
            if state.argc >= 5 {
                state.phase = 12;
                action(8, 5)
            } else {
                set_native(state)
            }
        }
        12 => {
            state.phase = 13;
            action(10, 0)
        }
        13 => {
            state.timer.data_ref = value.code;
            set_native(state)
        }
        14 => {
            state.result = value.code;
            if value.code < 0 {
                state.phase = 15;
                action(13, 0)
            } else if value.code != 0 {
                state.phase = 16;
                action(13, 1)
            } else {
                state.phase = 17;
                action(14, 0)
            }
        }
        15 => error(state, c"could not create timer", false),
        16 => {
            state.phase = 17;
            action(14, 0)
        }
        17 => {
            state.phase = 18;
            Action {
                data: if state.result != 0 {
                    c"replaced"
                } else {
                    c"created"
                }
                .as_ptr(),
                ..named(15, c"timer: '%s' %s. period %llu oneshot %u\n", 0)
            }
        }
        18 => done(state),
        _ => return None,
    };
    Some(next)
}
fn delete_log(state: &mut State) -> Action {
    state.phase = 5;
    Action {
        data: if state.result != 0 {
            c"deleted"
        } else {
            c"not found"
        }
        .as_ptr(),
        ..named(19, c"timer: '%s' %s\n", 0)
    }
}
fn delete_next(state: &mut State, value: &Value) -> Option<Action> {
    Some(match state.phase {
        0 => {
            state.phase = 1;
            action(2, 1)
        }
        1 => {
            if value.data.is_null() {
                return None;
            }
            state.name = value.data;
            state.phase = 2;
            action(17, 0)
        }
        2 => {
            if value.code != 0 {
                state.phase = 3;
                action(18, 0)
            } else {
                state.result = 0;
                delete_log(state)
            }
        }
        3 => {
            state.result = i32::from(value.code != 0);
            if state.result != 0 {
                state.phase = 4;
                action(13, 1)
            } else {
                delete_log(state)
            }
        }
        4 => {
            state.phase = 6;
            action(14, 0)
        }
        6 => delete_log(state),
        5 => {
            state.phase = 7;
            Action {
                integer: i64::from(state.result),
                ..action(20, 0)
            }
        }
        7 => done(state),
        _ => return None,
    })
}
fn literal(name: &std::ffi::CStr) -> Action {
    named(22, name, name.to_bytes().len() as i64)
}
fn info_next(state: &mut State, value: &Value) -> Option<Action> {
    Some(match state.phase {
        0 => {
            state.phase = 2;
            // Preserve the original C expression's pool observation before a
            // coercing name check can allocate or re-enter the timer API.
            action(30, 1)
        }
        2 => {
            if value.code != 0 {
                state.phase = 3;
                action(21, 0)
            } else {
                state.phase = 12;
                action(29, 0)
            }
        }
        3 => {
            state.phase = 4;
            literal(c"name")
        }
        4 => {
            state.phase = 5;
            Action {
                integer: i64::from(state.timer.name_ref),
                ..action(23, 0)
            }
        }
        5 => {
            state.phase = 6;
            action(24, -3)
        }
        6 => {
            state.phase = 7;
            literal(c"func")
        }
        7 => {
            state.phase = 8;
            Action {
                integer: i64::from(state.timer.func_ref),
                ..action(23, 0)
            }
        }
        8 => {
            state.phase = 9;
            action(24, -3)
        }
        9 => {
            state.phase = 10;
            named(25, c"period", state.timer.period as i64)
        }
        10 => {
            state.phase = 11;
            named(26, c"oneshot", i64::from(state.timer.oneshot != 0))
        }
        11 => {
            state.phase = 12;
            named(25, c"fires", i64::from(state.timer.fires))
        }
        12 => done(state),
        _ => return None,
    })
}
fn enum_next(state: &mut State, value: &Value) -> Option<Action> {
    Some(match state.phase {
        0 => {
            state.phase = 1;
            action(21, 0)
        }
        1 => {
            state.phase = 2;
            action(27, 0)
        }
        2 => {
            if value.code == 0 {
                done(state)
            } else {
                state.phase = 3;
                Action {
                    integer: i64::from(state.timer.name_ref),
                    ..action(23, 0)
                }
            }
        }
        3 => {
            let index = state.index;
            state.index = state.index.wrapping_add(1);
            state.phase = 4;
            Action {
                integer: index,
                ..action(28, -2)
            }
        }
        4 => {
            state.after = state.timer.id;
            state.phase = 2;
            action(27, 0)
        }
        _ => return None,
    })
}
fn step(state: &mut State, value: &Value) -> Option<Action> {
    match state.mode {
        0 => set_next(state, value),
        1 => delete_next(state, value),
        2 => info_next(state, value),
        3 => enum_next(state, value),
        _ => None,
    }
}
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
/// # Safety
/// Disjoint aligned outputs are writable. C keeps rooted strings and all state
/// storage alive until the selected entry returns or C unwinds a VM error.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_timer_begin(
    mode: u32,
    state: *mut State,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some((initial, action)) = begin(mode) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned state, observation and output storage is live/initialized.
/// C writes native timer snapshots before reporting a successful query. No Lua
/// callback executes until this function and all Rust borrows have returned.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_timer_step(
    state: *mut State,
    value: *const Value,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(value) || !valid(output) {
        return false;
    }
    let Some(action) = step(unsafe { &mut *state }, unsafe { &*value }) else {
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
    fn next(state: &mut State, integer: i64, code: i32) -> Action {
        step(
            state,
            &Value {
                integer,
                code,
                data: c"fixture".as_ptr(),
            },
        )
        .unwrap()
    }
    #[test]
    fn period_validation_precedes_callback_inspection() {
        let (mut state, arity) = begin(0).unwrap();
        assert_eq!((arity.kind, arity.integer, arity.index), (1, 3, 5));
        assert_eq!(next(&mut state, 3, 0).kind, 2);
        assert_eq!(next(&mut state, 0, 0).kind, 3);
        let failure = next(&mut state, 9, 0);
        assert_eq!(failure.kind, 16);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(failure.name) }.to_bytes(),
            b"invalid timer period. must be >=10 ms"
        );
    }
    #[test]
    fn replacement_releases_old_references_before_dirty_and_log() {
        let (mut state, _) = begin(0).unwrap();
        state.phase = 14;
        assert_eq!(next(&mut state, 0, 1).index, 1);
        assert_eq!(next(&mut state, 0, 0).kind, 14);
        let log = next(&mut state, 0, 0);
        assert_eq!(log.kind, 15);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(log.data) }.to_bytes(),
            b"replaced"
        );
        assert_eq!(next(&mut state, 0, 0).integer, 0);
    }
    #[test]
    fn creation_failure_releases_new_references_without_dirty_or_log() {
        let (mut state, _) = begin(0).unwrap();
        state.phase = 14;
        let release = next(&mut state, 0, -1);
        assert_eq!((release.kind, release.index), (13, 0));
        assert_eq!(next(&mut state, 0, 0).kind, 16);
        assert!(step(&mut state, &Value::default()).is_none());
    }
    #[test]
    fn optional_data_and_truthiness_keep_reference_creation_order() {
        let (mut state, _) = begin(0).unwrap();
        state.argc = 5;
        state.phase = 7;
        assert_eq!(next(&mut state, 0, 0).kind, 9);
        assert_eq!(next(&mut state, 0, -7).kind, 10);
        assert_eq!(state.timer.oneshot, 1);
        assert_eq!(next(&mut state, 0, 11).kind, 11);
        assert_eq!(next(&mut state, 0, 0).kind, 10);
        let data = next(&mut state, 0, 12);
        assert_eq!((data.kind, data.index), (8, 5));
        assert_eq!(next(&mut state, 0, 0).kind, 10);
        assert_eq!(next(&mut state, 0, -1).kind, 12);
        assert_eq!(
            (
                state.timer.func_ref,
                state.timer.name_ref,
                state.timer.data_ref
            ),
            (11, 12, -1)
        );
        let (mut absent, _) = begin(0).unwrap();
        absent.argc = 3;
        absent.phase = 7;
        assert_eq!(next(&mut absent, 0, 0).kind, 10);
        assert_eq!((absent.timer.oneshot, absent.timer.data_ref), (0, -2));
    }
    #[test]
    fn info_reads_references_after_keys_and_unsigned_values_at_publication() {
        let (mut state, _) = begin(2).unwrap();
        state.phase = 3;
        assert_eq!(next(&mut state, 0, 0).kind, 22);
        state.timer.name_ref = 123;
        assert_eq!(next(&mut state, 0, 0).integer, 123);
        state.phase = 9;
        state.timer.period = u64::MAX;
        assert_eq!(next(&mut state, 0, 0).integer, -1);
        state.timer.oneshot = u32::MAX;
        assert_eq!(next(&mut state, 0, 0).integer, 1);
        state.timer.fires = u32::MAX;
        assert_eq!(next(&mut state, 0, 0).integer, i64::from(u32::MAX));
    }
    #[test]
    fn info_keeps_pool_capture_and_name_check_in_the_original_c_expression() {
        let (mut state, _) = begin(2).unwrap();
        let query = next(&mut state, 0, 0);
        assert_eq!((query.kind, query.index, state.phase), (30, 1, 2));
        assert_eq!(next(&mut state, 0, 0).kind, 29);
        assert_eq!(next(&mut state, 0, 0).integer, 1);
    }
    #[test]
    fn enumeration_reads_the_next_id_after_rawseti() {
        let (mut state, _) = begin(3).unwrap();
        state.phase = 2;
        state.timer.id = 10;
        state.timer.name_ref = 19;
        assert_eq!(next(&mut state, 0, 1).integer, 19);
        let insert = next(&mut state, 0, 0);
        assert_eq!((insert.kind, insert.integer, state.after), (28, 1, 0));
        state.timer.id = 77;
        assert_eq!(next(&mut state, 0, 0).kind, 27);
        assert_eq!((state.after, state.index), (77, 2));
        assert_eq!(next(&mut state, 0, 0).integer, 1);
    }
    #[test]
    fn deletion_short_circuits_and_marks_dirty_only_after_removal() {
        let (mut absent, _) = begin(1).unwrap();
        absent.phase = 2;
        assert_eq!(next(&mut absent, 0, 0).kind, 19);
        assert_eq!(next(&mut absent, 0, 0).integer, 0);
        let (mut state, _) = begin(1).unwrap();
        state.phase = 2;
        assert_eq!(next(&mut state, 0, 1).kind, 18);
        assert_eq!(next(&mut state, 0, 1).kind, 13);
        assert_eq!(next(&mut state, 0, 0).kind, 14);
        assert_eq!(next(&mut state, 0, 0).kind, 19);
        assert_eq!(next(&mut state, 0, 0).integer, 1);
    }
    #[test]
    fn invalid_abi_preserves_outputs_and_layout_is_fixed() {
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<State>(), 112 + 2 * pointer);
        assert_eq!(size_of::<Action>(), 16 + 2 * pointer);
        assert_eq!(size_of::<Value>(), 24);
        let mut state = State::default();
        let mut out = action(91, 0);
        assert!(!unsafe { zapret_lua_timer_begin(4, &mut state, &mut out) });
        assert_eq!(out.kind, 91);
        assert!(!unsafe { zapret_lua_timer_step(&mut state, ptr::null(), &mut out) });
        assert_eq!(out.kind, 91);
    }
}
