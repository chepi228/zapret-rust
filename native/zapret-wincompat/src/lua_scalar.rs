//! Remaining scalar/system Lua entry decisions. C alone performs VM operations.
use std::ffi::{c_char, c_void};

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}
#[derive(Default)]
#[repr(C)]
struct State {
    pointer: *const c_void,
    text: *const c_char,
    integer: i64,
    length: usize,
    guard: i32,
    count: i32,
    mode: u32,
    phase: u32,
}
#[derive(Default)]
#[repr(C)]
struct Action {
    text: *const c_char,
    data: *const c_void,
    integer: i64,
    length: usize,
    kind: u32,
    index: i32,
    mode: u32,
    count: i32,
}
#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    pointer: *const c_void,
    integer: i64,
    status: i32,
    count: i32,
}

const NAMES: [&std::ffi::CStr; 15] = [
    c"DLOG",
    c"DLOG_ERR",
    c"DLOG_CONDUP",
    c"getpid",
    c"gettid",
    c"get_ifaddrs",
    c"get_source_ip",
    c"uname",
    c"clock_gettime",
    c"clock_getfloattime",
    c"stat",
    c"localtime",
    c"gmtime",
    c"timelocal",
    c"timegm",
];
fn action(kind: u32, index: i32) -> Action {
    Action {
        kind,
        index,
        ..Action::default()
    }
}
fn guarded(mode: u32) -> bool {
    (6..=9).contains(&mode)
}
fn initial(mode: u32) -> Action {
    match mode {
        0..=2 | 10 => action(2, 1),
        3 => action(30, 0),
        4 => action(31, 0),
        5 => action(32, 0),
        6 => action(3, 1),
        7 => action(34, 0),
        8 | 9 => action(35, 0),
        11 | 12 => action(4, 1),
        13 => action(39, 0),
        14 => action(40, 0),
        _ => action(0, 0),
    }
}
fn begin(mode: u32, count: i32) -> Option<(State, Action)> {
    let name = NAMES.get(mode as usize)?;
    if count < 0 {
        return None;
    }
    let expected = if (3..=5).contains(&mode) || (7..=9).contains(&mode) {
        0
    } else {
        1
    };
    let mut state = State {
        mode,
        count: 1,
        ..State::default()
    };
    if count != expected {
        state.phase = 99;
        return Some((
            state,
            Action {
                text: name.as_ptr(),
                integer: i64::from(expected),
                count,
                ..action(1, 0)
            },
        ));
    }
    state.phase = if guarded(mode) { 1 } else { 2 };
    let first = if guarded(mode) {
        action(5, 0)
    } else {
        initial(mode)
    };
    Some((state, first))
}
fn done(state: &mut State, count: i32) -> Action {
    state.phase = 99;
    state.count = count;
    Action {
        count,
        ..action(0, 0)
    }
}
fn finish(state: &mut State, count: i32) -> Action {
    state.count = count;
    if guarded(state.mode) {
        state.phase = 9;
        action(5, 0)
    } else {
        done(state, count)
    }
}
fn publish(state: &mut State, result: Action, count: i32) -> Action {
    state.phase = 8;
    state.count = count;
    result
}
fn error(state: &mut State, mode: u32) -> Action {
    state.phase = 99;
    let format = match mode {
        0 => c"invalid IP length %u",
        _ => c"stack guard failure",
    };
    Action {
        text: format.as_ptr(),
        mode,
        length: state.length,
        ..action(11, 0)
    }
}
fn projection(state: &mut State, mode: u32, data: *const c_void) -> Action {
    state.phase = 5;
    Action {
        mode,
        data,
        ..action(12, 0)
    }
}
fn step(state: &mut State, value: &Value) -> Option<Action> {
    if state.mode >= 15 {
        return None;
    }
    Some(match state.phase {
        1 => {
            state.guard = i32::try_from(value.integer).ok()?;
            state.phase = 2;
            initial(state.mode)
        }
        2 => match state.mode {
            0..=2 => {
                if value.span.data.is_null() {
                    return None;
                }
                state.phase = 3;
                Action {
                    text: c"LUA: %s\n".as_ptr(),
                    data: value.span.data.cast(),
                    mode: state.mode,
                    ..action(10, 0)
                }
            }
            3 | 4 => publish(
                state,
                Action {
                    integer: value.integer,
                    ..action(8, 0)
                },
                1,
            ),
            5 | 13 | 14 => done(state, 1),
            6 => {
                if value.span.length > isize::MAX as usize
                    || value.span.length != 0 && value.span.data.is_null()
                    || value
                        .span
                        .data
                        .addr()
                        .checked_add(value.span.length)
                        .is_none()
                {
                    return None;
                }
                state.pointer = value.span.data.cast();
                state.length = value.span.length;
                state.phase = 4;
                Action {
                    data: state.pointer,
                    length: state.length,
                    ..action(33, 0)
                }
            }
            7..=9 => {
                let mode = if state.mode == 7 {
                    1
                } else if state.mode == 8 {
                    4
                } else {
                    5
                };
                projection(
                    state,
                    mode,
                    if value.status == 0 {
                        value.pointer
                    } else {
                        std::ptr::null()
                    },
                )
            }
            10 => {
                if value.span.data.is_null() {
                    return None;
                }
                state.phase = 6;
                Action {
                    data: value.span.data.cast(),
                    ..action(36, 0)
                }
            }
            11 | 12 => {
                state.phase = 7;
                Action {
                    integer: value.integer,
                    ..action(if state.mode == 11 { 37 } else { 38 }, 0)
                }
            }
            _ => return None,
        },
        3 => done(state, 0),
        4 => match value.status {
            0 => publish(state, action(7, 0), 1),
            1 => publish(
                state,
                Action {
                    data: value.pointer,
                    length: state.length,
                    ..action(6, 0)
                },
                1,
            ),
            _ => error(state, 0),
        },
        5 => {
            let count = if state.mode == 11 || state.mode == 12 {
                1
            } else {
                value.count
            };
            finish(state, count)
        }
        6 => {
            if value.status == 0 {
                projection(state, 0, value.pointer)
            } else {
                state.phase = 10;
                action(7, 0)
            }
        }
        7 => projection(state, if state.mode == 11 { 2 } else { 3 }, value.pointer),
        8 => finish(state, state.count),
        9 => {
            if i64::from(state.guard) + i64::from(state.count) != value.integer {
                error(state, 1)
            } else {
                done(state, state.count)
            }
        }
        10 => {
            state.phase = 11;
            action(41, 0)
        }
        11 => {
            if value.span.data.is_null() {
                done(state, 1)
            } else {
                state.phase = 12;
                Action {
                    data: value.span.data.cast(),
                    ..action(9, 0)
                }
            }
        }
        12 => {
            state.phase = 13;
            action(42, 0)
        }
        13 => {
            state.phase = 14;
            Action {
                integer: value.integer,
                ..action(8, 0)
            }
        }
        14 => done(state, 3),
        _ => return None,
    })
}

/// # Safety
/// State and action are disjoint, aligned writable outputs. No VM calls occur.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_scalar_begin(
    mode: u32,
    count: i32,
    state: *mut State,
    output: *mut Action,
) -> bool {
    if state.is_null() || !state.is_aligned() || output.is_null() || !output.is_aligned() {
        return false;
    }
    let Some((initial, action)) = begin(mode, count) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint initialized pointers are aligned and valid. Strings, input spans and
/// opaque native views remain rooted/readable until their selected C operation
/// finishes. Native calls and all VM operations execute after this function returns.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_scalar_step(
    state: *mut State,
    value: *const Value,
    output: *mut Action,
) -> bool {
    if state.is_null()
        || !state.is_aligned()
        || value.is_null()
        || !value.is_aligned()
        || output.is_null()
        || !output.is_aligned()
    {
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
    use std::{ffi::CStr, mem, ptr};
    fn next(state: &mut State, value: Value) -> Action {
        step(state, &value).unwrap()
    }
    fn top(state: &mut State, value: i64) -> Action {
        next(
            state,
            Value {
                integer: value,
                ..Value::default()
            },
        )
    }
    #[test]
    fn all_remaining_entries_choose_public_arity_errors_before_observations() {
        let names = [
            c"DLOG",
            c"DLOG_ERR",
            c"DLOG_CONDUP",
            c"getpid",
            c"gettid",
            c"get_ifaddrs",
            c"get_source_ip",
            c"uname",
            c"clock_gettime",
            c"clock_getfloattime",
            c"stat",
            c"localtime",
            c"gmtime",
            c"timelocal",
            c"timegm",
        ];
        for (mode, name) in names.into_iter().enumerate() {
            let (_, action) = begin(mode as u32, 3).unwrap();
            assert_eq!((action.kind, action.count), (1, 3));
            assert_eq!(unsafe { CStr::from_ptr(action.text) }, name);
        }
        assert!(begin(15, 0).is_none());
        assert!(begin(0, -1).is_none());
    }
    #[test]
    fn logging_coerces_one_string_then_keeps_target_and_zero_results() {
        for mode in 0..3 {
            let (mut state, first) = begin(mode, 1).unwrap();
            assert_eq!((first.kind, first.index), (2, 1));
            let action = next(
                &mut state,
                Value {
                    span: Span {
                        data: c"hello".as_ptr().cast(),
                        length: 0,
                    },
                    ..Value::default()
                },
            );
            assert_eq!((action.kind, action.mode), (10, mode));
            assert_eq!(action.data, c"hello".as_ptr().cast());
            assert_eq!(unsafe { CStr::from_ptr(action.text) }, c"LUA: %s\n");
            assert_eq!(next(&mut state, Value::default()).count, 0);
        }
    }
    #[test]
    fn native_identity_reads_preserve_signed_pid_and_unsigned_thread_values() {
        for (mode, native, value) in [(3, 30, i64::from(i32::MIN)), (4, 31, i64::from(u32::MAX))] {
            let (mut state, first) = begin(mode, 0).unwrap();
            assert_eq!(first.kind, native);
            let push = top(&mut state, value);
            assert_eq!((push.kind, push.integer), (8, value));
            assert_eq!(next(&mut state, Value::default()).count, 1);
        }
        let (mut state, first) = begin(5, 0).unwrap();
        assert_eq!(first.kind, 32);
        let done = next(
            &mut state,
            Value {
                count: 0,
                ..Value::default()
            },
        );
        assert_eq!((done.kind, done.count), (0, 1));
    }
    #[test]
    fn uname_observation_and_projection_keep_deferred_stack_guard() {
        let (mut state, first) = begin(7, 0).unwrap();
        assert_eq!(first.kind, 5);
        assert_eq!(top(&mut state, 0).kind, 34);
        let view = next(
            &mut state,
            Value {
                pointer: ptr::without_provenance(16),
                status: 0,
                ..Value::default()
            },
        );
        assert_eq!((view.kind, view.mode), (12, 1));
        assert_eq!(view.data, ptr::without_provenance(16));
        assert_eq!(
            next(
                &mut state,
                Value {
                    count: 1,
                    ..Value::default()
                }
            )
            .kind,
            5
        );
        assert_eq!((top(&mut state, 1).kind, state.count), (0, 1));
    }
    #[test]
    fn clock_failure_passes_null_to_projection_and_guard_uses_returned_arity() {
        let (mut state, _) = begin(8, 0).unwrap();
        top(&mut state, 0);
        let view = next(
            &mut state,
            Value {
                status: -1,
                pointer: ptr::without_provenance(16),
                ..Value::default()
            },
        );
        assert_eq!((view.kind, view.mode), (12, 4));
        assert!(view.data.is_null());
        next(
            &mut state,
            Value {
                count: 2,
                ..Value::default()
            },
        );
        let error = top(&mut state, 1);
        assert_eq!((error.kind, error.mode), (11, 1));
    }
    #[test]
    fn source_lookup_keeps_strict_input_captured_length_and_late_guard() {
        let (mut state, _) = begin(6, 1).unwrap();
        assert_eq!(top(&mut state, 1).kind, 3);
        let data = [0u8; 16];
        let lookup = next(
            &mut state,
            Value {
                span: Span {
                    data: data.as_ptr(),
                    length: 16,
                },
                ..Value::default()
            },
        );
        assert_eq!((lookup.kind, lookup.length), (33, 16));
        let publish = next(
            &mut state,
            Value {
                pointer: data.as_ptr().cast(),
                status: 1,
                ..Value::default()
            },
        );
        assert_eq!((publish.kind, publish.length), (6, 16));
        assert_eq!(next(&mut state, Value::default()).kind, 5);
        assert_eq!(top(&mut state, 2).count, 1);
        let (mut state, _) = begin(6, 1).unwrap();
        top(&mut state, 1);
        next(
            &mut state,
            Value {
                span: Span {
                    data: data.as_ptr(),
                    length: 7,
                },
                ..Value::default()
            },
        );
        let error = next(
            &mut state,
            Value {
                status: 2,
                ..Value::default()
            },
        );
        assert_eq!((error.kind, error.mode, error.length), (11, 0, 7));
    }
    #[test]
    fn stat_error_reads_strerror_after_nil_and_errno_after_string_publication() {
        let (mut state, _) = begin(10, 1).unwrap();
        let read = next(
            &mut state,
            Value {
                span: Span {
                    data: c"path".as_ptr().cast(),
                    length: 0,
                },
                ..Value::default()
            },
        );
        assert_eq!(read.kind, 36);
        assert_eq!(
            next(
                &mut state,
                Value {
                    status: -1,
                    integer: 5,
                    ..Value::default()
                }
            )
            .kind,
            7
        );
        assert_eq!(next(&mut state, Value::default()).kind, 41);
        assert_eq!(
            next(
                &mut state,
                Value {
                    span: Span {
                        data: c"failure".as_ptr().cast(),
                        length: 0
                    },
                    ..Value::default()
                }
            )
            .kind,
            9
        );
        assert_eq!(next(&mut state, Value::default()).kind, 42);
        let publish = top(&mut state, 123);
        assert_eq!((publish.kind, publish.integer), (8, 123));
        let done = next(&mut state, Value::default());
        assert_eq!((done.kind, done.count), (0, 3));
    }
    #[test]
    fn stat_without_strerror_returns_one_nil_without_reading_errno() {
        let (mut state, _) = begin(10, 1).unwrap();
        next(
            &mut state,
            Value {
                span: Span {
                    data: c"path".as_ptr().cast(),
                    length: 0,
                },
                ..Value::default()
            },
        );
        next(
            &mut state,
            Value {
                status: -1,
                ..Value::default()
            },
        );
        next(&mut state, Value::default());
        let done = next(&mut state, Value::default());
        assert_eq!((done.kind, done.count), (0, 1));
    }
    #[test]
    fn time_conversions_retain_native_operation_and_outer_result_arity() {
        for (mode, operation, projection) in [(11, 37, 2), (12, 38, 3)] {
            let (mut state, first) = begin(mode, 1).unwrap();
            assert_eq!((first.kind, first.index), (4, 1));
            let native = top(&mut state, -1);
            assert_eq!((native.kind, native.integer), (operation, -1));
            let view = next(&mut state, Value::default());
            assert_eq!((view.kind, view.mode), (12, projection));
            let done = next(
                &mut state,
                Value {
                    count: 0,
                    ..Value::default()
                },
            );
            assert_eq!((done.kind, done.count), (0, 1));
        }
        for (mode, operation) in [(13, 39), (14, 40)] {
            let (mut state, first) = begin(mode, 1).unwrap();
            assert_eq!(first.kind, operation);
            assert_eq!(next(&mut state, Value::default()).count, 1);
        }
    }
    #[test]
    fn scalar_entry_layout_matches_native_disjoint_state_value_and_action() {
        let pointer = size_of::<usize>();
        assert_eq!(mem::size_of::<State>(), 2 * pointer + 32);
        assert_eq!(mem::size_of::<Action>(), 2 * pointer + 32);
        assert_eq!(mem::size_of::<Value>(), 2 * pointer + 24);
    }
}
