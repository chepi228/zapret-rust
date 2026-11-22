//! Binary-buffer entry policy. VM calls occur only after these steps return.
use std::ffi::c_char;
#[cfg(test)]
use std::ptr;

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

#[derive(Default)]
#[repr(C)]
struct State {
    first: Span,
    second: Span,
    output: *mut u8,
    length: usize,
    mode: u32,
    phase: u32,
}

#[derive(Default)]
#[repr(C)]
struct Action {
    // Binary output or a static format for an error.
    data: *const u8,
    length: usize,
    name: *const c_char,
    kind: u32,
    index: i32,
    argc: u32,
    error: u32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    integer: i64,
}

// Test backends may observe/inject native failures, but must not enter Lua,
// unwind, retain spans or output, or write beyond the supplied output length.
type Backend =
    unsafe extern "C" fn(u32, *const u8, usize, *const u8, usize, *mut u8, *mut usize) -> bool;

#[repr(C)]
struct Ops {
    run: Option<Backend>,
}

fn name(mode: u32) -> *const c_char {
    [
        c"brandom",
        c"brandom_az",
        c"brandom_az09",
        c"bcryptorandom",
        c"parse_hex",
        c"bxor",
        c"bor",
        c"band",
    ][mode as usize]
        .as_ptr()
}
fn action(kind: u32, index: i32) -> Action {
    Action {
        kind,
        index,
        ..Action::default()
    }
}
fn error(state: &mut State, code: u32) -> Action {
    state.phase = 8;
    let format = match code {
        1 => c"%s: invalid arg",
        2 => c"could not get entropy bytes",
        3 => c"string lengths must be the same\n",
        _ => c"invalid Lua buffer action",
    };
    Action {
        data: format.as_ptr().cast(),
        kind: 9,
        error: code,
        name: name(if code == 1 && state.mode < 3 {
            0
        } else {
            state.mode
        }),
        ..Action::default()
    }
}
fn span_valid(span: Span) -> bool {
    span.length <= isize::MAX as usize && (span.length == 0 || !span.data.is_null())
}
fn begin(mode: u32) -> Option<(State, Action)> {
    (mode < 8).then(|| {
        (
            State {
                mode,
                ..State::default()
            },
            Action {
                kind: 1,
                name: name(mode),
                argc: if mode < 5 { 1 } else { 2 },
                ..Action::default()
            },
        )
    })
}

unsafe fn native(state: &mut State) -> bool {
    use crate::helpers::*;
    // SAFETY: the step validator checked readable rooted input spans and a
    // Lua-owned output allocation of length bytes. Hex reads at most 2*length.
    unsafe {
        match state.mode {
            0 => zapret_helper_fill_random_bytes(state.output, state.length),
            1 => zapret_helper_fill_random_az(state.output, state.length),
            2 => zapret_helper_fill_random_az09(state.output, state.length),
            3 => return crate::stdio::zapret_engine_crypto_random(state.output, state.length),
            4 => {
                return zapret_helper_parse_hex_str(
                    state.first.data.cast(),
                    state.output,
                    &mut state.length,
                );
            }
            5 => zapret_helper_bxor(
                state.first.data,
                state.second.data,
                state.output,
                state.length,
            ),
            6 => zapret_helper_bor(
                state.first.data,
                state.second.data,
                state.output,
                state.length,
            ),
            7 => zapret_helper_band(
                state.first.data,
                state.second.data,
                state.output,
                state.length,
            ),
            _ => return false,
        }
    }
    true
}

unsafe fn step(state: &mut State, value: &Value, backend: Option<Backend>) -> Option<Action> {
    if state.mode >= 8 {
        return None;
    }
    match state.phase {
        0 => {
            state.phase = 1;
            return Some(action(if state.mode < 4 { 2 } else { 3 }, 1));
        }
        1 if state.mode < 4 => {
            if value.integer < 0 {
                return Some(error(state, 1));
            }
            state.length = value.integer as usize;
        }
        1 => {
            if !span_valid(value.span) {
                return None;
            }
            state.first = value.span;
            if state.mode >= 5 {
                state.phase = 2;
                return Some(action(3, 2));
            }
            if value.span.length & 1 != 0 {
                state.phase = 7;
                return Some(action(8, 0));
            }
            state.length = value.span.length / 2;
        }
        2 => {
            if !span_valid(value.span) {
                return None;
            }
            state.second = value.span;
            if state.first.length != state.second.length {
                return Some(error(state, 3));
            }
            state.length = state.first.length;
        }
        3 => {
            if !span_valid(value.span) || value.span.length != state.length {
                return None;
            }
            state.output = value.span.data.cast_mut();
            let capacity = state.length;
            // SAFETY: backend obeys the native-only callback contract above;
            // otherwise use the already migrated, bounded production helpers.
            let success = unsafe {
                match backend {
                    Some(run) => run(
                        state.mode,
                        state.first.data,
                        state.first.length,
                        state.second.data,
                        state.second.length,
                        state.output,
                        &mut state.length,
                    ),
                    None => native(state),
                }
            };
            if state.length > capacity {
                return None;
            }
            if !success {
                if state.mode != 4 {
                    return Some(error(state, 2));
                }
                state.phase = 6;
                return Some(action(6, 1));
            }
            state.phase = 4;
            return Some(Action {
                kind: 5,
                data: state.output,
                length: state.length,
                ..Action::default()
            });
        }
        4 => {
            state.phase = 5;
            return Some(action(7, -2));
        }
        5 | 7 => {
            state.phase = 8;
            return Some(Action {
                argc: 1,
                ..Action::default()
            });
        }
        6 => {
            state.phase = 7;
            return Some(action(8, 0));
        }
        _ => return None,
    }
    state.phase = 3;
    Some(Action {
        kind: 4,
        length: state.length,
        ..Action::default()
    })
}

/// # Safety
/// Aligned state/action outputs must be writable, initialized separately, and
/// disjoint. No VM operations or retained native resources occur in this call.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_buffer_begin(
    mode: u32,
    state: *mut State,
    output: *mut Action,
) -> bool {
    if state.is_null() || !state.is_aligned() || output.is_null() || !output.is_aligned() {
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
/// Disjoint initialized pointers must be aligned and valid. Root input strings
/// until completion, and supply a Lua-owned output of the requested size. Ops
/// is null or a valid native-only callback table with the contract above.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_buffer_step(
    state: *mut State,
    value: *const Value,
    output: *mut Action,
    ops: *const Ops,
) -> bool {
    if state.is_null()
        || !state.is_aligned()
        || value.is_null()
        || !value.is_aligned()
        || output.is_null()
        || !output.is_aligned()
        || !ops.is_null() && !ops.is_aligned()
    {
        return false;
    }
    let backend = if ops.is_null() {
        None
    } else {
        unsafe { (*ops).run }
    };
    let Some(action) = (unsafe { step(&mut *state, &*value, backend) }) else {
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
    fn negative_alphabet_length_keeps_shared_brandom_diagnostic() {
        for mode in 0..4 {
            let (mut state, action) = begin(mode).unwrap();
            assert_eq!((action.kind, action.argc), (1, 1));
            let action = unsafe { step(&mut state, &Value::default(), None) }.unwrap();
            assert_eq!((action.kind, action.index), (2, 1));
            let action = unsafe {
                step(
                    &mut state,
                    &Value {
                        integer: -1,
                        ..Value::default()
                    },
                    None,
                )
            }
            .unwrap();
            assert_eq!((action.kind, action.error), (9, 1));
            let name = unsafe { std::ffi::CStr::from_ptr(action.name) };
            assert_eq!(
                name.to_bytes(),
                if mode == 3 {
                    b"bcryptorandom".as_slice()
                } else {
                    b"brandom".as_slice()
                }
            );
        }
        assert!(begin(8).is_none());
    }

    fn read_first(mode: u32, bytes: &[u8]) -> (State, Action) {
        let (mut state, _) = begin(mode).unwrap();
        unsafe { step(&mut state, &Value::default(), None) }.unwrap();
        let action = unsafe {
            step(
                &mut state,
                &Value {
                    span: Span {
                        data: bytes.as_ptr(),
                        length: bytes.len(),
                    },
                    ..Value::default()
                },
                None,
            )
        }
        .unwrap();
        (state, action)
    }

    #[test]
    fn odd_hex_rejects_before_allocation_even_with_embedded_nul() {
        let (mut state, action) = read_first(4, b"00\0");
        assert_eq!(action.kind, 8);
        let done = unsafe { step(&mut state, &Value::default(), None) }.unwrap();
        assert_eq!((done.kind, done.argc), (0, 1));
    }

    #[test]
    fn hex_keeps_nul_termination_and_pops_failed_userdata_before_nil() {
        for (input, expected) in [
            (b"00\0Z".as_slice(), Some(b"\0".as_slice())),
            (b"0\0", None),
            (b"00ZZ", None),
        ] {
            let (mut state, allocate) = read_first(4, input);
            assert_eq!(allocate.kind, 4);
            let mut bytes = [0xa5; 4];
            let value = Value {
                span: Span {
                    data: bytes.as_mut_ptr(),
                    length: allocate.length,
                },
                ..Value::default()
            };
            let result = unsafe { step(&mut state, &value, None) }.unwrap();
            match expected {
                Some(expected) => {
                    assert_eq!(result.kind, 5);
                    assert_eq!(&bytes[..result.length], expected);
                }
                None => {
                    assert_eq!((result.kind, result.index), (6, 1));
                    assert_eq!(
                        unsafe { step(&mut state, &Value::default(), None) }
                            .unwrap()
                            .kind,
                        8
                    );
                }
            }
        }
    }

    #[test]
    fn binary_lengths_are_checked_after_both_strict_string_reads() {
        for mode in 5..8 {
            let (mut state, read) = read_first(mode, b"x");
            assert_eq!((read.kind, read.index), (3, 2));
            let failure = unsafe {
                step(
                    &mut state,
                    &Value {
                        span: Span {
                            data: b"xx".as_ptr(),
                            length: 2,
                        },
                        ..Value::default()
                    },
                    None,
                )
            }
            .unwrap();
            assert_eq!((failure.kind, failure.error), (9, 3));
        }
    }

    #[test]
    fn binary_backends_preserve_inputs_and_publish_before_removing_userdata() {
        let first = [0, 255, 85, 170];
        let second = [255, 15, 240, 0];
        for (mode, expected) in [
            (5, [255, 240, 165, 170]),
            (6, [255, 255, 245, 170]),
            (7, [0, 15, 80, 0]),
        ] {
            let (mut state, _) = read_first(mode, &first);
            let allocate = unsafe {
                step(
                    &mut state,
                    &Value {
                        span: Span {
                            data: second.as_ptr(),
                            length: 4,
                        },
                        ..Value::default()
                    },
                    None,
                )
            }
            .unwrap();
            assert_eq!((allocate.kind, allocate.length), (4, 4));
            let mut bytes = [0; 4];
            let publish = unsafe {
                step(
                    &mut state,
                    &Value {
                        span: Span {
                            data: bytes.as_mut_ptr(),
                            length: 4,
                        },
                        ..Value::default()
                    },
                    None,
                )
            }
            .unwrap();
            assert_eq!((publish.kind, publish.length), (5, 4));
            assert_eq!(bytes, expected);
            let remove = unsafe { step(&mut state, &Value::default(), None) }.unwrap();
            assert_eq!((remove.kind, remove.index), (7, -2));
            assert_eq!(
                unsafe { step(&mut state, &Value::default(), None) }
                    .unwrap()
                    .argc,
                1
            );
            assert!(unsafe { step(&mut state, &Value::default(), None) }.is_none());
        }
        assert_eq!(first, [0, 255, 85, 170]);
        assert_eq!(second, [255, 15, 240, 0]);
    }

    unsafe extern "C" fn no_entropy(
        mode: u32,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        _: *mut u8,
        _: *mut usize,
    ) -> bool {
        assert_eq!(mode, 3);
        false
    }

    #[test]
    fn entropy_failure_is_an_error_without_explicit_userdata_removal() {
        let (mut state, _) = begin(3).unwrap();
        unsafe { step(&mut state, &Value::default(), None) }.unwrap();
        let allocate = unsafe {
            step(
                &mut state,
                &Value {
                    integer: 1,
                    ..Value::default()
                },
                None,
            )
        }
        .unwrap();
        assert_eq!((allocate.kind, allocate.length), (4, 1));
        let mut byte = 0;
        let error = unsafe {
            step(
                &mut state,
                &Value {
                    span: Span {
                        data: &mut byte,
                        length: 1,
                    },
                    ..Value::default()
                },
                Some(no_entropy),
            )
        }
        .unwrap();
        assert_eq!((error.kind, error.error), (9, 2));
    }

    #[test]
    fn invalid_spans_and_abi_preserve_action_output() {
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<State>(), 6 * pointer + 8);
        assert_eq!(size_of::<Action>(), 3 * pointer + 16);
        assert_eq!(size_of::<Value>(), 2 * pointer + 8);
        assert_eq!(size_of::<Ops>(), pointer);
        let mut state = State::default();
        let mut output = action(91, 0);
        assert!(!unsafe { zapret_lua_buffer_begin(8, &mut state, &mut output) });
        assert_eq!(output.kind, 91);
        assert!(!unsafe {
            zapret_lua_buffer_step(ptr::null_mut(), &Value::default(), &mut output, ptr::null())
        });
        let (mut state, _) = read_first(5, b"x");
        assert!(
            unsafe {
                step(
                    &mut state,
                    &Value {
                        span: Span {
                            data: ptr::null(),
                            length: 1,
                        },
                        ..Value::default()
                    },
                    None,
                )
            }
            .is_none()
        );
    }
}
