//! Numeric entry decisions. C performs every VM operation after Rust returns.
use crate::lua_aux::zapret_lua_arity_error;
use std::{
    ffi::{CStr, c_char},
    slice,
};

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

#[derive(Default)]
#[repr(C)]
struct State {
    input: Span,
    offset: i64,
    bytes: [u8; 6],
    mode: u32,
    count: u32,
    phase: u32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Action {
    // Binary output or a static format for an error.
    data: *const u8,
    name: *const c_char,
    integer: i64,
    length: usize,
    kind: u32,
    count: u32,
    minimum: i32,
    maximum: i32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    numbers: *const i64,
    integer: i64,
    count: i32,
    kind: i32,
}

struct Entry {
    name: &'static CStr,
    operation: u32,
    width: u32,
    minimum: i32,
    maximum: i32,
}

impl Entry {
    const fn new(
        name: &'static CStr,
        operation: u32,
        width: u32,
        minimum: i32,
        maximum: i32,
    ) -> Self {
        Self {
            name,
            operation,
            width,
            minimum,
            maximum,
        }
    }
}

const ENTRIES: [Entry; 32] = [
    Entry::new(c"bitlshift", 0, 48, 2, 2),
    Entry::new(c"bitrshift", 1, 48, 2, 2),
    Entry::new(c"bitand", 2, 48, 2, 100),
    Entry::new(c"bitor", 3, 48, 1, 100),
    Entry::new(c"bitxor", 4, 48, 1, 100),
    Entry::new(c"bitnot8", 5, 8, 1, 1),
    Entry::new(c"bitnot16", 5, 16, 1, 1),
    Entry::new(c"bitnot24", 5, 24, 1, 1),
    Entry::new(c"bitnot32", 5, 32, 1, 1),
    Entry::new(c"bitnot48", 5, 48, 1, 1),
    Entry::new(c"bitget", 6, 48, 3, 3),
    Entry::new(c"bitset", 7, 48, 4, 4),
    Entry::new(c"swap16", 8, 16, 1, 1),
    Entry::new(c"swap24", 8, 24, 1, 1),
    Entry::new(c"swap32", 8, 32, 1, 1),
    Entry::new(c"swap48", 8, 48, 1, 1),
    Entry::new(c"u8add", 9, 8, 1, 100),
    Entry::new(c"u16add", 9, 16, 1, 100),
    Entry::new(c"u24add", 9, 24, 1, 100),
    Entry::new(c"u32add", 9, 32, 1, 100),
    Entry::new(c"u48add", 9, 48, 1, 100),
    Entry::new(c"divint", 10, 48, 2, 2),
    Entry::new(c"u8", 0, 8, 1, 2),
    Entry::new(c"u16", 0, 16, 1, 2),
    Entry::new(c"u24", 0, 24, 1, 2),
    Entry::new(c"u32", 0, 32, 1, 2),
    Entry::new(c"u48", 0, 48, 1, 2),
    Entry::new(c"bu8", 0, 8, 1, 1),
    Entry::new(c"bu16", 0, 16, 1, 1),
    Entry::new(c"bu24", 0, 24, 1, 1),
    Entry::new(c"bu32", 0, 32, 1, 1),
    Entry::new(c"bu48", 0, 48, 1, 1),
];

fn action(kind: u32) -> Action {
    Action {
        kind,
        ..Action::default()
    }
}

fn begin(mode: u32, count: i32) -> Option<(State, Action)> {
    let entry = ENTRIES.get(mode as usize)?;
    let count = u32::try_from(count).ok()?;
    let mut state = State {
        mode,
        count,
        offset: 1,
        ..State::default()
    };
    if count < entry.minimum as u32 || count > entry.maximum as u32 {
        state.phase = 8;
        let ranged = entry.minimum != entry.maximum;
        let format = zapret_lua_arity_error(count as i32, entry.minimum, entry.maximum, ranged);
        return Some((
            state,
            Action {
                data: format.cast(),
                name: entry.name.as_ptr(),
                kind: if ranged { 2 } else { 1 },
                count,
                minimum: entry.minimum,
                maximum: entry.maximum,
                ..Action::default()
            },
        ));
    }
    let first = if mode < 22 {
        action(3)
    } else if mode < 27 {
        state.phase = 1;
        action(4)
    } else {
        state.phase = 2;
        action(5)
    };
    Some((state, first))
}

fn numeric_result(state: &mut State, result: Result<u64, u32>) -> Action {
    state.phase = 7;
    match result {
        Ok(value) => Action {
            integer: value as i64,
            ..action(9)
        },
        Err(3) => action(11),
        Err(code) => {
            let format = if code == 2 {
                c"bit range invalid"
            } else {
                c"out of range"
            };
            Action {
                data: format.as_ptr().cast(),
                ..action(12)
            }
        }
    }
}

unsafe fn read_result(state: &mut State, width: u32) -> Action {
    let mut result = 0;
    // Bounds are checked before the borrowed input bytes are read. The C caller
    // roots the strict string throughout count/type/coercing offset operations.
    let success = unsafe {
        super::zapret_lua_read_number(
            state.input.data,
            state.input.length,
            state.offset,
            width,
            &mut result,
        )
    };
    numeric_result(state, if success { Ok(result) } else { Err(1) })
}

unsafe fn step(state: &mut State, value: &Value) -> Option<Action> {
    let entry = ENTRIES.get(state.mode as usize)?;
    match state.phase {
        0 => {
            let count = u32::try_from(value.count)
                .ok()
                .filter(|&count| count <= 100)?;
            state.count = count;
            state.phase = 3;
            Some(Action { count, ..action(6) })
        }
        1 => {
            if value.span.length > isize::MAX as usize
                || value.span.length != 0 && value.span.data.is_null()
            {
                return None;
            }
            state.input = value.span;
            state.phase = 4;
            Some(action(3))
        }
        2 => {
            let success = unsafe {
                super::zapret_lua_write_number(value.integer, entry.width, state.bytes.as_mut_ptr())
            };
            if !success {
                return Some(numeric_result(state, Err(1)));
            }
            state.phase = 7;
            Some(Action {
                data: state.bytes.as_ptr(),
                length: (entry.width / 8) as usize,
                ..action(10)
            })
        }
        3 => {
            if state.count > 100
                || value.count != state.count as i32
                || state.count != 0 && (value.numbers.is_null() || !value.numbers.is_aligned())
            {
                return None;
            }
            let values = if state.count == 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(value.numbers, state.count as usize) }
            };
            Some(numeric_result(
                state,
                super::calculate(entry.operation, entry.width, values),
            ))
        }
        4 => {
            if value.count == 2 {
                state.phase = 5;
                Some(action(7))
            } else {
                Some(unsafe { read_result(state, entry.width) })
            }
        }
        5 => {
            if value.kind == 0 {
                Some(unsafe { read_result(state, entry.width) })
            } else {
                state.phase = 6;
                Some(action(8))
            }
        }
        6 => {
            state.offset = value.integer;
            Some(unsafe { read_result(state, entry.width) })
        }
        7 => {
            state.phase = 8;
            Some(Action {
                count: 1,
                ..action(0)
            })
        }
        _ => None,
    }
}

/// # Safety
/// Disjoint, aligned state/action pointers must be writable. No VM calls occur.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_numeric_entry_begin(
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
/// Pointers are disjoint, aligned and initialized. Root the input string until
/// completion and provide exactly the requested readable integer batch. Keep
/// state at a stable address until the selected binary string is published.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_numeric_entry_step(
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
    let Some(action) = (unsafe { step(&mut *state, &*value) }) else {
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
        unsafe { step(state, &value) }.unwrap()
    }

    #[test]
    fn arity_errors_select_public_names_before_reading_operands() {
        let (_, exact) = begin(0, 1).unwrap();
        assert_eq!(
            (exact.kind, exact.minimum, exact.maximum, exact.count),
            (1, 2, 2, 1)
        );
        assert_eq!(
            unsafe { CStr::from_ptr(exact.name) }.to_bytes(),
            b"bitlshift"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(exact.data.cast()) },
            c"%s expect exactly %d arguments, got %d"
        );
        let (_, range) = begin(2, 101).unwrap();
        assert_eq!(
            (range.kind, range.minimum, range.maximum, range.count),
            (2, 2, 100, 101)
        );
        assert_eq!(unsafe { CStr::from_ptr(range.name) }.to_bytes(), b"bitand");
        assert_eq!(
            unsafe { CStr::from_ptr(range.data.cast()) },
            c"%s expect from %d to %d arguments, got %d"
        );
        assert!(begin(32, 0).is_none());
        assert!(begin(0, -1).is_none());
    }

    #[test]
    fn numeric_batch_waits_for_all_operands_before_range_validation() {
        let (mut state, action) = begin(2, 2).unwrap();
        assert_eq!(action.kind, 3); // Deferred second stack count.
        let read = next(
            &mut state,
            Value {
                count: 2,
                ..Value::default()
            },
        );
        assert_eq!((read.kind, read.count), (6, 2));
        let operands = [0x1_0000_0000_0000i64, 7];
        let error = next(
            &mut state,
            Value {
                numbers: operands.as_ptr(),
                count: 2,
                ..Value::default()
            },
        );
        assert_eq!(error.kind, 12);
        assert_eq!(
            unsafe { CStr::from_ptr(error.data.cast()) },
            c"out of range"
        );
    }

    #[test]
    fn numeric_batch_uses_late_count_and_publishes_one_lint() {
        let (mut state, _) = begin(17, 3).unwrap(); // u16add
        let read = next(
            &mut state,
            Value {
                count: 2,
                ..Value::default()
            },
        );
        assert_eq!((read.kind, read.count), (6, 2));
        let operands = [65535, 2];
        let result = next(
            &mut state,
            Value {
                numbers: operands.as_ptr(),
                count: 2,
                ..Value::default()
            },
        );
        assert_eq!((result.kind, result.integer), (9, 1));
        let done = next(&mut state, Value::default());
        assert_eq!((done.kind, done.count), (0, 1));
        assert!(unsafe { step(&mut state, &Value::default()) }.is_none());
    }

    #[test]
    fn empty_late_batch_retains_backend_out_of_range_error() {
        let (mut state, _) = begin(17, 2).unwrap();
        let read = next(&mut state, Value::default());
        assert_eq!((read.kind, read.count), (6, 0));
        let result = next(&mut state, Value::default());
        assert_eq!(result.kind, 12);
        assert_eq!(
            unsafe { CStr::from_ptr(result.data.cast()) },
            c"out of range"
        );
    }

    #[test]
    fn division_by_zero_and_overflow_publish_exactly_one_nil() {
        for operands in [[1, 0], [i64::MIN, -1]] {
            let (mut state, _) = begin(21, 2).unwrap();
            next(
                &mut state,
                Value {
                    count: 2,
                    ..Value::default()
                },
            );
            let action = next(
                &mut state,
                Value {
                    numbers: operands.as_ptr(),
                    count: 2,
                    ..Value::default()
                },
            );
            assert_eq!(action.kind, 11);
            assert_eq!(next(&mut state, Value::default()).count, 1);
        }
    }

    fn read_state(mode: u32, count: i32, data: &[u8]) -> State {
        let (mut state, first) = begin(mode, count).unwrap();
        assert_eq!(first.kind, 4); // Strict string first.
        let action = next(
            &mut state,
            Value {
                span: Span {
                    data: data.as_ptr(),
                    length: data.len(),
                },
                ..Value::default()
            },
        );
        assert_eq!(action.kind, 3); // Then observe the stack count.
        state
    }

    #[test]
    fn binary_read_distinguishes_absent_nil_and_explicit_offsets() {
        let data = [0x12, 0x34, 0x56];
        for count in [1, 2] {
            let mut state = read_state(23, count, &data); // u16
            let mut action = next(
                &mut state,
                Value {
                    count,
                    ..Value::default()
                },
            );
            if count == 2 {
                assert_eq!(action.kind, 7);
                action = next(
                    &mut state,
                    Value {
                        kind: 0,
                        ..Value::default()
                    },
                );
            }
            assert_eq!((action.kind, action.integer), (9, 0x1234));
        }
        let mut state = read_state(23, 2, &data);
        assert_eq!(
            next(
                &mut state,
                Value {
                    count: 2,
                    ..Value::default()
                }
            )
            .kind,
            7
        );
        assert_eq!(
            next(
                &mut state,
                Value {
                    kind: 1,
                    ..Value::default()
                }
            )
            .kind,
            8
        );
        let result = next(
            &mut state,
            Value {
                integer: 2,
                ..Value::default()
            },
        );
        assert_eq!((result.kind, result.integer), (9, 0x3456));
    }

    #[test]
    fn binary_read_borrows_bytes_until_after_offset_extraction() {
        let mut data = [1, 2, 3];
        let bytes = data.as_mut_ptr();
        let (mut state, _) = begin(23, 2).unwrap();
        next(
            &mut state,
            Value {
                span: Span {
                    data: bytes,
                    length: 3,
                },
                ..Value::default()
            },
        );
        next(
            &mut state,
            Value {
                count: 2,
                ..Value::default()
            },
        );
        next(
            &mut state,
            Value {
                kind: 3,
                ..Value::default()
            },
        );
        unsafe {
            bytes.add(1).write(0xAB);
        }
        let result = next(
            &mut state,
            Value {
                integer: 2,
                ..Value::default()
            },
        );
        assert_eq!((result.kind, result.integer), (9, 0xAB03));
    }

    #[test]
    fn read_boundaries_validate_before_touching_borrowed_memory() {
        for offset in [i64::MIN, -1, 0, 2, i64::MAX] {
            let data = [1; 6];
            let mut state = read_state(26, 2, &data);
            next(
                &mut state,
                Value {
                    count: 2,
                    ..Value::default()
                },
            );
            next(
                &mut state,
                Value {
                    kind: 3,
                    ..Value::default()
                },
            );
            let action = next(
                &mut state,
                Value {
                    integer: offset,
                    ..Value::default()
                },
            );
            assert_eq!(action.kind, 12);
            assert_eq!(
                unsafe { CStr::from_ptr(action.data.cast()) },
                c"out of range"
            );
        }
    }

    #[test]
    fn binary_write_selects_signed_low_bytes_and_exact_width() {
        for (mode, expected) in [
            (27, &b"\xFF"[..]),
            (28, &b"\xFF\xFF"[..]),
            (31, &b"\xFF\xFF\xFF\xFF\xFF\xFF"[..]),
        ] {
            let (mut state, first) = begin(mode, 1).unwrap();
            assert_eq!(first.kind, 5);
            let result = next(
                &mut state,
                Value {
                    integer: -1,
                    ..Value::default()
                },
            );
            assert_eq!(result.kind, 10);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(result.data, result.length) },
                expected
            );
            assert_eq!(next(&mut state, Value::default()).count, 1);
        }
        let (mut state, _) = begin(27, 1).unwrap();
        let action = next(
            &mut state,
            Value {
                integer: 256,
                ..Value::default()
            },
        );
        assert_eq!(action.kind, 12);
        assert_eq!(
            unsafe { CStr::from_ptr(action.data.cast()) },
            c"out of range"
        );
    }

    #[test]
    fn invalid_batches_and_spans_are_rejected_without_reading_memory() {
        let (mut state, _) = begin(2, 2).unwrap();
        next(
            &mut state,
            Value {
                count: 2,
                ..Value::default()
            },
        );
        assert!(
            unsafe {
                step(
                    &mut state,
                    &Value {
                        count: 2,
                        ..Value::default()
                    },
                )
            }
            .is_none()
        );
        let (mut state, _) = begin(22, 1).unwrap();
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
                )
            }
            .is_none()
        );
        let pointer = size_of::<usize>();
        assert_eq!(mem::size_of::<State>(), 2 * pointer + 32);
        assert_eq!(mem::size_of::<Action>(), 2 * pointer + 32);
        assert_eq!(mem::size_of::<Value>(), 2 * pointer + 24);
    }

    #[test]
    fn ffi_rejects_invalid_modes_and_pointers_without_publishing_outputs() {
        let mut state = State::default();
        let mut output = Action {
            kind: 77,
            ..Action::default()
        };
        assert!(!unsafe { zapret_lua_numeric_entry_begin(32, 1, &mut state, &mut output) });
        assert_eq!(output.kind, 77);
        assert!(!unsafe { zapret_lua_numeric_entry_begin(0, 2, ptr::null_mut(), &mut output) });
        assert_eq!(output.kind, 77);
        let unaligned = ptr::without_provenance_mut::<State>(1);
        assert!(!unsafe { zapret_lua_numeric_entry_begin(0, 2, unaligned, &mut output) });
        assert!(unsafe { zapret_lua_numeric_entry_begin(27, 1, &mut state, &mut output) });
        assert_eq!(output.kind, 5);
        assert!(!unsafe { zapret_lua_numeric_entry_step(&mut state, ptr::null(), &mut output) });
        assert_eq!(output.kind, 5);
        let value = Value {
            integer: 0x7F,
            ..Value::default()
        };
        assert!(unsafe { zapret_lua_numeric_entry_step(&mut state, &value, &mut output) });
        assert_eq!(output.kind, 10);
        assert_eq!(unsafe { *output.data }, 0x7F);
    }
}
