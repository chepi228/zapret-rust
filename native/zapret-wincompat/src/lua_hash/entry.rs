//! Complete hash/HKDF and IP entry policies, between C-owned VM operations.
use std::{
    ffi::{CStr, c_char},
    ptr,
};

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}
#[repr(C)]
struct State {
    inputs: [Span; 3],
    name: *const c_char,
    output: *mut u8,
    length: usize,
    bytes: [u8; 65],
    mode: u32,
    phase: u32,
    bits: u32,
    cursor: u32,
}
#[derive(Default)]
#[repr(C)]
struct Action {
    // API name for arity errors, or the static format for other errors.
    name: *const c_char,
    data: *const u8,
    length: usize,
    kind: u32,
    index: i32,
    count: u32,
    expected: i32,
    error: u32,
}
#[derive(Default)]
#[repr(C)]
struct Value {
    span: Span,
    integer: i64,
    kind: i32,
}
type Hash = unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize) -> usize;
type Hkdf = unsafe extern "C" fn(
    u32,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
) -> bool;
type Ntop = unsafe extern "C" fn(*const u8, usize, *mut c_char, usize) -> usize;
type Pton = unsafe extern "C" fn(*const c_char, *mut u8, usize) -> usize;
#[repr(C)]
struct Ops {
    hash: Option<Hash>,
    hkdf: Option<Hkdf>,
    ntop: Option<Ntop>,
    pton: Option<Pton>,
}

const NATIVE: Ops = Ops {
    hash: Some(super::zapret_lua_hash),
    hkdf: Some(super::zapret_lua_hkdf),
    ntop: Some(crate::address::zapret_lua_ntop),
    pton: Some(crate::address::zapret_lua_pton),
};
impl Span {
    fn valid(self) -> bool {
        self.length <= isize::MAX as usize
            && (self.length == 0 || !self.data.is_null())
            && self.data.addr().checked_add(self.length).is_some()
    }
}
fn action(kind: u32, index: i32) -> Action {
    Action {
        kind,
        index,
        ..Action::default()
    }
}
fn begin(mode: u32, count: i32) -> Option<(State, Action)> {
    let name = [c"hash", c"hkdf", c"ntop", c"pton"]
        .get(mode as usize)?
        .as_ptr();
    let count = u32::try_from(count).ok()?;
    let expected = [2, 5, 1, 1][mode as usize];
    let mut state = State {
        inputs: [Span::default(); 3],
        name: ptr::null(),
        output: ptr::null_mut(),
        length: 0,
        bytes: [0; 65],
        mode,
        phase: 1,
        bits: 0,
        cursor: 0,
    };
    if count != expected as u32 {
        state.phase = 15;
        return Some((
            state,
            Action {
                name,
                kind: 1,
                count,
                expected,
                ..Action::default()
            },
        ));
    }
    let first = if mode < 2 {
        action(2, 1)
    } else {
        state.phase = 2;
        action(if mode == 2 { 3 } else { 12 }, 1)
    };
    Some((state, first))
}
fn error(state: &mut State, code: u32) -> Action {
    state.phase = 15;
    let format = match code {
        1 => c"unsupported hash type %s",
        2 => c"hash failure",
        3 => c"hkdf: invalid arg",
        _ => c"invalid Lua hash/IP action",
    };
    Action {
        name: format.as_ptr(),
        error: code,
        data: state.name.cast(),
        ..action(11, 0)
    }
}
fn next_operand(state: &mut State) -> Action {
    state.cursor += 1;
    state.phase = if state.cursor < 3 { 3 } else { 5 };
    action(
        if state.cursor < 3 { 4 } else { 6 },
        state.cursor as i32 + 2,
    )
}
unsafe fn backend(state: &mut State, ops: &Ops) -> Option<Action> {
    let [first, second, third] = state.inputs;
    let capacity = match state.mode {
        0 => 32,
        1 => state.length,
        2 => 65,
        3 => 16,
        _ => return None,
    };
    let output = if state.mode == 1 {
        state.output
    } else {
        state.bytes.as_mut_ptr()
    };
    // Native callbacks must not enter Lua, unwind, retain pointers or exceed
    // capacity. Borrowed arguments remain rooted; HKDF output is disjoint.
    let length = unsafe {
        match state.mode {
            0 => ops.hash.map_or(0, |run| {
                run(state.bits, first.data, first.length, output, capacity)
            }),
            1 => {
                if ops.hkdf.is_some_and(|run| {
                    run(
                        state.bits,
                        first.data,
                        first.length,
                        second.data,
                        second.length,
                        third.data,
                        third.length,
                        output,
                        capacity,
                    )
                }) {
                    capacity
                } else {
                    0
                }
            }
            2 => ops.ntop.map_or(0, |run| {
                run(first.data, first.length, output.cast(), capacity)
            }),
            3 => ops
                .pton
                .map_or(0, |run| run(first.data.cast(), output, capacity)),
            _ => return None,
        }
    };
    if length > capacity {
        return None;
    }
    if state.mode == 0 && length == 0 {
        return Some(error(state, 2));
    }
    state.phase = if state.mode == 1 { 7 } else { 12 };
    Some(if length == 0 {
        action(9, 0)
    } else {
        Action {
            data: output,
            length,
            ..action(8, 0)
        }
    })
}
unsafe fn step(state: &mut State, value: &Value, ops: &Ops) -> Option<Action> {
    if state.mode > 3 || state.cursor > 3 {
        return None;
    }
    match state.phase {
        1 => {
            if value.span.data.is_null() {
                return None;
            }
            state.name = value.span.data.cast();
            state.bits = match unsafe { CStr::from_ptr(state.name) }.to_bytes() {
                b"sha256" => 256,
                b"sha224" => 224,
                _ => return Some(error(state, 1)),
            };
            state.phase = if state.mode == 0 { 2 } else { 3 };
            Some(action(if state.mode == 0 { 3 } else { 4 }, 2))
        }
        2 => {
            if !value.span.valid() || state.mode == 3 && value.span.data.is_null() {
                return None;
            }
            state.inputs[0] = value.span;
            unsafe { backend(state, ops) }
        }
        3 if state.cursor < 3 => {
            if value.kind == 0 {
                state.inputs[state.cursor as usize] = Span::default();
                Some(next_operand(state))
            } else {
                state.phase = 4;
                Some(action(5, state.cursor as i32 + 2))
            }
        }
        4 if state.cursor < 3 => {
            if !value.span.valid() {
                return None;
            }
            state.inputs[state.cursor as usize] = value.span;
            Some(next_operand(state))
        }
        5 => {
            if value.integer < 0 {
                return Some(error(state, 3));
            }
            if value.integer == 0 || value.integer > 255 * i64::from(state.bits / 8) {
                state.phase = 12;
                return Some(action(9, 0));
            }
            state.length = value.integer as usize;
            state.phase = 6;
            Some(Action {
                length: state.length,
                ..action(7, 0)
            })
        }
        6 => {
            if !value.span.valid() || value.span.data.is_null() || value.span.length != state.length
            {
                return None;
            }
            state.output = value.span.data.cast_mut();
            unsafe { backend(state, ops) }
        }
        7 => {
            state.phase = 8;
            Some(action(10, -2))
        }
        8 | 12 => {
            state.phase = 15;
            Some(Action {
                count: 1,
                ..action(0, 0)
            })
        }
        _ => None,
    }
}

/// # Safety
/// State/action outputs are disjoint, aligned and writable. No VM calls occur.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_hash_ip_entry_begin(
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
/// Initialized state/value/output pointers are disjoint and aligned. Root each
/// input through completion; name and pton input are readable C strings. HKDF
/// userdata is writable, disjoint from inputs and exactly the requested size.
/// State stays at a stable address until inline output is published. Optional
/// ops obey the native-only callback contract in backend, or are null.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_hash_ip_entry_step(
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
    let ops = if ops.is_null() {
        &NATIVE
    } else {
        unsafe { &*ops }
    };
    let Some(action) = (unsafe { step(&mut *state, &*value, ops) }) else {
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
    const NO_NATIVE: Ops = Ops {
        hash: None,
        hkdf: None,
        ntop: None,
        pton: None,
    };
    fn next(state: &mut State, value: Value) -> Action {
        unsafe { step(state, &value, &NO_NATIVE) }.unwrap()
    }
    fn name_value(name: &'static CStr) -> Value {
        Value {
            span: Span {
                data: name.as_ptr().cast(),
                length: 0,
            },
            ..Value::default()
        }
    }
    fn hkdf_state() -> State {
        let (mut state, first) = begin(1, 5).unwrap();
        assert_eq!((first.kind, first.index), (2, 1));
        let read = next(&mut state, name_value(c"sha256"));
        assert_eq!((read.kind, read.index), (4, 2));
        state
    }
    fn hkdf_nil_inputs(state: &mut State) {
        for index in 2..=4 {
            let read = next(
                state,
                Value {
                    kind: 0,
                    ..Value::default()
                },
            );
            assert_eq!(
                (read.kind, read.index),
                if index < 4 { (4, index + 1) } else { (6, 5) }
            );
        }
    }

    #[test]
    fn exact_arity_names_precede_any_argument_read() {
        for (mode, name, expected) in [
            (0, b"hash".as_slice(), 2),
            (1, b"hkdf".as_slice(), 5),
            (2, b"ntop".as_slice(), 1),
            (3, b"pton".as_slice(), 1),
        ] {
            let (_, error) = begin(mode, 0).unwrap();
            assert_eq!((error.kind, error.expected, error.count), (1, expected, 0));
            assert_eq!(unsafe { CStr::from_ptr(error.name) }.to_bytes(), name);
        }
        assert!(begin(4, 1).is_none());
    }

    #[test]
    fn algorithm_classification_preserves_c_string_termination_and_error_order() {
        let (mut state, _) = begin(0, 2).unwrap();
        let error = next(&mut state, name_value(c"SHA256"));
        assert_eq!((error.kind, error.error), (11, 1));
        assert_eq!(error.data, c"SHA256".as_ptr().cast());
        let (mut state, _) = begin(0, 2).unwrap();
        let bytes = b"sha224\0ignored\0";
        let read = next(
            &mut state,
            Value {
                span: Span {
                    data: bytes.as_ptr(),
                    length: bytes.len(),
                },
                ..Value::default()
            },
        );
        assert_eq!((read.kind, read.index, state.bits), (3, 2, 224));
    }

    #[test]
    fn hkdf_reads_nil_types_and_coercing_spans_in_salt_key_info_order() {
        let mut state = hkdf_state();
        for index in 2..=4 {
            let read = next(
                &mut state,
                Value {
                    kind: 3,
                    ..Value::default()
                },
            );
            assert_eq!((read.kind, read.index), (5, index));
            let read = next(
                &mut state,
                Value {
                    span: Span {
                        data: b"123".as_ptr(),
                        length: 3,
                    },
                    ..Value::default()
                },
            );
            assert_eq!(
                (read.kind, read.index),
                if index < 4 { (4, index + 1) } else { (6, 5) }
            );
        }
        assert_eq!(state.inputs.map(|v| v.length), [3, 3, 3]);
    }

    #[test]
    fn hkdf_checks_length_before_allocating_or_accessing_inputs() {
        for (length, kind, error) in [(-1, 11, 3), (0, 9, 0), (8161, 9, 0), (8160, 7, 0)] {
            let mut state = hkdf_state();
            hkdf_nil_inputs(&mut state);
            let action = next(
                &mut state,
                Value {
                    integer: length,
                    ..Value::default()
                },
            );
            assert_eq!((action.kind, action.error), (kind, error));
            if kind == 7 {
                assert_eq!(action.length, 8160);
            }
            if kind == 9 {
                assert_eq!(next(&mut state, Value::default()).count, 1);
            }
        }
    }

    #[test]
    fn sha224_retains_its_separate_hkdf_output_limit() {
        let (mut state, _) = begin(1, 5).unwrap();
        next(&mut state, name_value(c"sha224"));
        hkdf_nil_inputs(&mut state);
        assert_eq!(
            next(
                &mut state,
                Value {
                    integer: 7141,
                    ..Value::default()
                }
            )
            .kind,
            9
        );
    }

    #[test]
    fn failed_hkdf_still_removes_userdata_after_publishing_nil() {
        let mut state = hkdf_state();
        hkdf_nil_inputs(&mut state);
        assert_eq!(
            next(
                &mut state,
                Value {
                    integer: 1,
                    ..Value::default()
                }
            )
            .kind,
            7
        );
        let mut output = [0xAA];
        let result = next(
            &mut state,
            Value {
                span: Span {
                    data: output.as_mut_ptr(),
                    length: 1,
                },
                ..Value::default()
            },
        );
        assert_eq!(result.kind, 9);
        let remove = next(&mut state, Value::default());
        assert_eq!((remove.kind, remove.index), (10, -2));
        assert_eq!(next(&mut state, Value::default()).count, 1);
        assert_eq!(output, [0xAA]);
    }

    #[test]
    fn hash_and_ip_failures_keep_distinct_error_or_nil_results() {
        for mode in [0, 2, 3] {
            let (mut state, first) = begin(mode, if mode == 0 { 2 } else { 1 }).unwrap();
            let read = if mode == 0 {
                next(&mut state, name_value(c"sha256"))
            } else {
                first
            };
            assert_eq!(
                (read.kind, read.index),
                if mode == 0 {
                    (3, 2)
                } else if mode == 2 {
                    (3, 1)
                } else {
                    (12, 1)
                }
            );
            let result = next(
                &mut state,
                Value {
                    span: Span {
                        data: c"x".as_ptr().cast(),
                        length: 1,
                    },
                    ..Value::default()
                },
            );
            assert_eq!(
                (result.kind, result.error),
                if mode == 0 { (11, 2) } else { (9, 0) }
            );
        }
    }

    #[test]
    fn invalid_spans_are_rejected_before_backend_access() {
        let (mut state, _) = begin(2, 1).unwrap();
        assert!(
            unsafe {
                step(
                    &mut state,
                    &Value {
                        span: Span {
                            data: ptr::null(),
                            length: 4,
                        },
                        ..Value::default()
                    },
                    &NO_NATIVE,
                )
            }
            .is_none()
        );
        let pointer = size_of::<usize>();
        assert_eq!(
            mem::size_of::<State>(),
            if pointer == 8 { 160 } else { 120 }
        );
        assert_eq!(mem::size_of::<Action>(), if pointer == 8 { 48 } else { 32 });
        assert_eq!(mem::size_of::<Value>(), 2 * pointer + 16);
        assert_eq!(mem::size_of::<Ops>(), 4 * pointer);
    }

    #[test]
    fn ntop_preserves_the_windows_native_text_capacity() {
        unsafe extern "C" fn native_capacity(
            _input: *const u8,
            _length: usize,
            output: *mut c_char,
            capacity: usize,
        ) -> usize {
            if capacity != 65 {
                return 0;
            }
            unsafe {
                ptr::copy_nonoverlapping(b"::1".as_ptr(), output.cast(), 3);
            }
            3
        }
        let ops = Ops {
            ntop: Some(native_capacity),
            ..NO_NATIVE
        };
        let (mut state, _) = begin(2, 1).unwrap();
        let input = [0u8; 16];
        let result = unsafe {
            step(
                &mut state,
                &Value {
                    span: Span {
                        data: input.as_ptr(),
                        length: 16,
                    },
                    ..Value::default()
                },
                &ops,
            )
        }
        .unwrap();
        assert_eq!((result.kind, result.length), (8, 3));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(result.data, 3) },
            b"::1"
        );
    }
}
