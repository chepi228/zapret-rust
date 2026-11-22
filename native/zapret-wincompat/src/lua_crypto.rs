//! Complete crypto entry policy between C-owned VM calls; only borrowed spans.
use std::ffi::{CStr, c_char};
type Block = unsafe extern "C" fn(bool, *const u8, usize, *const u8, *mut u8) -> bool;
type Ctr = unsafe extern "C" fn(*const u8, usize, *const u8, *const u8, usize, *mut u8) -> bool;
type Gcm = unsafe extern "C" fn(
    bool,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    *mut u8,
) -> bool;
#[repr(C)]
struct Ops {
    block: Option<Block>,
    ctr: Option<Ctr>,
    gcm: Option<Gcm>,
}
const NATIVE: Ops = Ops {
    block: Some(crate::lua_aes::zapret_lua_aes_block),
    ctr: Some(crate::lua_aes::zapret_lua_aes_ctr),
    gcm: Some(crate::lua_gcm::zapret_lua_aes_gcm),
};
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Span {
    data: *const u8,
    length: usize,
}
impl Span {
    fn valid(self) -> bool {
        self.length <= isize::MAX as usize
            && (self.length == 0 || !self.data.is_null())
            && self.data.addr().checked_add(self.length).is_some()
    }
}
#[repr(C)]
#[derive(Default)]
struct State {
    key: Span,
    iv: Span,
    input: Span,
    associated: Span,
    output: *mut u8,
    mode: u32,
    phase: u32,
    encrypt: u32,
    success: u32,
    tag: [u8; 16],
    block: [u8; 16],
}
#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    // Binary output or a static format for an error.
    data: *const u8,
    length: usize,
    index: i32,
    kind: u32,
    minimum: i32,
    maximum: i32,
    error: u32,
    count: u32,
}
#[repr(C)]
#[derive(Default)]
struct Value {
    span: Span,
    truth: u32,
}
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn name(mode: u32) -> &'static CStr {
    match mode {
        0 => c"aes",
        1 => c"aes_ctr",
        _ => c"aes_gcm",
    }
}
fn action(state: &State, kind: u32, index: i32) -> Action {
    Action {
        name: name(state.mode).as_ptr(),
        kind,
        index,
        ..Default::default()
    }
}
fn key_action(state: &mut State) -> Action {
    state.phase = 3;
    action(state, 3, if state.mode == 1 { 1 } else { 2 })
}
fn input_action(state: &mut State) -> Action {
    state.phase = 5;
    action(
        state,
        if state.mode == 1 { 4 } else { 3 },
        if state.mode == 2 { 4 } else { 3 },
    )
}
fn error_action(state: &mut State, error: u32, length: usize) -> Action {
    state.phase = 12;
    let format = match error {
        1 => c"%s: wrong key length %u. should be 16,24,32.",
        2 => c"aes: wrong data length %u. should be 16.",
        3 => c"aes_gcm: zero iv length",
        4 => c"aes_ctr: wrong iv length %u. should be 16.",
        _ => c"invalid Lua crypto action",
    };
    Action {
        data: format.as_ptr().cast(),
        error,
        length,
        ..action(state, 10, 0)
    }
}
unsafe fn crypt(state: &mut State, ops: &Ops) -> Action {
    // SAFETY: inputs stay rooted on the C/Lua argument stack. Output is either
    // separate Lua-owned writable userdata or this call's inline block storage.
    let ok = unsafe {
        match (state.mode, ops.block, ops.ctr, ops.gcm) {
            (0, Some(run), _, _) => run(
                state.encrypt != 0,
                state.key.data,
                state.key.length,
                state.input.data,
                state.block.as_mut_ptr(),
            ),
            (1, _, Some(run), _) => run(
                state.key.data,
                state.key.length,
                state.iv.data,
                state.input.data,
                state.input.length,
                state.output,
            ),
            (2, _, _, Some(run)) => run(
                state.encrypt != 0,
                state.key.data,
                state.key.length,
                state.iv.data,
                state.iv.length,
                state.input.data,
                state.input.length,
                state.associated.data,
                state.associated.length,
                state.output,
                state.tag.as_mut_ptr(),
            ),
            _ => false,
        }
    };
    state.success = u32::from(ok);
    state.phase = 8;
    if ok {
        Action {
            data: if state.mode == 0 {
                state.block.as_ptr()
            } else {
                state.output
            },
            length: state.input.length,
            ..action(state, 7, 0)
        }
    } else {
        action(state, 8, 0)
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_crypto_begin(
    mode: u32,
    state: *mut State,
    output: *mut Action,
) -> bool {
    if mode > 2 || !aligned(state) || !aligned(output) {
        return false;
    }
    let value = State {
        mode,
        phase: 1,
        ..Default::default()
    };
    let result = Action {
        minimum: if mode == 2 { 4 } else { 3 },
        maximum: if mode == 2 { 5 } else { 3 },
        ..action(&value, 1, 0)
    };
    unsafe {
        state.write(value);
        output.write(result)
    };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_crypto_step(
    state: *mut State,
    value: *const Value,
    output: *mut Action,
    backend: *const Ops,
) -> bool {
    if !aligned(state) || !aligned(value) || !aligned(output) {
        return false;
    }
    // SAFETY: C owns disjoint initialized records. No VM function is called by
    // this step or the native Rust crypto routines it selects.
    if !backend.is_null() && !backend.is_aligned() {
        return false;
    }
    let ops = if backend.is_null() {
        &NATIVE
    } else {
        unsafe { &*backend }
    };
    let (state, value) = unsafe { (&mut *state, &*value) };
    if state.mode > 2 || state.encrypt > 1 || state.success > 1 || value.truth > 1 {
        return false;
    }
    let result = match state.phase {
        1 => {
            if state.mode == 1 {
                key_action(state)
            } else {
                state.phase = 2;
                action(state, 2, 1)
            }
        }
        2 => {
            state.encrypt = value.truth;
            key_action(state)
        }
        3 => {
            if !value.span.valid() {
                return false;
            }
            state.key = value.span;
            if !matches!(state.key.length, 16 | 24 | 32) {
                error_action(state, 1, state.key.length)
            } else if state.mode == 0 {
                input_action(state)
            } else {
                state.phase = 4;
                action(state, 3, if state.mode == 1 { 2 } else { 3 })
            }
        }
        4 => {
            if !value.span.valid() {
                return false;
            }
            state.iv = value.span;
            if state.mode == 1 && state.iv.length != 16 {
                error_action(state, 4, state.iv.length)
            } else if state.mode == 2 && state.iv.length == 0 {
                error_action(state, 3, 0)
            } else {
                input_action(state)
            }
        }
        5 => {
            if !value.span.valid() {
                return false;
            }
            state.input = value.span;
            if state.mode == 0 {
                if state.input.length != 16 {
                    error_action(state, 2, state.input.length)
                } else {
                    unsafe { crypt(state, ops) }
                }
            } else if state.mode == 2 {
                state.phase = 6;
                action(state, 5, 5)
            } else {
                state.phase = 7;
                Action {
                    length: state.input.length,
                    ..action(state, 6, 0)
                }
            }
        }
        6 => {
            if !value.span.valid() {
                return false;
            }
            state.associated = value.span;
            state.phase = 7;
            Action {
                length: state.input.length,
                ..action(state, 6, 0)
            }
        }
        7 => {
            if !value.span.valid() || value.span.length != state.input.length {
                return false;
            }
            state.output = value.span.data.cast_mut();
            unsafe { crypt(state, ops) }
        }
        8 => {
            if state.mode == 2 {
                state.phase = 9;
                if state.success != 0 {
                    Action {
                        data: state.tag.as_ptr(),
                        length: 16,
                        ..action(state, 7, 0)
                    }
                } else {
                    action(state, 8, 0)
                }
            } else if state.mode == 1 {
                state.phase = 10;
                action(state, 9, -2)
            } else {
                state.phase = 11;
                Action {
                    count: 1,
                    ..action(state, 0, 0)
                }
            }
        }
        9 => {
            state.phase = 10;
            action(state, 9, -3)
        }
        10 | 11 => {
            state.phase = 11;
            Action {
                count: if state.mode == 2 { 2 } else { 1 },
                ..action(state, 0, 0)
            }
        }
        _ => return false,
    };
    unsafe { output.write(result) };
    true
}
const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 9 * pointer + 48);
    assert!(std::mem::offset_of!(State, block) == 9 * pointer + 32);
    assert!(size_of::<Action>() == 3 * pointer + 24);
    assert!(size_of::<Value>() == 3 * pointer);
    assert!(size_of::<Ops>() == 3 * pointer);
};
#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    fn begin(mode: u32) -> (State, Action) {
        let mut state = State::default();
        let mut action = Action::default();
        assert!(unsafe { zapret_lua_crypto_begin(mode, &mut state, &mut action) });
        (state, action)
    }
    fn step(state: &mut State, value: Value) -> Action {
        let mut action = Action::default();
        assert!(unsafe { zapret_lua_crypto_step(state, &value, &mut action, ptr::null()) });
        action
    }
    fn bytes(value: &[u8]) -> Value {
        Value {
            span: Span {
                data: value.as_ptr(),
                length: value.len(),
            },
            ..Default::default()
        }
    }
    #[test]
    fn bad_key_stops_before_iv_or_payload_queries() {
        for mode in 0..=2 {
            let (mut state, action) = begin(mode);
            assert_eq!(
                (action.minimum, action.maximum),
                if mode == 2 { (4, 5) } else { (3, 3) }
            );
            let action = step(&mut state, Value::default());
            if mode != 1 {
                assert_eq!(action.kind, 2);
                step(&mut state, Value::default());
            }
            let action = step(&mut state, bytes(&[0; 15]));
            assert_eq!((action.kind, action.error, action.length), (10, 1, 15));
        }
    }
    #[test]
    fn ctr_accepts_loose_input_only_after_strict_key_and_iv() {
        let (mut state, _) = begin(1);
        assert_eq!(step(&mut state, Value::default()).index, 1);
        assert_eq!(step(&mut state, bytes(&[0; 16])).index, 2);
        let input = step(&mut state, bytes(&[0; 16]));
        assert_eq!((input.kind, input.index), (4, 3));
        let alloc = step(&mut state, bytes(b"123"));
        assert_eq!((alloc.kind, alloc.length), (6, 3));
        let mut output = [0; 3];
        let result = step(
            &mut state,
            Value {
                span: Span {
                    data: output.as_mut_ptr(),
                    length: 3,
                },
                ..Default::default()
            },
        );
        assert_eq!((result.kind, result.length), (7, 3));
        assert_eq!(step(&mut state, Value::default()).index, -2);
        assert_eq!(step(&mut state, Value::default()).count, 1);
    }
    #[test]
    fn block_entry_uses_fixed_output_and_independent_zero_key_vector() {
        let (mut state, _) = begin(0);
        step(&mut state, Value::default());
        step(
            &mut state,
            Value {
                truth: 1,
                ..Default::default()
            },
        );
        step(&mut state, bytes(&[0; 16]));
        let result = step(&mut state, bytes(&[0; 16]));
        assert_eq!(result.kind, 7);
        assert_eq!(
            state.block,
            [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e
            ]
        );
        assert_eq!(step(&mut state, Value::default()).count, 1);
    }
    #[test]
    fn iv_length_errors_precede_payload_validation() {
        for mode in [1, 2] {
            let (mut state, _) = begin(mode);
            step(&mut state, Value::default());
            if mode == 2 {
                step(&mut state, Value::default());
            }
            step(&mut state, bytes(&[0; 16]));
            let result = step(&mut state, bytes(if mode == 1 { &[0; 15] } else { &[] }));
            assert_eq!(
                (result.kind, result.error),
                (10, if mode == 1 { 4 } else { 3 })
            );
        }
    }
    #[test]
    fn gcm_publishes_two_values_before_releasing_userdata() {
        let (mut state, _) = begin(2);
        step(&mut state, Value::default());
        step(
            &mut state,
            Value {
                truth: 1,
                ..Default::default()
            },
        );
        step(&mut state, bytes(&[0; 16]));
        step(&mut state, bytes(&[0; 12]));
        assert_eq!(step(&mut state, bytes(&[])).kind, 5);
        assert_eq!(step(&mut state, Value::default()).kind, 6);
        let mut output = [0; 1];
        assert_eq!(
            step(
                &mut state,
                Value {
                    span: Span {
                        data: output.as_mut_ptr(),
                        length: 0
                    },
                    ..Default::default()
                }
            )
            .kind,
            7
        );
        let tag = step(&mut state, Value::default());
        assert_eq!((tag.kind, tag.length), (7, 16));
        assert_eq!(step(&mut state, Value::default()).index, -3);
        assert_eq!(step(&mut state, Value::default()).count, 2);
    }
    #[test]
    fn invalid_span_metadata_does_not_reach_crypto_or_vm_publication() {
        let (mut state, _) = begin(1);
        step(&mut state, Value::default());
        let mut action = Action::default();
        assert!(!unsafe {
            zapret_lua_crypto_step(
                &mut state,
                &Value {
                    span: Span {
                        data: ptr::null(),
                        length: 16,
                    },
                    ..Default::default()
                },
                &mut action,
                ptr::null(),
            )
        });
        assert!(!unsafe { zapret_lua_crypto_begin(3, &mut state, &mut action) });
        assert!(!unsafe {
            zapret_lua_crypto_step(ptr::null_mut(), &Value::default(), &mut action, ptr::null())
        });
    }
}
