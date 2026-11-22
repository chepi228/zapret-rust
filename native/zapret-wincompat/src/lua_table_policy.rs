//! Resource-free position/range and blob policy between C-owned Lua calls.
use std::{
    ffi::{c_char, c_void},
    ptr,
};

fn aligned<T>(p: *const T) -> bool {
    !p.is_null() && p.is_aligned()
}
fn blob_local_is_present(tag: i32) -> bool {
    tag != 0
}

#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    data: *const c_void,
    number: i64,
    kind: u32,
    flag: u32,
}
#[repr(C)]
struct Position {
    mode: u8,
    value: u32,
}
#[repr(C)]
struct Range {
    from: Position,
    to: Position,
    upper_cutoff: u8,
}
#[repr(C)]
struct RangeState {
    source: *const c_void,
    name: *const c_char,
    mode: u32,
    phase: u32,
}

fn range_begin(
    mode: u32,
    source: *const c_void,
    name: *const c_char,
) -> Option<(RangeState, Action)> {
    if mode > 1 || !aligned(source.cast::<Position>()) {
        return None;
    }
    Some((
        RangeState {
            source,
            name,
            mode,
            phase: 0,
        },
        Action {
            name,
            kind: 1,
            ..Action::default()
        },
    ))
}
unsafe fn range_step(state: &mut RangeState) -> Option<Action> {
    if state.mode > 1 || !aligned(state.source.cast::<Position>()) {
        return None;
    }
    let mut result = Action::default();
    // SAFETY: only the source field corresponding to the current VM boundary
    // is read. Native padding and the remaining fields may be uninitialized.
    unsafe {
        match (state.mode, state.phase) {
            (_, 0) => {
                result.kind = 2;
                result.name = state.name;
            }
            (0, 1) => {
                result.kind = 3;
                result.name = c"mode".as_ptr();
                result.number = i64::from((*state.source.cast::<Position>()).mode);
            }
            (0, 2) => {
                result.kind = 4;
                result.name = c"pos".as_ptr();
                result.number = i64::from((*state.source.cast::<Position>()).value);
            }
            (0, 3) | (1, 4) => {
                result.kind = 5;
                result.number = 1;
            }
            (0, 4) | (1, 5) => {}
            (1, 1) => {
                result.kind = 7;
                result.name = c"upper_cutoff".as_ptr();
                result.number = i64::from((*state.source.cast::<Range>()).upper_cutoff != 0);
            }
            (1, 2) => {
                result.kind = 6;
                result.name = c"from".as_ptr();
                result.data = ptr::addr_of!((*state.source.cast::<Range>()).from).cast();
            }
            (1, 3) => {
                result.kind = 6;
                result.name = c"to".as_ptr();
                result.data = ptr::addr_of!((*state.source.cast::<Range>()).to).cast();
            }
            _ => return None,
        }
    }
    state.phase += 1;
    Some(result)
}

#[repr(C)]
struct BlobState {
    blob: *const c_char,
    field: *const c_char,
    index: i32,
    mode: u32,
    phase: u32,
    success: u32,
}
fn blob_begin(
    mode: u32,
    index: i32,
    field: *const c_char,
    blob: *const c_char,
) -> Option<(BlobState, Action)> {
    if mode > 1 {
        return None;
    }
    Some((
        BlobState {
            blob,
            field,
            index,
            mode,
            phase: if mode == 1 { 0 } else { 1 },
            success: 0,
        },
        Action {
            kind: if mode == 1 { 1 } else { 2 },
            name: if mode == 1 { field } else { blob },
            number: i64::from(index),
            ..Action::default()
        },
    ))
}
fn blob_step(state: &mut BlobState, tag: i32) -> Option<Action> {
    if state.mode > 1 || state.success > 1 {
        return None;
    }
    let mut action = Action {
        name: state.blob,
        ..Action::default()
    };
    match state.phase {
        0 => {
            state.phase = 1;
            action.kind = 2;
            action.number = i64::from(state.index);
        }
        1 => {
            state.phase = 2;
            action.kind = 3;
        }
        2 | 5 if blob_local_is_present(tag) => {
            state.phase = 7;
            state.success = 1;
            action.kind = 6;
        }
        2 => {
            state.phase = 3;
            action.kind = 4;
            action.number = 1;
        }
        3 => {
            state.phase = 4;
            action.kind = 5;
        }
        4 => {
            state.phase = 5;
            action.kind = 3;
        }
        5 => {
            state.phase = 6;
            action.kind = 4;
            action.number = 1;
        }
        6 => {
            state.phase = 10;
            action.kind = 8;
            action.data = c"blob '%s' unavailable\n".as_ptr().cast();
        }
        7 if state.mode == 1 => {
            state.phase = 8;
            action.kind = 7;
            action.number = -3;
        }
        7..=9 => {
            state.phase = 11;
            action.flag = state.success;
        }
        10 if state.mode == 1 => {
            state.phase = 9;
            action.kind = 4;
            action.number = 1;
        }
        10 => {
            state.phase = 11;
        }
        _ => return None,
    }
    Some(action)
}

/// # Safety
/// Source is aligned native position/range storage, live for the whole operation.
/// Initialize each selected field before its read step. Disjoint state/action
/// outputs are aligned and writable; name is a borrowed C string for C VM calls.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_range_begin(
    mode: u32,
    source: *const c_void,
    name: *const c_char,
    state: *mut RangeState,
    output: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(output) {
        return false;
    }
    let Some((initial, action)) = range_begin(mode, source, name) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint initialized metadata is valid/aligned. The source fields remain
/// readable only when selected; C may mutate later fields between steps.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_range_step(state: *mut RangeState, output: *mut Action) -> bool {
    if !aligned(state) || !aligned(output) {
        return false;
    }
    let Some(action) = (unsafe { range_step(&mut *state) }) else {
        return false;
    };
    unsafe {
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint outputs are valid/aligned. Names are rooted C strings until done;
/// field may be null to retain Lua's existing nil-key behavior. No VM call runs.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_blob_begin(
    mode: u32,
    index: i32,
    field: *const c_char,
    blob: *const c_char,
    state: *mut BlobState,
    output: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(output) {
        return false;
    }
    let Some((initial, action)) = blob_begin(mode, index, field, blob) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint initialized state/output metadata must be valid/aligned. Supply
/// the Lua tag only for a type command. C alone enters Lua or invokes logging.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_blob_step(
    state: *mut BlobState,
    tag: i32,
    output: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(output) {
        return false;
    }
    let Some(action) = blob_step(unsafe { &mut *state }, tag) else {
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
    fn a_local_false_blob_is_present_and_does_not_fall_back_to_global() {
        assert!(blob_local_is_present(1));
        assert!(!blob_local_is_present(0));
    }

    #[test]
    fn position_fields_are_read_after_create_lookup_and_mode_publication() {
        let mut source = std::mem::MaybeUninit::<Position>::uninit();
        let source = source.as_mut_ptr();
        let (mut state, create) = range_begin(0, source.cast(), c"position".as_ptr()).unwrap();
        assert_eq!(create.kind, 1);
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().kind, 2);
        unsafe {
            ptr::addr_of_mut!((*source).mode).write(0);
        }
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().number, 0);
        unsafe {
            ptr::addr_of_mut!((*source).value).write(u32::MAX);
        }
        assert_eq!(
            unsafe { range_step(&mut state) }.unwrap().number,
            4294967295
        );
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().kind, 5);
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().kind, 0);
        assert!(unsafe { range_step(&mut state) }.is_none());
    }

    #[test]
    fn range_defers_child_fields_and_uses_native_offsets() {
        let mut source = std::mem::MaybeUninit::<Range>::uninit();
        let source = source.as_mut_ptr();
        let (mut state, _) = range_begin(1, source.cast(), c"range".as_ptr()).unwrap();
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().kind, 2);
        unsafe {
            ptr::addr_of_mut!((*source).upper_cutoff).write(1);
        }
        assert_eq!(unsafe { range_step(&mut state) }.unwrap().number, 1);
        let from = unsafe { range_step(&mut state) }.unwrap();
        let to = unsafe { range_step(&mut state) }.unwrap();
        assert_eq!(from.data, source.cast());
        assert_eq!(to.data, source.cast::<u8>().wrapping_add(8).cast());
        assert_eq!((from.kind, to.kind), (6, 6));
    }

    #[test]
    fn blob_lookup_keeps_the_original_relative_index_after_field_key_push() {
        let (mut state, key) = blob_begin(1, -1, c"field".as_ptr(), c"blob".as_ptr()).unwrap();
        assert_eq!(key.kind, 1);
        let local = blob_step(&mut state, 0).unwrap();
        assert_eq!((local.kind, local.number), (2, -1));
        assert_eq!(blob_step(&mut state, 0).unwrap().kind, 3);
        assert_eq!(blob_step(&mut state, 1).unwrap().kind, 6);
        assert_eq!(blob_step(&mut state, 0).unwrap().kind, 7);
        assert_eq!(blob_step(&mut state, 0).unwrap().flag, 1);
    }

    #[test]
    fn local_nil_falls_back_and_missing_field_blob_logs_before_key_cleanup() {
        let (mut state, _) = blob_begin(1, 1, c"field".as_ptr(), c"blob".as_ptr()).unwrap();
        let commands: Vec<_> = (0..9)
            .map(|_| blob_step(&mut state, 0).unwrap().kind)
            .collect();
        assert_eq!(commands, [2, 3, 4, 5, 3, 4, 8, 4, 0]);
        assert!(blob_step(&mut state, 0).is_none());
    }

    #[test]
    fn all_non_nil_tags_coerce_without_requiring_a_string() {
        for tag in [-1, 1, 2, 3, 4, 5, 6, 7, 8] {
            let (mut state, _) = blob_begin(0, 1, ptr::null(), c"blob".as_ptr()).unwrap();
            assert_eq!(blob_step(&mut state, 0).unwrap().kind, 3);
            assert_eq!(blob_step(&mut state, tag).unwrap().kind, 6);
            assert_eq!(blob_step(&mut state, 0).unwrap().flag, 1);
        }
    }

    #[test]
    fn invalid_metadata_preserves_outputs_and_layouts_match_native_c() {
        assert_eq!(size_of::<Position>(), 8);
        assert_eq!(size_of::<Range>(), 20);
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<RangeState>(), 2 * pointer + 8);
        assert_eq!(size_of::<BlobState>(), 2 * pointer + 16);
        assert_eq!(size_of::<Action>(), 2 * pointer + 16);
        let mut out = Action {
            kind: 91,
            ..Action::default()
        };
        let mut state = std::mem::MaybeUninit::<BlobState>::uninit();
        assert!(!unsafe {
            zapret_lua_blob_begin(2, 1, ptr::null(), ptr::null(), state.as_mut_ptr(), &mut out)
        });
        assert_eq!(out.kind, 91);
        assert!(!unsafe { zapret_lua_range_step(ptr::null_mut(), &mut out) });
        assert_eq!(out.kind, 91);
    }
}
