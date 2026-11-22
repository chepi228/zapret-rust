//! Per-field option publication between C-owned Lua queries and errors.
use std::{
    ffi::{CStr, c_char},
    ptr,
};
#[repr(C)]
#[derive(Clone, Copy)]
struct Targets {
    keepsum: *mut bool,
    badsum: *mut bool,
    preserve: *mut bool,
    protocol: *mut u8,
    repeats: *mut i32,
    mark: *mut u32,
    interface: *mut *const c_char,
    default_mark: *const u32,
}
#[repr(C)]
struct Cursor {
    targets: Targets,
    index: u32,
    mode: u32,
}
#[repr(C)]
struct Field {
    name: *const c_char,
    kind: u32,
}
#[repr(C)]
struct Value {
    data: *const c_char,
    number: i64,
    tag: i32,
    truth: u32,
}
const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Targets>() == 8 * pointer);
    assert!(size_of::<Cursor>() == 8 * pointer + 8);
    assert!(size_of::<Field>() == 2 * pointer);
    assert!(size_of::<Value>() == 24);
};
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn optional<T>(pointer: *const T) -> bool {
    pointer.is_null() || pointer.is_aligned()
}
impl Targets {
    fn valid(&self, mode: u32) -> bool {
        match mode {
            0 => true,
            1 => {
                optional(self.repeats)
                    && optional(self.mark)
                    && optional(self.interface)
                    && (self.mark.is_null() || aligned(self.default_mark))
            }
            _ => false,
        }
    }
}
impl Cursor {
    fn count(&self) -> u32 {
        if self.mode == 0 { 4 } else { 3 }
    }
    fn requested(&self) -> bool {
        match (self.mode, self.index) {
            (0, 0) => !self.targets.keepsum.is_null(),
            (0, 1) => !self.targets.badsum.is_null(),
            (0, 2) => !self.targets.preserve.is_null(),
            (0, 3) => !self.targets.protocol.is_null(),
            (1, 0) => !self.targets.repeats.is_null(),
            (1, 1) => !self.targets.mark.is_null(),
            (1, 2) => !self.targets.interface.is_null(),
            _ => false,
        }
    }
    fn next(&mut self, field: *mut Field) -> u32 {
        while self.index < self.count() {
            if self.requested() {
                let (name, kind): (&CStr, u32) = match (self.mode, self.index) {
                    (0, 0) => (c"keepsum", 1),
                    (0, 1) => (c"badsum", 1),
                    (0, 2) => (c"ip6_preserve_next", 1),
                    (0, 3) => (c"ip6_last_proto", 2),
                    (1, 0) => (c"repeats", 3),
                    (1, 1) => (c"fwmark", 4),
                    _ => (c"ifout", 5),
                };
                unsafe {
                    field.write(Field {
                        name: name.as_ptr(),
                        kind,
                    })
                };
                return 1;
            }
            self.index += 1;
        }
        0
    }
    unsafe fn defaults(&self) {
        unsafe {
            match self.mode {
                0 => {
                    if !self.targets.keepsum.is_null() {
                        self.targets.keepsum.write(false);
                    }
                    if !self.targets.badsum.is_null() {
                        self.targets.badsum.write(false);
                    }
                    if !self.targets.preserve.is_null() {
                        self.targets.preserve.write(false);
                    }
                    if !self.targets.protocol.is_null() {
                        self.targets.protocol.write(59);
                    }
                }
                _ => {
                    if !self.targets.repeats.is_null() {
                        self.targets.repeats.write(1);
                    }
                    if !self.targets.mark.is_null() {
                        self.targets.mark.write(self.targets.default_mark.read());
                    }
                    if !self.targets.interface.is_null() {
                        self.targets.interface.write(ptr::null());
                    }
                }
            }
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_options_begin(
    mode: u32,
    absent: u32,
    targets: *const Targets,
    cursor: *mut Cursor,
    field: *mut Field,
) -> u32 {
    if !aligned(targets) || !aligned(cursor) || !aligned(field) || mode > 1 || absent > 1 {
        return 2;
    }
    let targets = unsafe { *targets };
    if !targets.valid(mode) {
        return 2;
    }
    let mut state = Cursor {
        targets,
        index: 0,
        mode,
    };
    let status = if absent != 0 {
        unsafe { state.defaults() };
        state.index = state.count();
        0
    } else {
        state.next(field)
    };
    unsafe { cursor.write(state) };
    status
}
#[unsafe(no_mangle)]
extern "C" fn zapret_lua_packet_option_error_format(status: u32) -> *const c_char {
    match status {
        3 => c"rawsend: negative repeats",
        _ => c"invalid packet option cursor",
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_options_observe(
    cursor: *mut Cursor,
    value: *const Value,
    field: *mut Field,
) -> u32 {
    if !aligned(cursor) || !aligned(value) || !aligned(field) {
        return 2;
    }
    let state = unsafe { &mut *cursor };
    if !state.targets.valid(state.mode) || state.index >= state.count() || !state.requested() {
        return 2;
    }
    let value = unsafe { &*value };
    let truth = value.tag != 0 && (value.tag != 1 || value.truth != 0);
    // Outputs are disjoint from cursor/value metadata. Optional flag outputs
    // may alias each other, so publish raw scalars in the original query order.
    unsafe {
        match (state.mode, state.index) {
            (0, 0) => state.targets.keepsum.write(truth),
            (0, 1) => state.targets.badsum.write(truth),
            (0, 2) => state.targets.preserve.write(truth),
            (0, 3) => state.targets.protocol.write(if value.tag == 0 {
                59
            } else {
                value.number as u8
            }),
            (1, 0) => {
                let repeats = value.number as i32;
                state.targets.repeats.write(repeats);
                if repeats < 0 {
                    state.index = state.count();
                    return 3;
                }
                if repeats == 0 {
                    state.targets.repeats.write(1);
                }
            }
            (1, 1) => state
                .targets
                .mark
                .write(value.number as u32 | state.targets.default_mark.read()),
            (1, 2) => state.targets.interface.write(if value.tag == 4 {
                value.data
            } else {
                ptr::null()
            }),
            _ => return 2,
        }
    }
    state.index += 1;
    state.next(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;
    fn empty() -> Targets {
        Targets {
            keepsum: ptr::null_mut(),
            badsum: ptr::null_mut(),
            preserve: ptr::null_mut(),
            protocol: ptr::null_mut(),
            repeats: ptr::null_mut(),
            mark: ptr::null_mut(),
            interface: ptr::null_mut(),
            default_mark: ptr::null(),
        }
    }
    #[test]
    fn raw_repeats_are_narrowed_and_published_before_requesting_a_c_error() {
        let mut repeats = 9;
        let targets = Targets {
            repeats: &mut repeats,
            ..empty()
        };
        let mut cursor = MaybeUninit::uninit();
        let mut field = MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_begin(
                    1,
                    0,
                    &targets,
                    cursor.as_mut_ptr(),
                    field.as_mut_ptr(),
                )
            },
            1
        );
        let mut cursor = unsafe { cursor.assume_init() };
        let value = Value {
            data: ptr::null(),
            number: 4294967295,
            tag: 3,
            truth: 0,
        };
        assert_eq!(
            unsafe { zapret_lua_packet_options_observe(&mut cursor, &value, field.as_mut_ptr()) },
            3
        );
        assert_eq!(repeats, -1);
    }
    unsafe fn start(mode: u32, targets: &Targets) -> (Cursor, Field) {
        let mut cursor = MaybeUninit::uninit();
        let mut field = MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_begin(
                    mode,
                    0,
                    targets,
                    cursor.as_mut_ptr(),
                    field.as_mut_ptr(),
                )
            },
            1
        );
        unsafe { (cursor.assume_init(), field.assume_init()) }
    }
    #[test]
    fn optional_outputs_skip_lookups_and_aliased_flags_publish_in_order() {
        let mut flag = false;
        let pointer = ptr::from_mut(&mut flag);
        let targets = Targets {
            keepsum: pointer,
            badsum: pointer,
            ..empty()
        };
        let (mut cursor, mut field) = unsafe { start(0, &targets) };
        assert_eq!(unsafe { CStr::from_ptr(field.name) }, c"keepsum");
        let value = Value {
            data: ptr::null(),
            number: 0,
            tag: 3,
            truth: 0,
        };
        assert_eq!(
            unsafe { zapret_lua_packet_options_observe(&mut cursor, &value, &mut field) },
            1
        );
        assert!(flag);
        assert_eq!(unsafe { CStr::from_ptr(field.name) }, c"badsum");
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_observe(
                    &mut cursor,
                    &Value { tag: 0, ..value },
                    &mut field,
                )
            },
            0
        );
        assert!(!flag);
    }
    #[test]
    fn absent_options_initialize_only_requested_defaults() {
        let mut repeats = 9;
        let mut protocol = 0;
        let targets = Targets {
            repeats: &mut repeats,
            protocol: &mut protocol,
            ..empty()
        };
        let mut cursor = MaybeUninit::uninit();
        let mut field = MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_begin(
                    0,
                    1,
                    &targets,
                    cursor.as_mut_ptr(),
                    field.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(protocol, 59);
        assert_eq!(repeats, 9);
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_begin(
                    1,
                    1,
                    &targets,
                    cursor.as_mut_ptr(),
                    field.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(repeats, 1);
    }
    #[test]
    fn fwmark_reads_the_live_default_after_the_query_returns() {
        let mut default = 0x100;
        let mut mark = 0;
        let targets = Targets {
            mark: &mut mark,
            default_mark: ptr::from_mut(&mut default),
            ..empty()
        };
        let (mut cursor, mut field) = unsafe { start(1, &targets) };
        default = 0x800;
        assert_eq!(field.kind, 4);
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_observe(
                    &mut cursor,
                    &Value {
                        data: ptr::null(),
                        number: 3,
                        tag: 3,
                        truth: 0,
                    },
                    &mut field,
                )
            },
            0
        );
        assert_eq!(mark, default | 3);
    }
    #[test]
    fn repeat_zero_default_applies_after_signed_integer_narrowing() {
        for number in [0, -4294967296, 4294967296] {
            let mut repeats = 9;
            let targets = Targets {
                repeats: &mut repeats,
                ..empty()
            };
            let (mut cursor, mut field) = unsafe { start(1, &targets) };
            assert_eq!(
                unsafe {
                    zapret_lua_packet_options_observe(
                        &mut cursor,
                        &Value {
                            data: ptr::null(),
                            number,
                            tag: 4,
                            truth: 0,
                        },
                        &mut field,
                    )
                },
                0
            );
            assert_eq!(repeats, 1);
        }
    }
    #[test]
    fn interface_remains_a_borrowed_exact_string_and_terminal_state_rejects_reuse() {
        let mut interface = ptr::null();
        let targets = Targets {
            interface: &mut interface,
            ..empty()
        };
        let (mut cursor, mut field) = unsafe { start(1, &targets) };
        let value = Value {
            data: c"wifi".as_ptr(),
            number: 0,
            tag: 4,
            truth: 0,
        };
        assert_eq!(
            unsafe { zapret_lua_packet_options_observe(&mut cursor, &value, &mut field) },
            0
        );
        assert_eq!(interface, value.data);
        assert_eq!(
            unsafe { zapret_lua_packet_options_observe(&mut cursor, &value, &mut field) },
            2
        );
        let (mut cursor, mut field) = unsafe { start(1, &targets) };
        assert_eq!(
            unsafe {
                zapret_lua_packet_options_observe(
                    &mut cursor,
                    &Value { tag: 3, ..value },
                    &mut field,
                )
            },
            0
        );
        assert!(interface.is_null());
    }
}
