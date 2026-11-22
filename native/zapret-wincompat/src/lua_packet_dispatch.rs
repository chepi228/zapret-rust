//! Outer packet API policy, with every Lua/driver/pool operation outside Rust.
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};
#[repr(u32)]
#[derive(Clone, Copy)]
enum Mode {
    Raw = 0,
    Send = 1,
    Track = 2,
    Reconstruct = 3,
    Dissect = 4,
}
impl Mode {
    fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Raw),
            1 => Some(Self::Send),
            2 => Some(Self::Track),
            3 => Some(Self::Reconstruct),
            4 => Some(Self::Dissect),
            _ => None,
        }
    }
    fn name(self) -> &'static CStr {
        match self {
            Self::Raw => c"rawsend",
            Self::Send => c"rawsend_dissect",
            Self::Track => c"conntrack_feed",
            Self::Reconstruct => c"reconstruct_dissect",
            Self::Dissect => c"dissect",
        }
    }
    fn needs_buffer(self) -> bool {
        matches!(self, Self::Send | Self::Track | Self::Reconstruct)
    }
}
#[repr(u32)]
#[derive(Clone, Copy)]
enum Phase {
    Arguments = 1,
    Disabled,
    InputType,
    Table,
    Raw,
    String,
    SendOptions,
    ReconstructOptions,
    Reconstruct,
    NoPayload,
    Parse,
    Purge,
    Feed,
    Track,
    Direction,
    NilPair,
    Destination,
    Debug,
    Send,
    Boolean,
    Bytes,
    Dissect,
    Done,
    Error,
    PayloadFlag,
}
impl Phase {
    fn decode(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Arguments,
            2 => Self::Disabled,
            3 => Self::InputType,
            4 => Self::Table,
            5 => Self::Raw,
            6 => Self::String,
            7 => Self::SendOptions,
            8 => Self::ReconstructOptions,
            9 => Self::Reconstruct,
            10 => Self::NoPayload,
            11 => Self::Parse,
            12 => Self::Purge,
            13 => Self::Feed,
            14 => Self::Track,
            15 => Self::Direction,
            16 => Self::NilPair,
            17 => Self::Destination,
            18 => Self::Debug,
            19 => Self::Send,
            20 => Self::Boolean,
            21 => Self::Bytes,
            22 => Self::Dissect,
            23 => Self::Done,
            24 => Self::Error,
            25 => Self::PayloadFlag,
            _ => return None,
        })
    }
}
#[repr(C)]
struct State {
    buffer: *mut u8,
    data: *const u8,
    track: *mut c_void,
    capacity: usize,
    length: usize,
    mode: u32,
    phase: u32,
    reverse: u32,
    no_payload: u32,
    success: u32,
    error: u32,
}
#[repr(C)]
struct Action {
    name: *const c_char,
    kind: u32,
    index: i32,
    minimum: i32,
    maximum: i32,
    count: u32,
    error: u32,
}
#[repr(C)]
struct Value {
    data: *const u8,
    length: usize,
    track: *mut c_void,
    reverse: u32,
    success: u32,
    tag: i32,
    extra: u32,
}
const _: () = {
    use std::mem::offset_of;
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 5 * pointer + 24);
    assert!(offset_of!(State, mode) == 5 * pointer);
    assert!(size_of::<Action>() == pointer + 24);
    assert!(size_of::<Value>() == 3 * pointer + 16);
    assert!(offset_of!(Value, tag) == 3 * pointer + 8);
};
fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
fn span(data: *const u8, length: usize) -> bool {
    length <= isize::MAX as usize
        && (length == 0 || !data.is_null())
        && data.addr().checked_add(length).is_some()
}
impl State {
    fn action(&mut self, mode: Mode, phase: Phase) -> Action {
        self.phase = phase as u32;
        let name = match (phase, mode) {
            (Phase::Debug, Mode::Raw) => c"rawsend repeats=%d size=%zu ifout=%s fwmark=%08X\n",
            (Phase::Debug, _) => {
                c"rawsend_dissect repeats=%d size=%zu badsum=%u ifout=%s fwmark=%08X\n"
            }
            (Phase::Error, _) => match self.error {
                1 => c"invalid packet data type",
                2 => c"invalid dissect data",
                _ => c"bad ip4/ip6 header",
            },
            _ => mode.name(),
        };
        Action {
            name: name.as_ptr(),
            kind: phase as u32,
            index: if matches!(phase, Phase::SendOptions) {
                2
            } else if matches!(phase, Phase::ReconstructOptions) {
                if matches!(mode, Mode::Send) { 3 } else { 2 }
            } else if matches!(phase, Phase::Debug) {
                i32::from(matches!(mode, Mode::Send))
            } else {
                1
            },
            minimum: 1,
            maximum: if matches!(mode, Mode::Send) { 3 } else { 2 },
            count: if matches!(mode, Mode::Track) { 2 } else { 1 },
            error: self.error,
        }
    }
    fn fail(&mut self, mode: Mode, error: u32) -> Action {
        self.error = error;
        self.action(mode, Phase::Error)
    }
    fn valid(&self) -> Option<(Mode, Phase)> {
        let mode = Mode::decode(self.mode)?;
        let phase = Phase::decode(self.phase)?;
        if self.reverse > 1
            || self.no_payload > 1
            || self.success > 1
            || !span(self.data, self.length)
            || self.capacity > isize::MAX as usize
            || mode.needs_buffer() && !span(self.buffer, self.capacity)
        {
            return None;
        }
        let allowed = match mode {
            Mode::Raw => matches!(
                phase,
                Phase::Arguments
                    | Phase::Raw
                    | Phase::SendOptions
                    | Phase::Destination
                    | Phase::Debug
                    | Phase::Send
                    | Phase::Boolean
            ),
            Mode::Send => matches!(
                phase,
                Phase::Arguments
                    | Phase::Table
                    | Phase::SendOptions
                    | Phase::ReconstructOptions
                    | Phase::Reconstruct
                    | Phase::Destination
                    | Phase::Debug
                    | Phase::Send
                    | Phase::Boolean
            ),
            Mode::Track => matches!(
                phase,
                Phase::Arguments
                    | Phase::Disabled
                    | Phase::InputType
                    | Phase::ReconstructOptions
                    | Phase::Reconstruct
                    | Phase::String
                    | Phase::Parse
                    | Phase::Purge
                    | Phase::Feed
                    | Phase::Track
                    | Phase::Direction
                    | Phase::NilPair
            ),
            Mode::Reconstruct => matches!(
                phase,
                Phase::Arguments | Phase::ReconstructOptions | Phase::Reconstruct | Phase::Bytes
            ),
            Mode::Dissect => matches!(
                phase,
                Phase::Arguments
                    | Phase::Raw
                    | Phase::NoPayload
                    | Phase::PayloadFlag
                    | Phase::Parse
                    | Phase::Dissect
            ),
        };
        allowed.then_some((mode, phase))
    }
    fn observe(&mut self, mode: Mode, phase: Phase, value: &Value) -> Option<Action> {
        let next = match phase {
            Phase::Arguments => match mode {
                Mode::Raw | Mode::Dissect => Phase::Raw,
                Mode::Send => Phase::Table,
                Mode::Track => Phase::Disabled,
                Mode::Reconstruct => Phase::ReconstructOptions,
            },
            Phase::Disabled => {
                if value.success != 0 {
                    Phase::NilPair
                } else {
                    Phase::InputType
                }
            }
            Phase::InputType => match value.tag {
                5 => Phase::ReconstructOptions,
                4 => Phase::String,
                _ => return Some(self.fail(mode, 1)),
            },
            Phase::Table => Phase::SendOptions,
            Phase::Raw | Phase::String => {
                if !span(value.data, value.length) {
                    return None;
                }
                self.data = value.data;
                self.length = value.length;
                match mode {
                    Mode::Raw => Phase::SendOptions,
                    Mode::Track => Phase::Parse,
                    _ => Phase::NoPayload,
                }
            }
            Phase::SendOptions => {
                if matches!(mode, Mode::Send) {
                    Phase::ReconstructOptions
                } else {
                    Phase::Destination
                }
            }
            Phase::ReconstructOptions => Phase::Reconstruct,
            Phase::Reconstruct => {
                if value.success == 0 {
                    return Some(self.fail(mode, 2));
                }
                if value.length > self.capacity {
                    return None;
                }
                self.data = self.buffer;
                self.length = value.length;
                match mode {
                    Mode::Send => Phase::Destination,
                    Mode::Track => Phase::Parse,
                    _ => Phase::Bytes,
                }
            }
            Phase::NoPayload if value.tag >= 2 => Phase::PayloadFlag,
            Phase::NoPayload => Phase::Parse,
            Phase::PayloadFlag => {
                self.no_payload = value.success;
                Phase::Parse
            }
            Phase::Parse => {
                if matches!(mode, Mode::Track) {
                    Phase::Purge
                } else {
                    Phase::Dissect
                }
            }
            Phase::Purge => Phase::Feed,
            Phase::Feed => {
                if value.success != 0 {
                    self.track = value.track;
                    self.reverse = value.reverse;
                    Phase::Track
                } else {
                    Phase::NilPair
                }
            }
            Phase::Track => Phase::Direction,
            Phase::Destination => {
                if value.success == 0 {
                    return Some(self.fail(mode, 3));
                } else {
                    Phase::Debug
                }
            }
            Phase::Debug => Phase::Send,
            Phase::Send => {
                self.success = value.success;
                Phase::Boolean
            }
            Phase::Direction | Phase::NilPair | Phase::Boolean | Phase::Bytes | Phase::Dissect => {
                Phase::Done
            }
            Phase::Done | Phase::Error => return None,
        };
        Some(self.action(mode, next))
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_dispatch_begin(
    mode: u32,
    buffer: *mut u8,
    capacity: usize,
    state: *mut State,
    action: *mut Action,
) -> bool {
    let Some(kind) = Mode::decode(mode) else {
        return false;
    };
    if !aligned(state)
        || !aligned(action)
        || capacity > isize::MAX as usize
        || kind.needs_buffer() && !span(buffer, capacity)
    {
        return false;
    }
    let mut initial = State {
        buffer,
        data: ptr::null(),
        track: ptr::null_mut(),
        capacity,
        length: 0,
        mode,
        phase: 0,
        reverse: 0,
        no_payload: 0,
        success: 0,
        error: 0,
    };
    let next = initial.action(kind, Phase::Arguments);
    unsafe {
        state.write(initial);
        action.write(next)
    };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_dispatch_step(
    state: *mut State,
    value: *const Value,
    action: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(value) || !aligned(action) {
        return false;
    }
    let state = unsafe { &mut *state };
    let Some((mode, phase)) = state.valid() else {
        return false;
    };
    let value = unsafe { &*value };
    if value.success > 1 || value.reverse > 1 {
        return false;
    }
    let Some(next) = state.observe(mode, phase, value) else {
        return false;
    };
    unsafe { action.write(next) };
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;
    unsafe fn step(state: &mut State, success: u32, tag: i32) -> Action {
        let mut action = MaybeUninit::uninit();
        let value = Value {
            data: ptr::null(),
            length: 0,
            track: ptr::null_mut(),
            reverse: 0,
            success,
            tag,
            extra: 0,
        };
        assert!(unsafe { zapret_lua_packet_dispatch_step(state, &value, action.as_mut_ptr()) });
        unsafe { action.assume_init() }
    }
    #[test]
    fn disabled_conntrack_skips_input_type_and_returns_two_nil_values() {
        let mut buffer = [0u8; 64];
        let mut state = MaybeUninit::uninit();
        let mut action = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_packet_dispatch_begin(
                2,
                buffer.as_mut_ptr(),
                64,
                state.as_mut_ptr(),
                action.as_mut_ptr(),
            )
        });
        let mut state = unsafe { state.assume_init() };
        assert_eq!(unsafe { action.assume_init_ref() }.kind, 1);
        assert_eq!(unsafe { step(&mut state, 0, 0) }.kind, 2);
        assert_eq!(unsafe { step(&mut state, 1, 0) }.kind, 16);
        let action = unsafe { step(&mut state, 0, 0) };
        assert_eq!((action.kind, action.count), (23, 2));
    }
    unsafe fn start(mode: u32, buffer: &mut [u8]) -> State {
        let mut state = MaybeUninit::uninit();
        let mut action = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_packet_dispatch_begin(
                mode,
                buffer.as_mut_ptr(),
                buffer.len(),
                state.as_mut_ptr(),
                action.as_mut_ptr(),
            )
        });
        unsafe { state.assume_init() }
    }
    unsafe fn observe(state: &mut State, value: &Value) -> Action {
        let mut action = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_packet_dispatch_step(state, value, action.as_mut_ptr()) });
        unsafe { action.assume_init() }
    }
    fn empty() -> Value {
        Value {
            data: ptr::null(),
            length: 0,
            track: ptr::null_mut(),
            reverse: 0,
            success: 0,
            tag: 0,
            extra: 0,
        }
    }
    #[test]
    fn raw_send_extracts_options_before_destination_and_retains_a_false_send_result() {
        let mut bytes = [0; 40];
        let data = bytes.as_ptr();
        let mut s = unsafe { start(0, &mut bytes) };
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 5);
        assert_eq!(
            unsafe {
                observe(
                    &mut s,
                    &Value {
                        data,
                        length: 40,
                        ..empty()
                    },
                )
            }
            .kind,
            7
        );
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 17);
        assert_eq!(unsafe { step(&mut s, 1, 0) }.kind, 18);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 19);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 20);
        assert_eq!(s.success, 0);
        let action = unsafe { step(&mut s, 0, 0) };
        assert_eq!((action.kind, action.count), (23, 1));
    }
    #[test]
    fn dissect_send_validates_the_table_then_both_option_sets_before_assembly() {
        let mut bytes = [0; 64];
        let mut s = unsafe { start(1, &mut bytes) };
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 4);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 7);
        let action = unsafe { step(&mut s, 0, 0) };
        assert_eq!((action.kind, action.index), (8, 3));
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 9);
        let action = unsafe { step(&mut s, 0, 0) };
        assert_eq!((action.kind, action.error), (24, 2));
    }
    #[test]
    fn raw_tracking_purges_before_feed_and_keeps_the_observed_direction() {
        let mut bytes = [0; 64];
        let data = bytes.as_ptr();
        let mut s = unsafe { start(2, &mut bytes) };
        unsafe {
            step(&mut s, 0, 0);
            step(&mut s, 0, 0);
        }
        assert_eq!(unsafe { step(&mut s, 0, 4) }.kind, 6);
        assert_eq!(
            unsafe {
                observe(
                    &mut s,
                    &Value {
                        data,
                        length: 40,
                        ..empty()
                    },
                )
            }
            .kind,
            11
        );
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 12);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 13);
        let track = ptr::dangling_mut();
        let value = Value {
            track,
            success: 1,
            reverse: 1,
            ..empty()
        };
        assert_eq!(unsafe { observe(&mut s, &value) }.kind, 14);
        assert_eq!((s.track, s.reverse), (track, 1));
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 15);
        let action = unsafe { step(&mut s, 0, 0) };
        assert_eq!((action.kind, action.count), (23, 2));
    }
    #[test]
    fn malformed_tracking_input_is_rejected_only_after_the_disable_check() {
        let mut bytes = [0; 64];
        let mut s = unsafe { start(2, &mut bytes) };
        unsafe {
            step(&mut s, 0, 0);
            step(&mut s, 0, 0);
        }
        let action = unsafe { step(&mut s, 0, 3) };
        assert_eq!((action.kind, action.error), (24, 1));
    }
    #[test]
    fn failed_tracking_returns_two_nil_values_without_constructing_a_track() {
        let mut bytes = [0; 64];
        let data = bytes.as_ptr();
        let mut s = unsafe { start(2, &mut bytes) };
        unsafe {
            step(&mut s, 0, 0);
            step(&mut s, 0, 0);
            step(&mut s, 0, 4);
            observe(
                &mut s,
                &Value {
                    data,
                    length: 40,
                    ..empty()
                },
            );
            step(&mut s, 0, 0);
            step(&mut s, 0, 0);
        }
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 16);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.count, 2);
    }
    #[test]
    fn dissect_captures_the_payload_check_flag_before_parsing() {
        let mut bytes = [0; 64];
        let data = bytes.as_ptr();
        let mut s = unsafe { start(4, &mut bytes) };
        unsafe {
            step(&mut s, 0, 0);
        }
        assert_eq!(
            unsafe {
                observe(
                    &mut s,
                    &Value {
                        data,
                        length: 40,
                        ..empty()
                    },
                )
            }
            .kind,
            10
        );
        assert_eq!(unsafe { step(&mut s, 0, 2) }.kind, 25);
        assert_eq!(unsafe { step(&mut s, 1, 0) }.kind, 11);
        assert_eq!(s.no_payload, 1);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.kind, 22);
        assert_eq!(unsafe { step(&mut s, 0, 0) }.count, 1);
    }
    #[test]
    fn reconstruction_checks_the_borrowed_workspace_span_before_publishing() {
        let mut bytes = [0; 40];
        let mut s = unsafe { start(3, &mut bytes) };
        unsafe {
            step(&mut s, 0, 0);
            step(&mut s, 0, 0);
        }
        let mut action = Action {
            name: ptr::null(),
            kind: 99,
            index: 99,
            minimum: 99,
            maximum: 99,
            count: 99,
            error: 99,
        };
        let value = Value {
            length: 41,
            success: 1,
            ..empty()
        };
        assert!(!unsafe { zapret_lua_packet_dispatch_step(&mut s, &value, &mut action) });
        assert_eq!(action.kind, 99);
        assert_eq!(s.length, 0);
        assert_eq!(
            unsafe {
                observe(
                    &mut s,
                    &Value {
                        length: 40,
                        success: 1,
                        ..empty()
                    },
                )
            }
            .kind,
            21
        );
        assert_eq!(s.data, bytes.as_ptr());
        assert_eq!(s.length, 40);
    }
    #[test]
    fn invalid_mode_terminal_state_and_boolean_metadata_leave_actions_unpublished() {
        let mut bytes = [0; 40];
        let mut s = unsafe { start(0, &mut bytes) };
        let mut action = Action {
            name: ptr::null(),
            kind: 99,
            index: 99,
            minimum: 99,
            maximum: 99,
            count: 99,
            error: 99,
        };
        assert!(!unsafe {
            zapret_lua_packet_dispatch_begin(5, bytes.as_mut_ptr(), 40, &mut s, &mut action)
        });
        assert_eq!(action.kind, 99);
        assert!(!unsafe {
            zapret_lua_packet_dispatch_step(
                &mut s,
                &Value {
                    success: 2,
                    ..empty()
                },
                &mut action,
            )
        });
        assert_eq!(action.kind, 99);
        s.phase = 23;
        assert!(!unsafe { zapret_lua_packet_dispatch_step(&mut s, &empty(), &mut action) });
    }
}
