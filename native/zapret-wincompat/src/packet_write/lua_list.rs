//! Resource-free progression between C-owned Lua array and field operations.
use super::*;
use std::ffi::{CStr, c_char, c_void};

#[derive(Clone, Copy)]
enum Mode {
    Tcp,
    Ipv6,
}
impl Mode {
    fn from_raw(mode: u32) -> Option<Self> {
        match mode {
            0 => Some(Self::Tcp),
            1 => Some(Self::Ipv6),
            _ => None,
        }
    }
    fn base(self) -> usize {
        match self {
            Self::Tcp => TCP_HEADER,
            Self::Ipv6 => IPV6_HEADER,
        }
    }
    fn alignment(self) -> usize {
        match self {
            Self::Tcp => mem::align_of::<TcpFields>(),
            Self::Ipv6 => mem::align_of::<Ipv6Fields>(),
        }
    }
}
#[derive(Clone, Copy)]
#[repr(u32)]
enum Phase {
    List = 1,
    Item,
    Kind,
    Next,
    Data,
}
impl Phase {
    fn from_raw(phase: u32) -> Option<Self> {
        match phase {
            1 => Some(Self::List),
            2 => Some(Self::Item),
            3 => Some(Self::Kind),
            4 => Some(Self::Next),
            5 => Some(Self::Data),
            _ => None,
        }
    }
}
const TERMINAL: u32 = 6;

fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn fields_valid(fields: *const c_void, mode: Mode) -> bool {
    !fields.is_null() && fields.addr() & (mode.alignment() - 1) == 0
}

#[repr(C)]
struct State {
    output: *mut u8,
    fields: *const c_void,
    capacity: usize,
    used: usize,
    next_offset: usize,
    item: i64,
    phase: u32,
    mode: u32,
    kind: u8,
    next: u8,
    protocol: u8,
    preserve: u8,
}
#[repr(C)]
struct Action {
    item: i64,
    operation: u32,
    pop: u32,
    name: *const c_char,
    length: usize,
}
#[repr(C)]
struct Value {
    data: *const u8,
    length: usize,
    number: i64,
    tag: i32,
}

const _: () = {
    use std::mem::offset_of;
    let pointer = size_of::<usize>();
    let item = if pointer == 8 { 40 } else { 24 };
    assert!(size_of::<State>() == item + 24);
    assert!(offset_of!(State, item) == item);
    assert!(offset_of!(State, phase) == item + 8);
    assert!(size_of::<Action>() == 16 + 2 * pointer);
    assert!(offset_of!(Action, name) == 16);
    assert!(size_of::<Value>() == 16 + 2 * pointer);
};

impl State {
    fn limit(&self, mode: Mode) -> usize {
        match mode {
            Mode::Tcp => self.capacity.min(TCP_HEADER + MAX_OPTIONS),
            Mode::Ipv6 => self.capacity,
        }
    }
    fn valid(&self) -> Option<(Mode, Phase)> {
        let mode = Mode::from_raw(self.mode)?;
        let phase = Phase::from_raw(self.phase)?;
        let base = mode.base();
        if self.output.is_null()
            || self.capacity < base
            || self.capacity > isize::MAX as usize
            || self.output.addr().checked_add(self.capacity).is_none()
            || !fields_valid(self.fields, mode)
            || self.preserve > 1
            || self.used < base
            || self.used > self.limit(mode)
            || self.item < 1
        {
            return None;
        }
        match mode {
            Mode::Tcp
                if self.next_offset != 0
                    || self.item as usize > self.used - base + 1
                    || matches!(phase, Phase::Next)
                    || matches!(phase, Phase::Data) && self.kind <= 1 =>
            {
                return None;
            }
            Mode::Ipv6
                if self.next_offset != 6
                    && !(IPV6_HEADER..self.used).contains(&self.next_offset)
                    || self.item as usize > (self.used - base) / 8 + 1 =>
            {
                return None;
            }
            _ => {}
        }
        Some((mode, phase))
    }
    fn query(&mut self, mode: Mode, phase: Phase, pop: u32) -> Action {
        self.phase = phase as u32;
        let name = match phase {
            Phase::List => Some(match mode {
                Mode::Tcp => c"options",
                Mode::Ipv6 => c"exthdr",
            }),
            Phase::Item => None,
            Phase::Kind => Some(match mode {
                Mode::Tcp => c"kind",
                Mode::Ipv6 => c"type",
            }),
            Phase::Next => Some(c"next"),
            Phase::Data => Some(c"data"),
        };
        Action {
            item: self.item,
            operation: phase as u32,
            pop,
            name: name.map_or(ptr::null(), CStr::as_ptr),
            length: 0,
        }
    }
    fn fail(&mut self, pop: u32) -> Action {
        self.phase = TERMINAL;
        Action {
            item: self.item,
            operation: 6,
            pop,
            name: ptr::null(),
            length: 0,
        }
    }
    fn finish(&mut self, mode: Mode, pop: u32) -> Action {
        let length = match mode {
            Mode::Tcp => unsafe {
                zapret_write_tcp(
                    self.output,
                    self.capacity,
                    self.fields.cast(),
                    self.used - TCP_HEADER,
                )
            },
            Mode::Ipv6 => {
                unsafe {
                    zapret_finish_ipv6(
                        self.output,
                        self.used,
                        self.fields.cast(),
                        self.next_offset,
                        self.protocol,
                        self.preserve != 0,
                    )
                };
                self.used
            }
        };
        if length == 0 {
            return self.fail(pop);
        }
        self.phase = TERMINAL;
        Action {
            item: self.item,
            operation: 0,
            pop,
            name: ptr::null(),
            length,
        }
    }
    fn commit(&mut self, mode: Mode, data: *const u8, length: usize, pop: u32) -> Action {
        if length > isize::MAX as usize || length != 0 && data.is_null() {
            return self.fail(pop);
        }
        // C owns both spans and consumes the borrowed Lua string before its next
        // VM operation. The serializer sees only the remaining writable prefix.
        let written = unsafe {
            match mode {
                Mode::Tcp => zapret_write_tcp_option(
                    self.output.add(self.used),
                    self.limit(mode) - self.used,
                    self.kind,
                    data,
                    length,
                ),
                Mode::Ipv6 => zapret_write_ipv6_extension(
                    self.output.add(self.used),
                    self.capacity - self.used,
                    self.kind,
                    self.next,
                    data,
                    length,
                ),
            }
        };
        if written == 0 {
            return self.fail(pop);
        }
        if matches!(mode, Mode::Ipv6) {
            if self.preserve == 0 {
                unsafe { self.output.add(self.next_offset).write(self.kind) };
            }
            self.next_offset = self.used;
        }
        self.used += written;
        self.item += 1;
        self.query(mode, Phase::Item, pop)
    }
    fn observe(&mut self, mode: Mode, phase: Phase, value: &Value) -> Action {
        match phase {
            Phase::List => {
                if value.tag == 5 {
                    self.query(mode, Phase::Item, 0)
                } else {
                    self.finish(mode, 1)
                }
            }
            Phase::Item => {
                if value.tag == 0 {
                    self.finish(mode, 2)
                } else if value.tag != 5
                    || matches!(mode, Mode::Tcp) && self.used == self.limit(mode)
                {
                    self.fail(0)
                } else {
                    self.query(mode, Phase::Kind, 0)
                }
            }
            Phase::Kind => {
                if value.tag != 3 {
                    return self.fail(0);
                }
                self.kind = value.number as u8;
                match mode {
                    Mode::Tcp if self.kind <= 1 => self.commit(mode, ptr::null(), 0, 1),
                    Mode::Tcp => self.query(mode, Phase::Data, 0),
                    Mode::Ipv6 => self.query(mode, Phase::Next, 0),
                }
            }
            Phase::Next => {
                self.next = if value.tag == 3 {
                    value.number as u8
                } else {
                    59
                };
                self.query(mode, Phase::Data, 0)
            }
            Phase::Data => match mode {
                Mode::Ipv6 if value.tag != 4 => self.fail(0),
                Mode::Tcp if value.tag != 4 => self.commit(mode, ptr::null(), 0, 2),
                _ => self.commit(mode, value.data, value.length, 2),
            },
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_list_begin(
    mode: u32,
    output: *mut u8,
    capacity: usize,
    fields: *const c_void,
    protocol: u8,
    preserve: u8,
    state: *mut State,
    action: *mut Action,
) -> bool {
    let Some(variant) = Mode::from_raw(mode) else {
        return false;
    };
    if !aligned(state)
        || !aligned(action)
        || output.is_null()
        || capacity < variant.base()
        || capacity > isize::MAX as usize
        || output.addr().checked_add(capacity).is_none()
        || !fields_valid(fields, variant)
        || preserve > 1
    {
        return false;
    }
    let mut initial = State {
        output,
        fields,
        capacity,
        used: variant.base(),
        next_offset: if matches!(variant, Mode::Ipv6) { 6 } else { 0 },
        item: 1,
        phase: Phase::List as u32,
        mode,
        kind: 0,
        next: 59,
        protocol,
        preserve,
    };
    let query = initial.query(variant, Phase::List, 0);
    // Metadata and descriptors are disjoint C storage. No Lua callback is made
    // while these Rust borrows or any serializer slice exist.
    unsafe {
        if matches!(variant, Mode::Ipv6) {
            zapret_write_ipv6(output, fields.cast());
        }
        state.write(initial);
        action.write(query);
    }
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_list_step(
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
    let result = state.observe(mode, phase, unsafe { &*value });
    unsafe { action.write(result) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;
    fn number(value: i64) -> Value {
        Value {
            data: ptr::null(),
            length: 0,
            number: value,
            tag: 3,
        }
    }
    fn tag(tag: i32) -> Value {
        Value { tag, ..number(0) }
    }
    unsafe fn advance(state: &mut State, value: &Value) -> Action {
        let mut action = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_header_list_step(state, value, action.as_mut_ptr()) });
        unsafe { action.assume_init() }
    }
    #[test]
    fn tcp_end_skips_data_but_keeps_iterating_the_array() {
        let fields: TcpFields = unsafe { mem::zeroed() };
        let mut output = [0xa5; 64];
        let mut state = MaybeUninit::uninit();
        let mut action = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_list_begin(
                0,
                output.as_mut_ptr(),
                64,
                ptr::from_ref(&fields).cast(),
                59,
                0,
                state.as_mut_ptr(),
                action.as_mut_ptr(),
            )
        });
        let mut state = unsafe { state.assume_init() };
        assert_eq!(unsafe { action.assume_init_ref() }.operation, 1);
        let action = unsafe { advance(&mut state, &tag(5)) };
        assert_eq!((action.operation, action.item), (2, 1));
        let action = unsafe { advance(&mut state, &tag(5)) };
        assert_eq!(action.operation, 3);
        let action = unsafe { advance(&mut state, &number(256)) };
        assert_eq!((action.operation, action.pop, action.item), (2, 1, 2));
        assert_eq!(output[20], 0);
        let action = unsafe { advance(&mut state, &tag(0)) };
        assert_eq!((action.operation, action.pop, action.length), (0, 2, 24));
        assert_eq!(&output[21..24], &[0; 3]);
    }
    #[test]
    fn ipv6_commits_links_only_after_successful_extension_data() {
        let fields = Ipv6Fields {
            source: [0; 16],
            destination: [0; 16],
            flow: 0x60000000,
            payload_length: 0,
            next: 6,
            hop_limit: 64,
            has_payload_length: 0,
        };
        let mut output = [0xa5; 64];
        let mut state = MaybeUninit::uninit();
        let mut action = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_list_begin(
                1,
                output.as_mut_ptr(),
                64,
                ptr::from_ref(&fields).cast(),
                17,
                0,
                state.as_mut_ptr(),
                action.as_mut_ptr(),
            )
        });
        let mut state = unsafe { state.assume_init() };
        assert_eq!(output[6], 6);
        unsafe {
            advance(&mut state, &tag(5));
            advance(&mut state, &tag(5));
            advance(&mut state, &number(60));
            advance(&mut state, &tag(0));
        }
        assert_eq!(output[6], 6);
        let bytes = [1; 6];
        let value = Value {
            data: bytes.as_ptr(),
            length: 6,
            ..tag(4)
        };
        let action = unsafe { advance(&mut state, &value) };
        assert_eq!((action.operation, action.item), (2, 2));
        assert_eq!((output[6], output[40]), (60, 59));
        unsafe {
            advance(&mut state, &tag(5));
            advance(&mut state, &number(51));
            advance(&mut state, &number(6));
        }
        let action = unsafe { advance(&mut state, &tag(1)) };
        assert_eq!(action.operation, 6);
        assert_eq!(output[40], 59);
        assert_eq!(&output[48..], &[0xa5; 16]);
    }

    unsafe fn start(mode: u32, output: &mut [u8], fields: *const c_void, preserve: u8) -> State {
        let mut state = MaybeUninit::uninit();
        let mut action = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_list_begin(
                mode,
                output.as_mut_ptr(),
                output.len(),
                fields,
                17,
                preserve,
                state.as_mut_ptr(),
                action.as_mut_ptr(),
            )
        });
        unsafe { state.assume_init() }
    }
    #[test]
    fn tcp_capacity_exhaustion_tests_nil_before_rejecting_another_element() {
        let fields: TcpFields = unsafe { mem::zeroed() };
        for last in [0, 5] {
            let mut output = [0xa5; 24];
            let mut state = unsafe { start(0, &mut output, ptr::from_ref(&fields).cast(), 0) };
            unsafe {
                advance(&mut state, &tag(5));
            }
            for _ in 0..4 {
                unsafe {
                    advance(&mut state, &tag(5));
                    advance(&mut state, &number(1));
                }
            }
            let action = unsafe { advance(&mut state, &tag(last)) };
            assert_eq!(action.operation, if last == 0 { 0 } else { 6 });
            assert_eq!(&output[20..], &[1; 4]);
            if last == 0 {
                assert_eq!(action.length, 24);
            } else {
                assert_eq!(&output[..20], &[0xa5; 20]);
            }
        }
    }
    #[test]
    fn tcp_ignores_non_string_data_but_rejects_a_numeric_string_kind() {
        let fields: TcpFields = unsafe { mem::zeroed() };
        let mut output = [0xa5; 64];
        let mut state = unsafe { start(0, &mut output, ptr::from_ref(&fields).cast(), 0) };
        unsafe {
            advance(&mut state, &tag(5));
            advance(&mut state, &tag(5));
            advance(&mut state, &number(2));
        }
        let invalid_span = Value {
            data: ptr::dangling(),
            length: usize::MAX,
            ..tag(1)
        };
        let action = unsafe { advance(&mut state, &invalid_span) };
        assert_eq!(action.operation, 2);
        let action = unsafe { advance(&mut state, &tag(0)) };
        assert_eq!(action.length, 24);
        assert_eq!(&output[20..24], &[2, 2, 0, 0]);
        let mut state = unsafe { start(0, &mut output, ptr::from_ref(&fields).cast(), 0) };
        unsafe {
            advance(&mut state, &tag(5));
            advance(&mut state, &tag(5));
        }
        let action = unsafe {
            advance(
                &mut state,
                &Value {
                    tag: 4,
                    ..number(2)
                },
            )
        };
        assert_eq!(action.operation, 6);
    }
    #[test]
    fn tcp_final_alignment_failure_keeps_the_written_option_and_original_base() {
        let fields: TcpFields = unsafe { mem::zeroed() };
        let mut output = [0xa5; 21];
        let mut state = unsafe { start(0, &mut output, ptr::from_ref(&fields).cast(), 0) };
        unsafe {
            advance(&mut state, &tag(5));
            advance(&mut state, &tag(5));
            advance(&mut state, &number(1));
        }
        let action = unsafe { advance(&mut state, &tag(0)) };
        assert_eq!(action.operation, 6);
        assert_eq!(&output[..20], &[0xa5; 20]);
        assert_eq!(output[20], 1);
        let mut action = MaybeUninit::uninit();
        assert!(!unsafe { zapret_lua_header_list_step(&mut state, &tag(0), action.as_mut_ptr()) });
    }
    #[test]
    fn ipv6_payload_presence_and_preserved_next_headers_survive_finalization() {
        for preserve in [0, 1] {
            for explicit in [0, 1] {
                let fields = Ipv6Fields {
                    source: [0; 16],
                    destination: [0; 16],
                    flow: 0x60000000,
                    payload_length: 65535,
                    next: 6,
                    hop_limit: 64,
                    has_payload_length: explicit,
                };
                let mut output = [0xa5; 48];
                let mut state =
                    unsafe { start(1, &mut output, ptr::from_ref(&fields).cast(), preserve) };
                unsafe {
                    advance(&mut state, &tag(5));
                    advance(&mut state, &tag(5));
                    advance(&mut state, &number(60));
                    advance(&mut state, &number(257));
                }
                let bytes = [0; 6];
                unsafe {
                    advance(
                        &mut state,
                        &Value {
                            data: bytes.as_ptr(),
                            length: 6,
                            ..tag(4)
                        },
                    );
                }
                let action = unsafe { advance(&mut state, &tag(0)) };
                assert_eq!((action.operation, action.length), (0, 48));
                assert_eq!(get_u16(&output, 4), if explicit == 0 { 8 } else { 65535 });
                assert_eq!(
                    (output[6], output[40]),
                    if preserve == 0 { (60, 17) } else { (6, 1) }
                );
            }
        }
    }
    #[test]
    fn ipv6_rejects_extension_shape_and_capacity_before_linking_or_copying() {
        let fields: Ipv6Fields = unsafe { mem::zeroed() };
        let bytes = [7; 10];
        for (kind, length, capacity, valid) in [
            (60, 6, 48, true),
            (51, 10, 52, true),
            (60, 7, 64, false),
            (51, 10, 51, false),
        ] {
            let mut output = [0xa5; 64];
            let mut state =
                unsafe { start(1, &mut output[..capacity], ptr::from_ref(&fields).cast(), 0) };
            unsafe {
                advance(&mut state, &tag(5));
                advance(&mut state, &tag(5));
                advance(&mut state, &number(kind));
                advance(&mut state, &tag(0));
            }
            let action = unsafe {
                advance(
                    &mut state,
                    &Value {
                        data: bytes.as_ptr(),
                        length,
                        ..tag(4)
                    },
                )
            };
            assert_eq!(action.operation, if valid { 2 } else { 6 });
            if !valid {
                assert_eq!(output[6], 0);
                assert_eq!(&output[40..], &[0xa5; 24]);
            }
        }
    }
    #[test]
    fn invalid_state_metadata_cannot_write_output_or_advance_the_action() {
        let fields: TcpFields = unsafe { mem::zeroed() };
        let mut output = [0xa5; 64];
        let mut state = unsafe { start(0, &mut output, ptr::from_ref(&fields).cast(), 0) };
        state.used = 65;
        let mut action = Action {
            item: 99,
            operation: 99,
            pop: 99,
            name: ptr::null(),
            length: 99,
        };
        assert!(!unsafe { zapret_lua_header_list_step(&mut state, &tag(5), &mut action) });
        assert_eq!((action.item, action.operation, action.length), (99, 99, 99));
        assert_eq!(&output, &[0xa5; 64]);
        assert!(!unsafe {
            zapret_lua_header_list_begin(
                0,
                output.as_mut_ptr(),
                64,
                ptr::from_ref(&fields).cast(),
                17,
                2,
                &mut state,
                &mut action,
            )
        });
        assert_eq!(state.used, 65);
        assert_eq!(&output, &[0xa5; 64]);
    }
}
