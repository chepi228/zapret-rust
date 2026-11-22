//! Shared header entry and packet table policy.
use std::{
    ffi::{c_char, c_void},
    ptr,
};

fn capacity(kind: u32) -> Option<usize> {
    [60, 8, 8, 60, 512].get(kind as usize).copied()
}
fn field(kind: u32) -> Option<&'static std::ffi::CStr> {
    [c"tcp", c"udp", c"icmp", c"ip", c"ip6"]
        .get(kind as usize)
        .copied()
}
fn entry(mode: u32) -> &'static std::ffi::CStr {
    [
        c"dissect_tcphdr",
        c"dissect_udphdr",
        c"dissect_icmphdr",
        c"dissect_iphdr",
        c"dissect_ip6hdr",
        c"reconstruct_tcphdr",
        c"reconstruct_udphdr",
        c"reconstruct_icmphdr",
        c"reconstruct_iphdr",
        c"reconstruct_ip6hdr",
    ][mode as usize]
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_header_read_name(kind: u8) -> *const c_char {
    if kind < 5 {
        entry(u32::from(kind)).as_ptr()
    } else {
        ptr::null()
    }
}

fn diagnostic(kind: u32) -> &'static std::ffi::CStr {
    [
        c"invalid data for tcphdr",
        c"invalid data for udphdr",
        c"invalid data for icmphdr",
        c"invalid data for iphdr",
        c"invalid data for ip6hdr",
    ][kind as usize]
}
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

#[repr(C)]
struct WriteEntry {
    options_field: *const c_char,
    minimum: usize,
    table_tag: i32,
    options_tag: i32,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_header_write_entry(kind: u32) -> WriteEntry {
    WriteEntry {
        options_field: c"options".as_ptr(),
        minimum: match kind {
            0 | 2 => 20,
            1 => 40,
            _ => 0, // UDP and ICMP take fixed native destinations.
        },
        table_tag: 5,
        options_tag: 4,
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_dissect_field_name() -> *const c_char {
    c"dis".as_ptr()
}

#[repr(C)]
#[derive(Default)]
struct State {
    buffer: *mut u8,
    data: *const u8,
    length: usize,
    capacity: usize,
    mode: u32,
    phase: u32,
    preserve: u32,
    protocol: u32,
}
#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    data: *const u8,
    length: usize,
    kind: u32,
    index: i32,
    minimum: i32,
    maximum: i32,
    header: u32,
    count: u32,
}
#[repr(C)]
#[derive(Default)]
struct Value {
    data: *const u8,
    length: usize,
    success: u32,
    preserve: u32,
    protocol: u32,
}

fn command(state: &State, kind: u32) -> Action {
    Action {
        name: entry(state.mode).as_ptr(),
        data: state.data,
        length: state.length,
        kind,
        index: 1,
        header: state.mode % 5,
        ..Action::default()
    }
}
fn begin(mode: u32, buffer: *mut u8, available: usize) -> Option<(State, Action)> {
    if mode >= 10 || available > isize::MAX as usize {
        return None;
    }
    let limit = if mode >= 5 { capacity(mode % 5)? } else { 0 };
    if mode >= 5 && (buffer.is_null() || available < limit) {
        return None;
    }
    let state = State {
        buffer,
        data: if mode >= 5 { buffer } else { ptr::null() },
        length: limit,
        capacity: limit,
        mode,
        protocol: 59,
        ..State::default()
    };
    let action = Action {
        kind: 1,
        name: entry(mode).as_ptr(),
        minimum: 1,
        maximum: if mode == 9 { 2 } else { 1 },
        ..Action::default()
    };
    Some((state, action))
}
fn step(state: &mut State, value: &Value) -> Option<Action> {
    if state.mode >= 10
        || state.preserve > 1
        || state.protocol > 255
        || state.length > isize::MAX as usize
    {
        return None;
    }
    let header = state.mode % 5;
    if state.phase == 1 && state.mode >= 5
        || state.phase == 2 && state.mode != 9
        || state.phase == 3 && state.mode < 5
    {
        return None;
    }
    if state.mode >= 5
        && (state.buffer.is_null()
            || state.capacity != capacity(header)?
            || state.data != state.buffer)
    {
        return None;
    }
    let action = match state.phase {
        0 if state.mode < 5 => {
            state.phase = 1;
            command(state, 2)
        }
        0 if header == 4 => {
            state.phase = 2;
            let mut action = command(state, 3);
            action.index = 2;
            action
        }
        0 => {
            state.phase = 3;
            command(state, 4)
        }
        1 => {
            if value.length > isize::MAX as usize || value.length != 0 && value.data.is_null() {
                return None;
            }
            state.data = value.data;
            state.length = value.length;
            state.phase = 4;
            command(state, 5)
        }
        2 => {
            if value.preserve > 1 || value.protocol > 255 {
                return None;
            }
            state.preserve = value.preserve;
            state.protocol = value.protocol;
            state.phase = 3;
            command(state, 4)
        }
        3 => {
            if value.success == 0 {
                state.phase = 5;
                return Some(Action {
                    kind: 7,
                    name: diagnostic(header).as_ptr(),
                    ..Action::default()
                });
            }
            if value.success != 1
                || value.length > state.capacity
                || matches!(header, 1 | 2) && value.length != 8
            {
                return None;
            }
            state.length = value.length;
            state.phase = 4;
            command(state, 6)
        }
        4 => {
            state.phase = 5;
            Action {
                count: 1,
                ..Action::default()
            }
        }
        _ => return None,
    };
    Some(action)
}

// The C source may have uninitialized padding. Read only named fields, at the
// same boundary as the original caller. Native C bool occupies one byte.
#[repr(C)]
struct Dissect {
    packet: *const u8,
    packet_length: usize,
    ip: *const u8,
    ip6: *const u8,
    l3_length: usize,
    protocol: u8,
    tcp: *const u8,
    udp: *const u8,
    icmp: *const u8,
    l4_length: usize,
    transport_length: usize,
    payload: *const u8,
    payload_length: usize,
    fragment: u8,
    fragment_offset: u16,
}
#[repr(C)]
#[derive(Default)]
struct Projection {
    name: *const c_char,
    data: *const u8,
    length: usize,
    number: i64,
    kind: u32,
    header: u32,
}
unsafe fn project(source: *const Dissect, phase: &mut u32) -> Option<Projection> {
    if *phase > 12 || !source.is_null() && !source.is_aligned() {
        return None;
    }
    if *phase == 12 {
        *phase = 13;
        return Some(Projection::default());
    }
    if source.is_null() {
        if *phase != 0 {
            return None;
        }
        *phase = 12;
        return Some(Projection {
            kind: 1,
            ..Projection::default()
        });
    }
    let mut result = Projection::default();
    // SAFETY: source is live and aligned; only the selected initialized fields
    // are read. The caller may mutate later fields at intervening VM calls.
    unsafe {
        match *phase {
            0 => {
                result.kind = 2;
                result.number = 10 + i64::from((*source).fragment);
            }
            1 => {
                result.kind = 3;
                result.name = c"l4proto".as_ptr();
                result.number = i64::from((*source).protocol);
            }
            2 => {
                result.kind = 3;
                result.name = c"transport_len".as_ptr();
                result.number = (*source).transport_length as i64;
            }
            3 => {
                result.kind = 3;
                result.name = c"l3_len".as_ptr();
                result.number = (*source).l3_length as i64;
            }
            4 => {
                result.kind = 3;
                result.name = c"l4_len".as_ptr();
                result.number = (*source).l4_length as i64;
            }
            5 => {
                result.kind = 4;
                result.name = c"payload".as_ptr();
                result.data = (*source).payload;
                result.length = (*source).payload_length;
            }
            6 if (*source).fragment != 0 => {
                result.kind = 3;
                result.name = c"frag_off".as_ptr();
                result.number = i64::from((*source).fragment_offset);
            }
            6..=11 => {
                if *phase == 6 {
                    *phase = 7;
                }
                let (header, data, length) = match *phase {
                    7 => (3, (*source).ip, (*source).l3_length),
                    8 => (4, (*source).ip6, (*source).l3_length),
                    9 => (0, (*source).tcp, (*source).l4_length),
                    10 => (1, (*source).udp, (*source).l4_length),
                    _ => (2, (*source).icmp, (*source).l4_length),
                };
                result.kind = 5;
                result.name = field(header)?.as_ptr();
                result.header = header;
                result.data = data;
                result.length = length;
            }
            _ => return None,
        }
    }
    *phase += 1;
    Some(result)
}
#[repr(C)]
#[derive(Default)]
struct Address {
    data: *const u8,
    length: usize,
}

/// # Safety
/// Aligned disjoint output metadata must be writable. Buffer is caller-owned
/// storage of available bytes, rooted until the entry finishes.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_entry_begin(
    mode: u32,
    buffer: *mut u8,
    available: usize,
    state: *mut State,
    output: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(output) {
        return false;
    }
    let Some((initial, action)) = begin(mode, buffer, available) else {
        return false;
    };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned metadata is initialized and live. Input bytes remain rooted
/// in Lua; C performs the selected VM call after Rust has returned.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_entry_step(
    state: *mut State,
    value: *const Value,
    output: *mut Action,
) -> bool {
    if !aligned(state) || !aligned(value) || !aligned(output) {
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
#[unsafe(no_mangle)]
extern "C" fn zapret_lua_header_field_name(kind: u32) -> *const c_char {
    field(kind).map_or(ptr::null(), |name| name.as_ptr())
}

/// # Safety
/// Source is null or a live native dissect layout; initialize each selected
/// field before that step. Source, cursor and output must not alias. No source
/// field is read ahead of the corresponding C-owned VM operation.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_projection(
    source: *const Dissect,
    cursor: *mut u32,
    output: *mut Projection,
) -> bool {
    if !aligned(cursor) || !aligned(output) {
        return false;
    }
    let Some(action) = (unsafe { project(source, &mut *cursor) }) else {
        return false;
    };
    unsafe {
        output.write(action);
    }
    true
}
/// # Safety
/// Source is null or contains a readable native family. Known IPv4/IPv6
/// families have readable address bytes at native offsets 4/8. Unknown families
/// require only two bytes. Output is writable, aligned and disjoint from source.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_address(
    source: *const c_void,
    output: *mut Address,
) -> bool {
    if !aligned(output) {
        return false;
    }
    let mut result = Address::default();
    if !source.is_null() {
        // SAFETY: two family bytes are readable even for unknown/unaligned input.
        let family = unsafe { ptr::read_unaligned(source.cast::<u16>()) };
        let range = match family {
            2 => Some((4, 4)),
            23 => Some((8, 16)),
            _ => None,
        };
        if let Some((offset, length)) = range {
            result.data = source.cast::<u8>().wrapping_add(offset);
            result.length = length;
        }
    }
    unsafe {
        output.write(result);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_header_capacities_preserve_fixed_and_variable_outputs() {
        for (kind, expected) in [60, 8, 8, 60, 512].into_iter().enumerate() {
            assert_eq!(capacity(kind as u32), Some(expected));
        }
        assert_eq!(capacity(5), None);
    }

    #[test]
    fn ipv6_options_precede_native_header_validation() {
        let mut bytes = [0u8; 512];
        let (mut state, arity) = begin(9, bytes.as_mut_ptr(), bytes.len()).unwrap();
        assert_eq!((arity.minimum, arity.maximum), (1, 2));
        let options = step(&mut state, &Value::default()).unwrap();
        assert_eq!((options.kind, options.index), (3, 2));
        let build = step(
            &mut state,
            &Value {
                preserve: 1,
                protocol: 17,
                ..Value::default()
            },
        )
        .unwrap();
        assert_eq!((build.kind, build.header, build.length), (4, 4, 512));
        assert_eq!((state.preserve, state.protocol), (1, 17));
        let error = step(
            &mut state,
            &Value {
                length: usize::MAX,
                ..Value::default()
            },
        )
        .unwrap();
        assert_eq!(error.kind, 7);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(error.name) }.to_bytes(),
            b"invalid data for ip6hdr"
        );
    }

    #[test]
    fn strict_decode_input_is_borrowed_and_has_exactly_one_result() {
        for mode in 0..5 {
            let (mut state, arity) = begin(mode, ptr::null_mut(), 0).unwrap();
            assert_eq!((arity.minimum, arity.maximum), (1, 1));
            assert_eq!(step(&mut state, &Value::default()).unwrap().kind, 2);
            let input = b"binary\0input";
            let publish = step(
                &mut state,
                &Value {
                    data: input.as_ptr(),
                    length: input.len(),
                    ..Value::default()
                },
            )
            .unwrap();
            assert_eq!(
                (publish.kind, publish.header, publish.data, publish.length),
                (5, mode, input.as_ptr(), input.len())
            );
            assert_eq!(step(&mut state, &Value::default()).unwrap().count, 1);
            assert!(step(&mut state, &Value::default()).is_none());
        }
    }

    #[test]
    fn successful_serialization_publishes_only_the_native_written_span() {
        let mut bytes = [0u8; 512];
        for kind in 0..5 {
            let (mut state, _) = begin(kind + 5, bytes.as_mut_ptr(), bytes.len()).unwrap();
            let mut action = step(&mut state, &Value::default()).unwrap();
            if action.kind == 3 {
                action = step(
                    &mut state,
                    &Value {
                        protocol: 59,
                        ..Value::default()
                    },
                )
                .unwrap();
            }
            assert_eq!((action.kind, action.length), (4, capacity(kind).unwrap()));
            let length = if kind == 4 {
                40
            } else if kind == 0 || kind == 3 {
                20
            } else {
                8
            };
            let bytes = step(
                &mut state,
                &Value {
                    length,
                    success: 1,
                    ..Value::default()
                },
            )
            .unwrap();
            assert_eq!(
                (bytes.kind, bytes.data, bytes.length),
                (6, state.buffer.cast_const(), length)
            );
        }
    }

    #[test]
    fn composite_reads_source_fields_only_when_their_vm_action_is_selected() {
        let mut source = std::mem::MaybeUninit::<Dissect>::uninit();
        let source = source.as_mut_ptr();
        let mut cursor = 0;
        unsafe {
            ptr::addr_of_mut!((*source).fragment).write(0);
            assert_eq!(project(source, &mut cursor).unwrap().number, 10);
            ptr::addr_of_mut!((*source).protocol).write(17);
            assert_eq!(project(source, &mut cursor).unwrap().number, 17);
            ptr::addr_of_mut!((*source).transport_length).write(usize::MAX);
            assert_eq!(
                project(source, &mut cursor).unwrap().number,
                usize::MAX as i64
            );
            ptr::addr_of_mut!((*source).l3_length).write(40);
            assert_eq!(project(source, &mut cursor).unwrap().number, 40);
            ptr::addr_of_mut!((*source).l4_length).write(8);
            assert_eq!(project(source, &mut cursor).unwrap().number, 8);
            ptr::addr_of_mut!((*source).payload).write(ptr::null());
            ptr::addr_of_mut!((*source).payload_length).write(usize::MAX);
            let payload = project(source, &mut cursor).unwrap();
            assert!(payload.data.is_null());
            assert_eq!(payload.length, usize::MAX);
            ptr::addr_of_mut!((*source).fragment).write(1);
            ptr::addr_of_mut!((*source).fragment_offset).write(65535);
            assert_eq!(project(source, &mut cursor).unwrap().number, 65535);
            ptr::addr_of_mut!((*source).ip).write(ptr::dangling::<u8>());
            let ip = project(source, &mut cursor).unwrap();
            assert_eq!((ip.header, ip.length), (3, 40));
            ptr::addr_of_mut!((*source).ip6).write(ptr::null());
            ptr::addr_of_mut!((*source).l3_length).write(48);
            assert_eq!(project(source, &mut cursor).unwrap().length, 48);
        }
    }

    #[test]
    fn missing_fragment_skips_only_its_field_and_null_source_publishes_nil() {
        let source: Dissect = unsafe { std::mem::zeroed() };
        let mut cursor = 6;
        let header = unsafe { project(&source, &mut cursor) }.unwrap();
        assert_eq!((header.kind, header.header, cursor), (5, 3, 8));
        let mut cursor = 0;
        assert_eq!(
            unsafe { project(ptr::null(), &mut cursor) }.unwrap().kind,
            1
        );
        assert_eq!(
            unsafe { project(ptr::null(), &mut cursor) }.unwrap().kind,
            0
        );
        assert!(unsafe { project(ptr::null(), &mut cursor) }.is_none());
    }

    #[test]
    fn native_address_projection_uses_only_the_selected_family_and_offset() {
        let mut bytes = [0u8; 32];
        let mut address = Address::default();
        for (family, offset, length) in [(2u16, 4, 4), (23, 8, 16), (1, 0, 0), (65535, 0, 0)] {
            bytes[1..3].copy_from_slice(&family.to_ne_bytes());
            assert!(unsafe {
                zapret_lua_packet_address(bytes.as_ptr().add(1).cast(), &mut address)
            });
            assert_eq!(address.length, length);
            assert_eq!(
                address.data,
                if length == 0 {
                    ptr::null()
                } else {
                    bytes.as_ptr().wrapping_add(1 + offset)
                }
            );
        }
        assert!(unsafe { zapret_lua_packet_address(ptr::null(), &mut address) });
        assert!(address.data.is_null());
    }

    #[test]
    fn abi_and_invalid_metadata_leave_action_outputs_unchanged() {
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<State>(), 4 * pointer + 16);
        assert_eq!(size_of::<Action>(), 3 * pointer + 24);
        assert_eq!(size_of::<Value>(), if pointer == 8 { 32 } else { 20 });
        assert_eq!(size_of::<Dissect>(), 14 * pointer);
        assert_eq!(std::mem::offset_of!(Dissect, payload), 11 * pointer);
        assert_eq!(size_of::<Projection>(), if pointer == 8 { 40 } else { 32 });
        let mut state = State::default();
        let mut output = Action {
            kind: 91,
            ..Action::default()
        };
        assert!(!unsafe {
            zapret_lua_header_entry_begin(10, ptr::null_mut(), 0, &mut state, &mut output)
        });
        assert_eq!(output.kind, 91);
        assert!(begin(5, ptr::null_mut(), 60).is_none());
        assert!(begin(9, ptr::dangling_mut::<u8>(), 511).is_none());
        let (mut state, _) = begin(0, ptr::null_mut(), 0).unwrap();
        step(&mut state, &Value::default()).unwrap();
        assert!(
            step(
                &mut state,
                &Value {
                    length: 1,
                    ..Value::default()
                }
            )
            .is_none()
        );
        assert!(field(5).is_none());
    }
}
