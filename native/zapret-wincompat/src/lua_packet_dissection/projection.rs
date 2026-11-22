//! Metadata and publication policy around C-owned Lua VM operations.
use super::{Cursor, Header, Item, valid, zapret_lua_packet_header, zapret_lua_packet_item_next};
use std::ffi::{CStr, c_char};
#[cfg(test)]
use std::ptr;

const FIELDS: [&[&CStr]; 5] = [
    &[
        c"th_sport",
        c"th_dport",
        c"th_seq",
        c"th_ack",
        c"th_x2",
        c"th_off",
        c"th_flags",
        c"th_win",
        c"th_sum",
        c"th_urp",
    ],
    &[c"uh_sport", c"uh_dport", c"uh_ulen", c"uh_sum"],
    &[c"icmp_type", c"icmp_code", c"icmp_cksum", c"icmp_data"],
    &[
        c"ip_v", c"ip_hl", c"ip_tos", c"ip_len", c"ip_id", c"ip_off", c"ip_ttl", c"ip_p", c"ip_sum",
    ],
    &[c"ip6_flow", c"ip6_plen", c"ip6_nxt", c"ip6_hlim"],
];
#[repr(C)]
#[derive(Default)]
struct Action {
    name: *const c_char,
    data: *const u8,
    length: usize,
    number: i64,
    kind: u32,
    reserved: u32,
}
fn action(kind: u32, name: &CStr) -> Action {
    Action {
        kind,
        name: name.as_ptr(),
        ..Action::default()
    }
}
#[repr(C)]
struct HeaderState {
    header: Header,
    kind: u32,
    index: u32,
    phase: u32,
    present: u32,
}
unsafe fn header_begin(kind: u32, data: *const u8, length: usize) -> (HeaderState, Action) {
    let mut header = Header::default();
    // SAFETY: the caller roots readable wire bytes; the existing decoder guards
    // null/truncated/oversized input and captures scalars before VM publication.
    let present =
        kind < 5 && unsafe { zapret_lua_packet_header(kind as u8, data, length, &mut header) };
    let output = Action {
        kind: if present { 2 } else { 1 },
        number: i64::from(header.table_capacity),
        ..Action::default()
    };
    (
        HeaderState {
            header,
            kind,
            index: 0,
            phase: if present { 0 } else { 4 },
            present: u32::from(present),
        },
        output,
    )
}
fn header_step(state: &mut HeaderState) -> Option<Action> {
    if state.present > 1 || state.phase > 4 {
        return None;
    }
    if state.present == 0 && state.phase != 4 {
        return None;
    }
    if state.present != 0
        && (state.kind >= 5 || usize::from(state.header.count) > FIELDS[state.kind as usize].len())
    {
        return None;
    }
    loop {
        match state.phase {
            0 => {
                if state.index < u32::from(state.header.count) {
                    let index = state.index as usize;
                    state.index += 1;
                    let mut output = action(3, FIELDS[state.kind as usize].get(index)?);
                    output.number = i64::from(state.header.values[index]);
                    return Some(output);
                }
                state.phase = 1;
            }
            1 => {
                state.phase = 2;
                if state.header.address_width != 0 {
                    let mut output = action(
                        4,
                        if state.kind == 3 {
                            c"ip_src"
                        } else {
                            c"ip6_src"
                        },
                    );
                    output.data = state.header.source;
                    output.length = usize::from(state.header.address_width);
                    return Some(output);
                }
            }
            2 => {
                state.phase = 3;
                if state.header.address_width != 0 {
                    let mut output = action(
                        4,
                        if state.kind == 3 {
                            c"ip_dst"
                        } else {
                            c"ip6_dst"
                        },
                    );
                    output.data = state.header.destination;
                    output.length = usize::from(state.header.address_width);
                    return Some(output);
                }
            }
            3 => {
                state.phase = 4;
                match state.kind {
                    0 => return Some(action(5, c"options")),
                    4 => return Some(action(5, c"exthdr")),
                    3 if !state.header.cursor.data.is_null() => {
                        let mut output = action(4, c"options");
                        output.data = state.header.cursor.data;
                        output.length = state.header.cursor.length;
                        return Some(output);
                    }
                    _ => {}
                }
            }
            4 => {
                state.phase = 5;
                return Some(Action::default());
            }
            _ => return None,
        }
    }
}

#[repr(C)]
struct ItemState {
    cursor: *mut Cursor,
    item: Item,
    index: i64,
    phase: u32,
}
fn item_begin(field: *const c_char, cursor: *mut Cursor) -> (ItemState, Action) {
    (
        ItemState {
            cursor,
            item: Item::default(),
            index: 1,
            phase: 0,
        },
        Action {
            kind: 6,
            name: field,
            ..Action::default()
        },
    )
}
fn item_error(state: &mut ItemState) -> Action {
    state.phase = 9;
    action(9, c"invalid packet iterator state")
}
unsafe fn item_next(state: &mut ItemState) -> Option<Action> {
    // SAFETY: the original iterator validates metadata and only borrows readable
    // cursor spans. It mutates the caller's cursor, preserving C-visible progress.
    match unsafe { zapret_lua_packet_item_next(state.cursor, &mut state.item) } {
        0 => {
            state.phase = 8;
            Some(Action {
                kind: 8,
                number: -3,
                ..Action::default()
            })
        }
        1 => {
            let index = state.index;
            state.index = state.index.checked_add(1)?;
            state.phase = 2;
            Some(Action {
                kind: 7,
                number: index,
                ..Action::default()
            })
        }
        _ => Some(item_error(state)),
    }
}
fn item_data(state: &mut ItemState) -> Action {
    if state.item.has_data {
        state.phase = 6;
        let mut output = action(4, c"data");
        output.data = state.item.data;
        output.length = state.item.length;
        output
    } else {
        state.phase = 7;
        Action {
            kind: 8,
            number: -3,
            ..Action::default()
        }
    }
}
unsafe fn item_step(state: &mut ItemState) -> Option<Action> {
    if state.index < 1 {
        return None;
    }
    // Cursor kind is read after the same VM calls as in C, rather than being
    // cached alongside the item. Native callers may mutate it between steps.
    let output = match state.phase {
        0 => {
            state.phase = 1;
            Action {
                kind: 2,
                ..Action::default()
            }
        }
        1 | 7 => return unsafe { item_next(state) },
        2 => {
            if !valid(state.cursor) {
                return Some(item_error(state));
            }
            state.phase = 3;
            Action {
                kind: 2,
                number: if unsafe { (*state.cursor).kind } == 0 {
                    2
                } else {
                    3
                },
                ..Action::default()
            }
        }
        3 => {
            if !valid(state.cursor) {
                return Some(item_error(state));
            }
            state.phase = 4;
            let mut output = action(
                3,
                if unsafe { (*state.cursor).kind } == 0 {
                    c"kind"
                } else {
                    c"type"
                },
            );
            output.number = i64::from(state.item.kind);
            output
        }
        4 => {
            if !valid(state.cursor) {
                return Some(item_error(state));
            }
            if unsafe { (*state.cursor).kind } == 1 {
                state.phase = 5;
                let mut output = action(3, c"next");
                output.number = i64::from(state.item.next);
                output
            } else {
                item_data(state)
            }
        }
        5 => item_data(state),
        6 => {
            state.phase = 7;
            Action {
                kind: 8,
                number: -3,
                ..Action::default()
            }
        }
        8 => {
            state.phase = 9;
            Action::default()
        }
        _ => return None,
    };
    Some(output)
}

/// # Safety
/// Disjoint aligned outputs are writable; input wire bytes are readable/rooted
/// for the operation. Each returned command is executed by C after return.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_header_projection_begin(
    kind: u32,
    data: *const u8,
    length: usize,
    state: *mut HeaderState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let (initial, action) = unsafe { header_begin(kind, data, length) };
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint metadata is initialized/aligned and live. Keep the captured wire
/// spans rooted; C alone reads them when publishing the selected raw fields.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_header_projection_step(
    state: *mut HeaderState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some(action) = header_step(unsafe { &mut *state }) else {
        return false;
    };
    unsafe {
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint aligned outputs are writable. Kind is TCP (0) or IPv6 (4), and
/// wire data follows the decoder's contract. Failed decoding creates an empty
/// cursor of the requested iterator kind, just as the original public wrapper.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_items_prepare(
    kind: u32,
    data: *const u8,
    length: usize,
    cursor: *mut Cursor,
    field: *mut *const c_char,
) -> bool {
    if !valid(cursor) || !valid(field) || !matches!(kind, 0 | 4) {
        return false;
    }
    let mut header = Header::default();
    let present = unsafe { zapret_lua_packet_header(kind as u8, data, length, &mut header) };
    let selected = if present {
        header.cursor
    } else {
        Cursor {
            kind: u8::from(kind == 4),
            ..Cursor::default()
        }
    };
    unsafe {
        cursor.write(selected);
        field.write(if kind == 0 { c"options" } else { c"exthdr" }.as_ptr());
    }
    true
}
/// # Safety
/// Cursor is caller-owned metadata, validated only at its original read step.
/// State/action outputs are aligned, writable and disjoint from that cursor;
/// field is a borrowed C string. C performs root key/table publication first.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_items_begin(
    field: *const c_char,
    cursor: *mut Cursor,
    state: *mut ItemState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let (initial, action) = item_begin(field, cursor);
    unsafe {
        state.write(initial);
        output.write(action);
    }
    true
}
/// # Safety
/// Disjoint metadata is initialized/aligned. Cursor/native bytes remain live,
/// with source kind read after each selected C VM operation, and never cached.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_items_step(
    state: *mut ItemState,
    output: *mut Action,
) -> bool {
    if !valid(state) || !valid(output) {
        return false;
    }
    let Some(action) = (unsafe { item_step(&mut *state) }) else {
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
    fn all_scalar_metadata_precedes_addresses_and_optional_items() {
        let bytes = [0xffu8; 64];
        let counts = [10, 4, 4, 9, 4];
        for kind in 0..5 {
            let (mut state, table) = unsafe { header_begin(kind, bytes.as_ptr(), 64) };
            assert_eq!(table.kind, 2);
            for expected in FIELDS[kind as usize].iter().take(counts[kind as usize]) {
                let output = header_step(&mut state).unwrap();
                assert_eq!(output.kind, 3);
                assert_eq!(
                    unsafe { CStr::from_ptr(output.name) }.to_bytes(),
                    expected.to_bytes()
                );
            }
            if kind >= 3 {
                assert_eq!(header_step(&mut state).unwrap().kind, 4);
                assert_eq!(header_step(&mut state).unwrap().kind, 4);
            }
            if kind == 0 || kind == 4 {
                assert_eq!(header_step(&mut state).unwrap().kind, 5);
            }
            if kind == 3 {
                assert_eq!(header_step(&mut state).unwrap().kind, 4);
            }
            assert_eq!(header_step(&mut state).unwrap().kind, 0);
        }
    }
    #[test]
    fn scalars_are_captured_before_vm_but_address_bytes_remain_borrowed() {
        let mut bytes = [0u8; 24];
        bytes[0] = 0x45;
        bytes[12] = 192;
        let (mut state, _) = unsafe { header_begin(3, bytes.as_ptr(), bytes.len()) };
        bytes[0] = 0x6f;
        bytes[12] = 203;
        assert_eq!(header_step(&mut state).unwrap().number, 4);
        for _ in 1..9 {
            header_step(&mut state).unwrap();
        }
        let source = header_step(&mut state).unwrap();
        assert_eq!(source.data, bytes.as_ptr().wrapping_add(12));
        assert_eq!(unsafe { *source.data }, 203);
    }
    #[test]
    fn iterator_kind_reads_remain_deferred_between_index_table_and_field() {
        let bytes = [1u8, 2, 2];
        let mut cursor = Cursor {
            data: bytes.as_ptr(),
            length: 3,
            ..Cursor::default()
        };
        let (mut state, key) = item_begin(c"options".as_ptr(), &mut cursor);
        assert_eq!(key.kind, 6);
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().kind, 2);
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().number, 1);
        assert_eq!(cursor.offset, 1);
        cursor.kind = 1;
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().number, 3);
        cursor.kind = 0;
        let field = unsafe { item_step(&mut state) }.unwrap();
        assert_eq!(unsafe { CStr::from_ptr(field.name) }.to_bytes(), b"kind");
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().kind, 8);
        let next = unsafe { item_step(&mut state) }.unwrap();
        assert_eq!((next.kind, next.number), (7, 2));
        assert_eq!(cursor.offset, 3);
    }
    #[test]
    fn empty_data_is_present_and_invalid_cursor_errors_after_root_publication() {
        let bytes = [2u8, 2];
        let mut cursor = Cursor {
            data: bytes.as_ptr(),
            length: 2,
            ..Cursor::default()
        };
        let (mut state, _) = item_begin(c"options".as_ptr(), &mut cursor);
        for _ in 0..4 {
            unsafe { item_step(&mut state) }.unwrap();
        }
        let data = unsafe { item_step(&mut state) }.unwrap();
        assert_eq!((data.kind, data.length), (4, 0));
        assert!(!data.data.is_null());
        let (mut state, _) = item_begin(ptr::null(), ptr::null_mut());
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().kind, 2);
        assert_eq!(unsafe { item_step(&mut state) }.unwrap().kind, 9);
    }
    #[test]
    fn invalid_headers_publish_nil_and_bad_abi_leaves_action_untouched() {
        let (mut state, nil) = unsafe { header_begin(255, ptr::null(), usize::MAX) };
        assert_eq!(nil.kind, 1);
        assert_eq!(header_step(&mut state).unwrap().kind, 0);
        let (header, item, action) = if cfg!(target_pointer_width = "64") {
            (112, 48, 40)
        } else {
            (84, 32, 32)
        };
        assert_eq!(size_of::<HeaderState>(), header);
        assert_eq!(size_of::<ItemState>(), item);
        assert_eq!(size_of::<Action>(), action);
        let mut action = Action {
            kind: 91,
            ..Action::default()
        };
        assert!(!unsafe { zapret_lua_packet_items_step(ptr::null_mut(), &mut action) });
        assert_eq!(action.kind, 91);
        let mut cursor = Cursor::default();
        let mut field = ptr::null();
        assert!(!unsafe {
            zapret_lua_packet_items_prepare(1, ptr::null(), 0, &mut cursor, &mut field)
        });
    }
}
