//! Borrowed wire views for Lua table adapters. No function here invokes the VM.
use std::{ptr, slice};
mod projection;

#[repr(C)]
#[derive(Default)]
struct Cursor {
    data: *const u8,
    length: usize,
    offset: usize,
    next: u8,
    kind: u8,
    stopped: bool,
}
#[repr(C)]
#[derive(Default)]
struct Header {
    values: [u32; 10],
    source: *const u8,
    destination: *const u8,
    cursor: Cursor,
    count: u8,
    address_width: u8,
    table_capacity: u8,
}
#[repr(C)]
#[derive(Default)]
struct Item {
    data: *const u8,
    length: usize,
    kind: u8,
    next: u8,
    has_data: bool,
}
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
fn u16_at(data: &[u8], offset: usize) -> u32 {
    u32::from(u16::from_be_bytes([data[offset], data[offset + 1]]))
}
fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

// END bytes inside option data are ordinary data. An invalid non-END option
// resets a preceding END run, just as in the pinned two-pass Lua decoder.
fn trim_tcp_options(options: &[u8]) -> usize {
    let mut offset = 0;
    let mut trailing = None;
    while let Some(&kind) = options.get(offset) {
        if kind == 0 {
            trailing.get_or_insert(offset);
        } else {
            trailing = None;
        }
        if kind <= 1 {
            offset += 1;
        } else {
            let Some(&length) = options.get(offset + 1) else {
                break;
            };
            let length = usize::from(length);
            if length < 2 || length > options.len() - offset {
                break;
            }
            offset += length;
        }
    }
    trailing.unwrap_or(options.len())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_header(
    kind: u8,
    data: *const u8,
    length: usize,
    output: *mut Header,
) -> bool {
    let minimum = match kind {
        0 | 3 => 20,
        1 | 2 => 8,
        4 => 40,
        _ => return false,
    };
    if !valid(output) || data.is_null() || length < minimum || length > isize::MAX as usize {
        return false;
    }
    let bytes = unsafe { slice::from_raw_parts(data, length) };
    let mut header = Header {
        values: [0; 10],
        source: ptr::null(),
        destination: ptr::null(),
        cursor: Cursor {
            data: ptr::null(),
            length: 0,
            offset: 0,
            next: 0,
            kind: 2,
            stopped: false,
        },
        count: 0,
        address_width: 0,
        table_capacity: 0,
    };
    match kind {
        0 => {
            header.values = [
                u16_at(bytes, 0),
                u16_at(bytes, 2),
                u32_at(bytes, 4),
                u32_at(bytes, 8),
                u32::from(bytes[12] & 15),
                u32::from(bytes[12] >> 4),
                u32::from(bytes[13]),
                u16_at(bytes, 14),
                u16_at(bytes, 16),
                u16_at(bytes, 18),
            ];
            let end = (usize::from(bytes[12] >> 4) * 4).min(length).max(20);
            header.cursor.data = unsafe { data.add(20) };
            header.cursor.length = trim_tcp_options(&bytes[20..end]);
            header.cursor.kind = 0;
            header.count = 10;
            header.table_capacity = 11;
        }
        1 => {
            header.values[..4].copy_from_slice(&[
                u16_at(bytes, 0),
                u16_at(bytes, 2),
                u16_at(bytes, 4),
                u16_at(bytes, 6),
            ]);
            header.count = 4;
            header.table_capacity = 4;
        }
        2 => {
            header.values[..4].copy_from_slice(&[
                u32::from(bytes[0]),
                u32::from(bytes[1]),
                u16_at(bytes, 2),
                u32_at(bytes, 4),
            ]);
            header.count = 4;
            header.table_capacity = 4;
        }
        3 => {
            header.values[..9].copy_from_slice(&[
                u32::from(bytes[0] >> 4),
                u32::from(bytes[0] & 15),
                u32::from(bytes[1]),
                u16_at(bytes, 2),
                u16_at(bytes, 4),
                u16_at(bytes, 6),
                u32::from(bytes[8]),
                u32::from(bytes[9]),
                u16_at(bytes, 10),
            ]);
            header.source = unsafe { data.add(12) };
            header.destination = unsafe { data.add(16) };
            let end = usize::from(bytes[0] & 15) * 4;
            if end > 20 && end <= length {
                header.cursor.data = unsafe { data.add(20) };
                header.cursor.length = end - 20;
            }
            header.count = 9;
            header.address_width = 4;
            header.table_capacity = 11 + u8::from(!header.cursor.data.is_null());
        }
        4 => {
            header.values[..4].copy_from_slice(&[
                u32_at(bytes, 0),
                u16_at(bytes, 4),
                u32::from(bytes[6]),
                u32::from(bytes[7]),
            ]);
            header.source = unsafe { data.add(8) };
            header.destination = unsafe { data.add(24) };
            header.cursor.data = unsafe { data.add(40) };
            header.cursor.length = (length - 40).min(header.values[1] as usize);
            header.cursor.next = bytes[6];
            header.cursor.kind = 1;
            header.count = 4;
            header.address_width = 16;
            header.table_capacity = 7;
        }
        _ => unreachable!(),
    }
    unsafe { output.write(header) };
    true
}

// Status: 0 end or malformed/truncated wire input, 1 borrowed item, 2 bad metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_item_next(cursor: *mut Cursor, output: *mut Item) -> u32 {
    if !valid(cursor) || !valid(output) {
        return 2;
    }
    let cursor = unsafe { &mut *cursor };
    if cursor.length > isize::MAX as usize
        || cursor.offset > cursor.length
        || (cursor.data.is_null() && cursor.length != 0)
        || cursor.kind > 1
    {
        return 2;
    }
    if cursor.stopped || cursor.offset == cursor.length {
        return 0;
    }
    let bytes = unsafe {
        slice::from_raw_parts(
            cursor.data.add(cursor.offset),
            cursor.length - cursor.offset,
        )
    };
    let item;
    let consumed;
    if cursor.kind == 0 {
        let kind = bytes[0];
        if kind <= 1 {
            consumed = 1;
            item = Item {
                data: ptr::null(),
                length: 0,
                kind,
                next: 0,
                has_data: false,
            };
        } else {
            let Some(&length) = bytes.get(1) else {
                cursor.stopped = true;
                return 0;
            };
            consumed = usize::from(length);
            if consumed < 2 || consumed > bytes.len() {
                cursor.stopped = true;
                return 0;
            }
            item = Item {
                data: unsafe { bytes.as_ptr().add(2) },
                length: consumed - 2,
                kind,
                next: 0,
                has_data: true,
            };
        }
    } else {
        let Some(length) = crate::packet::ipv6_extension_length(cursor.next, bytes) else {
            cursor.stopped = true;
            return 0;
        };
        if length > bytes.len() {
            cursor.stopped = true;
            return 0;
        }
        consumed = length;
        item = Item {
            data: unsafe { bytes.as_ptr().add(2) },
            length: length - 2,
            kind: cursor.next,
            next: bytes[0],
            has_data: true,
        };
        if cursor.next == 44 {
            cursor.stopped = u16_at(bytes, 2) & 0xfff8 != 0;
        }
        cursor.next = bytes[0];
    }
    cursor.offset += consumed;
    unsafe { output.write(item) };
    1
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Cursor>() == 32);
    assert!(size_of::<Header>() == 96);
    assert!(size_of::<Item>() == 24);
};
