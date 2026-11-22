//! Complete scalar/table result calculation before the C adapter enters Lua.
use super::*;
use std::ptr;

#[repr(C)]
struct Entry {
    name: *const c_char,
    maximum: i32,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_position_entry(mode: u32) -> Entry {
    let (name, maximum) = match mode {
        0 => (c"resolve_pos", 4),
        1 => (c"resolve_multi_pos", 4),
        _ => (c"resolve_range", 5),
    };
    Entry {
        name: name.as_ptr(),
        maximum,
    }
}

#[repr(C)]
struct Flag {
    index: i32,
    mask: u32,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_position_flag(mode: u32, argc: i32, previous: u32) -> Flag {
    let (index, mask) = match (mode, previous) {
        (2, 0) if argc >= 4 => (4, 2),
        (2, 2) if argc >= 5 => (5, 1),
        (0 | 1, 0) if argc >= 4 => (4, 1),
        _ => (0, 0),
    };
    Flag { index, mask }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_position_error(status: u32) -> *const c_char {
    let format = match status {
        1 => c"bad payload type : '%s'",
        2 => c"bad marker : '%s'",
        3 => c"bad marker list",
        4 => c"resolve_range require 2 markers",
        _ => c"invalid position storage",
    };
    format.as_ptr()
}

#[repr(C)]
struct Output {
    values: [i64; 128],
    count: u32,
    kind: u32,
}
const _: () = {
    assert!(size_of::<Output>() == 1032);
};
fn range(length: usize, mut first: isize, mut last: isize, strict: bool) -> Option<[isize; 2]> {
    if first == -1 && last == -1 || strict && (first == -1 || last == -1) {
        return None;
    }
    if first == -1 {
        first = 0;
    }
    if last == -1 {
        last = length.wrapping_sub(1) as isize;
    }
    (first <= last).then_some([first, last])
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_positions(
    mode: u32,
    data: *const u8,
    length: usize,
    payload: *const c_char,
    markers: *const c_char,
    flags: u32,
    output: *mut Output,
) -> u32 {
    if mode > 2
        || flags > 3
        || output.is_null()
        || !output.is_aligned()
        || payload.is_null()
        || markers.is_null()
        || length > isize::MAX as usize
        || length != 0 && data.is_null()
    {
        return 5;
    }
    let Some(payload) = names::payload_index(unsafe { CStr::from_ptr(payload) }) else {
        return 1;
    };
    let mut parsed: [Position; 128] = std::array::from_fn(|_| Position {
        offset: 0,
        marker: 0,
    });
    let mut result = Output {
        values: [0; 128],
        count: 0,
        kind: 0,
    };
    let data_slice = unsafe { bytes(data, length) };
    let base = i64::from(flags & 1 == 0);
    if mode == 0 {
        if !parse(
            unsafe { CStr::from_ptr(markers) }.to_bytes(),
            &mut parsed[0],
        ) {
            return 2;
        }
        let value = resolve(data_slice, payload, &parsed[0]);
        if value != -1 {
            result.kind = 1;
            result.count = 1;
            result.values[0] = value as i64 + base;
        }
    } else {
        let mut count = if mode == 1 { 128 } else { 2 };
        if !unsafe { posmarker_list_parse(markers, parsed.as_mut_ptr(), &mut count) } {
            return 3;
        }
        if mode == 2 {
            if count != 2 {
                return 4;
            }
            if let Some(values) = range(
                length,
                resolve(data_slice, payload, &parsed[0]),
                resolve(data_slice, payload, &parsed[1]),
                flags & 2 != 0,
            ) {
                result.kind = 2;
                result.count = 2;
                result.values[0] = values[0] as i64 + base;
                result.values[1] = values[1] as i64 + base;
            }
        } else {
            let mut positions = [0isize; 128];
            let mut found = 0;
            unsafe {
                ResolveMultiPos(
                    data,
                    length,
                    payload,
                    parsed.as_ptr(),
                    count,
                    positions.as_mut_ptr(),
                    &mut found,
                )
            };
            result.kind = 2;
            result.count = found as u32;
            for (slot, value) in result.values.iter_mut().zip(&positions[..found as usize]) {
                *slot = *value as i64 + base;
            }
        }
    }
    // Fixed stack storage is fully published before C creates a Lua object or
    // raises an error. All protocol parsing borrows end at this return boundary.
    unsafe { ptr::write(output, result) };
    0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_missing_endpoint_expands_unless_strict_and_preserves_lua_index_base() {
        let mut result = Output {
            values: [99; 128],
            count: 99,
            kind: 99,
        };
        assert_eq!(
            unsafe {
                zapret_lua_positions(
                    2,
                    b"abcd".as_ptr(),
                    4,
                    c"unknown".as_ptr(),
                    c"0,9999".as_ptr(),
                    0,
                    &mut result,
                )
            },
            0
        );
        assert_eq!(
            (
                result.kind,
                result.count,
                result.values[0],
                result.values[1]
            ),
            (2, 2, 1, 4)
        );
        assert_eq!(
            unsafe {
                zapret_lua_positions(
                    2,
                    b"abcd".as_ptr(),
                    4,
                    c"unknown".as_ptr(),
                    c"0,9999".as_ptr(),
                    2,
                    &mut result,
                )
            },
            0
        );
        assert_eq!(result.kind, 0);
    }
    unsafe fn call(mode: u32, payload: &CStr, markers: &CStr, flags: u32) -> Output {
        let mut output = Output {
            values: [99; 128],
            count: 99,
            kind: 99,
        };
        assert_eq!(
            unsafe {
                zapret_lua_positions(
                    mode,
                    b"abcd".as_ptr(),
                    4,
                    payload.as_ptr(),
                    markers.as_ptr(),
                    flags,
                    &mut output,
                )
            },
            0
        );
        output
    }
    #[test]
    // Embedded NULs are deliberate inputs: only the C-prefix is a name.
    #[allow(clippy::manual_c_str_literals)]
    fn single_positions_preserve_embedded_nul_names_and_the_requested_base() {
        let output = unsafe { call(0, c"unknown", c"-1", 0) };
        assert_eq!((output.kind, output.count, output.values[0]), (1, 1, 4));
        let mut output = Output {
            values: [99; 128],
            count: 99,
            kind: 99,
        };
        assert_eq!(
            unsafe {
                zapret_lua_positions(
                    0,
                    b"abcd".as_ptr(),
                    4,
                    b"unknown\0ignored\0".as_ptr().cast(),
                    b"1\0ignored\0".as_ptr().cast(),
                    1,
                    &mut output,
                )
            },
            0
        );
        assert_eq!(output.values[0], 1);
    }
    #[test]
    fn empty_multi_results_are_tables_and_resolved_positions_are_sorted_and_unique() {
        let output = unsafe { call(1, c"unknown", c"", 0) };
        assert_eq!((output.kind, output.count), (2, 0));
        let output = unsafe { call(1, c"unknown", c"-1,1,1,99,0", 1) };
        assert_eq!((output.kind, output.count), (2, 3));
        assert_eq!(&output.values[..3], &[0, 1, 3]);
        let output = unsafe { call(0, c"unknown", c"host", 0) };
        assert_eq!((output.kind, output.count), (0, 0));
    }
    #[test]
    fn payload_parse_and_marker_count_errors_leave_the_output_unpublished() {
        for (mode, payload, markers, status) in [
            (0, c"bad", c"bad", 1),
            (0, c"unknown", c"bad", 2),
            (2, c"unknown", c"", 4),
            (2, c"unknown", c"1", 4),
            (2, c"unknown", c"1,2,3", 3),
            (1, c"unknown", c"1,,2", 3),
        ] {
            let mut output = Output {
                values: [99; 128],
                count: 99,
                kind: 99,
            };
            assert_eq!(
                unsafe {
                    zapret_lua_positions(
                        mode,
                        b"abcd".as_ptr(),
                        4,
                        payload.as_ptr(),
                        markers.as_ptr(),
                        0,
                        &mut output,
                    )
                },
                status
            );
            assert_eq!((output.count, output.kind, output.values[0]), (99, 99, 99));
        }
    }
    #[test]
    fn range_empty_both_missing_reversed_and_zero_based_boundaries_remain_distinct() {
        assert_eq!(range(0, -1, -1, false), None);
        assert_eq!(range(0, 0, -1, false), None);
        let output = unsafe { call(2, c"unknown", c"3,1", 0) };
        assert_eq!(output.kind, 0);
        let output = unsafe { call(2, c"unknown", c"9999,-1", 1) };
        assert_eq!(&output.values[..2], &[0, 3]);
        let output = unsafe { call(2, c"unknown", c"9998,9999", 0) };
        assert_eq!(output.kind, 0);
    }
}
