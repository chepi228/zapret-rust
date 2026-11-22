//! Borrowed file/system/time views; every VM operation runs after Rust returns.
use std::{
    ffi::{CStr, c_char, c_void},
    fmt::{self, Write},
    ptr,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeTime {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
}
unsafe extern "C" {
    fn strftime(
        output: *mut c_char,
        size: usize,
        format: *const c_char,
        time: *const NativeTime,
    ) -> usize;
}
#[repr(C)]
struct NativeClock {
    seconds: i64,
    nanos: i32,
}
#[repr(C)]
struct NativeFile {
    device: u64,
    inode: u64,
    size: i64,
    mode: u32,
    modified: NativeClock,
}
#[repr(C)]
struct NativeUname {
    sysname: [c_char; 65],
    nodename: [c_char; 256],
    release: [c_char; 65],
    version: [c_char; 65],
    machine: [c_char; 65],
}
#[repr(C)]
struct Field {
    name: *const c_char,
    data: *const c_char,
    integer: i64,
    number: f64,
    kind: u32,
    text: [u8; 128],
}
impl Default for Field {
    fn default() -> Self {
        Self {
            name: ptr::null(),
            data: ptr::null(),
            integer: 0,
            number: 0.,
            kind: 0,
            text: [0; 128],
        }
    }
}
#[repr(C)]
#[derive(Default)]
struct TimeCursor {
    time: NativeTime,
    index: u32,
}
const _: () = {
    assert!(size_of::<NativeTime>() == 36);
    assert!(size_of::<NativeTime>() == size_of::<libc::tm>());
    assert!(size_of::<NativeClock>() == 16);
    assert!(size_of::<NativeFile>() == 48);
    assert!(std::mem::offset_of!(NativeFile, modified) == 32);
    assert!(size_of::<NativeUname>() == 516);
    let pointer = size_of::<usize>();
    assert!(size_of::<Field>() == 2 * pointer + 152);
    assert!(std::mem::offset_of!(Field, text) == 2 * pointer + 20);
    assert!(size_of::<TimeCursor>() == 40);
};

fn year_from_lua(value: i64) -> i32 {
    (value as i32).wrapping_sub(1900)
}
fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
fn float_time(seconds: i64, nanos: i32) -> f64 {
    seconds as f64 + f64::from(nanos) / 1_000_000_000.
}
fn named_integer(field: &mut Field, name: &CStr, value: i64) {
    field.name = name.as_ptr();
    field.kind = 2;
    field.integer = value;
}
fn named_string(field: &mut Field, name: &CStr, value: *const c_char) {
    field.name = name.as_ptr();
    field.kind = 4;
    field.data = value;
}
struct BoundedText<'a> {
    bytes: &'a mut [u8],
    written: usize,
}
impl Write for BoundedText<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = self.bytes.len().saturating_sub(self.written + 1);
        let count = available.min(value.len());
        self.bytes[self.written..self.written + count].copy_from_slice(&value.as_bytes()[..count]);
        self.written += count;
        Ok(())
    }
}
fn calendar_string(time: &NativeTime, output: &mut [u8]) {
    let mut text = BoundedText {
        bytes: output,
        written: 0,
    };
    // ASCII decimal formatting matches the pinned snprintf widths, including
    // signs and truncation to the original 40-byte scratch buffer.
    let _ = write!(
        text,
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
        time.mday,
        time.mon.wrapping_add(1),
        time.year.wrapping_add(1900),
        time.hour,
        time.min,
        time.sec
    );
    if let Some(byte) = text.bytes.get_mut(text.written) {
        *byte = 0;
    }
}

/// Produce one operation against a borrowed native snapshot. The source and
/// output must be disjoint, correctly sized storage; any string is terminated.
/// Neither this function nor the CRT formatter may call Lua.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_system_field(
    mode: u32,
    index: u32,
    source: *const c_void,
    output: *mut Field,
) -> bool {
    if mode > 6 || !aligned(output) || (mode == 0 && source.is_null()) {
        return false;
    }
    let end = if source.is_null() {
        if mode == 4 { 2 } else { 1 }
    } else {
        match mode {
            0 | 1 => 6,
            2 | 3 => 12,
            4 => 2,
            5 | 6 => 1,
            _ => return false,
        }
    };
    if index > end {
        return false;
    }
    let valid_source = source.is_null()
        || match mode {
            0 => source.cast::<NativeFile>().is_aligned(),
            1 => true,
            2 | 3 => source.cast::<NativeTime>().is_aligned(),
            4 | 5 => source.cast::<NativeClock>().is_aligned(),
            6 => source.cast::<i64>().is_aligned(),
            _ => false,
        };
    if !valid_source {
        return false;
    }
    let mut field = Field::default();
    if index == end {
        field.integer = if mode == 4 { 2 } else { 1 };
    } else if source.is_null() {
        field.kind = 8;
    } else if mode <= 3 && index == 0 {
        field.kind = 1;
        field.integer = if mode <= 1 { 5 } else { 11 };
    } else {
        // SAFETY: C owns each snapshot for the complete entry call. The checks
        // above validate metadata; each source type/layout is asserted on both
        // sides of the ABI. A VM call occurs only after the output is returned.
        unsafe {
            match mode {
                0 => {
                    let file = &*source.cast::<NativeFile>();
                    match index {
                        1 => named_integer(&mut field, c"dev", file.device as i64),
                        2 => named_integer(&mut field, c"inode", file.inode as i64),
                        3 => named_integer(&mut field, c"size", file.size),
                        4 => {
                            field.name = c"mtime".as_ptr();
                            field.kind = 3;
                            field.number = float_time(file.modified.seconds, file.modified.nanos);
                        }
                        5 => named_string(
                            &mut field,
                            c"type",
                            if file.mode & 0xf000 == 0x4000 {
                                c"dir".as_ptr()
                            } else {
                                c"file".as_ptr()
                            },
                        ),
                        _ => return false,
                    }
                }
                1 => {
                    let value = &*source.cast::<NativeUname>();
                    let (name, data): (&CStr, *const c_char) = match index {
                        1 => (c"sysname", value.sysname.as_ptr()),
                        2 => (c"nodename", value.nodename.as_ptr()),
                        3 => (c"release", value.release.as_ptr()),
                        4 => (c"version", value.version.as_ptr()),
                        5 => (c"machine", value.machine.as_ptr()),
                        _ => return false,
                    };
                    named_string(&mut field, name, data);
                }
                2 | 3 => {
                    let time = &*source.cast::<NativeTime>();
                    let item = match index {
                        1 => Some((c"sec", time.sec)),
                        2 => Some((c"min", time.min)),
                        3 => Some((c"hour", time.hour)),
                        4 => Some((c"mday", time.mday)),
                        5 => Some((c"mon", time.mon)),
                        6 => Some((c"year", time.year.wrapping_add(1900))),
                        7 => Some((c"wday", time.wday)),
                        8 => Some((c"yday", time.yday)),
                        9 => Some((c"isdst", time.isdst)),
                        10 | 11 => None,
                        _ => return false,
                    };
                    if let Some((name, value)) = item {
                        named_integer(&mut field, name, i64::from(value));
                    } else {
                        field.kind = 5;
                        if index == 10 {
                            field.name = c"zone".as_ptr();
                            if mode == 3 {
                                field.text[..4].copy_from_slice(b"UTC\0");
                            } else if strftime(
                                field.text.as_mut_ptr().cast(),
                                field.text.len(),
                                c"%Z".as_ptr(),
                                source.cast(),
                            ) == 0
                            {
                                field.text[0] = 0;
                            }
                        } else {
                            field.name = c"str".as_ptr();
                            calendar_string(time, &mut field.text[..40]);
                        }
                    }
                }
                4 | 5 => {
                    let clock = &*source.cast::<NativeClock>();
                    if mode == 5 {
                        field.kind = 7;
                        field.number = float_time(clock.seconds, clock.nanos);
                    } else {
                        field.kind = 6;
                        field.integer = if index == 0 {
                            clock.seconds
                        } else {
                            i64::from(clock.nanos)
                        };
                    }
                }
                6 => {
                    let seconds = source.cast::<i64>().read();
                    field.kind = if seconds == -1 { 8 } else { 6 };
                    field.integer = seconds;
                }
                _ => return false,
            }
        }
    }
    // SAFETY: validated writable output, disjoint from borrowed source data.
    unsafe { output.write(field) };
    true
}

const TIME_FIELDS: [&CStr; 7] = [c"sec", c"min", c"hour", c"mday", c"mon", c"year", c"isdst"];

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_time_error_format(status: u32, observing_field: bool) -> *const c_char {
    match (status, observing_field) {
        (_, true) => c"invalid tm.%s",
        (1, false) => c"invalid tm structure",
        _ => c"invalid time cursor",
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_time_begin(tag: i32, cursor: *mut TimeCursor) -> u32 {
    if !aligned(cursor) {
        return 2;
    }
    if tag != 5 {
        return 1;
    }
    // SAFETY: caller owns writable storage, and no VM operation is called here.
    unsafe { cursor.write(TimeCursor::default()) };
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_time_next(
    cursor: *const TimeCursor,
    name: *mut *const c_char,
) -> u32 {
    if !aligned(cursor) || !aligned(name) {
        return 2;
    }
    // SAFETY: C owns both disjoint values throughout this scalar operation.
    let index = unsafe { (*cursor).index as usize };
    match index {
        7 => 0,
        0..=6 => {
            unsafe { name.write(TIME_FIELDS[index].as_ptr()) };
            1
        }
        _ => 2,
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_time_observe(
    cursor: *mut TimeCursor,
    tag: i32,
    number: i64,
) -> u32 {
    if !aligned(cursor) {
        return 2;
    }
    // SAFETY: no Lua reference or owned resource crosses this fixed-state ABI.
    let cursor = unsafe { &mut *cursor };
    if cursor.index >= 7 {
        return 2;
    }
    if tag != 3 {
        return 1;
    }
    let value = number as i32;
    match cursor.index {
        0 => cursor.time.sec = value,
        1 => cursor.time.min = value,
        2 => cursor.time.hour = value,
        3 => cursor.time.mday = value,
        4 => cursor.time.mon = value,
        5 => cursor.time.year = year_from_lua(number),
        6 => cursor.time.isdst = value,
        _ => return 2,
    }
    cursor.index += 1;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_year_narrows_before_subtracting_epoch() {
        assert_eq!(year_from_lua(2023), 123);
        assert_eq!(year_from_lua(0x1_0000_07e7), 123);
        assert_eq!(year_from_lua(i64::from(i32::MIN)), i32::MAX - 1899);
    }

    fn projected(mode: u32, index: u32, source: *const c_void) -> Field {
        let mut field = Field::default();
        assert!(unsafe { zapret_lua_system_field(mode, index, source, &mut field) });
        field
    }

    #[test]
    fn stat_preserves_unsigned_identity_and_native_file_classification() {
        let mut file = NativeFile {
            device: u64::MAX,
            inode: 0x8000_0000_0000_0001,
            size: -9,
            mode: 0x4000 | 0o777,
            modified: NativeClock {
                seconds: -2,
                nanos: 999_999_999,
            },
        };
        let source = (&raw const file).cast();
        assert_eq!(projected(0, 0, source).integer, 5);
        assert_eq!(projected(0, 1, source).integer, -1);
        assert_eq!(projected(0, 2, source).integer, i64::MIN + 1);
        assert_eq!(projected(0, 3, source).integer, -9);
        assert_eq!(
            projected(0, 4, source).number,
            -2. + 999_999_999. / 1_000_000_000.
        );
        assert_eq!(
            unsafe { CStr::from_ptr(projected(0, 5, source).data) },
            c"dir"
        );
        file.mode = 0xa000;
        assert_eq!(
            unsafe { CStr::from_ptr(projected(0, 5, (&raw const file).cast()).data) },
            c"file"
        );
    }

    #[test]
    fn calendar_schema_keeps_zero_based_month_and_late_text() {
        let time = NativeTime {
            sec: 20,
            min: 13,
            hour: 22,
            mday: 14,
            mon: 10,
            year: 123,
            wday: 2,
            yday: 317,
            isdst: 0,
        };
        let source = (&raw const time).cast();
        assert_eq!(projected(3, 5, source).integer, 10);
        assert_eq!(projected(3, 6, source).integer, 2023);
        assert_eq!(&projected(3, 10, source).text[..4], b"UTC\0");
        assert_eq!(
            &projected(3, 11, source).text[..20],
            b"14.11.2023 22:13:20\0"
        );
        assert_eq!(projected(3, 12, source).kind, 0);
    }

    #[test]
    fn bounded_calendar_format_preserves_signs_and_truncation() {
        let mut text = [0xa5; 48];
        let time = NativeTime {
            sec: -1,
            min: 0,
            hour: 9,
            mday: 2,
            mon: -2,
            year: -1901,
            ..Default::default()
        };
        calendar_string(&time, &mut text[..40]);
        assert_eq!(&text[..20], b"02.-1.-001 09:00:-1\0");
        assert_eq!(text[20..], [0xa5; 28]);
        let time = NativeTime {
            sec: i32::MIN,
            min: i32::MAX,
            hour: i32::MIN,
            mday: i32::MAX,
            mon: i32::MAX,
            year: i32::MAX,
            ..Default::default()
        };
        calendar_string(&time, &mut text[..40]);
        assert_eq!(text[39], 0);
        assert_eq!(text[40..], [0xa5; 8]);
    }

    #[test]
    fn failed_native_queries_keep_result_arity_and_time_minus_one_is_nil() {
        for mode in 1..=6 {
            let count = if mode == 4 { 2 } else { 1 };
            for index in 0..count {
                assert_eq!(projected(mode, index, ptr::null()).kind, 8);
            }
            assert_eq!(
                projected(mode, count, ptr::null()).integer,
                i64::from(count)
            );
        }
        let mut seconds = -1i64;
        assert_eq!(projected(6, 0, (&raw const seconds).cast()).kind, 8);
        seconds = 0;
        assert_eq!(projected(6, 0, (&raw const seconds).cast()).kind, 6);
    }

    #[test]
    fn integer_clock_is_not_rounded_through_double() {
        let clock = NativeClock {
            seconds: i64::MAX,
            nanos: -1,
        };
        let source = (&raw const clock).cast();
        assert_eq!(projected(4, 0, source).integer, i64::MAX);
        assert_eq!(projected(4, 1, source).integer, -1);
        assert_eq!(
            projected(5, 0, source).number,
            i64::MAX as f64 - 1. / 1_000_000_000.
        );
    }

    #[test]
    fn time_lookup_order_and_strict_types_preserve_partial_state() {
        let mut cursor = TimeCursor::default();
        assert_eq!(unsafe { zapret_lua_time_begin(5, &mut cursor) }, 0);
        let values = [20, 13, 22, 14, 10, 2023, -1];
        for (index, value) in values.into_iter().enumerate() {
            let mut name = ptr::null();
            assert_eq!(unsafe { zapret_lua_time_next(&cursor, &mut name) }, 1);
            assert_eq!(unsafe { CStr::from_ptr(name) }, TIME_FIELDS[index]);
            assert_eq!(unsafe { zapret_lua_time_observe(&mut cursor, 4, value) }, 1);
            assert_eq!(cursor.index as usize, index);
            assert_eq!(unsafe { zapret_lua_time_observe(&mut cursor, 3, value) }, 0);
        }
        assert_eq!(cursor.time.year, 123);
        assert_eq!(cursor.time.isdst, -1);
        assert_eq!(
            unsafe { zapret_lua_time_next(&cursor, &mut ptr::null()) },
            0
        );
        assert_eq!(unsafe { zapret_lua_time_observe(&mut cursor, 3, 0) }, 2);
    }

    #[test]
    fn invalid_metadata_does_not_publish_output() {
        let mut output = Field {
            integer: 123,
            ..Default::default()
        };
        let time = NativeTime::default();
        let source: *const c_void = (&raw const time).cast();
        for (mode, index, input) in [
            (7, 0, source),
            (0, 0, ptr::null()),
            (3, 13, source),
            (3, 1, unsafe { source.cast::<u8>().add(1).cast() }),
        ] {
            assert!(!unsafe { zapret_lua_system_field(mode, index, input, &mut output) });
            assert_eq!(output.integer, 123);
        }
        assert!(!unsafe { zapret_lua_system_field(3, 0, source, ptr::null_mut()) });
        let mut cursor = TimeCursor {
            index: 99,
            ..Default::default()
        };
        assert_eq!(unsafe { zapret_lua_time_begin(0, &mut cursor) }, 1);
        assert_eq!(cursor.index, 99);
        assert_eq!(unsafe { zapret_lua_time_begin(5, ptr::null_mut()) }, 2);
        assert_eq!(
            unsafe { zapret_lua_time_next(&cursor, &mut ptr::null()) },
            2
        );
        assert_eq!(unsafe { zapret_lua_time_observe(&mut cursor, 3, 0) }, 2);
    }
}
