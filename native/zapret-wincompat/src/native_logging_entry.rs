//! Native logging and comparison policies for the Windows engine.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_env = "gnu"))]
mod stdio;

pub(super) use crate::logging::LogSink;
use std::{
    ffi::c_char,
    fmt::{self, Write},
    slice,
};

#[repr(C)]
#[derive(Default)]
pub struct LogState {
    phase: u32,
    pub result: i32,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_log_entry_step(
    state: &mut LogState,
    condup: bool,
    observation: i32,
) -> u32 {
    let (phase, action) = match state.phase {
        0 => (if condup { 1 } else { 4 }, 1),
        1 => {
            if observation != 0 {
                (2, 2)
            } else {
                (3, 3)
            }
        }
        2 => {
            if observation == 0 {
                (4, 1)
            } else {
                (3, 3)
            }
        }
        3 => (4, 1),
        4 => {
            if observation != 0 {
                (5, 2)
            } else {
                (8, 8)
            }
        }
        5 => match observation {
            0 => (6, 4),
            1 => (7, 5),
            2 => (7, 6),
            _ => (8, 8),
        },
        6 => {
            state.result = observation;
            (8, 8)
        }
        7 => {
            state.result = 1;
            (8, 8)
        }
        8 => (8, 8),
        _ => return 0,
    };
    state.phase = phase;
    action
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_log_append_step(
    state: &mut LogState,
    timestamp: bool,
    observation: i32,
) -> u32 {
    let (phase, action) = match state.phase {
        0 => (1, 1),
        1 => {
            if observation == 0 {
                state.result = -1;
                (7, 7)
            } else if timestamp {
                (2, 2)
            } else {
                (4, 4)
            }
        }
        2 => (3, 3),
        3 => (4, 4),
        4 => {
            state.result = observation;
            if timestamp { (5, 5) } else { (6, 6) }
        }
        5 => (6, 6),
        6 | 7 => (7, 7),
        _ => return 0,
    };
    state.phase = phase;
    action
}

#[unsafe(no_mangle)]
pub extern "C" fn zapret_log_console_error(priority: i32) -> bool {
    priority == 3
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_log_perror(
    label: *const c_char,
    description: *const c_char,
    error: LogSink,
) -> i32 {
    unsafe { error(c"%s: %s\n".as_ptr(), label, description) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_log_path_enabled(path: *const c_char) -> bool {
    !path.is_null() && unsafe { path.read() } != 0
}

struct Text<'a> {
    bytes: &'a mut [u8],
    used: usize,
}
impl fmt::Write for Text<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        if end >= self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.used..end].copy_from_slice(text.as_bytes());
        self.bytes[end] = 0;
        self.used = end;
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_log_timestamp(
    fields: *const i32,
    output: *mut u8,
    capacity: usize,
) -> bool {
    if fields.is_null()
        || !fields.is_aligned()
        || output.is_null()
        || capacity == 0
        || capacity > isize::MAX as usize
    {
        return false;
    }
    let fields = unsafe { slice::from_raw_parts(fields, 6) };
    let mut text = Text {
        bytes: unsafe { slice::from_raw_parts_mut(output, capacity) },
        used: 0,
    };
    text.bytes[0] = 0;
    write!(
        text,
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
        fields[0],
        fields[1].wrapping_add(1),
        fields[2].wrapping_add(1900),
        fields[3],
        fields[4],
        fields[5]
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_output_observes_debug_and_target_again_after_the_write() {
        let mut state = LogState::default();
        // Observe debug, then target, duplicate; a writer disables debugging.
        for (input, expected) in [(0, 1), (1, 2), (1, 3), (-7, 1), (0, 8)] {
            assert_eq!(
                unsafe { zapret_log_entry_step(&mut state, true, input) },
                expected
            );
        }
        assert_eq!(state.result, 0);
    }
    #[test]
    fn console_result_is_native_and_buffered_result_is_one() {
        for target in 0..=3 {
            let mut state = LogState::default();
            assert_eq!(unsafe { zapret_log_entry_step(&mut state, false, 0) }, 1);
            assert_eq!(unsafe { zapret_log_entry_step(&mut state, false, 1) }, 2);
            let action = unsafe { zapret_log_entry_step(&mut state, false, target) };
            assert_eq!(
                action,
                match target {
                    0 => 4,
                    1 => 5,
                    2 => 6,
                    _ => 8,
                }
            );
            if target < 3 {
                assert_eq!(unsafe { zapret_log_entry_step(&mut state, false, -19) }, 8);
            }
            assert_eq!(
                state.result,
                match target {
                    0 => -19,
                    1 | 2 => 1,
                    _ => 0,
                }
            );
        }
    }
    #[test]
    fn append_keeps_only_body_result_and_closes_even_after_body_failure() {
        let mut state = LogState::default();
        for (input, expected) in [(0, 1), (1, 2), (0, 3), (0, 4), (-13, 5), (0, 6), (0, 7)] {
            assert_eq!(
                unsafe { zapret_log_append_step(&mut state, true, input) },
                expected
            );
        }
        assert_eq!(state.result, -13);
        let mut direct = LogState::default();
        for (input, expected) in [(0, 1), (1, 4), (-13, 6), (-1, 7)] {
            assert_eq!(
                unsafe { zapret_log_append_step(&mut direct, false, input) },
                expected
            );
        }
        assert_eq!(direct.result, -13);
        for timestamp in [false, true] {
            let mut failed = LogState::default();
            assert_eq!(
                unsafe { zapret_log_append_step(&mut failed, timestamp, 0) },
                1
            );
            assert_eq!(
                unsafe { zapret_log_append_step(&mut failed, timestamp, 0) },
                7
            );
            assert_eq!(failed.result, -1);
        }
    }
    #[test]
    fn timestamp_has_native_calendar_adjustments_and_minimum_widths() {
        let fields = [7, 0, 126, 1, 2, 3];
        let mut output = [0u8; 64];
        assert!(unsafe {
            zapret_log_timestamp(fields.as_ptr(), output.as_mut_ptr(), output.len())
        });
        assert_eq!(&output[..20], b"07.01.2026 01:02:03\0");
        assert!(zapret_log_console_error(3));
        assert!(!zapret_log_console_error(7));
        assert!(unsafe { zapret_log_path_enabled(c"x".as_ptr()) });
        assert!(!unsafe { zapret_log_path_enabled(c"".as_ptr()) });
    }
}
