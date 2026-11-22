//! Bounded bytes and diagnostics in the caller's C buffer, without allocation.
use std::{ffi::c_char, fmt, ptr};

pub(super) struct TextBuffer {
    output: *mut u8,
    capacity: usize,
    written: usize,
}
impl TextBuffer {
    /// The nonempty buffer must be writable for its declared capacity.
    pub(super) unsafe fn new(output: *mut c_char, capacity: usize) -> Option<Self> {
        if capacity == 0 || capacity > isize::MAX as usize || output.is_null() {
            return None;
        }
        Some(Self {
            output: output.cast(),
            capacity,
            written: 0,
        })
    }

    pub(super) fn bytes(&mut self, text: &[u8]) -> bool {
        let count = text.len().min(self.capacity - 1 - self.written);
        if count != 0 {
            unsafe {
                ptr::copy_nonoverlapping(text.as_ptr(), self.output.add(self.written), count)
            };
            self.written += count;
        }
        count == text.len()
    }
}
impl fmt::Write for TextBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes(text.as_bytes());
        Ok(())
    }
}
impl Drop for TextBuffer {
    fn drop(&mut self) {
        unsafe { self.output.add(self.written).write(0) };
    }
}

pub(super) fn decimal(mut value: u32, digits: &mut [u8; 10]) -> &[u8] {
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    &digits[start..]
}
