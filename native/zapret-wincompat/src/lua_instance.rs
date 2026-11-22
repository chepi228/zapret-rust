//! Format the per-rule lookup key without a CRT formatting call or allocation.
use crate::text_buffer::{TextBuffer, decimal};
use std::ffi::{CStr, c_char};
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_desync_instance(
    function: *const c_char,
    profile: u32,
    number: u32,
    output: *mut c_char,
    capacity: usize,
) {
    let Some(mut output) = (unsafe { TextBuffer::new(output, capacity) }) else {
        return;
    };
    if function.is_null() {
        return;
    }
    let name = unsafe { CStr::from_ptr(function) }.to_bytes();
    if !output.bytes(name) || !output.bytes(b"_") {
        return;
    }
    let mut digits = [0u8; 10];
    if !output.bytes(decimal(profile, &mut digits)) || !output.bytes(b"_") {
        return;
    }
    output.bytes(decimal(number, &mut digits));
}
