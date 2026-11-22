//! Comma-separated startup inputs without editing the command-line storage.
use std::ffi::{CStr, c_char, c_void};

pub(super) unsafe fn each(
    text: *const c_char,
    mut insert: impl FnMut(*mut c_char) -> bool,
) -> bool {
    if text.is_null() {
        return true;
    }
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
    let maximum = bytes
        .split(|&byte| byte == b',')
        .map(<[u8]>::len)
        .max()
        .unwrap_or(0);
    if maximum == 0 {
        return true;
    }
    let Some(capacity) = maximum.checked_add(1) else {
        return false;
    };
    let mut local = [0; 256];
    let mut extended = Vec::new();
    let buffer = if capacity <= local.len() {
        &mut local[..capacity]
    } else {
        if extended.try_reserve_exact(capacity).is_err() {
            return false;
        }
        extended.resize(capacity, 0);
        extended.as_mut_slice()
    };
    for part in bytes
        .split(|&byte| byte == b',')
        .filter(|part| !part.is_empty())
    {
        buffer[..part.len()].copy_from_slice(part);
        buffer[part.len()] = 0;
        // The existing pool normalizer edits its token. Pass the private
        // mutable copy without keeping a shared CStr reference to that copy.
        if !insert(buffer.as_mut_ptr().cast()) {
            return false;
        }
    }
    true
}

type Insert = unsafe extern "C" fn(*mut c_void, *mut c_char) -> bool;
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_config_list(
    text: *const c_char,
    target: *mut c_void,
    insert: Option<Insert>,
) -> bool {
    let Some(insert) = insert else {
        return false;
    };
    if target.is_null() {
        return false;
    }
    unsafe { each(text, |value| insert(target, value)) }
}
