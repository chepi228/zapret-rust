//! Parse a Lua invocation without editing the command line or calling Lua.
#[cfg(windows)]
mod view;
use crate::{collections::append_staged_call, helpers::identifier};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

#[repr(C)]
struct Ops {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    start: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
    add: unsafe extern "C" fn(*mut c_void, *mut c_char, *mut c_char) -> bool,
}

#[repr(C)]
struct ParseError {
    format: *const c_char,
    length: i32,
}

fn parameter(text: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let (key, value) = if let Some(split) = text.iter().position(|&byte| byte == b'=') {
        (&text[..split], Some(&text[split + 1..]))
    } else {
        (text, None)
    };
    identifier(key).then_some((key, value))
}

fn token(text: &[u8]) -> (&[u8], &[u8], bool) {
    let mut escaped = false;
    let mut index = 0;
    while index < text.len() {
        match &text[index..] {
            [b'\\', b':', ..] => {
                index += 2;
                escaped = true;
            }
            [b':', rest @ ..] => return (&text[..index], rest, escaped),
            _ => index += 1,
        }
    }
    (text, &[], escaped)
}

fn unescape(mut text: &[u8]) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    value.try_reserve_exact(text.len()).ok()?;
    while let Some((&first, rest)) = text.split_first() {
        if first == b'\\' && rest.starts_with(b":") {
            value.push(b':');
            text = &rest[1..];
        } else {
            value.push(first);
            text = rest;
        }
    }
    Some(value)
}

unsafe fn copy_argument(ops: &Ops, bytes: &[u8]) -> *mut c_char {
    let Some(length) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let copy = unsafe { (ops.allocate)(length) }.cast::<u8>();
    if !copy.is_null() {
        // SAFETY: the native allocator returned a fresh block of length bytes.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len());
            copy.add(bytes.len()).write(0);
        }
    }
    copy.cast()
}

unsafe fn add_parameter(ops: &Ops, args: *mut c_void, key: &[u8], value: Option<&[u8]>) -> bool {
    let name = unsafe { copy_argument(ops, key) };
    let text = value.map_or(ptr::null_mut(), |value| unsafe {
        copy_argument(ops, value)
    });
    if !name.is_null()
        && (value.is_none() || !text.is_null())
        && unsafe { (ops.add)(args, name, text) }
    {
        return true;
    }
    unsafe {
        (ops.release)(text.cast());
        (ops.release)(name.cast());
    }
    false
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_add_argument(
    text: *const c_char,
    args: *mut c_void,
    ops: &Ops,
) -> bool {
    let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
    let Some((key, value)) = parameter(bytes) else {
        return false;
    };
    unsafe { add_parameter(ops, args, key, value) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_parse_arguments(
    text: *const c_char,
    staged: *mut c_void,
    target: *mut c_void,
    ops: &Ops,
    error: &mut ParseError,
) -> *mut c_void {
    let text = unsafe { CStr::from_ptr(text) }.to_bytes();
    let (name, mut rest) = match text.iter().position(|&byte| byte == b':') {
        Some(split) => (&text[..split], &text[split + 1..]),
        None => (text, &[][..]),
    };
    if !identifier(name) {
        *error = ParseError {
            format: c"bad identifier '%.*s'\n".as_ptr(),
            length: name.len() as i32,
        };
        return ptr::null_mut();
    }
    let text = unsafe { copy_argument(ops, name) };
    if text.is_null() {
        return ptr::null_mut();
    }
    let args = unsafe { (ops.start)(staged, text) };
    unsafe { (ops.release)(text.cast()) };
    if args.is_null() {
        return ptr::null_mut();
    }
    while !rest.is_empty() {
        let (part, next, escaped) = token(rest);
        let Some((key, value)) = parameter(part) else {
            return ptr::null_mut();
        };
        let allocated;
        let value = if escaped {
            let Some(value) = value.and_then(unescape) else {
                return ptr::null_mut();
            };
            allocated = value;
            Some(allocated.as_slice())
        } else {
            value
        };
        if !unsafe { add_parameter(ops, args, key, value) } {
            return ptr::null_mut();
        }
        rest = next;
    }
    unsafe { append_staged_call(target, staged) }
}
