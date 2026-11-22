//! Windows capture option policy. Callbacks reuse the native Rust backend ABIs.
use crate::{cli::Perror, logging::LogSink};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr, slice,
};

#[repr(C)]
struct Target {
    first: *mut c_void,
    second: *mut c_void,
    capacity: usize,
    hash: *mut u32,
    secondary_hash: *mut u32,
    collection: *mut c_void,
}
type Render = unsafe extern "C" fn(
    *const c_char,
    u32,
    *const c_char,
    *const c_char,
    *mut c_char,
    usize,
) -> bool;
#[repr(C)]
struct Ops {
    render: Option<Render>,
    versions: Option<unsafe extern "C" fn(*const c_char, *mut bool, *mut bool) -> bool>,
    read: Option<unsafe extern "C" fn(*const c_char, i64, *mut c_void, *mut usize) -> u32>,
    append: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> bool>,
    strings: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> bool>,
    number: Option<unsafe extern "C" fn(*const c_char, *mut bool) -> bool>,
    networks: Option<unsafe extern "C" fn(bool) -> bool>,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct ResultCode {
    status: u32,
    error: u32,
}
impl ResultCode {
    fn status(status: u32) -> Self {
        Self { status, error: 0 }
    }
}
fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 13);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 8);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 13);
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 12);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 16);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 5);
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 3);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 10);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 15);
}
fn hash(bytes: &[u8]) -> u32 {
    let (mut a, mut b, mut c) = (0x9e3779b9u32, 0x9e3779b9u32, 0xfeedbeefu32);
    let mut chunks = bytes.chunks_exact(12);
    for chunk in &mut chunks {
        a = a.wrapping_add(u32::from_le_bytes(chunk[..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(chunk[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(chunk[8..12].try_into().unwrap()));
        mix(&mut a, &mut b, &mut c);
    }
    c = c.wrapping_add(bytes.len() as u32);
    for (index, &byte) in chunks.remainder().iter().enumerate() {
        match index {
            0..=3 => a = a.wrapping_add(u32::from(byte) << (index * 8)),
            4..=7 => b = b.wrapping_add(u32::from(byte) << ((index - 4) * 8)),
            _ => c = c.wrapping_add(u32::from(byte) << ((index - 7) * 8)),
        }
    }
    mix(&mut a, &mut b, &mut c);
    c
}
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_cli_capture_hash(data: *const u8, length: u32) -> u32 {
    if length == 0 {
        return hash(&[]);
    }
    if data.is_null() {
        return 0;
    }
    hash(unsafe { slice::from_raw_parts(data, length as usize) })
}
fn buffer(capacity: usize) -> Result<Vec<u8>, u32> {
    if !(2..=65536).contains(&capacity) {
        return Err(1);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity + 1).map_err(|_| 3u32)?;
    bytes.resize(capacity + 1, 0);
    Ok(bytes)
}
unsafe fn raw(text: *const c_char, capacity: usize, ops: &Ops) -> Result<Vec<u8>, ResultCode> {
    if !(2..=65536).contains(&capacity) {
        return Err(ResultCode::status(1));
    }
    let input = unsafe { CStr::from_ptr(text) }.to_bytes();
    if input.first() != Some(&b'@') && input.len() >= capacity {
        return Err(ResultCode::status(5));
    }
    let mut bytes = buffer(capacity).map_err(ResultCode::status)?;
    if input.first() == Some(&b'@') {
        let Some(read) = ops.read else {
            return Err(ResultCode::status(1));
        };
        let mut size = capacity;
        let error = unsafe { read(text.add(1), 0, bytes.as_mut_ptr().cast(), &mut size) };
        if error != 0 {
            return Err(ResultCode { status: 4, error });
        }
        if size >= capacity {
            return Err(ResultCode::status(5));
        }
        bytes[size] = 0;
        bytes.truncate(size + 1);
    } else {
        bytes[..input.len()].copy_from_slice(input);
        bytes.truncate(input.len() + 1);
    }
    Ok(bytes)
}
unsafe fn apply(
    kind: u32,
    text: *const c_char,
    target: &Target,
    ops: &Ops,
) -> Result<(), ResultCode> {
    let fail = ResultCode::status;
    if text.is_null() && !matches!(kind, 13 | 17 | 19 | 21 | 22) {
        return Err(fail(1));
    }
    if kind == 22 {
        let Some(networks) = ops.networks else {
            return Err(fail(1));
        };
        let all = !text.is_null() && unsafe { CStr::from_ptr(text) }.to_bytes() == b"all";
        return Err(fail(if unsafe { networks(all) } { 8 } else { 7 }));
    }
    if kind == 0 {
        if !valid(target.first.cast::<u32>()) || !valid(target.second.cast::<u32>()) {
            return Err(fail(1));
        }
        let (mut index, mut sub) = unsafe {
            (
                target.first.cast::<u32>().read(),
                target.second.cast::<u32>().read(),
            )
        };
        if unsafe { libc::sscanf(text, c"%u.%u".as_ptr(), &mut index, &mut sub) } < 1 {
            return Err(fail(2));
        }
        unsafe {
            target.first.cast::<u32>().write(index);
            target.second.cast::<u32>().write(sub)
        };
        return Ok(());
    }
    if kind == 1 {
        if !valid(target.first.cast::<bool>()) || !valid(target.second.cast::<bool>()) {
            return Err(fail(1));
        }
        let Some(versions) = ops.versions else {
            return Err(fail(1));
        };
        let (mut v4, mut v6) = unsafe {
            (
                target.first.cast::<bool>().read(),
                target.second.cast::<bool>().read(),
            )
        };
        if !unsafe { versions(text, &mut v4, &mut v6) } {
            return Err(fail(2));
        }
        unsafe {
            target.first.cast::<bool>().write(v4);
            target.second.cast::<bool>().write(v6)
        };
        return Ok(());
    }
    if matches!(kind, 13..=15 | 17 | 19 | 21) {
        if !valid(target.first.cast::<bool>()) {
            return Err(fail(1));
        }
        if matches!(kind, 19 | 21) {
            if !valid(target.hash) {
                return Err(fail(1));
            }
            let Some(number) = ops.number else {
                return Err(fail(1));
            };
            let mut value = false;
            if !unsafe { number(text, &mut value) } {
                return Err(fail(2));
            }
            unsafe {
                target.first.cast::<bool>().write(value);
                target.hash.write(u32::from(value))
            };
        } else {
            let value = text.is_null() || unsafe { libc::atoi(text) } != 0;
            unsafe { target.first.cast::<bool>().write(value) };
        }
        return Ok(());
    }
    if kind == 16 {
        if target.first.is_null() || !(2..=65536).contains(&target.capacity) {
            return Err(fail(1));
        }
        let bytes = unsafe { CStr::from_ptr(text) }.to_bytes_with_nul();
        if bytes.len() > target.capacity {
            return Err(fail(5));
        }
        unsafe { ptr::copy(bytes.as_ptr(), target.first.cast(), bytes.len()) };
        return Ok(());
    }
    if !valid(target.hash) {
        return Err(fail(1));
    }
    if matches!(kind, 18 | 20) {
        if target.collection.is_null() {
            return Err(fail(1));
        }
        let Some(strings) = ops.strings else {
            return Err(fail(1));
        };
        if !unsafe { strings(text, target.collection) } {
            return Err(fail(6));
        }
        unsafe { target.hash.write(hash(CStr::from_ptr(text).to_bytes())) };
        return Ok(());
    }
    if matches!(kind, 10..=12) {
        if (kind != 11 && target.first.is_null())
            || (kind == 11 && target.collection.is_null())
            || (kind == 12 && !valid(target.secondary_hash))
        {
            return Err(fail(1));
        }
        if kind == 11 && ops.append.is_none() {
            return Err(fail(1));
        }
        let bytes = unsafe { raw(text, target.capacity, ops) }?;
        let input = unsafe { CStr::from_ptr(text) }.to_bytes();
        let output = unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }.to_bytes();
        let fingerprint = hash(output);
        if kind == 11 {
            if !unsafe { ops.append.unwrap()(target.collection, bytes.as_ptr().cast()) } {
                return Err(fail(6));
            }
            unsafe { target.hash.write(target.hash.read() ^ fingerprint) };
        } else {
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), target.first.cast(), bytes.len()) };
            if kind == 12 {
                unsafe {
                    target.hash.write(hash(input));
                    target.secondary_hash.write(fingerprint)
                };
            } else {
                unsafe { target.hash.write(fingerprint) };
            }
        }
        return Ok(());
    }
    if !(2..=9).contains(&kind) || target.first.is_null() || (kind <= 5 && target.second.is_null())
    {
        return Err(fail(1));
    }
    let Some(render) = ops.render else {
        return Err(fail(1));
    };
    let mut first = buffer(target.capacity).map_err(fail)?;
    let protocol = if kind <= 3 {
        c"tcp".as_ptr()
    } else if kind <= 5 {
        c"udp".as_ptr()
    } else {
        ptr::null()
    };
    let parse_kind = if kind <= 5 {
        0
    } else if kind <= 7 {
        1
    } else {
        2
    };
    if !unsafe {
        render(
            text,
            parse_kind,
            protocol,
            if kind <= 5 {
                c"SrcPort".as_ptr()
            } else {
                ptr::null()
            },
            first.as_mut_ptr().cast(),
            target.capacity,
        )
    } {
        return Err(fail(2));
    }
    if kind <= 5 {
        let mut second = buffer(target.capacity).map_err(fail)?;
        if !unsafe {
            render(
                text,
                0,
                protocol,
                c"DstPort".as_ptr(),
                second.as_mut_ptr().cast(),
                target.capacity,
            )
        } {
            return Err(fail(2));
        }
        let Some(end) = second[..target.capacity].iter().position(|&b| b == 0) else {
            return Err(fail(1));
        };
        // Validate both bounded outputs before publishing either field.
        let Some(first_end) = first[..target.capacity].iter().position(|&b| b == 0) else {
            return Err(fail(1));
        };
        unsafe {
            ptr::copy_nonoverlapping(second.as_ptr(), target.second.cast(), end + 1);
            ptr::copy_nonoverlapping(first.as_ptr(), target.first.cast(), first_end + 1)
        };
    } else {
        let Some(end) = first[..target.capacity].iter().position(|&b| b == 0) else {
            return Err(fail(1));
        };
        unsafe { ptr::copy_nonoverlapping(first.as_ptr(), target.first.cast(), end + 1) };
    }
    unsafe { target.hash.write(hash(CStr::from_ptr(text).to_bytes())) };
    Ok(())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_capture_option(
    kind: u32,
    text: *const c_char,
    target: *const Target,
    ops: *const Ops,
) -> ResultCode {
    if kind > 22 || !valid(target) || !valid(ops) {
        return ResultCode::status(1);
    }
    unsafe { apply(kind, text, &*target, &*ops) }
        .map_or_else(std::convert::identity, |()| ResultCode::status(0))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_capture_report(
    result: ResultCode,
    name: *const c_char,
    publish_error: unsafe extern "C" fn(u32),
    error: LogSink,
    perror: Perror,
) -> c_int {
    unsafe {
        match result.status {
            0 => return 1,
            8 => return 2,
            1 => error(c"invalid capture option storage\n".as_ptr()),
            3 | 6 => error(c"out of memory\n".as_ptr()),
            4 => {
                publish_error(result.error);
                perror(c"read capture filter".as_ptr())
            }
            5 => error(c"value for --%s is too long\n".as_ptr(), name),
            7 => error(c"could not get list of NLM networks\n".as_ptr()),
            _ => error(c"bad value for --%s\n".as_ptr(), name),
        };
    }
    -1
}

#[cfg(windows)]
const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Target>() == 6 * pointer);
    assert!(size_of::<Ops>() == 7 * pointer);
    assert!(size_of::<ResultCode>() == 8);
};
