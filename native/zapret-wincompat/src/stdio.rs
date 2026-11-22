//! Bounded retry helpers over the engine's shared UCRT streams.
mod gzip;
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

unsafe extern "C" {
    fn _errno() -> *mut c_int;
    fn clearerr(stream: *mut libc::FILE);
}
#[repr(C)]
struct Ops {
    read_fd: unsafe extern "C" fn(c_int, *mut c_void, u32) -> c_int,
    read_file: unsafe extern "C" fn(*mut c_void, usize, usize, *mut libc::FILE) -> usize,
    read_line: unsafe extern "C" fn(*mut c_char, c_int, *mut libc::FILE) -> *mut c_char,
    failed: unsafe extern "C" fn(*mut libc::FILE) -> c_int,
    ended: unsafe extern "C" fn(*mut libc::FILE) -> c_int,
    clear: unsafe extern "C" fn(*mut libc::FILE),
    errno: unsafe extern "C" fn() -> *mut c_int,
}
const NATIVE: Ops = Ops {
    read_fd: libc::read,
    read_file: libc::fread,
    read_line: libc::fgets,
    failed: libc::ferror,
    ended: libc::feof,
    clear: clearerr,
    errno: _errno,
};
const RETRIES: usize = 1024;
unsafe fn ops<'a>(input: *const Ops) -> &'a Ops {
    if input.is_null() {
        &NATIVE
    } else {
        unsafe { &*input }
    }
}
unsafe fn error(ops: &Ops, value: i32) {
    unsafe { (ops.errno)().write(value) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_read(
    fd: c_int,
    output: *mut c_void,
    count: usize,
    input: *const Ops,
) -> isize {
    let ops = unsafe { ops(input) };
    if count > i32::MAX as usize || count != 0 && output.is_null() {
        unsafe { error(ops, libc::EINVAL) };
        return -1;
    }
    for _ in 0..RETRIES {
        let read = unsafe { (ops.read_fd)(fd, output, count as u32) };
        if read >= 0 || unsafe { (ops.errno)().read() } != libc::EINTR {
            return read as isize;
        }
    }
    -1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_fread(
    output: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
    read: *mut usize,
    input: *const Ops,
) -> bool {
    let ops = unsafe { ops(input) };
    if read.is_null() {
        unsafe { error(ops, libc::EINVAL) };
        return false;
    }
    unsafe { read.write(0) };
    let Some(bytes) = size
        .checked_mul(count)
        .filter(|&bytes| bytes <= isize::MAX as usize)
    else {
        unsafe { error(ops, libc::EINVAL) };
        return false;
    };
    if stream.is_null() || bytes != 0 && output.is_null() {
        unsafe { error(ops, libc::EINVAL) };
        return false;
    }
    let mut total = 0;
    let mut interruptions = 0;
    while total < count {
        unsafe { error(ops, 0) };
        let remaining = count - total;
        let destination = output.cast::<u8>().wrapping_add(total * size).cast();
        let result = unsafe { (ops.read_file)(destination, size, remaining, stream) };
        if result > remaining {
            unsafe { error(ops, libc::EIO) };
            return false;
        }
        total += result;
        unsafe { read.write(total) };
        if result < remaining {
            if unsafe { (ops.failed)(stream) } != 0 {
                if unsafe { (ops.errno)().read() } == libc::EINTR && interruptions < RETRIES {
                    interruptions += 1;
                    unsafe { (ops.clear)(stream) };
                    continue;
                }
                return false;
            }
            break;
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_fgets(
    output: *mut c_char,
    capacity: c_int,
    stream: *mut libc::FILE,
    input: *const Ops,
) -> *mut c_char {
    let ops = unsafe { ops(input) };
    if output.is_null() || stream.is_null() || capacity <= 0 {
        unsafe { error(ops, libc::EINVAL) };
        return ptr::null_mut();
    }
    for _ in 0..RETRIES {
        unsafe { error(ops, 0) };
        let result = unsafe { (ops.read_line)(output, capacity, stream) };
        if !result.is_null() {
            return result;
        }
        if unsafe { (ops.failed)(stream) } != 0 {
            if unsafe { (ops.errno)().read() } == libc::EINTR {
                unsafe { (ops.clear)(stream) };
                continue;
            }
            return ptr::null_mut();
        }
        if unsafe { (ops.ended)(stream) } != 0 {
            return ptr::null_mut();
        }
        // A null result without an error or EOF must not spin indefinitely.
        unsafe { error(ops, libc::EIO) };
        return ptr::null_mut();
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_engine_crypto_random(output: *mut u8, count: usize) -> bool {
    if count > isize::MAX as usize || count != 0 && output.is_null() {
        return false;
    }
    let mut offset = 0;
    while offset < count {
        let chunk = (count - offset).min(u32::MAX as usize);
        if unsafe { crate::system::zapret_getrandom(output.add(offset), chunk, 1) }
            != chunk as isize
        {
            return false;
        }
        offset += chunk;
    }
    true
}
