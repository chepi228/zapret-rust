//! UCRT-owned argv publication after one bounded Rust expansion.
use super::{MAX_BYTES, MAX_INPUT, MAX_WORDS, NOSPACE, Result, expand};
use std::{
    ffi::{c_char, c_int, c_void},
    mem, ptr,
};

const NOCMD: c_int = 4;
const REUSE: c_int = 8;
const SHOWERR: c_int = 16;
const NOSYS: c_int = 6;
const MAX_CONFIG: usize = 16_384 - 3;

#[repr(C)]
struct Wordexp {
    count: usize,
    words: *mut *mut c_char,
    offset: usize,
}
const _: () = {
    assert!(size_of::<Wordexp>() == 3 * size_of::<usize>());
    assert!(mem::offset_of!(Wordexp, words) == size_of::<usize>());
};

impl Wordexp {
    const EMPTY: Self = Self {
        count: 0,
        words: ptr::null_mut(),
        offset: 0,
    };
}
#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}
const UCRT: Allocator = Allocator {
    allocate: libc::malloc,
    release: libc::free,
};

struct Allocation<'a> {
    pointer: *mut c_void,
    allocator: &'a Allocator,
}
impl Allocation<'_> {
    fn take(&mut self) -> *mut c_void {
        mem::replace(&mut self.pointer, ptr::null_mut())
    }
}
impl Drop for Allocation<'_> {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe { (self.allocator.release)(self.pointer) };
        }
    }
}
fn allocate(size: usize, allocator: &Allocator) -> Result<Allocation<'_>> {
    let pointer = unsafe { (allocator.allocate)(size) };
    if pointer.is_null() {
        return Err(NOSPACE);
    }
    Ok(Allocation { pointer, allocator })
}
unsafe fn release(result: *mut Wordexp, allocator: &Allocator) {
    if result.is_null() {
        return;
    }
    let words = unsafe { (*result).words };
    if !words.is_null() {
        unsafe {
            (allocator.release)(words.read().cast());
            (allocator.release)(words.cast());
        }
    }
    unsafe { result.write(Wordexp::EMPTY) };
}
fn publish(input: &[u8], allocator: &Allocator) -> Result<Wordexp> {
    let input = std::str::from_utf8(input).map_err(|_| super::SYNTAX)?;
    let variables = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let directory = std::env::current_dir().map_err(|_| super::SYNTAX)?;
    // Expand only once. The resulting words supply both dimensions and bytes.
    let words = expand(input, variables, directory)?;
    if words.len() > MAX_WORDS {
        return Err(NOSPACE);
    }
    let size = words
        .iter()
        .try_fold(0usize, |size, word| {
            size.checked_add(word.len())?.checked_add(1)
        })
        .filter(|&size| size <= MAX_BYTES)
        .ok_or(NOSPACE)?;
    let mut data = if size == 0 {
        None
    } else {
        Some(allocate(size, allocator)?)
    };
    let mut vector = allocate((words.len() + 1) * mem::size_of::<*mut c_char>(), allocator)?;
    let pointers = vector.pointer.cast::<*mut c_char>();
    let start = data
        .as_ref()
        .map_or(ptr::null_mut(), |data| data.pointer.cast::<u8>());
    let mut offset = 0;
    for (index, word) in words.iter().enumerate() {
        unsafe {
            ptr::copy_nonoverlapping(word.as_ptr(), start.add(offset), word.len());
            start.add(offset + word.len()).write(0);
            pointers.add(index).write(start.add(offset).cast());
        }
        offset += word.len() + 1;
    }
    unsafe { pointers.add(words.len()).write(ptr::null_mut()) };
    if let Some(data) = &mut data {
        data.take();
    }
    Ok(Wordexp {
        count: words.len(),
        words: vector.take().cast(),
        offset: 0,
    })
}
unsafe fn bounded_input<'a>(input: *const c_char) -> Result<&'a [u8]> {
    for length in 0..=MAX_INPUT {
        if unsafe { input.add(length).read() } == 0 {
            return Ok(unsafe { std::slice::from_raw_parts(input.cast(), length) });
        }
    }
    Err(NOSPACE)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_wordfree(result: *mut Wordexp, allocator: *const Allocator) {
    if let Some(allocator) = unsafe { allocator.as_ref() } {
        unsafe { release(result, allocator) };
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_wordexp(
    input: *const c_char,
    result: *mut Wordexp,
    flags: c_int,
    allocator: *const Allocator,
) -> c_int {
    let Some(allocator) = (unsafe { allocator.as_ref() }) else {
        return NOSPACE;
    };
    if result.is_null() {
        return NOSPACE;
    }
    if flags & REUSE != 0 {
        unsafe { release(result, allocator) };
    }
    unsafe { result.write(Wordexp::EMPTY) };
    if input.is_null() || flags & !(NOCMD | REUSE | SHOWERR) != 0 || flags & NOCMD == 0 {
        return NOSYS;
    }
    let expanded = std::panic::catch_unwind(|| {
        let input = unsafe { bounded_input(input) }?;
        publish(input, allocator)
    });
    match expanded {
        Ok(Ok(words)) => {
            unsafe { result.write(words) };
            0
        }
        Ok(Err(error)) => error,
        Err(_) => NOSPACE,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wordexp(input: *const c_char, result: *mut Wordexp, flags: c_int) -> c_int {
    unsafe { zapret_native_wordexp(input, result, flags, &UCRT) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wordfree(result: *mut Wordexp) {
    unsafe { release(result, &UCRT) };
}

// Config outcomes are independent of WRDE statuses: load / split / size / memory.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_config_file(
    filename: *const c_char,
    result: *mut Wordexp,
    error: *mut u32,
    allocator: *const Allocator,
) -> c_int {
    let Some(allocator) = (unsafe { allocator.as_ref() }) else {
        return 4;
    };
    if result.is_null() || error.is_null() {
        return 4;
    }
    unsafe { error.write(0) };
    let expanded = std::panic::catch_unwind(|| {
        let mut input = Vec::new();
        input.try_reserve_exact(MAX_CONFIG + 4).map_err(|_| 4)?;
        input.resize(MAX_CONFIG + 4, 0);
        input[0] = b'x';
        input[1] = b' ';
        // One additional byte detects the former silent truncation boundary.
        let mut length = MAX_CONFIG + 1;
        let status = unsafe {
            crate::file_helpers::zapret_engine_load_file(
                filename,
                0,
                input.as_mut_ptr().add(2).cast(),
                &mut length,
            )
        };
        if status != 0 {
            unsafe { error.write(status) };
            return Err(1);
        }
        if length > MAX_CONFIG {
            return Err(3);
        }
        input.truncate(length + 2);
        if let Some(end) = input.iter().position(|&byte| byte == 0) {
            input.truncate(end);
        }
        for byte in &mut input {
            if matches!(*byte, b'\r' | b'\n' | b'\t') {
                *byte = b' ';
            }
        }
        publish(&input, allocator).map_err(|_| 2)
    });
    match expanded {
        Ok(Ok(words)) => {
            unsafe {
                release(result, allocator);
                result.write(words)
            };
            0
        }
        Ok(Err(status)) => status,
        Err(_) => 4,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_config_read(
    filename: *const c_char,
    result: *mut Wordexp,
    allocator: *const Allocator,
    set_error: unsafe extern "C" fn(u32),
    report: crate::native_logging_entry::LogSink,
) -> bool {
    let allocator = unsafe { allocator.as_ref() }.unwrap_or(&UCRT);
    let mut error = 0;
    let status = unsafe { zapret_native_config_file(filename, result, &mut error, allocator) };
    if status == 0 {
        return true;
    }
    unsafe {
        if error != 0 {
            set_error(error);
        }
        match status {
            1 => report(c"could not load config file '%s'\n".as_ptr(), filename),
            3 => report(
                c"config file '%s' exceeds %u bytes\n".as_ptr(),
                filename,
                MAX_CONFIG as u32,
            ),
            4 => report(
                c"not enough memory for config file '%s'\n".as_ptr(),
                filename,
            ),
            _ => report(
                c"failed to split command line options from file '%s'\n".as_ptr(),
                filename,
            ),
        };
    }
    false
}
