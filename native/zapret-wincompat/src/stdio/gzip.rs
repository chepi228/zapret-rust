//! File decompression with UCRT output ownership and a finite codec progress loop.
use std::{
    ffi::{c_char, c_int, c_long, c_void},
    mem, ptr,
};
use zlib_rs::{ReturnCode, c_api::z_stream};

const OK: c_int = ReturnCode::Ok as c_int;
const END: c_int = ReturnCode::StreamEnd as c_int;
const IO_ERROR: c_int = ReturnCode::ErrNo as c_int;
const DATA_ERROR: c_int = ReturnCode::DataError as c_int;
const MEMORY_ERROR: c_int = ReturnCode::MemError as c_int;
const STREAM_ERROR: c_int = ReturnCode::StreamError as c_int;
const BUFFER_ERROR: c_int = ReturnCode::BufError as c_int;
const INPUT: usize = 16384;
const INITIAL: usize = 128 * 1024;

#[repr(C)]
struct Ops {
    read: Option<unsafe extern "C" fn(*mut libc::FILE, *mut u8, usize, *mut usize) -> bool>,
    read_raw: Option<unsafe extern "C" fn(*mut c_void, usize, usize, *mut libc::FILE) -> usize>,
    seek: Option<unsafe extern "C" fn(*mut libc::FILE, c_long, c_int) -> c_int>,
    resize: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
    init: Option<unsafe extern "C" fn(*mut z_stream, c_int) -> c_int>,
    process: Option<unsafe extern "C" fn(*mut z_stream, c_int) -> c_int>,
    end: Option<unsafe extern "C" fn(*mut z_stream) -> c_int>,
}
unsafe extern "C" fn read(
    stream: *mut libc::FILE,
    data: *mut u8,
    capacity: usize,
    count: *mut usize,
) -> bool {
    unsafe { super::zapret_engine_fread(data.cast(), 1, capacity, stream, count, ptr::null()) }
}
const NATIVE: Ops = Ops {
    read: Some(read),
    read_raw: Some(libc::fread),
    seek: Some(libc::fseek),
    resize: Some(libc::realloc),
    release: Some(libc::free),
    init: Some(crate::compression::zapret_inflate_init),
    process: Some(crate::compression::zapret_inflate),
    end: Some(crate::compression::zapret_inflate_end),
};
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
unsafe fn operations<'a>(input: *const Ops) -> Option<&'a Ops> {
    if input.is_null() {
        Some(&NATIVE)
    } else if input.is_aligned() {
        Some(unsafe { &*input })
    } else {
        None
    }
}
struct Buffer {
    data: *mut u8,
    length: usize,
    capacity: usize,
    extra: usize,
    resize: unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.data.is_null() {
            unsafe { (self.release)(self.data.cast()) };
        }
    }
}
impl Buffer {
    fn reserve(&mut self) -> Result<(), c_int> {
        let limit = isize::MAX as usize - self.extra;
        if self.capacity - self.length < 128 && self.capacity < limit {
            let next = if self.capacity == 0 {
                INITIAL.min(limit)
            } else {
                self.capacity.saturating_mul(2).min(limit)
            };
            if next <= self.capacity {
                return Err(MEMORY_ERROR);
            }
            let allocation = unsafe { (self.resize)(self.data.cast(), next + self.extra) };
            if allocation.is_null() {
                return Err(MEMORY_ERROR);
            }
            self.data = allocation.cast();
            self.capacity = next;
        }
        if self.capacity == self.length {
            return Err(MEMORY_ERROR);
        }
        Ok(())
    }
    fn shrink(&mut self) {
        if self.length < self.capacity {
            let size = self.length + self.extra;
            if size == 0 {
                unsafe { (self.release)(self.data.cast()) };
                self.data = ptr::null_mut();
            } else {
                let smaller = unsafe { (self.resize)(self.data.cast(), size) };
                if !smaller.is_null() {
                    self.data = smaller.cast();
                }
            }
        }
    }
}
struct Inflater<'a> {
    stream: z_stream,
    ops: &'a Ops,
    initialized: bool,
}
impl Drop for Inflater<'_> {
    fn drop(&mut self) {
        if self.initialized {
            self.stream.next_in = ptr::null();
            self.stream.avail_in = 0;
            self.stream.next_out = ptr::null_mut();
            self.stream.avail_out = 0;
            unsafe { self.ops.end.unwrap()(&mut self.stream) };
        }
    }
}
unsafe fn decompress(
    file: *mut libc::FILE,
    buffer: &mut Buffer,
    inflater: &mut Inflater<'_>,
) -> c_int {
    let mut input = [0u8; INPUT];
    loop {
        let mut count = 0;
        if !unsafe { inflater.ops.read.unwrap()(file, input.as_mut_ptr(), input.len(), &mut count) }
        {
            return IO_ERROR;
        }
        if count > input.len() {
            return STREAM_ERROR;
        }
        if count == 0 {
            return DATA_ERROR;
        }
        inflater.stream.next_in = input.as_ptr();
        inflater.stream.avail_in = count as u32;
        loop {
            if let Err(error) = buffer.reserve() {
                return error;
            }
            let available = (buffer.capacity - buffer.length).min(u32::MAX as usize) as u32;
            inflater.stream.next_out = unsafe { buffer.data.add(buffer.length) };
            inflater.stream.avail_out = available;
            let before = inflater.stream.avail_in;
            let result = unsafe { inflater.ops.process.unwrap()(&mut inflater.stream, 0) };
            if inflater.stream.avail_out > available || inflater.stream.avail_in > before {
                return STREAM_ERROR;
            }
            let produced = (available - inflater.stream.avail_out) as usize;
            buffer.length += produced;
            if result == END {
                return END;
            }
            if result == BUFFER_ERROR && inflater.stream.avail_in == 0 {
                break;
            }
            if result != OK {
                return result;
            }
            if produced == 0 && inflater.stream.avail_in == before {
                return BUFFER_ERROR;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_gzip_read(
    file: *mut libc::FILE,
    output: *mut *mut c_char,
    length: *mut usize,
    extra: usize,
    input: *const Ops,
) -> c_int {
    if !valid(output) || !valid(length) {
        return STREAM_ERROR;
    }
    unsafe {
        output.write(ptr::null_mut());
        length.write(0);
    }
    let Some(ops) = (unsafe { operations(input) }) else {
        return STREAM_ERROR;
    };
    if file.is_null()
        || ops.read.is_none()
        || ops.resize.is_none()
        || ops.release.is_none()
        || ops.init.is_none()
        || ops.process.is_none()
        || ops.end.is_none()
    {
        return STREAM_ERROR;
    }
    if extra > isize::MAX as usize - INITIAL {
        return MEMORY_ERROR;
    }
    let mut buffer = Buffer {
        data: ptr::null_mut(),
        length: 0,
        capacity: 0,
        extra,
        resize: ops.resize.unwrap(),
        release: ops.release.unwrap(),
    };
    // The stream stays at this address from initialization through end. It is
    // destroyed before buffer, even on a read, allocation or malformed-codec error.
    let mut inflater = Inflater {
        stream: unsafe { mem::zeroed() },
        ops,
        initialized: false,
    };
    let result = unsafe { ops.init.unwrap()(&mut inflater.stream, 47) };
    if result != OK {
        return result;
    }
    inflater.initialized = true;
    let result = unsafe { decompress(file, &mut buffer, &mut inflater) };
    unsafe { length.write(buffer.length) };
    if result == END {
        buffer.shrink();
        unsafe { output.write(buffer.data.cast()) };
        buffer.data = ptr::null_mut();
    }
    result
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_is_gzip(file: *mut libc::FILE, input: *const Ops) -> bool {
    let Some(ops) = (unsafe { operations(input) }) else {
        return false;
    };
    let (Some(seek), Some(read)) = (ops.seek, ops.read_raw) else {
        return false;
    };
    if file.is_null() {
        return false;
    }
    let mut magic = [0u8; 2];
    let matched = unsafe {
        seek(file, 0, libc::SEEK_SET) == 0
            && read(magic.as_mut_ptr().cast(), 1, 2, file) == 2
            && magic == [0x1f, 0x8b]
    };
    unsafe { seek(file, 0, libc::SEEK_SET) };
    matched
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_z_readfile(
    file: *mut libc::FILE,
    output: *mut *mut c_char,
    length: *mut usize,
    extra: usize,
) -> c_int {
    unsafe { zapret_engine_gzip_read(file, output, length, extra, ptr::null()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_crt_is_gzip(file: *mut libc::FILE) -> bool {
    unsafe { zapret_engine_is_gzip(file, ptr::null()) }
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Ops>() == 64);
};
