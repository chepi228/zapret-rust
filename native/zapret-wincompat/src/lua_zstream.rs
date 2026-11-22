//! Streaming Lua codec buffers, with no VM calls in a Rust frame.
use std::{
    ffi::{c_char, c_int},
    mem, ptr,
};
use zlib_rs::{ReturnCode, c_api::z_stream};
const OK: c_int = ReturnCode::Ok as c_int;
const END: c_int = ReturnCode::StreamEnd as c_int;
const STREAM_ERROR: c_int = ReturnCode::StreamError as c_int;
const MEMORY_ERROR: c_int = ReturnCode::MemError as c_int;
const BUFFER_ERROR: c_int = ReturnCode::BufError as c_int;
// The pinned LuaJIT LJ_MAX_STR/LJ_MAX_MEM32 limit, checked by the native builder.
const MAX_OUTPUT: usize = 0x7fff_ff00;

#[repr(C)]
struct Entry {
    name: *const c_char,
    minimum: i32,
    maximum: i32,
    results: i32,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_zstream_entry(inflating: bool) -> Entry {
    Entry {
        name: if inflating {
            c"gunzip_inflate"
        } else {
            c"gzip_deflate"
        }
        .as_ptr(),
        minimum: if inflating { 2 } else { 1 },
        maximum: 3,
        results: 2,
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_zstream_output_label(finalizer: bool) -> *const c_char {
    if finalizer {
        c"__gc"
    } else {
        c"zapret_zstream_output"
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_zstream_next(action: u32, inflating: bool, argc: i32, value: i64) -> u32 {
    const ARITY: u32 = 0;
    const STREAM: u32 = 1;
    const INPUT: u32 = 2;
    const COUNT: u32 = 3;
    const INPUT_OMITTED: u32 = 4;
    const HINT: u32 = 5;
    const PROCESS: u32 = 6;
    const PROCESS_WITH_HINT: u32 = 7;
    const DROP_OUTPUT: u32 = 8;
    const NIL_RESULTS: u32 = 9;
    const PUBLISH: u32 = 10;
    const DONE: u32 = 11;
    const INVALID: u32 = 12;
    match action {
        ARITY => STREAM,
        STREAM if inflating => INPUT,
        STREAM => COUNT,
        INPUT if inflating => COUNT,
        COUNT if !inflating && argc >= 2 => INPUT_OMITTED,
        INPUT_OMITTED if value == 0 => INPUT,
        COUNT | INPUT | INPUT_OMITTED if argc >= 3 => HINT,
        COUNT | INPUT | INPUT_OMITTED => PROCESS,
        HINT if value < 0 => NIL_RESULTS,
        HINT => PROCESS_WITH_HINT,
        PROCESS | PROCESS_WITH_HINT if value == i64::from(OK) => PUBLISH,
        PROCESS | PROCESS_WITH_HINT => DROP_OUTPUT,
        DROP_OUTPUT => NIL_RESULTS,
        NIL_RESULTS | PUBLISH | DONE => DONE,
        _ => INVALID,
    }
}

#[repr(C)]
struct Output {
    data: *mut u8,
    length: usize,
    capacity: usize,
    finished: bool,
}
impl Output {
    const EMPTY: Self = Self {
        data: ptr::null_mut(),
        length: 0,
        capacity: 0,
        finished: false,
    };
}
#[repr(C)]
struct Ops {
    process: Option<unsafe extern "C" fn(*mut z_stream, c_int) -> c_int>,
    before_reserve: Option<unsafe extern "C" fn(usize) -> bool>,
}
const INFLATE: Ops = Ops {
    process: Some(crate::compression::zapret_inflate),
    before_reserve: None,
};
const DEFLATE: Ops = Ops {
    process: Some(crate::compression::zapret_deflate),
    before_reserve: None,
};
struct Bindings<'a> {
    stream: &'a mut z_stream,
}
impl Drop for Bindings<'_> {
    fn drop(&mut self) {
        self.stream.next_in = ptr::null();
        self.stream.avail_in = 0;
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_out = 0;
    }
}
unsafe fn process(
    stream: &mut z_stream,
    inflating: bool,
    input: *const u8,
    length: usize,
    hint: u64,
    hinted: bool,
    ops: &Ops,
) -> Result<(Vec<u8>, bool), c_int> {
    let Some(process) = ops.process else {
        return Err(STREAM_ERROR);
    };
    if length > MAX_OUTPUT || length != 0 && input.is_null() || stream.state.is_null() {
        return Err(STREAM_ERROR);
    }
    let estimate = if hinted {
        usize::try_from(hint).map_err(|_| MEMORY_ERROR)?
    } else if inflating {
        length.saturating_mul(4).min(MAX_OUTPUT)
    } else {
        length / 2
    };
    let initial = if inflating {
        estimate
    } else {
        estimate.checked_add(64).ok_or(MEMORY_ERROR)?
    }
    .max(64);
    if initial > MAX_OUTPUT {
        return Err(MEMORY_ERROR);
    }
    let increment = (initial / 2).max(if inflating { 16384 } else { 8192 });
    let mut buffer: Vec<u8> = Vec::new();
    // Declared after buffer so the borrowed pointers clear before its deallocation.
    let io = Bindings { stream };
    io.stream.next_in = input;
    io.stream.avail_in = length as u32;
    let flush = if !inflating && length == 0 { 4 } else { 0 };
    let mut capacity = 0usize;
    loop {
        if capacity - buffer.len() < 64 && capacity < MAX_OUTPUT {
            let next = if capacity == 0 {
                initial
            } else {
                capacity
                    .saturating_add(capacity.max(increment))
                    .min(MAX_OUTPUT)
            };
            if let Some(allow) = ops.before_reserve {
                if !unsafe { allow(next) } {
                    return Err(MEMORY_ERROR);
                }
            }
            buffer
                .try_reserve_exact(next - buffer.len())
                .map_err(|_| MEMORY_ERROR)?;
            capacity = next;
        }
        let available = capacity - buffer.len();
        if available == 0 {
            return Err(MEMORY_ERROR);
        }
        let before = io.stream.avail_in;
        io.stream.next_out = unsafe { buffer.as_mut_ptr().add(buffer.len()) };
        io.stream.avail_out = available as u32;
        let result = unsafe { process(io.stream, flush) };
        if io.stream.avail_out as usize > available || io.stream.avail_in > before {
            return Err(STREAM_ERROR);
        }
        let produced = available - io.stream.avail_out as usize;
        // The codec initializes exactly the bytes it reports as produced.
        unsafe { buffer.set_len(buffer.len() + produced) };
        if result == END {
            return Ok((buffer, true));
        }
        if inflating && result == BUFFER_ERROR && io.stream.avail_in == 0 {
            return Ok((buffer, false));
        }
        if result != OK {
            return Err(result);
        }
        if !inflating && io.stream.avail_out != 0 && io.stream.avail_in == 0 && flush != 4 {
            return Ok((buffer, false));
        }
        if produced == 0 && io.stream.avail_in == before {
            return Err(BUFFER_ERROR);
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_zstream_process(
    stream: *mut z_stream,
    inflating: bool,
    input: *const u8,
    length: usize,
    hint: u64,
    hinted: bool,
    output: *mut Output,
    ops: *const Ops,
) -> c_int {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return STREAM_ERROR;
    };
    if !output.data.is_null() || output.length != 0 || output.capacity != 0 {
        return STREAM_ERROR;
    }
    let Some(stream) = (unsafe { stream.as_mut() }) else {
        return STREAM_ERROR;
    };
    let ops = if ops.is_null() {
        if inflating { &INFLATE } else { &DEFLATE }
    } else {
        unsafe { &*ops }
    };
    match unsafe { process(stream, inflating, input, length, hint, hinted, ops) } {
        Ok((mut buffer, finished)) => {
            *output = Output {
                data: buffer.as_mut_ptr(),
                length: buffer.len(),
                capacity: buffer.capacity(),
                finished,
            };
            mem::forget(buffer);
            OK
        }
        Err(error) => error,
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_zstream_release(output: *mut Output) {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return;
    };
    let previous = mem::replace(output, Output::EMPTY);
    if !previous.data.is_null() {
        drop(unsafe { Vec::from_raw_parts(previous.data, previous.length, previous.capacity) });
    }
}
#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Entry>() == 24);
    assert!(size_of::<Output>() == 32);
    assert!(mem::offset_of!(Output, finished) == 24);
    assert!(size_of::<Ops>() == 16);
};
