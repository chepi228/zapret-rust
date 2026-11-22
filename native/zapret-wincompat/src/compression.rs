//! The zlib ABI subset used by the pinned engine's gzip and Lua functions.

use std::ffi::c_int;
use zlib_rs::{
    DeflateConfig, DeflateFlush, InflateConfig, InflateFlush, Method, ReturnCode, Strategy,
    c_api::z_stream,
    deflate::{self, DeflateStream},
    inflate::{self, InflateStream},
};

const STREAM_ERROR: c_int = ReturnCode::StreamError as c_int;

// The engine owns each z_stream and passes the same initialized object to
// process and end. C creates the input/output slices for each individual call.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_inflate_init(
    stream: *mut z_stream,
    window_bits: c_int,
) -> c_int {
    let Some(stream) = (unsafe { stream.as_mut() }) else {
        return STREAM_ERROR;
    };
    inflate::init(stream, InflateConfig { window_bits }) as c_int
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_inflate(stream: *mut z_stream, flush: c_int) -> c_int {
    let Ok(flush) = InflateFlush::try_from(flush) else {
        return STREAM_ERROR;
    };
    let Some(stream) = (unsafe { InflateStream::from_stream_mut(stream) }) else {
        return STREAM_ERROR;
    };
    unsafe { inflate::inflate(stream, flush) as c_int }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_inflate_end(stream: *mut z_stream) -> c_int {
    let Some(stream) = (unsafe { InflateStream::from_stream_mut(stream) }) else {
        return STREAM_ERROR;
    };
    inflate::end(stream);
    ReturnCode::Ok as c_int
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_deflate_init(
    stream: *mut z_stream,
    level: c_int,
    method: c_int,
    window_bits: c_int,
    mem_level: c_int,
    strategy: c_int,
) -> c_int {
    let (Ok(method), Ok(strategy)) = (Method::try_from(method), Strategy::try_from(strategy))
    else {
        return STREAM_ERROR;
    };
    let Some(stream) = (unsafe { stream.as_mut() }) else {
        return STREAM_ERROR;
    };
    let config = DeflateConfig {
        level,
        method,
        window_bits,
        mem_level,
        strategy,
    };
    deflate::init(stream, config) as c_int
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_deflate(stream: *mut z_stream, flush: c_int) -> c_int {
    let Ok(flush) = DeflateFlush::try_from(flush) else {
        return STREAM_ERROR;
    };
    let Some(stream) = (unsafe { DeflateStream::from_stream_mut(stream) }) else {
        return STREAM_ERROR;
    };
    deflate::deflate(stream, flush) as c_int
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_deflate_end(stream: *mut z_stream) -> c_int {
    let Some(stream) = (unsafe { DeflateStream::from_stream_mut(stream) }) else {
        return STREAM_ERROR;
    };
    if deflate::end(stream).is_ok() {
        ReturnCode::Ok as c_int
    } else {
        ReturnCode::DataError as c_int
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<z_stream>() == 88);
    assert!(offset_of!(z_stream, next_out) == 16);
    assert!(offset_of!(z_stream, zalloc) == 48);
    assert!(offset_of!(z_stream, data_type) == 72);
};

#[cfg(all(windows, target_pointer_width = "32"))]
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<z_stream>() == 56);
    assert!(offset_of!(z_stream, next_out) == 12);
    assert!(offset_of!(z_stream, zalloc) == 32);
    assert!(offset_of!(z_stream, data_type) == 44);
};
