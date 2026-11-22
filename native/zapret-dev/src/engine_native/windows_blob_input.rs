//! Bind the local blob readers to the Windows engine allocator and logs.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
};

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

#[repr(C)]
pub struct Blob {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct BlobHead {
    first: *mut Blob,
}

#[repr(C)]
struct Params {
    _prefix: [MaybeUninit<u8>; PARAMS.blobs],
    blobs: BlobHead,
}

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}

#[repr(C)]
struct Logs {
    debug: Log,
    error: Log,
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<BlobHead>() == pointer && offset_of!(BlobHead, first) == 0);
    assert!(offset_of!(Params, blobs) == PARAMS.blobs);
    assert!(size_of::<Allocator>() == 2 * pointer && size_of::<Logs>() == 2 * pointer);
};

unsafe extern "C" {
    static mut params: Params;

    fn malloc(size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;

    fn zapret_blob_read_fixed(
        argument: *const c_char,
        buffer: *mut c_void,
        size: *mut usize,
        logs: &Logs,
    ) -> bool;
    fn zapret_blob_read_named(
        head: *mut BlobHead,
        argument: *const c_char,
        maximum: usize,
        reserve: usize,
        allocator: &Allocator,
        logs: &Logs,
    ) -> *mut Blob;
    fn zapret_blob_read_const(
        head: *mut BlobHead,
        name: *const c_char,
        data: *const c_void,
        size: usize,
        reserve: usize,
        allocator: &Allocator,
        logs: &Logs,
    ) -> *mut Blob;
}

const ALLOCATOR: Allocator = Allocator {
    allocate: malloc,
    release: free,
};
const LOGS: Logs = Logs {
    debug: DLOG,
    error: DLOG_ERR,
};

/// # Safety
/// The argument is terminated and `buffer` has the writable capacity in `size`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_native_blob_read_fixed(
    argument: *const c_char,
    buffer: *mut c_void,
    size: *mut usize,
) -> bool {
    unsafe { zapret_blob_read_fixed(argument, buffer, size, &LOGS) }
}

/// # Safety
/// The head is writable engine list storage and the argument is terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_native_blob_read_named(
    head: *mut BlobHead,
    argument: *const c_char,
    maximum: usize,
    reserve: usize,
) -> *mut Blob {
    unsafe { zapret_blob_read_named(head, argument, maximum, reserve, &ALLOCATOR, &LOGS) }
}

/// # Safety
/// The blob head is writable, the name is terminated and `data` holds `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_publish_const_blob(
    head: *mut c_void,
    name: *const c_char,
    data: *const c_void,
    size: usize,
    reserve: usize,
) -> *mut Blob {
    unsafe { zapret_blob_read_const(head.cast(), name, data, size, reserve, &ALLOCATOR, &LOGS) }
}

/// # Safety
/// The argument remains valid during parsing on the engine's startup thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_native_cli_read_blob(
    argument: *const c_char,
    maximum: usize,
    reserve: usize,
) -> bool {
    !unsafe { zapret_native_blob_read_named(&raw mut params.blobs, argument, maximum, reserve) }
        .is_null()
}
