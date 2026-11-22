//! Engine file and clock exports over the shared Rust and UCRT owners.
use core::{
    ffi::{c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr,
};

const PATH_MAX: usize = 4096;
const CLOCK_MONOTONIC: c_int = 1;

#[repr(C)]
pub(super) struct Timespec {
    seconds: i64,
    nanoseconds: i32,
}

#[repr(C)]
pub(super) struct FileStamp {
    modified: Timespec,
    size: i64,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(size_of::<FileStamp>() == 24);
};

unsafe extern "C" {
    pub(super) fn clock_gettime(clock: c_int, output: *mut Timespec) -> c_int;
    fn zapret_boot_time(status: c_int, time: *const Timespec, milliseconds: bool) -> u64;
    fn zapret_engine_read(
        fd: c_int,
        output: *mut c_void,
        count: usize,
        ops: *const c_void,
    ) -> isize;
    fn zapret_engine_fread(
        output: *mut c_void,
        size: usize,
        count: usize,
        stream: *mut c_void,
        read: *mut usize,
        ops: *const c_void,
    ) -> bool;
    fn zapret_engine_fgets(
        output: *mut c_char,
        capacity: c_int,
        stream: *mut c_void,
        ops: *const c_void,
    ) -> *mut c_char;
    fn zapret_engine_crypto_random(output: *mut u8, count: usize) -> bool;
    fn zapret_engine_load_file(
        filename: *const c_char,
        offset: i64,
        output: *mut c_void,
        size: *mut usize,
    ) -> u32;
    fn zapret_engine_save_file(filename: *const c_char, bytes: *const u8, size: usize) -> u32;
    fn zapret_engine_append_line(filename: *const c_char, text: *const c_char) -> u32;
    fn zapret_engine_file_size(filename: *const c_char, size: *mut i64) -> u32;
    fn zapret_engine_file_stamp(filename: *const c_char, stamp: *mut FileStamp) -> u32;
    fn zapret_engine_file_probe(filename: *const c_char, flags: c_int) -> u32;
    fn zapret_engine_set_exedir() -> u32;
    fn zapret_engine_realpath(filename: *const c_char, output: *mut c_char, capacity: usize)
    -> u32;
    fn wf_error(error: u32);
    fn wf_state_result(error: u32) -> bool;
}

fn monotonic(milliseconds: bool) -> u64 {
    let mut time = MaybeUninit::<Timespec>::uninit();
    let status = unsafe { clock_gettime(CLOCK_MONOTONIC, time.as_mut_ptr()) };
    unsafe { zapret_boot_time(status, time.as_ptr(), milliseconds) }
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn boottime() -> i64 {
    monotonic(false) as i64
}

#[unsafe(no_mangle)]
extern "C" fn boottime_ms() -> u64 {
    monotonic(true)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn read_intr(fd: c_int, output: *mut c_void, count: usize) -> isize {
    unsafe { zapret_engine_read(fd, output, count, ptr::null()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn fread_safe(
    output: *mut c_void,
    size: usize,
    count: usize,
    file: *mut c_void,
    read: *mut usize,
) -> bool {
    unsafe { zapret_engine_fread(output, size, count, file, read, ptr::null()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn fgets_safe(
    output: *mut c_char,
    capacity: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    unsafe { zapret_engine_fgets(output, capacity, stream, ptr::null()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn fill_crypto_random_bytes(output: *mut u8, size: usize) -> bool {
    unsafe { zapret_engine_crypto_random(output, size) }
}

fn file_result(error: u32) -> bool {
    if error == 0 {
        true
    } else {
        unsafe { wf_error(error) };
        false
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn load_file(
    filename: *const c_char,
    offset: i64,
    output: *mut c_void,
    size: *mut usize,
) -> bool {
    file_result(unsafe { zapret_engine_load_file(filename, offset, output, size) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn save_file(filename: *const c_char, data: *const u8, size: usize) -> bool {
    file_result(unsafe { zapret_engine_save_file(filename, data, size) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn append_to_list_file(filename: *const c_char, text: *const c_char) -> bool {
    file_result(unsafe { zapret_engine_append_line(filename, text) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn file_size(filename: *const c_char, size: *mut i64) -> bool {
    unsafe { wf_state_result(zapret_engine_file_size(filename, size)) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn file_mod_signature(
    filename: *const c_char,
    stamp: *mut FileStamp,
) -> bool {
    unsafe { wf_state_result(zapret_engine_file_stamp(filename, stamp)) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn file_open_test(filename: *const c_char, flags: c_int) -> bool {
    unsafe { wf_state_result(zapret_engine_file_probe(filename, flags)) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn set_env_exedir(_argv0: *const c_char) -> bool {
    unsafe { wf_state_result(zapret_engine_set_exedir()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn realpath_any(filename: *const c_char, output: *mut c_char) -> bool {
    unsafe { wf_state_result(zapret_engine_realpath(filename, output, PATH_MAX)) }
}
