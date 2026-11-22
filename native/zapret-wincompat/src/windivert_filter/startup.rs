//! Native capture preparation before opening any interception handle.
#[cfg(windows)]
mod diagnostics;

use super::*;
use std::ffi::c_void;

#[repr(C)]
struct Target {
    output: *mut *mut c_char,
    save: *const c_char,
    hashes: *const u32,
    mutex: *mut *mut c_void,
    sources: [*const c_char; 12],
    raw: *const c_char,
    parts: *const Part,
    capacity: usize,
    index: u32,
    sub_index: u32,
    ipv4: bool,
    ipv6: bool,
    lan: bool,
    loopback: bool,
    empty: bool,
    intercept: bool,
    server: bool,
    duplicate: bool,
    dry: bool,
}
#[repr(C)]
struct MutexResult {
    handle: *mut c_void,
    error: u32,
}
#[repr(C)]
struct Ops {
    resize: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    release_clauses: Option<unsafe extern "C" fn()>,
    save: Option<unsafe extern "C" fn(*const c_char, *const u8, usize) -> u32>,
    create: Option<unsafe extern "C" fn(*const c_char) -> MutexResult>,
    close: Option<unsafe extern "C" fn(*mut c_void)>,
    report: Option<unsafe extern "C" fn(u32, usize, *const c_char)>,
}
#[repr(C)]
struct ResultCode {
    status: u32,
    error: u32,
}
fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn status(status: u32) -> ResultCode {
    ResultCode { status, error: 0 }
}
unsafe fn prepare(target: &Target, ops: &Ops) -> ResultCode {
    if !valid(target.output)
        || !valid(target.mutex)
        || target.save.is_null()
        || !(6..=65536).contains(&target.capacity)
    {
        return status(1);
    }
    let mut output = unsafe { target.output.read() };
    if output.is_null() || !unsafe { target.mutex.read() }.is_null() {
        return status(1);
    }
    let (Some(release), Some(save), Some(create), Some(close), Some(report)) = (
        ops.release_clauses,
        ops.save,
        ops.create,
        ops.close,
        ops.report,
    ) else {
        return status(1);
    };
    if target.duplicate && target.intercept && !target.dry && !valid(target.hashes) {
        return status(1);
    }
    if !target.intercept {
        unsafe { ptr::copy_nonoverlapping(c"false".as_ptr(), output, 6) };
    } else if unsafe { output.read() } == 0 {
        if target.sources.iter().any(|source| source.is_null()) || target.raw.is_null() {
            return status(1);
        }
        if [0, 2, 4, 6, 8, 9, 10, 11]
            .iter()
            .all(|&index| unsafe { target.sources[index].read() } == 0)
            && target.parts.is_null()
        {
            return status(2);
        }
        let mut bytes = Vec::<u8>::new();
        if bytes.try_reserve_exact(target.capacity).is_err() {
            return status(4);
        }
        bytes.resize(target.capacity, 0);
        let p = &target.sources;
        let filter = Filter {
            tcp_source_out: p[usize::from(target.server)],
            tcp_destination_out: p[usize::from(!target.server)],
            tcp_source_in: p[2 + usize::from(target.server)],
            tcp_destination_in: p[2 + usize::from(!target.server)],
            udp_source_in: p[4 + usize::from(target.server)],
            udp_destination_out: p[7 - usize::from(target.server)],
            icmp_out: p[8],
            icmp_in: p[9],
            ip_out: p[10],
            ip_in: p[11],
            raw: target.raw,
            parts: target.parts,
            index: target.index,
            sub_index: target.sub_index,
            flags: (u32::from(target.ipv4) * IPV4)
                | (u32::from(target.ipv6) * IPV6)
                | (u32::from(target.empty) * EMPTY_TCP)
                | (u32::from(target.lan) * EXCLUDE_LAN)
                | (u32::from(target.loopback) * EXCLUDE_LOOPBACK),
        };
        let success = unsafe {
            format_into(bytes.as_mut_ptr().cast(), bytes.len(), |buffer| {
                compile(&filter, buffer)
            })
        };
        // All clause strings have finished being read before the C allocator releases them.
        unsafe { release() };
        if !success {
            return status(3);
        }
        let length = unsafe { CStr::from_ptr(bytes.as_ptr().cast()) }
            .to_bytes_with_nul()
            .len();
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().cast(), output, length) };
        if let Some(resize) = ops.resize {
            let resized = unsafe { resize(output.cast(), length) }.cast::<c_char>();
            if !resized.is_null() {
                output = resized;
                unsafe { target.output.write(output) };
            }
        }
    }
    let data = unsafe { CStr::from_ptr(output) };
    unsafe { report(0, data.to_bytes().len(), output) };
    if unsafe { target.save.read() } != 0 {
        let error = unsafe { save(target.save, data.to_bytes().as_ptr(), data.to_bytes().len()) };
        if error != 0 {
            return ResultCode { status: 5, error };
        }
        unsafe { report(1, 0, target.save) };
        return status(8);
    }
    if target.duplicate && target.intercept && !target.dry {
        let fingerprint = unsafe {
            crate::cli_capture_options::zapret_cli_capture_hash(target.hashes.cast(), 64)
        };
        let mut digits = [0; 10];
        let digits = crate::text_buffer::decimal(fingerprint, &mut digits);
        const PREFIX: &[u8] = b"Global\\winws2_arg_";
        let mut name = [0u8; 32];
        name[..PREFIX.len()].copy_from_slice(PREFIX);
        name[PREFIX.len()..PREFIX.len() + digits.len()].copy_from_slice(digits);
        let mutex = unsafe { create(name.as_ptr().cast()) };
        if mutex.handle.is_null() {
            return ResultCode {
                status: 7,
                error: if mutex.error == 0 { 31 } else { mutex.error },
            };
        }
        if mutex.error == 183 {
            unsafe { close(mutex.handle) };
            return status(6);
        }
        unsafe { target.mutex.write(mutex.handle) };
    }
    status(0)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_capture_prepare(target: *const Target, ops: *const Ops) -> ResultCode {
    if !valid(target) || !valid(ops) {
        return status(1);
    }
    unsafe { prepare(&*target, &*ops) }
}
#[cfg(windows)]
const _: () = {
    use std::mem::offset_of;
    let pointer = size_of::<usize>();
    assert!(size_of::<Target>() == if pointer == 4 { 96 } else { 176 });
    assert!(
        offset_of!(Target, sources) == 4 * pointer && offset_of!(Target, capacity) == 18 * pointer
    );
    assert!(
        offset_of!(Target, index) == 19 * pointer && offset_of!(Target, dry) == 19 * pointer + 16
    );
    assert!(size_of::<Ops>() == 6 * pointer);
    assert!(size_of::<MutexResult>() == 2 * pointer);
    assert!(size_of::<ResultCode>() == 8);
};
