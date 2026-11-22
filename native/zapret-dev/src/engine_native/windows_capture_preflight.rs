//! Bind the filter compiler and argument mutex to the live Windows CLI.
use super::{CaptureCli, CaptureResult, c_char, c_int, c_void, params};
use core::ptr;

type Handle = *mut c_void;

#[repr(C)]
struct Target {
    output: *mut *mut c_char,
    save: *const c_char,
    hashes: *const u32,
    mutex: *mut Handle,
    sources: [*const c_char; 12],
    raw: *const c_char,
    parts: *const c_void,
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
    handle: Handle,
    error: u32,
}

#[repr(C)]
struct Ops {
    resize: unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void,
    release_clauses: unsafe extern "C" fn(),
    save: unsafe extern "C" fn(*const c_char, *const u8, usize) -> u32,
    create: unsafe extern "C" fn(*const c_char) -> MutexResult,
    close: unsafe extern "C" fn(Handle),
    report: unsafe extern "C" fn(u32, usize, *const c_char),
}

const _: () = {
    use core::mem::offset_of;
    let pointer = size_of::<Handle>();
    assert!(size_of::<Target>() == if pointer == 4 { 96 } else { 176 });
    assert!(
        offset_of!(Target, sources) == 4 * pointer && offset_of!(Target, capacity) == 18 * pointer
    );
    assert!(
        offset_of!(Target, index) == 19 * pointer && offset_of!(Target, dry) == 19 * pointer + 16
    );
    assert!(size_of::<Ops>() == 6 * pointer);
    assert!(size_of::<MutexResult>() == 2 * pointer);
};

unsafe extern "C" {
    fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    fn cleanup_windivert_portfilters(settings: *mut c_void);
    fn zapret_engine_capture_capacity() -> usize;
    fn zapret_engine_save_file(path: *const c_char, bytes: *const u8, length: usize) -> u32;
    fn zapret_capture_prepare(target: *const Target, ops: *const Ops) -> CaptureResult;
    fn native_capture_prepare_report(event: u32, size: usize, text: *const c_char);
    fn native_capture_prepare_status(status: u32, error: u32, save: *const c_char);
}

unsafe extern "system" {
    fn CreateMutexA(attributes: *const c_void, owner: c_int, name: *const c_char) -> Handle;
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn CloseHandle(handle: Handle) -> c_int;
}

unsafe extern "C" fn release_clauses() {
    unsafe { cleanup_windivert_portfilters((&raw mut params).cast()) };
}

unsafe extern "C" fn create(name: *const c_char) -> MutexResult {
    unsafe {
        SetLastError(0);
        let handle = CreateMutexA(ptr::null(), 1, name);
        MutexResult {
            handle,
            error: GetLastError(),
        }
    }
}

unsafe extern "C" fn close(handle: Handle) {
    unsafe { CloseHandle(handle) };
}

const OPS: Ops = Ops {
    resize: realloc,
    release_clauses,
    save: zapret_engine_save_file,
    create,
    close,
    report: native_capture_prepare_report,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_capture_prepare(
    capture: *const CaptureCli,
    dry: bool,
    mutex: *mut Handle,
) -> CaptureResult {
    let settings = &raw mut params;
    let target = unsafe {
        let capture = &*capture;
        Target {
            output: &raw mut (*settings).windivert_filter,
            save: capture.save,
            hashes: capture.hashes,
            mutex,
            sources: [
                (*settings).wf_pf_tcp_src_out,
                (*settings).wf_pf_tcp_dst_out,
                (*settings).wf_pf_tcp_src_in,
                (*settings).wf_pf_tcp_dst_in,
                (*settings).wf_pf_udp_src_in,
                (*settings).wf_pf_udp_dst_in,
                (*settings).wf_pf_udp_src_out,
                (*settings).wf_pf_udp_dst_out,
                (*settings).wf_icf_out,
                (*settings).wf_icf_in,
                (*settings).wf_ipf_out,
                (*settings).wf_ipf_in,
            ]
            .map(|source| source.cast_const()),
            raw: (*settings).wf_raw_filter,
            parts: (*settings).wf_raw_part,
            capacity: zapret_engine_capture_capacity(),
            index: capture.index.read(),
            sub_index: capture.sub_index.read(),
            ipv4: capture.ipv4.read(),
            ipv6: capture.ipv6.read(),
            lan: capture.lan.read(),
            loopback: capture.loopback.read(),
            empty: capture.empty.read(),
            intercept: (*settings).intercept,
            server: (*settings).server,
            duplicate: capture.duplicate.read(),
            dry,
        }
    };
    let result = unsafe { zapret_capture_prepare(&target, &OPS) };
    unsafe { native_capture_prepare_status(result.status, result.error, target.save) };
    result
}
