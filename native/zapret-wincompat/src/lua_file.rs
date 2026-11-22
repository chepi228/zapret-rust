//! Native file owners finish before C enters Lua; loader state owns no resources.
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};
type Open = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> i32;
type Probe = unsafe extern "C" fn(*mut c_void) -> bool;
type Allocate = unsafe extern "C" fn(usize) -> *mut c_void;
type Release = unsafe extern "C" fn(*mut c_void);
type Read = unsafe extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, usize) -> i32;
#[repr(C)]
struct Ops {
    open: Option<Open>,
    close: Option<Close>,
    probe: Option<Probe>,
    allocate: Option<Allocate>,
    release: Option<Release>,
    read: Option<Read>,
}
#[derive(Clone, Copy)]
struct Ready {
    open: Open,
    close: Close,
    probe: Probe,
    allocate: Allocate,
    release: Release,
    read: Read,
}
impl Ops {
    fn ready(&self) -> Option<Ready> {
        Some(Ready {
            open: self.open?,
            close: self.close?,
            probe: self.probe?,
            allocate: self.allocate?,
            release: self.release?,
            read: self.read?,
        })
    }
}
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
unsafe fn operations(pointer: *const Ops) -> Option<Ready> {
    if !aligned(pointer) {
        return None;
    }
    // SAFETY: caller keeps a valid callback table alive. These native callbacks
    // cannot call Lua or unwind, and their allocations use one matching heap.
    unsafe { (&*pointer).ready() }
}
struct File {
    raw: *mut c_void,
    close: Close,
}
impl Drop for File {
    fn drop(&mut self) {
        unsafe { (self.close)(self.raw) };
    }
}
struct Buffer {
    raw: *mut c_void,
    release: Release,
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { (self.release)(self.raw) };
        }
    }
}
unsafe fn publish_path(output: *mut c_char, capacity: usize, bytes: &[u8]) {
    if output.is_null() {
        return;
    }
    let count = bytes.len().min(capacity - 1);
    // SAFETY: output is a separate caller-owned capacity-byte span. All inputs
    // are rooted outside the callbacks, and a trailing NUL fits by validation.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast(), count);
        output.add(count).write(0);
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_file_probe(
    filename: *const c_char,
    gzip: *mut u8,
    output: *mut c_char,
    capacity: usize,
    ops: *const Ops,
) -> bool {
    if filename.is_null() || capacity > isize::MAX as usize || (output.is_null() != (capacity == 0))
    {
        return false;
    }
    let Some(io) = (unsafe { operations(ops) }) else {
        return false;
    };
    // SAFETY: filename is a caller-owned terminated string; callbacks may only
    // borrow it. The optional output spans are disjoint from it and metadata.
    let name = unsafe { CStr::from_ptr(filename) }.to_bytes();
    let first = unsafe { (io.open)(filename, c"rb".as_ptr()) };
    let raw = if first.is_null() {
        let Some(size) = name
            .len()
            .checked_add(4)
            .filter(|&size| size <= isize::MAX as usize)
        else {
            return false;
        };
        let scratch = Buffer {
            raw: unsafe { (io.allocate)(size) },
            release: io.release,
        };
        if scratch.raw.is_null() {
            return false;
        }
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), scratch.raw.cast(), name.len());
            ptr::copy_nonoverlapping(
                c".gz".to_bytes_with_nul().as_ptr(),
                scratch.raw.cast::<u8>().add(name.len()),
                4,
            );
            let expanded = std::slice::from_raw_parts(scratch.raw.cast::<u8>(), size - 1);
            publish_path(output, capacity, expanded);
            (io.open)(scratch.raw.cast(), c"rb".as_ptr())
        }
        // scratch is released here, before magic probing/close, as in C.
    } else {
        unsafe { publish_path(output, capacity, name) };
        first
    };
    if raw.is_null() {
        return false;
    }
    let file = File {
        raw,
        close: io.close,
    };
    if !gzip.is_null() {
        unsafe { gzip.write(u8::from((io.probe)(file.raw))) };
    }
    true
}
// 0 ready, 1 reopen failed, 2 decompression failed, 3 invalid native metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_file_read(
    filename: *const c_char,
    output: *mut *mut c_char,
    length: *mut usize,
    ops: *const Ops,
) -> u32 {
    if filename.is_null() || !aligned(output) || !aligned(length) {
        return 3;
    }
    let Some(io) = (unsafe { operations(ops) }) else {
        return 3;
    };
    let raw = unsafe { (io.open)(filename, c"rb".as_ptr()) };
    if raw.is_null() {
        return 1;
    }
    let file = File {
        raw,
        close: io.close,
    };
    let mut data = ptr::null_mut();
    let mut size = 0;
    let status = unsafe { (io.read)(file.raw, &mut data, &mut size, 0) };
    drop(file);
    let mut buffer = Buffer {
        raw: data.cast(),
        release: io.release,
    };
    if status != 1 {
        return 2;
    }
    if size > isize::MAX as usize || (size != 0 && data.is_null()) {
        return 3;
    }
    // SAFETY: disjoint writable outputs receive ownership only after the file
    // has closed. C frees this UCRT buffer after protected compilation returns.
    unsafe {
        output.write(data);
        length.write(size)
    };
    buffer.raw = ptr::null_mut();
    0
}
fn can_execute(status: i32) -> bool {
    status == 0
}
#[repr(C)]
#[derive(Default)]
struct Flow {
    phase: u32,
    status: i32,
}
#[repr(C)]
#[derive(Default)]
struct Feedback {
    status: i32,
    found: u32,
    gzip: u32,
}
// 0 done, 1 probe, 2 loadfile/execute, 3 read compressed, 4 loadbuffer,
// 5 release bytes, 6 execute, 7 missing, 8 reopen error, 9 unzip error, 10 invalid.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_file_step(flow: *mut Flow, feedback: *const Feedback) -> u32 {
    if !aligned(flow) || !aligned(feedback) {
        return 10;
    }
    // SAFETY: C owns disjoint fixed state and feedback; no callback occurs here.
    let (flow, value) = unsafe { (&mut *flow, &*feedback) };
    if value.found > 1 || value.gzip > 1 {
        return 10;
    }
    match flow.phase {
        0 => {
            flow.phase = 1;
            1
        }
        1 => {
            if value.found == 0 {
                flow.phase = 6;
                flow.status = 6;
                7
            } else if value.gzip == 0 {
                flow.phase = 5;
                2
            } else {
                flow.phase = 2;
                3
            }
        }
        2 => match value.status {
            0 => {
                flow.phase = 3;
                4
            }
            1 | 2 => {
                flow.phase = 6;
                flow.status = 6;
                if value.status == 1 { 8 } else { 9 }
            }
            _ => 10,
        },
        3 => {
            flow.status = value.status;
            flow.phase = 4;
            5
        }
        4 => {
            if can_execute(flow.status) {
                flow.phase = 5;
                6
            } else {
                flow.phase = 6;
                0
            }
        }
        5 => {
            flow.status = value.status;
            flow.phase = 6;
            0
        }
        6 => 0,
        _ => 10,
    }
}
const _: () = {
    assert!(size_of::<Ops>() == 6 * size_of::<usize>());
    assert!(std::mem::offset_of!(Ops, read) == 5 * size_of::<usize>());
    assert!(size_of::<Flow>() == 8);
    assert!(size_of::<Feedback>() == 12);
};
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Sample {
        trace: Vec<String>,
        opened: usize,
        success: usize,
        fail_alloc: bool,
        read_status: i32,
        live: usize,
    }
    thread_local! {static SAMPLE:RefCell<Sample>=RefCell::new(Sample::default());}
    unsafe extern "C" fn open(name: *const c_char, _mode: *const c_char) -> *mut c_void {
        SAMPLE.with(|sample| {
            let mut sample = sample.borrow_mut();
            sample.opened += 1;
            let text = unsafe { CStr::from_ptr(name) }.to_string_lossy();
            sample.trace.push(format!("open:{text}"));
            if sample.success == sample.opened {
                ptr::dangling_mut::<c_void>()
            } else {
                ptr::null_mut()
            }
        })
    }
    unsafe extern "C" fn close(_file: *mut c_void) -> i32 {
        SAMPLE.with(|sample| sample.borrow_mut().trace.push("close".into()));
        0
    }
    unsafe extern "C" fn probe(_file: *mut c_void) -> bool {
        SAMPLE.with(|sample| sample.borrow_mut().trace.push("probe".into()));
        true
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut c_void {
        SAMPLE.with(|sample| {
            let mut sample = sample.borrow_mut();
            sample.trace.push(format!("alloc:{size}"));
            if sample.fail_alloc {
                ptr::null_mut()
            } else {
                sample.live += 1;
                unsafe { libc::malloc(size) }
            }
        })
    }
    unsafe extern "C" fn release(data: *mut c_void) {
        SAMPLE.with(|sample| {
            let mut sample = sample.borrow_mut();
            sample.trace.push("free".into());
            sample.live -= 1;
        });
        unsafe { libc::free(data) };
    }
    unsafe extern "C" fn read(
        _file: *mut c_void,
        output: *mut *mut c_char,
        length: *mut usize,
        extra: usize,
    ) -> i32 {
        assert_eq!(extra, 0);
        let status = SAMPLE.with(|sample| {
            let mut sample = sample.borrow_mut();
            sample.trace.push("read".into());
            sample.read_status
        });
        if status == 1 {
            unsafe {
                output.write(allocate(4).cast());
                length.write(4)
            }
        }
        status
    }
    fn ops() -> Ops {
        Ops {
            open: Some(open),
            close: Some(close),
            probe: Some(probe),
            allocate: Some(allocate),
            release: Some(release),
            read: Some(read),
        }
    }
    fn setup(success: usize, fail_alloc: bool, read_status: i32) {
        SAMPLE.with(|s| {
            *s.borrow_mut() = Sample {
                success,
                fail_alloc,
                read_status,
                ..Default::default()
            }
        });
    }
    #[test]
    fn syntax_failure_must_not_execute_the_chunk() {
        assert!(can_execute(0));
        assert!(!can_execute(3));
    }
    #[test]
    fn fallback_frees_its_name_before_optional_magic_and_close() {
        setup(2, false, 1);
        let mut path = [0i8; 32];
        let mut gzip = 99;
        assert!(unsafe {
            zapret_lua_file_probe(
                c"test.lua".as_ptr(),
                &mut gzip,
                path.as_mut_ptr(),
                path.len(),
                &ops(),
            )
        });
        assert_eq!(gzip, 1);
        assert_eq!(unsafe { CStr::from_ptr(path.as_ptr()) }, c"test.lua.gz");
        SAMPLE.with(|s| {
            assert_eq!(
                s.borrow().trace,
                [
                    "open:test.lua",
                    "alloc:12",
                    "open:test.lua.gz",
                    "free",
                    "probe",
                    "close"
                ]
            )
        });
    }
    #[test]
    fn preflight_without_gzip_output_does_not_read_magic() {
        setup(1, false, 1);
        assert!(unsafe {
            zapret_lua_file_probe(
                c"test".as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &ops(),
            )
        });
        SAMPLE.with(|s| assert_eq!(s.borrow().trace, ["open:test", "close"]));
    }
    #[test]
    fn failed_fallback_preserves_partial_path_and_gzip_but_alloc_failure_does_not_publish() {
        let mut path = [b'X' as c_char; 8];
        let mut gzip = 99;
        setup(0, true, 1);
        assert!(!unsafe {
            zapret_lua_file_probe(
                c"test.lua".as_ptr(),
                &mut gzip,
                path.as_mut_ptr(),
                path.len(),
                &ops(),
            )
        });
        assert_eq!(path, [b'X' as c_char; 8]);
        assert_eq!(gzip, 99);
        setup(0, false, 1);
        assert!(!unsafe {
            zapret_lua_file_probe(
                c"test.lua".as_ptr(),
                &mut gzip,
                path.as_mut_ptr(),
                path.len(),
                &ops(),
            )
        });
        assert_eq!(unsafe { CStr::from_ptr(path.as_ptr()) }, c"test.lu");
        assert_eq!(gzip, 99);
        SAMPLE.with(|s| assert_eq!(s.borrow().live, 0));
    }
    #[test]
    fn prepared_bytes_are_published_after_file_close_and_failures_leave_outputs() {
        setup(1, false, 1);
        let mut data = ptr::null_mut();
        let mut size = 99;
        assert_eq!(
            unsafe { zapret_lua_file_read(c"test".as_ptr(), &mut data, &mut size, &ops()) },
            0
        );
        assert_eq!(size, 4);
        SAMPLE.with(|s| assert_eq!(s.borrow().trace, ["open:test", "read", "alloc:4", "close"]));
        unsafe { release(data.cast()) };
        setup(1, false, -3);
        data = ptr::dangling_mut();
        size = 99;
        assert_eq!(
            unsafe { zapret_lua_file_read(c"test".as_ptr(), &mut data, &mut size, &ops()) },
            2
        );
        assert_eq!(data, ptr::dangling_mut());
        assert_eq!(size, 99);
        SAMPLE.with(|s| assert_eq!(s.borrow().trace, ["open:test", "read", "close"]));
    }
    #[test]
    fn loader_releases_bytes_before_successful_call_or_compile_error() {
        for status in [0, 3, 4, 5, -1] {
            let mut state = Flow::default();
            let mut value = Feedback {
                found: 1,
                gzip: 1,
                ..Default::default()
            };
            for action in [1, 3, 4] {
                assert_eq!(unsafe { zapret_lua_file_step(&mut state, &value) }, action);
            }
            value.status = status;
            assert_eq!(unsafe { zapret_lua_file_step(&mut state, &value) }, 5);
            assert_eq!(
                unsafe { zapret_lua_file_step(&mut state, &value) },
                if status == 0 { 6 } else { 0 }
            );
            assert_eq!(unsafe { zapret_lua_file_step(&mut state, &value) }, 0);
            assert_eq!(state.status, status);
        }
    }
    #[test]
    fn loader_shortcuts_and_native_errors_keep_their_stage() {
        for (found, gzip, read_status, expected) in
            [(0, 0, 0, 7), (1, 0, 0, 2), (1, 1, 1, 8), (1, 1, 2, 9)]
        {
            let mut state = Flow::default();
            let value = Feedback {
                found,
                gzip,
                status: read_status,
            };
            assert_eq!(unsafe { zapret_lua_file_step(&mut state, &value) }, 1);
            let action = unsafe { zapret_lua_file_step(&mut state, &value) };
            if gzip == 1 {
                assert_eq!(action, 3);
                assert_eq!(
                    unsafe { zapret_lua_file_step(&mut state, &value) },
                    expected
                );
            } else {
                assert_eq!(action, expected);
            }
        }
    }
    #[test]
    fn invalid_abi_metadata_does_not_call_native_operations() {
        setup(1, false, 1);
        let mut output = [0i8; 1];
        assert!(!unsafe {
            zapret_lua_file_probe(
                c"test".as_ptr(),
                ptr::null_mut(),
                output.as_mut_ptr(),
                0,
                &ops(),
            )
        });
        assert!(!unsafe {
            zapret_lua_file_probe(
                c"test".as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        });
        assert_eq!(
            unsafe { zapret_lua_file_read(c"test".as_ptr(), ptr::null_mut(), &mut 0, &ops()) },
            3
        );
        assert_eq!(
            unsafe { zapret_lua_file_step(ptr::null_mut(), &Feedback::default()) },
            10
        );
        SAMPLE.with(|s| assert!(s.borrow().trace.is_empty()));
    }
}
