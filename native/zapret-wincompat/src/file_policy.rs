//! Compatibility and ownership policy for the native UCRT file facade.
mod ucrt;
pub(super) use ucrt::wf_error;

use crate::files::FileMetadata as Metadata;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Flags {
    append: c_int,
    text: c_int,
    binary: c_int,
    noinherit: c_int,
    rdwr: c_int,
    rdonly: c_int,
    wronly: c_int,
    create: c_int,
    truncate: c_int,
    exclusive: c_int,
    directory: c_int,
    regular: c_int,
}
#[derive(Debug, Eq, PartialEq)]
struct Mode {
    flags: c_int,
    canonical: [u16; 4],
}
fn mode_plan(input: Option<&[u8]>, native: &Flags) -> Option<Mode> {
    let input = input?;
    let input = &input[..input.iter().position(|&b| b == 0).unwrap_or(input.len())];
    let first = *input.first()?;
    if !b"rwa".contains(&first) {
        return None;
    }
    let update = input.contains(&b'+');
    let text = input.contains(&b't') && !input.contains(&b'b');
    let mut flags = if update {
        native.rdwr
    } else if first == b'r' {
        native.rdonly
    } else {
        native.wronly
    };
    if first == b'w' {
        flags |= native.create | native.truncate;
    }
    if first == b'a' {
        flags |= native.create | native.append;
    }
    if first != b'r' && input.contains(&b'x') {
        flags |= native.exclusive;
    }
    if input.contains(&b'e') {
        flags |= native.noinherit;
    }
    flags |= if text { native.text } else { native.binary };
    Some(Mode {
        flags,
        canonical: [
            first as u16,
            if text { 116 } else { 98 },
            if update { 43 } else { 0 },
            0,
        ],
    })
}
fn error_class(error: u32) -> u32 {
    match error {
        2 | 3 | 15 => 1,
        5 | 1314 | 32 | 33 => 2,
        183 | 80 => 3,
        17 => 4,
        267 => 5,
        145 => 6,
        112 | 39 => 7,
        8 | 14 => 8,
        206 => 9,
        1113 => 10,
        123 | 87 => 11,
        _ => 0,
    }
}
fn binary_flags(flags: c_int, native: &Flags) -> c_int {
    if flags & native.text == 0 {
        flags | native.binary
    } else {
        flags
    }
}

type Allocate = unsafe extern "C" fn(usize) -> *mut c_void;
type PathText = unsafe extern "C" fn(*const c_char, Allocate, *mut *mut u8) -> u32;
type Text = unsafe extern "C" fn(Allocate, *mut *mut u8) -> u32;

#[repr(C)]
struct FileIo {
    allocate: Allocate,
    realpath: unsafe extern "C" fn(*const c_char, c_int, Allocate, *mut *mut u8) -> u32,
    stat: unsafe extern "C" fn(*const c_char, *mut Metadata) -> u32,
    exedir: Text,
    getenv: PathText,
    setenv: unsafe extern "C" fn(*const c_char, *const c_char) -> u32,
    open: unsafe extern "C" fn(*const c_char, c_int, c_int, *mut *mut c_void) -> u32,
    getcwd: Text,
    path: unsafe extern "C" fn(*const c_char, Allocate, *mut *mut u16) -> u32,
    utf8: unsafe extern "C" fn(*const u16, Allocate, *mut *mut u8) -> u32,
    allocate_zeroed: unsafe extern "C" fn(usize, usize) -> *mut c_void,
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_void),
    compare_names: unsafe extern "C" fn(*const c_char, *const c_char) -> c_int,
    lock_environment: unsafe extern "C" fn(bool),
    read_errno: unsafe extern "C" fn() -> c_int,
    write_errno: unsafe extern "C" fn(c_int),
    report_error: unsafe extern "C" fn(u32),
    descriptor: unsafe extern "C" fn(isize, c_int) -> c_int,
    close_handle: unsafe extern "system" fn(*mut c_void) -> c_int,
    fdopen: unsafe extern "C" fn(c_int, *const u16) -> *mut libc::FILE,
    close_descriptor: unsafe extern "C" fn(c_int) -> c_int,
    publish_stat: unsafe extern "C" fn(*mut c_void, *const Metadata, u32),
    write_errno_class: unsafe extern "C" fn(u32),
    chdir: unsafe extern "C" fn(*const u16) -> c_int,
}

#[repr(C)]
struct Environment {
    next: *mut Environment,
    name: *mut c_char,
    value: *mut c_char,
}
// Every native callback is non-VM and non-throwing. It observes/copies only during
// its call. A callback never retains a Rust reference or borrowed stack buffer.
fn status(error: usize, native: impl Fn(u32, usize, usize, usize, usize) -> usize) -> isize {
    if error == 0 {
        0
    } else {
        native(16, error, 0, 0, 0);
        -1
    }
}
unsafe fn environment_read(
    name: usize,
    root: usize,
    native: impl Fn(u32, usize, usize, usize, usize) -> usize + Copy,
) -> usize {
    unsafe {
        let mut value = 0usize;
        let error = native(4, name, ptr::addr_of_mut!(value) as usize, 0, 0);
        if error == 203 || status(error, native) != 0 {
            return 0;
        }
        native(13, 1, 0, 0, 0);
        let root = root as *mut *mut Environment;
        let mut entry = root.read();
        while !entry.is_null() && native(12, (*entry).name as usize, name, 0, 0) != 0 {
            entry = (*entry).next;
        }
        if entry.is_null() {
            entry = native(9, 1, size_of::<Environment>(), 0, 0) as *mut Environment;
            if !entry.is_null() {
                (*entry).name = native(10, name, 0, 0, 0) as *mut c_char;
            }
            if entry.is_null() || (*entry).name.is_null() {
                native(11, entry as usize, 0, 0, 0);
                native(11, value, 0, 0, 0);
                native(13, 0, 0, 0, 0);
                native(16, 8, 0, 0, 0);
                return 0;
            }
            (*entry).next = root.read();
            root.write(entry);
        }
        if !(*entry).value.is_null()
            && CStr::from_ptr((*entry).value) == CStr::from_ptr(value as *const c_char)
        {
            native(11, value, 0, 0, 0);
        } else {
            native(11, (*entry).value as usize, 0, 0, 0);
            (*entry).value = value as *mut c_char;
        }
        let result = (*entry).value as usize;
        native(13, 0, 0, 0, 0);
        result
    }
}
unsafe fn environment_write(
    name: usize,
    value: usize,
    overwrite: usize,
    root: usize,
    native: impl Fn(u32, usize, usize, usize, usize) -> usize + Copy,
) -> isize {
    unsafe {
        if name == 0
            || value == 0
            || CStr::from_ptr(name as *const c_char).to_bytes().is_empty()
            || CStr::from_ptr(name as *const c_char)
                .to_bytes()
                .contains(&b'=')
        {
            native(16, 87, 0, 0, 0);
            return -1;
        }
        if overwrite == 0 && environment_read(name, root, native) != 0 {
            return 0;
        }
        status(native(5, name, value, 0, 0), native)
    }
}
fn descriptor(
    path: usize,
    flags: c_int,
    mode: c_int,
    native: &Flags,
    call: impl Fn(u32, usize, usize, usize, usize) -> usize + Copy,
) -> isize {
    let mut handle = 0usize;
    if status(
        call(
            6,
            path,
            flags as usize,
            mode as usize,
            ptr::addr_of_mut!(handle) as usize,
        ),
        call,
    ) != 0
    {
        return -1;
    }
    let mask = native.append | native.text | native.binary | native.noinherit;
    let result = call(17, handle, (flags & mask) as usize, 0, 0) as isize;
    if result < 0 {
        let error = call(14, 0, 0, 0, 0);
        call(18, handle, 0, 0, 0);
        call(15, error, 0, 0, 0);
    }
    result
}
unsafe fn facade(
    entry: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    flags: &Flags,
    native: impl Fn(u32, usize, usize, usize, usize) -> usize + Copy,
) -> usize {
    unsafe {
        match entry {
            0 => status(a, native) as usize,
            1 => {
                let mut result = 0usize;
                if status(
                    native(1, a, c, ptr::addr_of_mut!(result) as usize, 0),
                    native,
                ) != 0
                {
                    return 0;
                }
                if b == 0 {
                    return result;
                }
                let size = CStr::from_ptr(result as *const c_char)
                    .to_bytes_with_nul()
                    .len();
                if size > 4096 {
                    native(11, result, 0, 0, 0);
                    native(16, 206, 0, 0, 0);
                    return 0;
                }
                ptr::copy_nonoverlapping(result as *const u8, b as *mut u8, size);
                native(11, result, 0, 0, 0);
                b
            }
            2 => {
                let mut raw = Metadata::default();
                let error = native(2, a, ptr::addr_of_mut!(raw) as usize, 0, 0);
                if error == 534 {
                    native(22, 12, 0, 0, 0);
                    return (-1isize) as usize;
                }
                if status(error, native) != 0 {
                    return (-1isize) as usize;
                }
                let mode = if raw.directory != 0 {
                    flags.directory
                } else {
                    flags.regular
                };
                native(21, b, ptr::addr_of!(raw) as usize, mode as usize, 0);
                0
            }
            3 => {
                let mut result = 0usize;
                if status(
                    native(3, ptr::addr_of_mut!(result) as usize, 0, 0, 0),
                    native,
                ) != 0
                {
                    return 0;
                }
                let ok = environment_write(c"EXEDIR".as_ptr() as usize, result, 1, a, native) == 0;
                native(11, result, 0, 0, 0);
                usize::from(ok)
            }
            4 => environment_read(a, b, native),
            5 => environment_write(a, b, c, d, native) as usize,
            6 => {
                let input = if b == 0 {
                    None
                } else {
                    Some(CStr::from_ptr(b as *const c_char).to_bytes())
                };
                let Some(plan) = mode_plan(input, flags) else {
                    native(22, 11, 0, 0, 0);
                    return 0;
                };
                // The caller supplies native create permission bits; they are
                // not reconstructed as Rust/Linux libc constants.
                let fd = descriptor(a, plan.flags, c as c_int, flags, native);
                if fd < 0 {
                    return 0;
                }
                let file = native(19, fd as usize, plan.canonical.as_ptr() as usize, 0, 0);
                if file == 0 {
                    let error = native(14, 0, 0, 0, 0);
                    native(20, fd as usize, 0, 0, 0);
                    native(15, error, 0, 0, 0);
                }
                file
            }
            7 => descriptor(
                a,
                binary_flags(b as c_int, flags),
                c as c_int,
                flags,
                native,
            ) as usize,
            8 => {
                let mut result = 0usize;
                if status(
                    native(7, ptr::addr_of_mut!(result) as usize, 0, 0, 0),
                    native,
                ) != 0
                {
                    return 0;
                }
                if a == 0 {
                    return result;
                }
                let size = CStr::from_ptr(result as *const c_char)
                    .to_bytes_with_nul()
                    .len();
                if size > b {
                    native(11, result, 0, 0, 0);
                    native(22, 13, 0, 0, 0);
                    return 0;
                }
                ptr::copy_nonoverlapping(result as *const u8, a as *mut u8, size);
                native(11, result, 0, 0, 0);
                a
            }
            9 => {
                if a == 0 {
                    1
                } else {
                    if a == 534 {
                        native(22, 12, 0, 0, 0);
                    } else {
                        native(16, a, 0, 0, 0);
                    }
                    0
                }
            }
            10..=12 => {
                let mut result = 0usize;
                status(
                    native(
                        if entry == 11 { 24 } else { 23 },
                        a,
                        ptr::addr_of_mut!(result) as usize,
                        0,
                        0,
                    ),
                    native,
                );
                if entry != 12 {
                    return result;
                }
                if result == 0 {
                    return (-1isize) as usize;
                }
                let changed = native(25, result, 0, 0, 0);
                native(11, result, 0, 0, 0);
                changed
            }
            _ => 0,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_file_facade(
    entry: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    flags: &Flags,
    io: &FileIo,
) -> usize {
    // The native table supplies individual operations and uses the caller's CRT.
    let call = |op, a: usize, b: usize, c: usize, d: usize| unsafe {
        match op {
            1 => (io.realpath)(
                a as *const c_char,
                b as c_int,
                io.allocate,
                c as *mut *mut u8,
            ) as usize,
            2 => (io.stat)(a as *const c_char, b as *mut Metadata) as usize,
            3 => (io.exedir)(io.allocate, a as *mut *mut u8) as usize,
            4 => (io.getenv)(a as *const c_char, io.allocate, b as *mut *mut u8) as usize,
            5 => (io.setenv)(a as *const c_char, b as *const c_char) as usize,
            6 => (io.open)(
                a as *const c_char,
                b as c_int,
                c as c_int,
                d as *mut *mut c_void,
            ) as usize,
            7 => (io.getcwd)(io.allocate, a as *mut *mut u8) as usize,
            9 => (io.allocate_zeroed)(a, b) as usize,
            10 => (io.duplicate)(a as *const c_char) as usize,
            11 => {
                (io.release)(a as *mut c_void);
                0
            }
            12 => (io.compare_names)(a as *const c_char, b as *const c_char) as usize,
            13 => {
                (io.lock_environment)(a != 0);
                0
            }
            14 => (io.read_errno)() as usize,
            15 => {
                (io.write_errno)(a as c_int);
                0
            }
            16 => {
                (io.report_error)(a as u32);
                0
            }
            17 => (io.descriptor)(a as isize, b as c_int) as usize,
            18 => {
                (io.close_handle)(a as *mut c_void);
                0
            }
            19 => (io.fdopen)(a as c_int, b as *const u16) as usize,
            20 => (io.close_descriptor)(a as c_int) as usize,
            21 => {
                (io.publish_stat)(a as *mut c_void, b as *const Metadata, c as u32);
                0
            }
            22 => {
                (io.write_errno_class)(a as u32);
                0
            }
            23 => (io.path)(a as *const c_char, io.allocate, b as *mut *mut u16) as usize,
            24 => (io.utf8)(a as *const u16, io.allocate, b as *mut *mut u8) as usize,
            25 => (io.chdir)(a as *const u16) as usize,
            _ => 0,
        }
    };
    unsafe { facade(entry, a, b, c, d, flags, call) }
}
#[unsafe(no_mangle)]
extern "C" fn zapret_file_error_class(error: u32) -> u32 {
    error_class(error)
}
#[unsafe(no_mangle)]
extern "C" fn zapret_file_open_mode_needed(flags: c_int, native: &Flags) -> bool {
    flags & native.create != 0
}

const _: () = {
    assert!(size_of::<Flags>() == 48);
    assert!(size_of::<Metadata>() == 40);
    assert!(size_of::<FileIo>() == 25 * size_of::<Allocate>());
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        cell::RefCell,
        collections::BTreeMap,
        ffi::CString,
    };
    const FLAGS: Flags = Flags {
        append: 8,
        text: 0x4000,
        binary: 0x8000,
        noinherit: 0x80,
        rdwr: 2,
        rdonly: 0,
        wronly: 1,
        create: 0x100,
        truncate: 0x200,
        exclusive: 0x400,
        directory: 0x4000,
        regular: 0x8000,
    };

    #[test]
    fn compatible_modes_keep_binary_precedence_and_extensions() {
        for (input, flags, canonical) in [
            (&b"rbt+xe"[..], 0x8082, [114, 98, 43, 0]),
            (&b"wtexe"[..], 0x4781, [119, 116, 0, 0]),
            (&b"aunknown"[..], 0x8109, [97, 98, 0, 0]),
            (&b"r+unknown"[..], 0x8002, [114, 98, 43, 0]),
            (&b"rt\0be+"[..], 0x4000, [114, 116, 0, 0]),
        ] {
            assert_eq!(
                mode_plan(Some(input), &FLAGS),
                Some(Mode { flags, canonical })
            );
        }
    }
    #[test]
    fn invalid_modes_fail_before_any_native_open() {
        for input in [
            None,
            Some(&b""[..]),
            Some(&b"\0r"[..]),
            Some(&b"br"[..]),
            Some(&b"R"[..]),
        ] {
            assert_eq!(mode_plan(input, &FLAGS), None);
        }
    }
    #[test]
    fn native_error_groups_keep_fallback_and_overflow_separate() {
        for (native, class) in [
            (2, 1),
            (3, 1),
            (15, 1),
            (5, 2),
            (1314, 2),
            (32, 2),
            (33, 2),
            (183, 3),
            (80, 3),
            (17, 4),
            (267, 5),
            (145, 6),
            (112, 7),
            (39, 7),
            (8, 8),
            (14, 8),
            (206, 9),
            (1113, 10),
            (123, 11),
            (87, 11),
            (534, 0),
            (0, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(error_class(native), class, "native error {native}");
        }
    }
    #[test]
    fn open_defaults_binary_only_without_explicit_text() {
        assert_eq!(binary_flags(0x100, &FLAGS), 0x8100);
        assert_eq!(binary_flags(0x4100, &FLAGS), 0x4100);
        assert_eq!(binary_flags(0xc100, &FLAGS), 0xc100);
    }
    struct Fixture {
        text: CString,
        status: usize,
        errno: usize,
        trace: Vec<u32>,
        allocations: BTreeMap<usize, Layout>,
        attempts: usize,
        fail_at: usize,
        descriptor: isize,
        file: usize,
        opened_flags: usize,
        canonical: Vec<u16>,
    }
    impl Default for Fixture {
        fn default() -> Self {
            Self {
                text: c"abc".to_owned(),
                status: 0,
                errno: 88,
                trace: Vec::new(),
                allocations: BTreeMap::new(),
                attempts: 0,
                fail_at: 0,
                descriptor: 7,
                file: 1,
                opened_flags: 0,
                canonical: Vec::new(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for (p, l) in &self.allocations {
                unsafe { dealloc(*p as *mut u8, *l) };
            }
        }
    }
    impl Fixture {
        fn allocate(&mut self, size: usize) -> usize {
            self.attempts += 1;
            if self.attempts == self.fail_at {
                return 0;
            }
            let l = Layout::from_size_align(size.max(1), 8).unwrap();
            let p = unsafe { alloc_zeroed(l) };
            self.allocations.insert(p as usize, l);
            p as usize
        }
        fn duplicate(&mut self, bytes: &[u8]) -> usize {
            let p = self.allocate(bytes.len());
            if p != 0 {
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len()) };
            }
            p
        }
    }
    thread_local! { static FIX: RefCell<Fixture> = RefCell::new(Fixture::default()); }
    fn reset() {
        FIX.with(|f| *f.borrow_mut() = Fixture::default());
    }
    fn native(op: u32, a: usize, b: usize, c: usize, d: usize) -> usize {
        FIX.with(|f| {
            let mut f = f.borrow_mut();
            f.trace.push(op);
            match op {
                1 | 3 | 4 | 7 | 23 | 24 => {
                    if f.status != 0 {
                        return f.status;
                    }
                    let text = f.text.as_bytes_with_nul().to_vec();
                    let p = f.duplicate(&text);
                    let out = match op {
                        1 => c,
                        4 => b,
                        23 | 24 => b,
                        _ => a,
                    };
                    unsafe { (out as *mut usize).write(p) };
                    if p == 0 { 8 } else { 0 }
                }
                2 => f.status,
                5 => 0,
                6 => {
                    f.opened_flags = b;
                    unsafe { (d as *mut usize).write(123) };
                    f.status
                }
                9 => f.allocate(b),
                10 => {
                    let text = unsafe { CStr::from_ptr(a as *const c_char) }.to_bytes_with_nul();
                    f.duplicate(text)
                }
                11 => {
                    if let Some(l) = f.allocations.remove(&a) {
                        unsafe { dealloc(a as *mut u8, l) }
                    };
                    0
                }
                12 => {
                    let a = unsafe { CStr::from_ptr(a as *const c_char) }.to_bytes();
                    let b = unsafe { CStr::from_ptr(b as *const c_char) }.to_bytes();
                    usize::from(!a.eq_ignore_ascii_case(b))
                }
                13 => 0,
                14 => f.errno,
                15 => {
                    f.errno = a;
                    0
                }
                16 => {
                    f.errno = a;
                    0
                }
                17 => f.descriptor as usize,
                18 | 20 => {
                    f.errno = 999;
                    0
                }
                19 => {
                    f.canonical =
                        unsafe { std::slice::from_raw_parts(b as *const u16, 4) }.to_vec();
                    f.file
                }
                21 => 0,
                22 => {
                    f.errno = 1000 + a;
                    0
                }
                _ => panic!("unexpected native operation {op}"),
            }
        })
    }
    #[test]
    fn cwd_rejects_nul_overflow_without_touching_caller_bytes() {
        reset();
        let mut output = [0x69u8; 8];
        let result = unsafe { facade(8, output.as_mut_ptr() as usize, 3, 0, 0, &FLAGS, native) };
        assert_eq!(result, 0);
        assert_eq!(output, [0x69; 8]);
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.errno, 1013);
            assert_eq!(f.trace, [7, 11, 22]);
        });
        reset();
        let result = unsafe { facade(8, output.as_mut_ptr() as usize, 4, 0, 0, &FLAGS, native) };
        assert_eq!(result, output.as_mut_ptr() as usize);
        assert_eq!(&output[..5], b"abc\0i");
    }
    #[test]
    fn descriptor_failure_closes_handle_and_restores_original_errno() {
        reset();
        FIX.with(|f| f.borrow_mut().descriptor = -1);
        let result = unsafe { facade(7, c"name".as_ptr() as usize, 0x100, 0, 0, &FLAGS, native) };
        assert_eq!(result as isize, -1);
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.errno, 88);
            assert_eq!(f.opened_flags, 0x8100);
            assert_eq!(f.trace, [6, 17, 14, 18, 15]);
        });
    }
    #[test]
    fn fdopen_failure_closes_descriptor_after_canonical_mode() {
        reset();
        FIX.with(|f| f.borrow_mut().file = 0);
        assert_eq!(
            unsafe {
                facade(
                    6,
                    c"name".as_ptr() as usize,
                    c"wtx".as_ptr() as usize,
                    0,
                    0,
                    &FLAGS,
                    native,
                )
            },
            0
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.opened_flags, 0x4701);
            assert_eq!(f.canonical, [119, 116, 0, 0]);
            assert_eq!(f.errno, 88);
            assert_eq!(f.trace, [6, 17, 19, 14, 20, 15]);
        });
    }
    #[test]
    fn environment_reuses_case_insensitive_unchanged_value_and_replaces_late() {
        reset();
        let mut root = ptr::null_mut::<Environment>();
        let root_ptr = ptr::addr_of_mut!(root) as usize;
        let first = unsafe { facade(4, c"foo".as_ptr() as usize, root_ptr, 0, 0, &FLAGS, native) };
        assert_ne!(first, 0);
        assert_eq!(
            unsafe { facade(4, c"FOO".as_ptr() as usize, root_ptr, 0, 0, &FLAGS, native) },
            first
        );
        FIX.with(|f| f.borrow_mut().text = c"changed".to_owned());
        let changed =
            unsafe { facade(4, c"foo".as_ptr() as usize, root_ptr, 0, 0, &FLAGS, native) };
        assert_ne!(changed, first);
        assert_eq!(
            unsafe { CStr::from_ptr(changed as *const c_char) },
            c"changed"
        );
        assert_eq!(unsafe { CStr::from_ptr((*root).name) }, c"foo");
    }
    #[test]
    fn environment_allocation_failure_unlocks_and_releases_partial_result() {
        reset();
        FIX.with(|f| f.borrow_mut().fail_at = 2);
        let mut root = ptr::null_mut::<Environment>();
        assert_eq!(
            unsafe {
                facade(
                    4,
                    c"foo".as_ptr() as usize,
                    ptr::addr_of_mut!(root) as usize,
                    0,
                    0,
                    &FLAGS,
                    native,
                )
            },
            0
        );
        assert!(root.is_null());
        FIX.with(|f| {
            let f = f.borrow();
            assert!(f.allocations.is_empty());
            assert_eq!(f.trace, [4, 13, 9, 11, 11, 13, 16]);
            assert_eq!(f.errno, 8);
        });
    }
    #[test]
    fn no_overwrite_still_reads_cache_and_skips_native_environment_write() {
        reset();
        let mut root = ptr::null_mut::<Environment>();
        assert_eq!(
            unsafe {
                facade(
                    5,
                    c"foo".as_ptr() as usize,
                    c"new".as_ptr() as usize,
                    0,
                    ptr::addr_of_mut!(root) as usize,
                    &FLAGS,
                    native,
                )
            },
            0
        );
        assert!(!root.is_null());
        FIX.with(|f| assert!(!f.borrow().trace.contains(&5)));
    }
    #[test]
    fn stat_overflow_has_errno_only_and_no_native_error_or_publication() {
        reset();
        FIX.with(|f| f.borrow_mut().status = 534);
        assert_eq!(
            unsafe { facade(2, c"x".as_ptr() as usize, 1, 0, 0, &FLAGS, native) } as isize,
            -1
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.errno, 1012);
            assert_eq!(f.trace, [2, 22]);
        });
    }
}
