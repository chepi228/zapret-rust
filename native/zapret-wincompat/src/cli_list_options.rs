//! Profile list registration policy; storage and CSV parsing use the existing Rust backends.
use crate::{
    cli::{FileClose, FileOpen},
    logging::LogSink,
};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

#[repr(C)]
struct Target {
    profile: *mut c_void,
    cached: *mut *mut c_void,
    autolist: *mut *mut c_void,
    skip: bool,
}

#[repr(C)]
struct Backend {
    register: unsafe extern "C" fn(*mut c_void, bool, *const c_char) -> *mut c_void,
    parse: unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
}

#[repr(C)]
struct Ops {
    hosts: Backend,
    ips: Backend,
    probe_auto: unsafe extern "C" fn(*const c_char) -> u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_auto_probe(
    path: *const c_char,
    open: FileOpen,
    is_gzip: unsafe extern "C" fn(*mut c_void) -> bool,
    read_error: unsafe extern "C" fn(*mut c_void) -> c_int,
    close: FileClose,
) -> u32 {
    let file = unsafe { open(path, c"a+b".as_ptr()) };
    if file.is_null() {
        return 2;
    }
    let gzip = unsafe { is_gzip(file) };
    let failed = unsafe { read_error(file) } != 0;
    let closed = unsafe { close(file) } == 0;
    if failed {
        3
    } else if !closed {
        4
    } else {
        u32::from(gzip)
    }
}

// C supplies valid callback functions and NUL-terminated arguments. Callbacks return
// normally: diagnostics and exit_clean stay outside this Rust frame.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_list_option(
    kind: u32,
    text: *const c_char,
    target: *const Target,
    ops: *const Ops,
) -> u32 {
    if target.is_null() || !target.is_aligned() || ops.is_null() || !ops.is_aligned() || kind > 8 {
        return 1;
    }
    let target = unsafe { &*target };
    // Skipped profiles must neither access arguments nor touch the filesystem.
    if target.skip {
        return 0;
    }
    if target.profile.is_null() || text.is_null() {
        return 1;
    }
    let ops = unsafe { &*ops };
    let backend = if kind >= 5 { &ops.ips } else { &ops.hosts };
    let exclude = matches!(kind, 2 | 3 | 7 | 8);
    if kind == 4 {
        if target.autolist.is_null() || !target.autolist.is_aligned() {
            return 1;
        }
        if !unsafe { target.autolist.read() }.is_null() {
            return 5;
        }
        match unsafe { (ops.probe_auto)(text) } {
            0 => {}
            1 => return 7,
            2 => return 6,
            3 => return 8,
            4 => return 9,
            _ => return 1,
        }
        let file = unsafe { (backend.register)(target.profile, false, text) };
        if file.is_null() {
            return 2;
        }
        unsafe { target.autolist.write(file) };
        return 0;
    }
    if matches!(kind, 1 | 3 | 6 | 8) {
        if target.cached.is_null() || !target.cached.is_aligned() {
            return 1;
        }
        let mut file = unsafe { target.cached.read() };
        if file.is_null() {
            file = unsafe { (backend.register)(target.profile, exclude, ptr::null()) };
            if file.is_null() {
                return 3;
            }
            // A later parse failure keeps the registered entry, as the original C did.
            unsafe { target.cached.write(file) };
        }
        if !unsafe { (backend.parse)(file, text) } {
            return 4;
        }
    } else if unsafe { (backend.register)(target.profile, exclude, text) }.is_null() {
        return 2;
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_list_report(
    kind: u32,
    status: u32,
    text: *const c_char,
    error: LogSink,
) -> c_int {
    let (label, items) = if kind >= 5 {
        (c"ipset", c"subnets")
    } else {
        (c"hostlist", c"domains")
    };
    unsafe {
        match status {
            0 => return 1,
            2 => error(
                c"failed to register %s '%s'\n".as_ptr(),
                label.as_ptr(),
                text,
            ),
            3 => error(
                c"failed to register anonymous %s\n".as_ptr(),
                label.as_ptr(),
            ),
            4 => error(
                c"failed to add %s to anonymous %s\n".as_ptr(),
                items.as_ptr(),
                label.as_ptr(),
            ),
            5 => error(c"only one auto hostlist per profile is supported\n".as_ptr()),
            6 => error(c"cannot create %s\n".as_ptr(), text),
            7 => error(c"gzipped auto hostlists are not supported\n".as_ptr()),
            8 => error(c"cannot read auto hostlist '%s'\n".as_ptr(), text),
            9 => error(c"cannot close auto hostlist '%s'\n".as_ptr(), text),
            _ => error(c"invalid list option storage\n".as_ptr()),
        };
    }
    -1
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Target>() == 32);
    assert!(size_of::<Ops>() == 40);
};
