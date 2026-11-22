//! Startup iteration and policy between C-owned Lua VM operations.
use crate::{
    blob::{Allocator, Blob, zapret_blob_destroy, zapret_blob_pop},
    collections::{Node, StringValue},
    logging::LogSink,
    lua_context::aligned,
    lua_rules::Rule,
    profile_config::{profile_lua, profile_next},
};
use std::{
    ffi::{c_char, c_void},
    mem::MaybeUninit,
    ptr,
};

#[repr(C)]
struct Script {
    text: *const c_char,
    file: bool,
    preview: [c_char; 128],
}

#[repr(C)]
struct Scripts {
    current: *const Node<StringValue>,
    yielded: bool,
}

#[repr(C)]
struct Functions {
    profile: *const c_void,
    rule: *const Rule,
    yielded: bool,
    started: bool,
}

#[repr(C)]
struct Path {
    global: *const c_char,
    field: *const c_char,
    nested: *const c_char,
}

#[repr(C)]
struct BlobView {
    expected: *mut Blob,
    name: *const c_char,
    data: *const u8,
    length: usize,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_startup_text(event: u32) -> *const c_char {
    let text = match event {
        0 => c"\nLUA INIT\n",
        1 => c"LUA INIT DONE\n\n",
        2 => c"LUA REMOVE:",
        3 => c"\n",
        4 => c"invalid sandbox table '%s'",
        5 => c"invalid sandbox table '%s.%s'",
        6 => c"startup blob changed during publication",
        _ => return ptr::null(),
    };
    text.as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_script_view(
    text: *const c_char,
    debug: bool,
    output: *mut Script,
) -> bool {
    if text.is_null() || !aligned(output) {
        return false;
    }
    let file = unsafe { text.read() == b'@' as c_char };
    let mut view = Script {
        text: if file { unsafe { text.add(1) } } else { text },
        file,
        preview: [0; 128],
    };
    if debug && !file {
        for index in 0..127 {
            let byte = unsafe { text.add(index).read() };
            view.preview[index] = byte;
            if byte == 0 {
                break;
            }
        }
    }
    unsafe { output.write(view) };
    true
}

// 0 end, 1 borrowed script, 2 invalid state, 3 quit before the next script.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_script_next(
    cursor: *mut Scripts,
    quit: bool,
    debug: bool,
    output: *mut Script,
) -> u32 {
    if !aligned(cursor) || !aligned(output) {
        return 2;
    }
    let cursor = unsafe { &mut *cursor };
    if cursor.yielded {
        if !aligned(cursor.current) {
            return 2;
        }
        cursor.current = unsafe { (*cursor.current).next };
        cursor.yielded = false;
    }
    if cursor.current.is_null() {
        return 0;
    }
    if !aligned(cursor.current) {
        return 2;
    }
    if quit {
        return 3;
    }
    let text = unsafe { (*cursor.current).value.0 };
    if !unsafe { zapret_lua_script_view(text, debug, output) } {
        return 2;
    }
    cursor.yielded = true;
    1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_test_init_scripts(
    first: *const Node<StringValue>,
    probe: unsafe extern "C" fn(*const c_char, *mut bool, *mut c_char) -> bool,
    error: LogSink,
) -> bool {
    let mut cursor = Scripts {
        current: first,
        yielded: false,
    };
    let mut script = MaybeUninit::uninit();
    loop {
        match unsafe { zapret_lua_script_next(&mut cursor, false, false, script.as_mut_ptr()) } {
            0 => return true,
            1 => {
                let script = unsafe { script.assume_init_ref() };
                if script.file && !unsafe { probe(script.text, ptr::null_mut(), ptr::null_mut()) } {
                    unsafe {
                        error(
                            c"LUA file '%s' or '%s.gz' not accessible\n".as_ptr(),
                            script.text,
                            script.text,
                        );
                    }
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_script_report(script: &Script, log: LogSink) {
    let (format, text) = if script.file {
        (c"LUA RUN FILE: %s\n", script.text)
    } else {
        (c"LUA RUN STR: %s\n", script.preview.as_ptr())
    };
    unsafe { log(format.as_ptr(), text) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_harden_report(path: &Path, log: LogSink) {
    unsafe {
        if !path.nested.is_null() {
            log(c" %s.%s.%s".as_ptr(), path.global, path.field, path.nested);
        } else if !path.field.is_null() {
            log(c" %s.%s".as_ptr(), path.global, path.field);
        } else {
            log(c" %s".as_ptr(), path.global);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_startup_blob_report(blob: &BlobView, log: LogSink) {
    unsafe {
        log(
            c"LUA BLOB: %s (size=%zu)\n".as_ptr(),
            blob.name,
            blob.length,
        )
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_function_next(
    cursor: *mut Functions,
    output: *mut *const c_char,
) -> u32 {
    if !aligned(cursor) || !aligned(output) {
        return 2;
    }
    let cursor = unsafe { &mut *cursor };
    if cursor.profile.is_null() {
        return 0;
    }
    if !aligned(cursor.profile.cast::<u64>()) {
        return 2;
    }
    if !cursor.started {
        cursor.rule = unsafe { profile_lua(cursor.profile).cast() };
        cursor.started = true;
    } else if cursor.yielded {
        if !aligned(cursor.rule) {
            return 2;
        }
        cursor.rule = unsafe { (*cursor.rule).next };
        cursor.yielded = false;
    }
    while cursor.rule.is_null() {
        cursor.profile = unsafe { profile_next(cursor.profile) };
        if cursor.profile.is_null() {
            return 0;
        }
        if !aligned(cursor.profile.cast::<u64>()) {
            return 2;
        }
        cursor.rule = unsafe { profile_lua(cursor.profile).cast() };
    }
    if !aligned(cursor.rule) {
        return 2;
    }
    let name = unsafe { (*cursor.rule).name };
    if name.is_null() {
        return 2;
    }
    unsafe { output.write(name) };
    cursor.yielded = true;
    1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_harden_next(index: *mut u32, output: *mut Path) -> u32 {
    const PATHS: [(
        &std::ffi::CStr,
        Option<&std::ffi::CStr>,
        Option<&std::ffi::CStr>,
    ); 5] = [
        (c"os", Some(c"execute"), None),
        (c"io", Some(c"popen"), None),
        (c"package", Some(c"loadlib"), None),
        (c"debug", None, None),
        (c"package", Some(c"loaded"), Some(c"debug")),
    ];
    if !aligned(index) || !aligned(output) {
        return 2;
    }
    let current = unsafe { index.read() };
    if current == PATHS.len() as u32 {
        return 0;
    }
    let Some(&(global, field, nested)) = PATHS.get(current as usize) else {
        return 2;
    };
    unsafe {
        output.write(Path {
            global: global.as_ptr(),
            field: field.map_or(ptr::null(), |s| s.as_ptr()),
            nested: nested.map_or(ptr::null(), |s| s.as_ptr()),
        });
        index.write(current + 1);
    }
    1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_startup_blob(head: *const *mut Blob, output: *mut BlobView) -> u32 {
    if !aligned(head) || !aligned(output) {
        return 2;
    }
    let blob = unsafe { head.read() };
    if blob.is_null() {
        return 0;
    }
    if !aligned(blob) {
        return 2;
    }
    let (name, data, length) = unsafe { ((*blob).name, (*blob).data, (*blob).size) };
    if name.is_null() || length > isize::MAX as usize || data.is_null() && length != 0 {
        return 2;
    }
    unsafe {
        output.write(BlobView {
            expected: blob,
            name,
            data,
            length,
        })
    };
    1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_startup_blob_commit(
    head: *mut *mut Blob,
    expected: *mut Blob,
    allocator: *const Allocator,
) -> bool {
    if !aligned(head)
        || !aligned(expected)
        || !aligned(allocator)
        || unsafe { head.read() != expected }
    {
        return false;
    }
    unsafe { zapret_blob_destroy(zapret_blob_pop(head), &*allocator) };
    true
}

// Each step returns before C invokes the VM. Failed scripts/function checks
// select cleanup, while the earlier void initialization steps have no result.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_startup_step(state: *mut u32, previous_ok: bool) -> u32 {
    if !aligned(state) {
        return 11;
    }
    let current = unsafe { state.read() };
    let next = match current {
        7 | 8 if !previous_ok => 10,
        0..=8 => current + 1,
        9 | 10 => current,
        _ => return 11,
    };
    unsafe { state.write(next) };
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CStr, mem::MaybeUninit};

    #[test]
    fn file_marker_is_removed_but_inline_debug_text_is_bounded_in_raw_bytes() {
        let text = c"@script.lua";
        let mut out = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_script_view(text.as_ptr(), true, out.as_mut_ptr()) });
        let out = unsafe { out.assume_init() };
        assert!(out.file);
        assert_eq!(unsafe { CStr::from_ptr(out.text) }, c"script.lua");
        let inline = [b'x'; 201];
        let mut bytes = inline;
        bytes[200] = 0;
        let mut out = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_script_view(bytes.as_ptr().cast(), true, out.as_mut_ptr()) });
        let out = unsafe { out.assume_init() };
        assert!(!out.file);
        assert_eq!(out.text, bytes.as_ptr().cast());
        assert!(
            out.preview[..127]
                .iter()
                .all(|&byte| byte == b'x' as c_char)
        );
        assert_eq!(out.preview[127], 0);
    }

    #[test]
    fn quit_after_the_last_script_does_not_turn_an_exhausted_list_into_failure() {
        let mut cursor = Scripts {
            current: ptr::null(),
            yielded: false,
        };
        let mut out = MaybeUninit::<Script>::uninit();
        assert_eq!(
            unsafe { zapret_lua_script_next(&mut cursor, true, true, out.as_mut_ptr()) },
            0
        );
    }

    #[test]
    fn startup_failure_selects_cleanup_only_after_the_status_returning_steps() {
        let mut state = 0;
        for expected in 1..=7 {
            assert_eq!(
                unsafe { zapret_lua_startup_step(&mut state, false) },
                expected
            );
        }
        assert_eq!(unsafe { zapret_lua_startup_step(&mut state, false) }, 10);
        assert_eq!(unsafe { zapret_lua_startup_step(&mut state, true) }, 10);
        state = 0;
        for expected in 1..=9 {
            assert_eq!(
                unsafe { zapret_lua_startup_step(&mut state, true) },
                expected
            );
        }
        assert_eq!(unsafe { zapret_lua_startup_step(&mut state, false) }, 9);
    }

    #[test]
    fn sandbox_policy_keeps_order_and_ends_without_writing_another_path() {
        let mut index = 0;
        let mut out = MaybeUninit::<Path>::uninit();
        for expected in [c"os", c"io", c"package", c"debug", c"package"] {
            assert_eq!(
                unsafe { zapret_lua_harden_next(&mut index, out.as_mut_ptr()) },
                1
            );
            assert_eq!(
                unsafe { CStr::from_ptr(out.assume_init_ref().global) },
                expected
            );
        }
        assert_eq!(
            unsafe { zapret_lua_harden_next(&mut index, out.as_mut_ptr()) },
            0
        );
        assert_eq!(index, 5);
    }
}
