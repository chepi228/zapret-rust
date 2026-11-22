//! Borrowed registration metadata between C-owned Lua VM calls.
mod catalog;
use crate::lua_context::aligned;
use std::{
    ffi::{CStr, c_char},
    ptr,
};

#[repr(C)]
struct Values {
    version: *const c_char,
    mark: u32,
    debug: bool,
    daemon: bool,
    server: bool,
    cache_hostname: bool,
    ctrack_disable: bool,
}

#[repr(C)]
struct Group {
    title: *const c_char,
    before_log: u32,
    after_log: u32,
}

// Preserve when runtime values are captured relative to each diagnostic.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_registry_group(index: u32, output: *mut Group) -> u32 {
    if !aligned(output) {
        return 2;
    }
    let (title, before_log, after_log) = match index {
        0 => (c"LUA STR:", 1, 0),
        1 => (c"\nLUA NUMERIC:", 2, 0),
        2 => (c"\nLUA BOOL:", 0, 3),
        3 => (c"\n", 0, 0),
        _ => return 2,
    };
    unsafe {
        output.write(Group {
            title: title.as_ptr(),
            before_log,
            after_log,
        });
    }
    u32::from(index != 3)
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_registry_entry_format() -> *const c_char {
    c" %s".as_ptr()
}

#[repr(C)]
struct Constant {
    name: *const c_char,
    text: *const c_char,
    value: u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_registry_constant(
    group: u32,
    index: usize,
    values: *const Values,
    output: *mut Constant,
) -> u32 {
    if !aligned(values) || !aligned(output) {
        return 2;
    }
    const FLAGS: [&CStr; 5] = [
        c"b_debug",
        c"b_daemon",
        c"b_server",
        c"b_ipcache_hostname",
        c"b_ctrack_disable",
    ];
    let count = match group {
        0 => 1,
        1 => catalog::NUMBERS.len(),
        2 => FLAGS.len(),
        _ => return 2,
    };
    if index == count {
        return 0;
    }
    if index > count {
        return 2;
    }
    // C keeps the group snapshot alive for this call; nothing is retained by Rust.
    let values = unsafe { &*values };
    let mut entry = Constant {
        name: ptr::null(),
        text: ptr::null(),
        value: 0,
    };
    match group {
        0 => {
            entry.name = c"NFQWS2_VER".as_ptr();
            entry.text = values.version;
        }
        1 => {
            let (name, value) = catalog::NUMBERS[index];
            entry.name = name.as_ptr();
            entry.value = if index == 0 { values.mark } else { value };
        }
        2 => {
            entry.name = FLAGS[index].as_ptr();
            entry.value = u32::from(
                [
                    values.debug,
                    values.daemon,
                    values.server,
                    values.cache_hostname,
                    values.ctrack_disable,
                ][index],
            );
        }
        _ => return 2,
    }
    // The caller supplies a writable, aligned C output object.
    unsafe { output.write(entry) };
    1
}

#[repr(C)]
struct Function {
    name: *const c_char,
    slot: u32,
}

#[repr(C)]
struct Metatable {
    name: *const c_char,
    first: *const c_char,
    second: *const c_char,
    action: u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_registry_function(
    index: usize,
    count: usize,
    output: *mut Function,
) -> u32 {
    if !aligned(output) || count != catalog::FUNCTIONS.len() {
        return 2;
    }
    if index == count {
        return 0;
    }
    let Some(name) = catalog::FUNCTIONS.get(index) else {
        return 2;
    };
    // C owns the callback table; only its validated slot crosses this boundary.
    unsafe {
        output.write(Function {
            name: name.as_ptr(),
            slot: index as u32,
        })
    };
    1
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_registry_metatable(index: usize, output: *mut Metatable) -> u32 {
    if !aligned(output) {
        return 2;
    }
    let (name, first, second, action) = match index {
        0 => (
            c"userdata_zstream".as_ptr(),
            c"__gc".as_ptr(),
            c"__close".as_ptr(),
            1,
        ),
        1 => (c"desync_ctx".as_ptr(), ptr::null(), ptr::null(), 2),
        2 => (ptr::null(), ptr::null(), ptr::null(), 3),
        3 => return 0,
        _ => return 2,
    };
    // All strings have static storage; C completes the VM operation after return.
    unsafe {
        output.write(Metatable {
            name,
            first,
            second,
            action,
        })
    };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn constants_keep_the_runtime_mark_duplicate_flag_and_five_boolean_values() {
        let values = Values {
            version: c"v0".as_ptr(),
            mark: u32::MAX,
            debug: true,
            daemon: false,
            server: true,
            cache_hostname: false,
            ctrack_disable: true,
        };
        let mut output = MaybeUninit::<Constant>::uninit();
        assert_eq!(
            unsafe { zapret_lua_registry_constant(0, 0, &values, output.as_mut_ptr()) },
            1
        );
        let entry = unsafe { output.assume_init_ref() };
        assert_eq!(unsafe { CStr::from_ptr(entry.name) }, c"NFQWS2_VER");
        assert_eq!(entry.text, values.version);
        let mut index = 0;
        let mut fin = 0;
        loop {
            let status =
                unsafe { zapret_lua_registry_constant(1, index, &values, output.as_mut_ptr()) };
            if status == 0 {
                break;
            }
            assert_eq!(status, 1);
            let entry = unsafe { output.assume_init_ref() };
            let name = unsafe { CStr::from_ptr(entry.name) };
            if index == 0 {
                assert_eq!(name, c"desync_fwmark");
                assert_eq!(entry.value, u32::MAX);
            }
            if name == c"TH_FIN" {
                fin += 1;
                assert_eq!(entry.value, 1);
            }
            index += 1;
        }
        assert_eq!(fin, 2);
        for index in 0..5 {
            assert_eq!(
                unsafe { zapret_lua_registry_constant(2, index, &values, output.as_mut_ptr()) },
                1
            );
            assert_eq!(
                unsafe { output.assume_init_ref() }.value,
                u32::from(index % 2 == 0)
            );
        }
        assert_eq!(
            unsafe { zapret_lua_registry_constant(2, 5, &values, output.as_mut_ptr()) },
            0
        );
    }

    #[test]
    fn api_catalog_retains_its_alias_and_does_not_publish_unsafe_memcpy() {
        let mut output = MaybeUninit::<Function>::uninit();
        let mut names = Vec::new();
        for index in 0..101 {
            assert_eq!(
                unsafe { zapret_lua_registry_function(index, 101, output.as_mut_ptr()) },
                1
            );
            let entry = unsafe { output.assume_init_ref() };
            assert_eq!(entry.slot as usize, index);
            names.push(unsafe { CStr::from_ptr(entry.name) });
        }
        assert_eq!(names[0], c"DLOG");
        assert_eq!(names[100], c"timer_enum");
        assert!(names.contains(&c"bitnot") && names.contains(&c"bitnot48"));
        assert!(!names.contains(&c"memcpy"));
        assert_eq!(
            unsafe { zapret_lua_registry_function(101, 101, output.as_mut_ptr()) },
            0
        );
        assert_eq!(
            unsafe { zapret_lua_registry_function(0, 100, output.as_mut_ptr()) },
            2
        );
    }

    #[test]
    fn metatables_register_both_stream_finalizers_before_context_creation() {
        let mut output = MaybeUninit::<Metatable>::uninit();
        for (index, name, action) in [
            (0, Some(c"userdata_zstream"), 1),
            (1, Some(c"desync_ctx"), 2),
            (2, None, 3),
        ] {
            assert_eq!(
                unsafe { zapret_lua_registry_metatable(index, output.as_mut_ptr()) },
                1
            );
            let entry = unsafe { output.assume_init_ref() };
            assert_eq!(entry.action, action);
            if let Some(name) = name {
                assert_eq!(unsafe { CStr::from_ptr(entry.name) }, name);
            } else {
                assert!(entry.name.is_null());
            }
            if index == 0 {
                assert_eq!(unsafe { CStr::from_ptr(entry.first) }, c"__gc");
                assert_eq!(unsafe { CStr::from_ptr(entry.second) }, c"__close");
            } else {
                assert!(entry.first.is_null() && entry.second.is_null());
            }
        }
        assert_eq!(
            unsafe { zapret_lua_registry_metatable(3, output.as_mut_ptr()) },
            0
        );
    }

    #[test]
    fn refuses_a_changed_callback_table_without_overwriting_the_previous_entry() {
        let mut output = Function {
            name: c"sentinel".as_ptr(),
            slot: 123,
        };
        for count in [0, 100, 102, usize::MAX] {
            assert_eq!(
                unsafe { zapret_lua_registry_function(0, count, &mut output) },
                2
            );
            assert_eq!(output.slot, 123);
            assert_eq!(output.name, c"sentinel".as_ptr());
        }
        assert_eq!(
            unsafe { zapret_lua_registry_function(usize::MAX, 101, &mut output) },
            2
        );
        assert_eq!(output.slot, 123);
    }
}
