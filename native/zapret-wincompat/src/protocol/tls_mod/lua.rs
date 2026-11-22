//! Prepare a bounded TLS workspace before C allocates Lua-owned userdata.
use super::*;
use std::ptr;

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_tls_text(label: u32) -> *const c_char {
    match label {
        0 => c"tls_mod",
        1 => APPLIED_TLS_FLAGS,
        2 => c"invalid tls mod list : '%s'",
        _ => c"TLS buffer length overflow",
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_tls_payload(argc: i32, known_tag: bool, tag: i32) -> bool {
    argc >= 3 && (!known_tag || tag != 0)
}

#[repr(C)]
struct Workspace {
    options: FakeTlsMod,
    mode: u32,
    length: usize,
    capacity: usize,
}
const _: () = {
    assert!(size_of::<Workspace>() == 264 + 2 * size_of::<usize>());
    assert!(std::mem::offset_of!(Workspace, length) == 264);
};
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_tls_prepare(
    text: *const c_char,
    length: usize,
    workspace: *mut Workspace,
) -> u32 {
    if text.is_null() || workspace.is_null() || !workspace.is_aligned() {
        return 4;
    }
    let mut options = FakeTlsMod {
        sni: [0; 256],
        flags: 0,
    };
    if !parse_list(unsafe { CStr::from_ptr(text) }.to_bytes(), &mut options) {
        return 2;
    }
    let mode = u32::from(options.flags != 0);
    let capacity = if mode == 0 {
        if length > isize::MAX as usize {
            return 3;
        }
        0
    } else {
        let Some(capacity) = length
            .checked_add(260)
            .filter(|n| *n <= isize::MAX as usize)
        else {
            return 3;
        };
        capacity
    };
    unsafe {
        workspace.write(Workspace {
            options,
            mode,
            length,
            capacity,
        })
    };
    mode
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_tls_apply(
    workspace: *const Workspace,
    data: *const u8,
    payload: *const u8,
    payload_length: usize,
    output: *mut u8,
    written: *mut usize,
    reporter: Reporter,
) -> bool {
    if workspace.is_null()
        || !workspace.is_aligned()
        || written.is_null()
        || !written.is_aligned()
        || output.is_null()
    {
        return false;
    }
    let workspace = unsafe { &*workspace };
    if workspace.mode != 1
        || workspace.options.flags == 0
        || workspace.length > isize::MAX as usize
        || workspace.length.checked_add(260) != Some(workspace.capacity)
        || workspace.capacity > isize::MAX as usize
        || workspace.length != 0 && data.is_null()
    {
        return false;
    }
    // The caller's original string remains rooted in Lua while userdata is
    // allocated. Copy it in this call and drop every Rust slice before returning.
    if workspace.length != 0 {
        unsafe { ptr::copy(data, output, workspace.length) };
    }
    let mut length = workspace.length;
    let result = unsafe {
        zapret_tls_mod(
            &workspace.options,
            payload,
            payload_length,
            output,
            &mut length,
            workspace.capacity,
            reporter,
        )
    };
    if result {
        unsafe { written.write(length) };
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_unmodified_tls_call_does_not_require_an_extra_workspace() {
        let mut workspace = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { zapret_lua_tls_prepare(c"none".as_ptr(), 123, workspace.as_mut_ptr()) },
            0
        );
        let workspace = unsafe { workspace.assume_init() };
        assert_eq!(
            (workspace.mode, workspace.length, workspace.capacity),
            (0, 123, 0)
        );
    }
    #[test]
    fn a_modification_reserves_the_existing_260_byte_growth_budget() {
        let mut workspace = MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                zapret_lua_tls_prepare(c"sni=example.org".as_ptr(), 81, workspace.as_mut_ptr())
            },
            1
        );
        let workspace = unsafe { workspace.assume_init() };
        assert_eq!(
            (workspace.mode, workspace.length, workspace.capacity),
            (1, 81, 341)
        );
        assert_eq!(workspace.options.flags, SNI);
    }
    #[test]
    fn invalid_options_and_capacity_overflow_do_not_publish_partial_metadata() {
        let mut workspace = Workspace {
            options: FakeTlsMod {
                sni: [0; 256],
                flags: 99,
            },
            mode: 99,
            length: 99,
            capacity: 99,
        };
        assert_eq!(
            unsafe { zapret_lua_tls_prepare(c"sni=".as_ptr(), usize::MAX, &mut workspace) },
            2
        );
        assert_eq!(workspace.mode, 99);
        assert_eq!(
            unsafe { zapret_lua_tls_prepare(c"rnd".as_ptr(), usize::MAX, &mut workspace) },
            3
        );
        assert_eq!(workspace.mode, 99);
    }
    #[test]
    fn failed_transform_retains_the_source_copy_and_leaves_the_published_length_unchanged() {
        let mut workspace = MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                zapret_lua_tls_prepare(c"sni=example.org".as_ptr(), 3, workspace.as_mut_ptr())
            },
            1
        );
        let workspace = unsafe { workspace.assume_init() };
        let mut output = [0xa5; 263];
        let mut written = 99;
        assert!(!unsafe {
            zapret_lua_tls_apply(
                &workspace,
                b"abc".as_ptr(),
                ptr::null(),
                0,
                output.as_mut_ptr(),
                &mut written,
                None,
            )
        });
        assert_eq!(written, 99);
        assert_eq!(&output[..3], b"abc");
        assert!(output[3..].iter().all(|v| *v == 0xa5));
    }
    #[test]
    fn invalid_workspace_cannot_write_the_output_or_read_the_source() {
        let mut workspace = Workspace {
            options: FakeTlsMod {
                sni: [0; 256],
                flags: RND,
            },
            mode: 1,
            length: 1,
            capacity: 1,
        };
        let mut output = [0xa5; 16];
        let mut written = 99;
        assert!(!unsafe {
            zapret_lua_tls_apply(
                &workspace,
                ptr::null(),
                ptr::null(),
                0,
                output.as_mut_ptr(),
                &mut written,
                None,
            )
        });
        assert_eq!(written, 99);
        assert_eq!(output, [0xa5; 16]);
        workspace.mode = 0;
        workspace.capacity = 261;
        assert!(!unsafe {
            zapret_lua_tls_apply(
                &workspace,
                ptr::null(),
                ptr::null(),
                0,
                output.as_mut_ptr(),
                &mut written,
                None,
            )
        });
    }
}
