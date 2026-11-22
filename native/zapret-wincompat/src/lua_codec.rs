//! Codec options and native lifecycle; no callback here may enter Lua or unwind.
use std::{mem, ptr};
use zlib_rs::c_api::{alloc_func, free_func, z_stream};
#[repr(C)]
struct Userdata {
    valid: u8,
    inflate: u8,
    stream: z_stream,
}
#[repr(C)]
#[derive(Default)]
struct Options {
    values: [i32; 3],
    index: u32,
    role: u32,
    argc: u32,
}
impl Options {
    fn valid(&self) -> bool {
        self.role <= 1 && self.argc <= if self.role == 1 { 1 } else { 3 } && self.index <= self.argc
    }
}
#[repr(C)]
struct Allocators {
    allocate: Option<alloc_func>,
    release: Option<free_func>,
}
type Inflate = unsafe extern "C" fn(*mut z_stream, i32) -> i32;
type Deflate = unsafe extern "C" fn(*mut z_stream, i32, i32, i32, i32, i32) -> i32;
type End = unsafe extern "C" fn(*mut z_stream) -> i32;
#[repr(C)]
struct Ops {
    inflate: Option<Inflate>,
    deflate: Option<Deflate>,
    end_inflate: Option<End>,
    end_deflate: Option<End>,
}
const NATIVE: Ops = Ops {
    inflate: Some(crate::compression::zapret_inflate_init),
    deflate: Some(crate::compression::zapret_deflate_init),
    end_inflate: Some(crate::compression::zapret_inflate_end),
    end_deflate: Some(crate::compression::zapret_deflate_end),
};
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn narrow_option(number: i64) -> i32 {
    number as i32
}
unsafe fn operations<'a>(input: *const Ops) -> Option<&'a Ops> {
    if input.is_null() {
        Some(&NATIVE)
    } else if input.is_aligned() {
        Some(unsafe { &*input })
    } else {
        None
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_options_begin(
    role: u32,
    argc: u32,
    output: *mut Options,
) -> bool {
    if !aligned(output) || role > 1 || argc > if role == 1 { 1 } else { 3 } {
        return false;
    }
    // SAFETY: C owns writable fixed storage, separate from all other metadata.
    unsafe {
        output.write(Options {
            values: if role == 1 { [47, 0, 0] } else { [31, 9, 8] },
            index: 0,
            role,
            argc,
        })
    };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_options_next(
    options: *const Options,
    index: *mut i32,
) -> u32 {
    if !aligned(options) || !aligned(index) {
        return 2;
    }
    let options = unsafe { &*options };
    if !options.valid() {
        return 2;
    }
    if options.index == options.argc {
        return 0;
    }
    unsafe { index.write(options.index as i32 + 1) };
    1
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_options_observe(
    options: *mut Options,
    absent: u32,
    number: i64,
) -> bool {
    if !aligned(options) || absent > 1 {
        return false;
    }
    let options = unsafe { &mut *options };
    if !options.valid() || options.index >= options.argc {
        return false;
    }
    if absent == 0 {
        options.values[options.index as usize] = narrow_option(number);
    }
    options.index += 1;
    true
}
// Validation reads the valid byte first; closed streams never inspect role/state.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_validate(userdata: *const Userdata, role: u32) -> u32 {
    if !aligned(userdata) || role > 1 {
        return 3;
    }
    let valid = unsafe { ptr::addr_of!((*userdata).valid).read() };
    if valid == 0 {
        return 1;
    }
    if valid != 1 {
        return 3;
    }
    let actual = unsafe { ptr::addr_of!((*userdata).inflate).read() };
    if actual > 1 {
        3
    } else if u32::from(actual) != role {
        2
    } else {
        0
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_initialize(
    userdata: *mut Userdata,
    options: *const Options,
    allocators: *const Allocators,
    input: *const Ops,
) -> i32 {
    if !aligned(userdata) || !aligned(options) {
        return -2;
    }
    let options = unsafe { &*options };
    if !options.valid() || options.index != options.argc {
        return -2;
    }
    let Some(ops) = (unsafe { operations(input) }) else {
        return -2;
    };
    let callbacks = if options.role == 0 {
        if !aligned(allocators) {
            return -2;
        }
        let values = unsafe { &*allocators };
        let (Some(allocate), Some(release)) = (values.allocate, values.release) else {
            return -2;
        };
        Some((allocate, release))
    } else {
        None
    };
    if (options.role == 1 && ops.inflate.is_none()) || (options.role == 0 && ops.deflate.is_none())
    {
        return -2;
    }
    // SAFETY: the Lua-owned userdata can have uninitialized flag bytes here.
    // Zero only the z_stream region, without forming a reference to the whole
    // object or reading its flags/padding before native initialization succeeds.
    let stream = unsafe { ptr::addr_of_mut!((*userdata).stream) };
    unsafe { stream.write(mem::zeroed()) };
    if let Some((allocate, release)) = callbacks {
        unsafe {
            (*stream).zalloc = Some(allocate);
            (*stream).zfree = Some(release)
        };
    }
    let result = match (options.role, ops.inflate, ops.deflate) {
        (1, Some(start), _) => unsafe { start(stream, options.values[0]) },
        (0, _, Some(start)) => unsafe {
            start(
                stream,
                options.values[1],
                8,
                options.values[0],
                options.values[2],
                0,
            )
        },
        _ => return -2,
    };
    if result == 0 {
        unsafe {
            ptr::addr_of_mut!((*userdata).inflate).write(options.role as u8);
            ptr::addr_of_mut!((*userdata).valid).write(1)
        };
    }
    result
}
// role 0/1 is an explicitly validated close; role 2 is an idempotent GC visit.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_codec_finish(
    userdata: *mut Userdata,
    role: u32,
    input: *const Ops,
) -> i32 {
    if !aligned(userdata) || role > 2 {
        return -2;
    }
    let valid = unsafe { ptr::addr_of!((*userdata).valid).read() };
    if valid == 0 {
        return 0;
    }
    if valid != 1 {
        return -2;
    }
    let actual = unsafe { ptr::addr_of!((*userdata).inflate).read() };
    if actual > 1 {
        return -2;
    }
    let requested = if role == 2 { u32::from(actual) } else { role };
    let Some(ops) = (unsafe { operations(input) }) else {
        return -2;
    };
    let Some(end) = (if requested == 1 {
        ops.end_inflate
    } else {
        ops.end_deflate
    }) else {
        return -2;
    };
    let stream = unsafe { ptr::addr_of_mut!((*userdata).stream) };
    let result = unsafe { end(stream) };
    // The native callback can modify other fields; valid clears after it returns.
    unsafe { ptr::addr_of_mut!((*userdata).valid).write(0) };
    result
}
const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Userdata>() == size_of::<z_stream>() + pointer);
    assert!(mem::offset_of!(Userdata, stream) == pointer);
    assert!(size_of::<Options>() == 24);
    assert!(size_of::<Allocators>() == 2 * pointer);
    assert!(size_of::<Ops>() == 4 * pointer);
};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_option_narrowing_preserves_low_native_bits() {
        assert_eq!(narrow_option(0x1_0000_001f), 31);
        assert_eq!(narrow_option(-0x1_0000_000f), -15);
    }
    fn options(role: u32, values: &[Option<i64>]) -> Options {
        let mut options = Options::default();
        assert!(unsafe { zapret_lua_codec_options_begin(role, values.len() as u32, &mut options) });
        for (expected, value) in values.iter().enumerate() {
            let mut index = 0;
            assert_eq!(
                unsafe { zapret_lua_codec_options_next(&options, &mut index) },
                1
            );
            assert_eq!(index, expected as i32 + 1);
            assert!(unsafe {
                zapret_lua_codec_options_observe(
                    &mut options,
                    u32::from(value.is_none()),
                    value.unwrap_or(0),
                )
            });
        }
        assert_eq!(
            unsafe { zapret_lua_codec_options_next(&options, &mut 0) },
            0
        );
        options
    }
    #[test]
    fn absent_and_nil_options_keep_native_defaults_in_query_order() {
        assert_eq!(options(0, &[]).values, [31, 9, 8]);
        assert_eq!(options(1, &[]).values, [47, 0, 0]);
        assert_eq!(
            options(0, &[None, Some(0x1_0000_0006), None]).values,
            [31, 6, 8]
        );
        assert_eq!(options(1, &[Some(0xffff_fff1)]).values, [-15, 0, 0]);
    }
    #[test]
    fn role_validation_checks_closed_state_before_the_role() {
        let mut userdata = Userdata {
            valid: 0,
            inflate: 255,
            stream: unsafe { mem::zeroed() },
        };
        assert_eq!(unsafe { zapret_lua_codec_validate(&userdata, 0) }, 1);
        userdata.valid = 1;
        userdata.inflate = 1;
        assert_eq!(unsafe { zapret_lua_codec_validate(&userdata, 0) }, 2);
        assert_eq!(unsafe { zapret_lua_codec_validate(&userdata, 1) }, 0);
        userdata.inflate = 0;
        assert_eq!(unsafe { zapret_lua_codec_validate(&userdata, 0) }, 0);
    }
    unsafe extern "C" fn allocate(
        _opaque: *mut std::ffi::c_void,
        items: u32,
        size: u32,
    ) -> *mut std::ffi::c_void {
        unsafe { libc::malloc(items as usize * size as usize) }
    }
    unsafe extern "C" fn release(_opaque: *mut std::ffi::c_void, value: *mut std::ffi::c_void) {
        unsafe { libc::free(value) }
    }
    #[test]
    fn actual_codecs_publish_flags_only_after_success_and_gc_is_idempotent() {
        let callbacks = Allocators {
            allocate: Some(allocate),
            release: Some(release),
        };
        for role in 0..=1 {
            let mut userdata = Userdata {
                valid: 0xa5,
                inflate: 0xa5,
                stream: unsafe { mem::zeroed() },
            };
            assert_eq!(
                unsafe {
                    zapret_lua_codec_initialize(
                        &mut userdata,
                        &options(role, &[]),
                        &callbacks,
                        ptr::null(),
                    )
                },
                0
            );
            assert_eq!((userdata.valid, userdata.inflate), (1, role as u8));
            assert!(!userdata.stream.state.is_null());
            assert_eq!(
                unsafe { zapret_lua_codec_finish(&mut userdata, role, ptr::null()) },
                0
            );
            assert_eq!(userdata.valid, 0);
            assert_eq!(
                unsafe { zapret_lua_codec_finish(&mut userdata, 2, ptr::null()) },
                0
            );
        }
        let mut userdata = Userdata {
            valid: 0xa5,
            inflate: 0xa5,
            stream: unsafe { mem::zeroed() },
        };
        assert_ne!(
            unsafe {
                zapret_lua_codec_initialize(
                    &mut userdata,
                    &options(1, &[Some(99)]),
                    ptr::null(),
                    ptr::null(),
                )
            },
            0
        );
        assert_eq!((userdata.valid, userdata.inflate), (0xa5, 0xa5));
    }
    #[test]
    fn metadata_failures_cannot_initialize_or_advance_options() {
        let mut option = Options::default();
        assert!(!unsafe { zapret_lua_codec_options_begin(1, 2, &mut option) });
        assert!(!unsafe { zapret_lua_codec_options_observe(&mut option, 2, 99) });
        assert_eq!(
            unsafe {
                zapret_lua_codec_initialize(ptr::null_mut(), &option, ptr::null(), ptr::null())
            },
            -2
        );
        assert_eq!(
            unsafe { zapret_lua_codec_finish(ptr::null_mut(), 2, ptr::null()) },
            -2
        );
        assert_eq!(unsafe { zapret_lua_codec_validate(ptr::null(), 1) }, 3);
    }
}
