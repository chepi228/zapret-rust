//! Local Lua option text and native argument-list ownership.
use super::DLOG_ERR;
use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

type Record = *mut c_void;
type Head = *mut Record;

#[repr(C)]
struct Argument {
    name: *mut c_char,
    value: *mut c_char,
}

#[repr(C)]
struct Call {
    _prefix: [u8; 56],
    arguments: Record,
}

#[repr(C)]
struct ArgumentOps {
    allocate: unsafe extern "C" fn(usize) -> Record,
    release: unsafe extern "C" fn(Record),
    start: unsafe extern "C" fn(Head, *const c_char) -> Head,
    add: unsafe extern "C" fn(Head, *mut c_char, *mut c_char) -> bool,
}

#[derive(Default)]
#[repr(C)]
struct ParseError {
    format: *const c_char,
    length: c_int,
}

const _: () = {
    let pointer = size_of::<Record>();
    assert!(
        size_of::<Argument>() == 2 * pointer && core::mem::offset_of!(Argument, value) == pointer
    );
    assert!(core::mem::offset_of!(Call, arguments) == 56);
    assert!(size_of::<ArgumentOps>() == 4 * pointer && size_of::<ParseError>() == 2 * pointer);
};

unsafe extern "C" {
    fn malloc(size: usize) -> Record;
    fn free(pointer: Record);
    fn str2list_add(head: Head) -> Record;
    fn funclist_add_tail(head: Head, name: *const c_char) -> Record;
    fn funclist_destroy(head: Head);
    fn zapret_lua_add_argument(text: *const c_char, args: Head, ops: &ArgumentOps) -> bool;
    fn zapret_lua_parse_arguments(
        text: *const c_char,
        staged: Head,
        target: Head,
        ops: &ArgumentOps,
        error: &mut ParseError,
    ) -> Record;
}

unsafe extern "C" fn add_argument(args: Head, name: *mut c_char, value: *mut c_char) -> bool {
    let entry = unsafe { str2list_add(args) }.cast::<Argument>();
    if entry.is_null() {
        return false;
    }
    unsafe { entry.write(Argument { name, value }) };
    true
}

unsafe extern "C" fn start_call(staged: Head, name: *const c_char) -> Head {
    let entry = unsafe { funclist_add_tail(staged, name) }.cast::<Call>();
    if entry.is_null() {
        ptr::null_mut()
    } else {
        unsafe { &raw mut (*entry).arguments }
    }
}

const OPS: ArgumentOps = ArgumentOps {
    allocate: malloc,
    release: free,
    start: start_call,
    add: add_argument,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn lua_call_param_add(text: *const c_char, args: Head) -> bool {
    unsafe { zapret_lua_add_argument(text, args, &OPS) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn parse_lua_call(text: *const c_char, head: Head) -> Record {
    let mut staged = ptr::null_mut();
    let mut error = ParseError::default();
    let entry =
        unsafe { zapret_lua_parse_arguments(text, &raw mut staged, head, &OPS, &mut error) };
    if entry.is_null() {
        unsafe {
            if !error.format.is_null() {
                DLOG_ERR(error.format, error.length, text);
            }
            funclist_destroy(&raw mut staged);
        }
    }
    entry
}
