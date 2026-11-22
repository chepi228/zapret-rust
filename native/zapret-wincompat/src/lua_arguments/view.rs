//! Borrowed argument substitutions between C-owned Lua calls.
use crate::collections::{Node, Pair};
use std::ffi::c_char;
#[repr(C)]
struct Argument {
    name: *const c_char,
    text: *const c_char,
    kind: u32,
}
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
// 0 end, 1 borrowed argument, 2 invalid metadata. No VM call or allocation.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_argument_view_next(
    cursor: *mut *const Node<Pair>,
    substitute: bool,
    output: *mut Argument,
) -> u32 {
    if !valid(cursor) || !valid(output) {
        return 2;
    }
    let node = unsafe { cursor.read() };
    if node.is_null() {
        return 0;
    }
    if !node.is_aligned() {
        return 2;
    }
    let pair = unsafe { &(*node).value };
    let mut text = if pair.second.is_null() {
        c"".as_ptr()
    } else {
        pair.second
    };
    let kind = if substitute {
        // Only these first two bytes decide substitution. Lua itself reads
        // the C string later; do not scan every value twice on the packet path.
        match unsafe { text.cast::<u8>().read() } {
            b'\\' if matches!(unsafe { text.add(1).cast::<u8>().read() }, b'%' | b'#') => {
                text = unsafe { text.add(1) };
                0
            }
            b'%' => {
                text = unsafe { text.add(1) };
                1
            }
            b'#' => {
                text = unsafe { text.add(1) };
                2
            }
            _ => 0,
        }
    } else {
        0
    };
    unsafe {
        output.write(Argument {
            name: pair.first,
            text,
            kind,
        });
        cursor.write((*node).next);
    }
    1
}
#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Argument>() == 24);
    assert!(size_of::<Node<Pair>>() == 32);
    assert!(std::mem::offset_of!(Node<Pair>, next) == 16);
};
