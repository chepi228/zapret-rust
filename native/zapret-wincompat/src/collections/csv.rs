//! Stage string tokens before prepending them in the original reverse order.
use super::{Allocator, Node, Owned, Staged, StringValue};
use std::{ffi::c_char, ptr};

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_collection_parse_strings(
    head: *mut *mut Node<StringValue>,
    text: *const c_char,
    allocator: *const Allocator,
) -> bool {
    if head.is_null() || allocator.is_null() {
        return false;
    }
    let allocator = unsafe { &*allocator };
    let mut staged = Staged::<StringValue> {
        first: ptr::null_mut(),
        last: ptr::null_mut(),
        allocator,
    };
    let okay = unsafe {
        crate::config_lists::each(text, |text| {
            let Some(node) = Owned::copy(&StringValue(text), allocator) else {
                return false;
            };
            let node = node.into_raw();
            (*node).next = staged.first;
            if staged.first.is_null() {
                staged.last = node;
            } else {
                (*staged.first).previous = ptr::addr_of_mut!((*node).next);
            }
            staged.first = node;
            true
        })
    };
    if !okay {
        return false;
    }
    if !staged.first.is_null() {
        let old = unsafe { head.read() };
        unsafe {
            (*staged.last).next = old;
            if !old.is_null() {
                (*old).previous = ptr::addr_of_mut!((*staged.last).next);
            }
            (*staged.first).previous = head;
            head.write(staged.first);
        }
        staged.first = ptr::null_mut();
        staged.last = ptr::null_mut();
    }
    true
}
