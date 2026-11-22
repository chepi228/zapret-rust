//! Intrusive engine lists with C allocator ownership and transactional copies.
mod csv;
use std::{
    ffi::{CStr, c_char, c_void},
    ptr::{self, NonNull},
};

#[repr(C)]
pub(super) struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}
#[repr(C)]
pub(super) struct Node<T> {
    pub(super) value: T,
    pub(super) next: *mut Node<T>,
    previous: *mut *mut Node<T>,
}
#[repr(transparent)]
pub(super) struct StringValue(pub(super) *mut c_char);
#[repr(C)]
pub(super) struct Pair {
    pub(super) first: *mut c_char,
    pub(super) second: *mut c_char,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Position {
    mode: u8,
    value: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Range {
    from: Position,
    to: Position,
    upper: bool,
}
#[repr(C)]
struct Call {
    function: *mut c_char,
    payload: u64,
    incoming: Range,
    outgoing: Range,
    args: *mut Node<Pair>,
}

unsafe fn duplicate(value: *const c_char, allocator: &Allocator) -> Option<*mut c_char> {
    if value.is_null() {
        return Some(ptr::null_mut());
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes_with_nul();
    let copy = NonNull::new(unsafe { (allocator.allocate)(bytes.len()) })?;
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), copy.as_ptr().cast(), bytes.len()) };
    Some(copy.as_ptr().cast())
}
// All implementations have valid zeroed storage; copy may initialize only a
// prefix before failing, and dispose must reclaim precisely that prefix.
pub(super) trait Value: Sized {
    unsafe fn copy(source: &Self, target: *mut Self, allocator: &Allocator) -> bool;
    unsafe fn dispose(value: *mut Self, allocator: &Allocator);
}
impl Value for StringValue {
    unsafe fn copy(source: &Self, target: *mut Self, allocator: &Allocator) -> bool {
        let Some(value) = (unsafe { duplicate(source.0, allocator) }) else {
            return false;
        };
        unsafe { (*target).0 = value };
        true
    }
    unsafe fn dispose(value: *mut Self, allocator: &Allocator) {
        unsafe { (allocator.release)((*value).0.cast()) };
    }
}
impl Value for Pair {
    unsafe fn copy(source: &Self, target: *mut Self, allocator: &Allocator) -> bool {
        let Some(first) = (unsafe { duplicate(source.first, allocator) }) else {
            return false;
        };
        unsafe { (*target).first = first };
        let Some(second) = (unsafe { duplicate(source.second, allocator) }) else {
            return false;
        };
        unsafe { (*target).second = second };
        true
    }
    unsafe fn dispose(value: *mut Self, allocator: &Allocator) {
        unsafe {
            (allocator.release)((*value).first.cast());
            (allocator.release)((*value).second.cast());
        }
    }
}
impl Value for Call {
    unsafe fn copy(source: &Self, target: *mut Self, allocator: &Allocator) -> bool {
        if source.function.is_null() {
            return false;
        }
        let Some(function) = (unsafe { duplicate(source.function, allocator) }) else {
            return false;
        };
        unsafe {
            (*target).function = function;
            (*target).payload = source.payload;
            (*target).incoming = source.incoming;
            (*target).outgoing = source.outgoing;
        }
        let Some(args) = (unsafe { clone_list(source.args, allocator) }) else {
            return false;
        };
        // The target is already in its final C allocation. A child's first
        // previous pointer must never point into a temporary Rust stack value.
        unsafe { args.commit(ptr::addr_of_mut!((*target).args)) };
        true
    }
    unsafe fn dispose(value: *mut Self, allocator: &Allocator) {
        unsafe {
            (allocator.release)((*value).function.cast());
            destroy(ptr::addr_of_mut!((*value).args), allocator);
        }
    }
}

struct Owned<'a, T: Value> {
    node: NonNull<Node<T>>,
    allocator: &'a Allocator,
}
impl<'a, T: Value> Owned<'a, T> {
    unsafe fn copy(source: &T, allocator: &'a Allocator) -> Option<Self> {
        let node =
            NonNull::new(unsafe { (allocator.allocate)(size_of::<Node<T>>()) }.cast::<Node<T>>())?;
        unsafe { node.as_ptr().write_bytes(0, 1) };
        let owned = Self { node, allocator };
        if unsafe { T::copy(source, ptr::addr_of_mut!((*node.as_ptr()).value), allocator) } {
            Some(owned)
        } else {
            None
        }
    }
    fn into_raw(self) -> *mut Node<T> {
        let node = self.node.as_ptr();
        std::mem::forget(self);
        node
    }
}
impl<T: Value> Drop for Owned<'_, T> {
    fn drop(&mut self) {
        unsafe {
            T::dispose(
                ptr::addr_of_mut!((*self.node.as_ptr()).value),
                self.allocator,
            );
            (self.allocator.release)(self.node.as_ptr().cast());
        }
    }
}
unsafe fn tail<T>(mut slot: *mut *mut Node<T>) -> *mut *mut Node<T> {
    while !unsafe { slot.read() }.is_null() {
        slot = unsafe { ptr::addr_of_mut!((*slot.read()).next) };
    }
    slot
}
unsafe fn insert<T>(slot: *mut *mut Node<T>, node: *mut Node<T>) {
    let next = unsafe { slot.read() };
    unsafe {
        (*node).next = next;
        (*node).previous = slot;
        if !next.is_null() {
            (*next).previous = ptr::addr_of_mut!((*node).next);
        }
        slot.write(node);
    }
}

/// Publish the one complete rule built by the Lua argument parser.
pub(super) unsafe fn append_staged_call(target: *mut c_void, staged: *mut c_void) -> *mut c_void {
    let target = target.cast::<*mut Node<Call>>();
    let staged = staged.cast::<*mut Node<Call>>();
    if target == staged || target.is_null() || staged.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: both records are distinct C list heads, and the staged list
    // contains only the new rule. Preserve the node and repair its backlink.
    let node = unsafe { staged.read() };
    if node.is_null() || !unsafe { (*node).next.is_null() } {
        return ptr::null_mut();
    }
    unsafe {
        staged.write(ptr::null_mut());
        insert(tail(target), node);
    }
    node.cast()
}

pub(super) unsafe fn destroy<T: Value>(head: *mut *mut Node<T>, allocator: &Allocator) {
    let mut node = unsafe { head.read() };
    while !node.is_null() {
        let next = unsafe { (*node).next };
        unsafe {
            head.write(next);
            if !next.is_null() {
                (*next).previous = head;
            }
            T::dispose(ptr::addr_of_mut!((*node).value), allocator);
            (allocator.release)(node.cast());
        }
        node = next;
    }
}
struct Staged<'a, T: Value> {
    first: *mut Node<T>,
    last: *mut Node<T>,
    allocator: &'a Allocator,
}
impl<T: Value> Staged<'_, T> {
    unsafe fn push(&mut self, node: Owned<'_, T>) {
        let node = node.into_raw();
        if self.last.is_null() {
            self.first = node;
        } else {
            unsafe {
                (*self.last).next = node;
                (*node).previous = ptr::addr_of_mut!((*self.last).next);
            }
        }
        self.last = node;
    }
    unsafe fn commit(mut self, head: *mut *mut Node<T>) {
        if !self.first.is_null() {
            let slot = unsafe { tail(head) };
            unsafe {
                (*self.first).previous = slot;
                slot.write(self.first);
            }
            self.first = ptr::null_mut();
            self.last = ptr::null_mut();
        }
    }
}
impl<T: Value> Drop for Staged<'_, T> {
    fn drop(&mut self) {
        // Staged roots intentionally have no backlink to this movable value.
        let mut node = self.first;
        while !node.is_null() {
            unsafe {
                let next = (*node).next;
                T::dispose(ptr::addr_of_mut!((*node).value), self.allocator);
                (self.allocator.release)(node.cast());
                node = next;
            }
        }
    }
}
unsafe fn clone_list<'a, T: Value>(
    mut source: *mut Node<T>,
    allocator: &'a Allocator,
) -> Option<Staged<'a, T>> {
    let mut staged = Staged {
        first: ptr::null_mut(),
        last: ptr::null_mut(),
        allocator,
    };
    while !source.is_null() {
        let node = unsafe { Owned::copy(&(*source).value, allocator) }?;
        unsafe {
            staged.push(node);
            source = (*source).next;
        }
    }
    Some(staged)
}
pub(super) unsafe fn add<T: Value>(
    head: *mut *mut Node<T>,
    value: &T,
    append: bool,
    allocator: &Allocator,
) -> *mut c_void {
    let Some(node) = (unsafe { Owned::copy(value, allocator) }) else {
        return ptr::null_mut();
    };
    let node = node.into_raw();
    let slot = if append { unsafe { tail(head) } } else { head };
    unsafe { insert(slot, node) };
    node.cast()
}
pub(super) unsafe fn copy<T: Value>(
    target: *mut *mut Node<T>,
    source: *const *mut Node<T>,
    allocator: &Allocator,
) -> bool {
    let Some(staged) = (unsafe { clone_list(source.read(), allocator) }) else {
        return false;
    };
    // Read the original list to completion before publishing, including when
    // source and target are the same head.
    unsafe { staged.commit(target) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_collection_add(
    kind: u32,
    head: *mut c_void,
    name: *const c_char,
    append: bool,
    allocator: *const Allocator,
) -> *mut c_void {
    if head.is_null() || allocator.is_null() {
        return ptr::null_mut();
    }
    let allocator = unsafe { &*allocator };
    unsafe {
        match kind {
            0 => add(
                head.cast(),
                &StringValue(name.cast_mut()),
                append,
                allocator,
            ),
            1 => add(
                head.cast(),
                &Pair {
                    first: ptr::null_mut(),
                    second: ptr::null_mut(),
                },
                append,
                allocator,
            ),
            2 => {
                let always = Range {
                    from: Position {
                        mode: b'a',
                        value: 0,
                    },
                    to: Position {
                        mode: b'a',
                        value: 0,
                    },
                    upper: false,
                };
                add(
                    head.cast(),
                    &Call {
                        function: name.cast_mut(),
                        payload: 0,
                        incoming: always,
                        outgoing: always,
                        args: ptr::null_mut(),
                    },
                    append,
                    allocator,
                )
            }
            _ => ptr::null_mut(),
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_collection_copy(
    kind: u32,
    target: *mut c_void,
    source: *const c_void,
    allocator: *const Allocator,
) -> bool {
    if target.is_null() || source.is_null() || allocator.is_null() {
        return false;
    }
    let allocator = unsafe { &*allocator };
    unsafe {
        match kind {
            0 => copy::<StringValue>(target.cast(), source.cast(), allocator),
            1 => copy::<Pair>(target.cast(), source.cast(), allocator),
            2 => copy::<Call>(target.cast(), source.cast(), allocator),
            _ => false,
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_collection_destroy(
    kind: u32,
    head: *mut c_void,
    allocator: *const Allocator,
) {
    if head.is_null() || allocator.is_null() {
        return;
    }
    let allocator = unsafe { &*allocator };
    unsafe {
        match kind {
            0 => destroy::<StringValue>(head.cast(), allocator),
            1 => destroy::<Pair>(head.cast(), allocator),
            2 => destroy::<Call>(head.cast(), allocator),
            _ => {}
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_collection_search(
    head: *const *mut Node<StringValue>,
    name: *const c_char,
) -> bool {
    if head.is_null() || name.is_null() {
        return false;
    }
    let name = unsafe { CStr::from_ptr(name) };
    let mut node = unsafe { head.read() };
    while !node.is_null() {
        let value = unsafe { (*node).value.0 };
        if !value.is_null() && unsafe { CStr::from_ptr(value) } == name {
            return true;
        }
        node = unsafe { (*node).next };
    }
    false
}
