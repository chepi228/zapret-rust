use std::{
    alloc::{Layout, alloc},
    ptr::NonNull,
};

/// Allocate a value fallibly on the same allocator as Box.
/// The caller must transfer ownership or reclaim it with Box::from_raw.
pub(super) fn try_allocate<T>(value: T) -> Option<NonNull<T>> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        return Some(NonNull::from(Box::leak(Box::new(value))));
    }
    let allocation = NonNull::new(unsafe { alloc(layout) }.cast::<T>())?;
    unsafe { allocation.as_ptr().write(value) };
    Some(allocation)
}
