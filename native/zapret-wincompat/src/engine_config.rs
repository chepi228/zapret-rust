//! Global engine defaults and transactional capture-filter storage.
use std::{
    ffi::{c_char, c_void},
    ptr, slice,
};

#[repr(C)]
struct Layout {
    size: usize,
    offsets: [usize; 10],
}
const WIDTHS: [usize; 10] = [1, 4, 4, 4, 4, 4, 4, 8, 8, 8];
const DEFAULTS: [u64; 10] = [1, 0, 60, 300, 60, 60, 7200, 60_000, 1 << 31, 1 << 31];

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_config_init(
    output: *mut u8,
    capacity: usize,
    layout: *const Layout,
) -> bool {
    if output.is_null() || layout.is_null() {
        return false;
    }
    let layout = unsafe { &*layout };
    if capacity != layout.size || capacity > isize::MAX as usize {
        return false;
    }
    for (index, (&offset, &width)) in layout.offsets.iter().zip(&WIDTHS).enumerate() {
        let Some(end) = offset.checked_add(width) else {
            return false;
        };
        if end > capacity {
            return false;
        }
        for (&previous, &previous_width) in layout.offsets[..index].iter().zip(&WIDTHS) {
            if offset < previous.saturating_add(previous_width) && previous < end {
                return false;
            }
        }
    }
    // Validate the complete layout before changing any caller-owned bytes.
    // Windows globals consist of zero-valid flags, integers and pointers.
    unsafe { output.write_bytes(0, capacity) };
    for ((&offset, &width), value) in layout.offsets.iter().zip(&WIDTHS).zip(DEFAULTS) {
        unsafe {
            match width {
                1 => output.add(offset).write(value as u8),
                4 => ptr::write_unaligned(output.add(offset).cast::<u32>(), value as u32),
                _ => ptr::write_unaligned(output.add(offset).cast::<u64>(), value),
            }
        }
    }
    true
}

#[repr(C)]
struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}
const FILTERS: usize = 13;
unsafe fn slots<'a>(
    slots: *const *mut *mut c_char,
    count: usize,
) -> Option<&'a [*mut *mut c_char]> {
    if count != FILTERS || slots.is_null() {
        return None;
    }
    let slots = unsafe { slice::from_raw_parts(slots, count) };
    for (index, &slot) in slots.iter().enumerate() {
        if slot.is_null() || slots[..index].contains(&slot) {
            return None;
        }
    }
    Some(slots)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_filter_buffers(
    slots_input: *const *mut *mut c_char,
    count: usize,
    allocator: *const Allocator,
) -> bool {
    if allocator.is_null() {
        return false;
    }
    let Some(slots) = (unsafe { slots(slots_input, count) }) else {
        return false;
    };
    let allocator = unsafe { &*allocator };
    let mut staged = [ptr::null_mut::<c_char>(); FILTERS];
    for (index, target) in staged.iter_mut().enumerate() {
        *target = unsafe { (allocator.allocate)(if index == FILTERS - 1 { 65_536 } else { 4096 }) }
            .cast();
        if target.is_null() {
            for pointer in staged {
                unsafe { (allocator.release)(pointer.cast()) };
            }
            return false;
        }
        unsafe { target.write(0) };
    }
    for (&slot, pointer) in slots.iter().zip(staged) {
        let old = unsafe { slot.replace(pointer) };
        unsafe { (allocator.release)(old.cast()) };
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_filter_clear(
    slots_input: *const *mut *mut c_char,
    count: usize,
    allocator: *const Allocator,
) -> bool {
    if allocator.is_null() {
        return false;
    }
    let Some(slots) = (unsafe { slots(slots_input, count) }) else {
        return false;
    };
    let allocator = unsafe { &*allocator };
    for &slot in slots {
        let pointer = unsafe { slot.replace(ptr::null_mut()) };
        unsafe { (allocator.release)(pointer.cast()) };
    }
    true
}
