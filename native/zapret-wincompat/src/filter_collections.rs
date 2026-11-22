//! Intrusive packet-filter lists share transactional ownership with string lists.
use crate::{
    collections::{Allocator, Node, Value, add, copy, destroy},
    filters::{IcmpFilter, IpProtocolFilter, PortFilter, SKIP},
};
use std::{ffi::c_void, ptr};

impl Value for PortFilter {
    unsafe fn copy(source: &Self, target: *mut Self, _: &Allocator) -> bool {
        unsafe {
            target.write(Self {
                from: source.from,
                to: source.to,
                negated: source.negated,
            })
        };
        true
    }
    unsafe fn dispose(_: *mut Self, _: &Allocator) {}
}
impl Value for IcmpFilter {
    unsafe fn copy(source: &Self, target: *mut Self, _: &Allocator) -> bool {
        unsafe {
            target.write(Self {
                mode: source.mode,
                kind: source.kind,
                code: source.code,
                code_valid: source.code_valid,
            })
        };
        true
    }
    unsafe fn dispose(_: *mut Self, _: &Allocator) {}
}
impl Value for IpProtocolFilter {
    unsafe fn copy(source: &Self, target: *mut Self, _: &Allocator) -> bool {
        unsafe {
            target.write(Self {
                mode: source.mode,
                protocol: source.protocol,
            })
        };
        true
    }
    unsafe fn dispose(_: *mut Self, _: &Allocator) {}
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_collection_add(
    kind: u32,
    head: *mut c_void,
    filter: *const c_void,
    allocator: *const Allocator,
) -> bool {
    if head.is_null() || filter.is_null() || allocator.is_null() {
        return false;
    }
    let allocator = unsafe { &*allocator };
    let node = unsafe {
        match kind {
            0 => add(head.cast(), &*filter.cast::<PortFilter>(), false, allocator),
            1 => add(head.cast(), &*filter.cast::<IcmpFilter>(), false, allocator),
            2 => add(
                head.cast(),
                &*filter.cast::<IpProtocolFilter>(),
                false,
                allocator,
            ),
            _ => ptr::null_mut(),
        }
    };
    !node.is_null()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_collection_copy(
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
            0 => copy::<PortFilter>(target.cast(), source.cast(), allocator),
            1 => copy::<IcmpFilter>(target.cast(), source.cast(), allocator),
            2 => copy::<IpProtocolFilter>(target.cast(), source.cast(), allocator),
            _ => false,
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_collection_destroy(
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
            0 => destroy::<PortFilter>(head.cast(), allocator),
            1 => destroy::<IcmpFilter>(head.cast(), allocator),
            2 => destroy::<IpProtocolFilter>(head.cast(), allocator),
            _ => {}
        }
    }
}
unsafe fn any<T>(head: *const *mut Node<T>, matches: impl Fn(&T) -> bool) -> bool {
    let mut node = unsafe { head.read() };
    if node.is_null() {
        return true;
    }
    while !node.is_null() {
        if matches(unsafe { &(*node).value }) {
            return true;
        }
        node = unsafe { (*node).next };
    }
    false
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_collection_matches(
    kind: u32,
    head: *const c_void,
    first: u16,
    second: u8,
) -> bool {
    if head.is_null() {
        return false;
    }
    unsafe {
        match kind {
            0 => any::<PortFilter>(head.cast(), |filter| filter.matches(first)),
            1 => any::<IcmpFilter>(head.cast(), |filter| filter.matches(first as u8, second)),
            2 => any::<IpProtocolFilter>(head.cast(), |filter| filter.matches(first as u8)),
            _ => false,
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_collection_deny_empty(
    kind: u32,
    head: *mut c_void,
    allocator: *const Allocator,
) -> bool {
    if kind > 2 || head.is_null() || allocator.is_null() {
        return false;
    }
    if !unsafe { head.cast::<*mut c_void>().read() }.is_null() {
        return true;
    }
    let allocator = unsafe { &*allocator };
    let node = unsafe {
        match kind {
            0 => add(
                head.cast(),
                &PortFilter {
                    from: 0,
                    to: 0,
                    negated: true,
                },
                false,
                allocator,
            ),
            1 => add(
                head.cast(),
                &IcmpFilter {
                    mode: SKIP,
                    kind: 0,
                    code: 0,
                    code_valid: false,
                },
                false,
                allocator,
            ),
            _ => add(
                head.cast(),
                &IpProtocolFilter {
                    mode: SKIP,
                    protocol: 255,
                },
                false,
                allocator,
            ),
        }
    };
    !node.is_null()
}
