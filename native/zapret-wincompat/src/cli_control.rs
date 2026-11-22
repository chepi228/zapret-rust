//! Remaining option control and reset of the next profile's transient context.
use crate::packet_policy::{Limit, Range};
use std::{
    ffi::{c_char, c_void},
    ptr,
};
#[repr(C)]
struct Target {
    flow: *mut c_void,
    profile: *mut c_void,
    skip: *mut bool,
    template: *mut bool,
    caches: [*mut *mut c_void; 4],
    payload: *mut u64,
    incoming: *mut Range,
    outgoing: *mut Range,
    dry: *mut bool,
}
#[repr(C)]
struct Ops {
    next: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> u32>,
    label: Option<unsafe extern "C" fn(*mut c_void, bool, *const c_char) -> u32>,
    import: Option<unsafe extern "C" fn(*const c_void, *const c_char) -> u32>,
}
fn valid<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
const fn range(mode: u8) -> Range {
    Range {
        from: Limit { mode, value: 0 },
        to: Limit { mode, value: 0 },
        upper_cutoff: false,
    }
}
pub(super) const DEFAULT_INCOMING: Range = range(b'x');
pub(super) const DEFAULT_OUTGOING: Range = range(b'a');
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_control(
    kind: u32,
    text: *const c_char,
    target: *const Target,
    ops: *const Ops,
) -> u32 {
    if kind > 8 || !valid(target) || !valid(ops) {
        return 6;
    }
    let target = unsafe { &*target };
    let ops = unsafe { &*ops };
    match kind {
        0 => {
            if target.flow.is_null()
                || !target.caches.iter().all(|&slot| valid(slot))
                || !valid(target.payload)
                || !valid(target.incoming)
                || !valid(target.outgoing)
            {
                return 6;
            }
            let Some(next) = ops.next else {
                return 6;
            };
            let status = unsafe { next(target.flow, text) };
            if status != 0 {
                return status;
            }
            unsafe {
                for &slot in &target.caches {
                    slot.write(ptr::null_mut());
                }
                target.payload.write(0);
                target.incoming.write(DEFAULT_INCOMING);
                target.outgoing.write(DEFAULT_OUTGOING);
            }
            0
        }
        1 => {
            if !valid(target.skip) {
                return 6;
            }
            unsafe { target.skip.write(true) };
            0
        }
        2..=4 => {
            if target.profile.is_null() || (kind == 2 && !valid(target.template)) {
                return 6;
            }
            let Some(label) = ops.label else {
                return 6;
            };
            let status = unsafe { label(target.profile, kind == 4, text) };
            if status == 0 && kind == 2 {
                unsafe { target.template.write(true) };
            }
            status
        }
        5 => {
            if target.flow.is_null() || text.is_null() {
                return 6;
            }
            let Some(import) = ops.import else {
                return 6;
            };
            unsafe { import(target.flow, text) }
        }
        6 => {
            if !valid(target.dry) {
                return 6;
            }
            unsafe { target.dry.write(true) };
            0
        }
        7 => 8,
        _ => 0,
    }
}

type PublishProfile = unsafe extern "C" fn(*const c_void, *mut c_void, *mut c_void);

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_control_apply(
    kind: u32,
    text: *const c_char,
    target: &Target,
    ops: &Ops,
    entry_slot: *mut c_void,
    profile_slot: *mut c_void,
    publish: PublishProfile,
) -> i32 {
    match unsafe { zapret_cli_control(kind, text, target, ops) } {
        0 => {
            if kind == 0 {
                // A successful new profile resets the transient options before
                // the current native entry and profile addresses are published.
                unsafe { publish(target.flow, entry_slot, profile_slot) };
            }
            1
        }
        8 => 2,
        status => (-1i32).wrapping_sub(status as i32),
    }
}

#[cfg(windows)]
const _: () = {
    let pointer = size_of::<*mut c_void>();
    assert!(size_of::<Target>() == 12 * pointer);
    assert!(size_of::<Ops>() == 3 * pointer);
};
