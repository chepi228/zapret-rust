//! Execution-plan metadata is selected before the C adapter enters the VM.
use super::Rule;
use crate::packet_policy::Range;
use crate::{
    lua_context::{Context, aligned},
    profile_config::{profile_lua, profile_number},
};
use std::{
    ffi::{c_char, c_void},
    ptr,
};
#[repr(C)]
struct Cursor {
    next: *const Rule,
    number: u32,
    completed: u32,
    profile: u32,
    incoming: bool,
}
#[repr(C)]
struct Entry {
    name: *const c_char,
    args: *const c_void,
    range: *const Range,
    payload: u64,
    number: u32,
    index: u32,
    instance: [c_char; 256],
}
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_plan_begin_context(
    context: *const Context,
    output: *mut Cursor,
) -> bool {
    if !aligned(context) || !valid(output) {
        return false;
    }
    let profile = unsafe { (*context).profile };
    if !aligned(profile.cast::<u64>()) {
        return false;
    }
    unsafe {
        zapret_lua_plan_begin(
            profile_lua(profile).cast(),
            (*context).number,
            profile_number(profile),
            (*context).incoming != 0,
            output,
        )
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_plan_begin(
    first: *const Rule,
    completed: u32,
    profile: u32,
    incoming: bool,
    cursor: *mut Cursor,
) -> bool {
    if !valid(cursor) || !first.is_null() && !first.is_aligned() {
        return false;
    }
    unsafe {
        cursor.write(Cursor {
            next: first,
            number: 0,
            completed,
            profile,
            incoming,
        })
    };
    true
}
// 0 end, 1 borrowed entry, 2 invalid metadata or an unrepresentable rule number.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_plan_next(cursor: *mut Cursor, output: *mut Entry) -> u32 {
    if !valid(cursor) || !valid(output) {
        return 2;
    }
    let cursor = unsafe { &mut *cursor };
    while !cursor.next.is_null() {
        if !cursor.next.is_aligned() || cursor.number == u32::MAX {
            return 2;
        }
        let rule = unsafe { &*cursor.next };
        cursor.next = rule.next;
        cursor.number += 1;
        if cursor.number <= cursor.completed {
            continue;
        }
        let mut entry = Entry {
            name: rule.name,
            args: ptr::addr_of!(rule.args).cast(),
            range: if cursor.incoming {
                ptr::addr_of!(rule.incoming)
            } else {
                ptr::addr_of!(rule.outgoing)
            },
            payload: rule.payload_mask,
            number: cursor.number,
            index: cursor.number - cursor.completed,
            instance: [0; 256],
        };
        unsafe {
            crate::lua_instance::zapret_desync_instance(
                rule.name,
                cursor.profile,
                cursor.number,
                entry.instance.as_mut_ptr(),
                entry.instance.len(),
            );
            output.write(entry);
        }
        return 1;
    }
    0
}
#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Cursor>() == 24);
    assert!(size_of::<Entry>() == 296);
};
