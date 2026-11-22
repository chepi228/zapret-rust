//! Select the script rules for a packet. The Lua VM runs between calls to
//! these iterators, so a Lua error never has to unwind a Rust rule iterator.
#[cfg(windows)]
mod diagnostics;
#[cfg(windows)]
mod plan;
use crate::{
    conntrack::{Position, Positions},
    packet_policy::{Range, zapret_check_packet_cutoff, zapret_check_packet_range},
    play_prolog::connection,
    protocol::l7_payload_match,
};
use std::{
    ffi::{c_char, c_void},
    ptr,
};

#[repr(C)]
struct Direction {
    positions: *const Positions,
    current: *const Position,
    opposite: *const Position,
    cutoff: *mut bool,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_rule_direction(
    track: *mut c_void,
    mut positions: *const Positions,
    incoming: bool,
    server: bool,
    result: *mut Direction,
) -> bool {
    let mut cutoff = ptr::null_mut();
    if !track.is_null() {
        let connection = unsafe { connection(track) };
        cutoff = if incoming {
            unsafe { ptr::addr_of_mut!((*connection).lua_in_cutoff) }
        } else {
            unsafe { ptr::addr_of_mut!((*connection).lua_out_cutoff) }
        };
        if unsafe { cutoff.read() } {
            return false;
        }
        if positions.is_null() {
            positions = unsafe { track.byte_add(24).cast() };
        }
    }
    let (mut current, mut opposite) = (ptr::null(), ptr::null());
    if !positions.is_null() {
        current = unsafe { ptr::addr_of!((*positions).client) };
        opposite = unsafe { ptr::addr_of!((*positions).server) };
        if incoming ^ server {
            std::mem::swap(&mut current, &mut opposite);
        }
    }
    unsafe {
        result.write(Direction {
            positions,
            current,
            opposite,
            cutoff,
        })
    };
    true
}

// Prefix of the C function list node through its next link. The VM uses the
// C-owned name and arguments after each call returns.
#[repr(C)]
pub(super) struct Rule {
    pub(super) name: *const c_char,
    pub(super) payload_mask: u64,
    pub(super) incoming: Range,
    pub(super) outgoing: Range,
    pub(super) args: *const c_void,
    pub(super) next: *mut Rule,
}

#[repr(C)]
struct Cursor {
    next: *mut Rule,
    position: *const Position,
    number: u32,
    payload: u32,
    incoming: bool,
    all_cutoff: bool,
    wanted: bool,
}

#[repr(C)]
struct Step {
    rule: *mut Rule,
    range: *const Range,
    number: u32,
    accepts_payload: bool,
    in_range: bool,
    cutoff: bool,
}

impl Cursor {
    unsafe fn next_step(&mut self) -> Option<Step> {
        let rule = self.next;
        if rule.is_null() {
            return None;
        }
        unsafe {
            self.next = (*rule).next;
            self.number = self.number.wrapping_add(1);
            Some(Step {
                rule,
                range: if self.incoming {
                    ptr::addr_of!((*rule).incoming)
                } else {
                    ptr::addr_of!((*rule).outgoing)
                },
                number: self.number,
                accepts_payload: l7_payload_match(self.payload, (*rule).payload_mask),
                in_range: false,
                cutoff: false,
            })
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_scan_next(cursor: &mut Cursor, result: *mut Step) -> bool {
    // Once a function is open and the payload matches any rule, the result
    // of the preflight scan is known. No more Lua table lookups are needed.
    while cursor.all_cutoff || !cursor.wanted {
        let Some(mut step) = (unsafe { cursor.next_step() }) else {
            break;
        };
        cursor.wanted |= step.accepts_payload;
        if cursor.all_cutoff {
            step.cutoff = unsafe { zapret_check_packet_cutoff(cursor.position, &*step.range) };
            unsafe { result.write(step) };
            return true;
        }
    }
    false
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_scan_observe(cursor: &mut Cursor, step: &Step, voluntary: bool) {
    cursor.all_cutoff &= step.cutoff || voluntary;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_scan_result(cursor: &Cursor, direction: &Direction) -> u32 {
    if cursor.all_cutoff {
        if !direction.cutoff.is_null() {
            unsafe { direction.cutoff.write(true) };
        }
        0
    } else if !cursor.wanted {
        1
    } else {
        2
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_invoke_next(
    cursor: &mut Cursor,
    result: *mut Step,
    allow_skip: bool,
) -> bool {
    while let Some(mut step) = unsafe { cursor.next_step() } {
        step.in_range = unsafe { zapret_check_packet_range(cursor.position, &*step.range) };
        if !allow_skip || step.in_range && step.accepts_payload {
            unsafe { result.write(step) };
            return true;
        }
    }
    false
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_lua_verdict(value: i64) -> i32 {
    if value & !7 == 0 { value as i32 } else { -1 }
}
