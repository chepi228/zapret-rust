//! Rule diagnostics run only between Lua operations and borrow the current fields.
use super::{Cursor, Step};
use crate::{
    logging::LogSink,
    lua_context::Context,
    packet_policy::{zapret_packet_position, zapret_packet_position_overflow},
    protocol::l7payload_str,
};
use std::ffi::{CStr, c_char};

fn direction(incoming: bool) -> &'static CStr {
    if incoming { c"in" } else { c"out" }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_rule_scan_report(
    cursor: &Cursor,
    step: &Step,
    context: *const Context,
    instance: *const c_char,
    voluntary: bool,
    log: LogSink,
) {
    if voluntary {
        unsafe { log(c"* lua '%s' : voluntary cutoff\n".as_ptr(), instance) };
    } else if step.cutoff {
        let range = unsafe { &*step.range };
        let tracked = if unsafe { (*context).track.is_null() } {
            c"disabled"
        } else {
            c"enabled"
        };
        unsafe {
            log(
                c"* lua '%s' : %s pos %c%llu %c%llu overflow %u %u is beyond range %c%u%c%c%u (ctrack %s)\n".as_ptr(),
                instance,
                direction(cursor.incoming).as_ptr(),
                i32::from(range.from.mode),
                zapret_packet_position(cursor.position, range.from.mode),
                i32::from(range.to.mode),
                zapret_packet_position(cursor.position, range.to.mode),
                u32::from(zapret_packet_position_overflow(cursor.position, range.from.mode)),
                u32::from(zapret_packet_position_overflow(cursor.position, range.to.mode)),
                i32::from(range.from.mode),
                range.from.value,
                i32::from(if range.upper_cutoff { b'<' } else { b'-' }),
                i32::from(range.to.mode),
                range.to.value,
                tracked.as_ptr(),
            )
        };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_rule_range_report(
    cursor: &Cursor,
    step: &Step,
    instance: *const c_char,
    log: LogSink,
) {
    let format = if step.in_range {
        c"* lua '%s' : %s pos %c%llu %c%llu in range %c%u%c%c%u\n"
    } else {
        c"* lua '%s' : %s pos %c%llu %c%llu out of range %c%u%c%c%u\n"
    };
    let range = unsafe { &*step.range };
    unsafe {
        log(
            format.as_ptr(),
            instance,
            direction(cursor.incoming).as_ptr(),
            i32::from(range.from.mode),
            zapret_packet_position(cursor.position, range.from.mode),
            i32::from(range.to.mode),
            zapret_packet_position(cursor.position, range.to.mode),
            i32::from(range.from.mode),
            range.from.value,
            i32::from(if range.upper_cutoff { b'<' } else { b'-' }),
            i32::from(range.to.mode),
            range.to.value,
        )
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_rule_payload_report(
    cursor: &Cursor,
    step: &Step,
    instance: *const c_char,
    log: LogSink,
) {
    let accepts = step.accepts_payload;
    let format = if accepts {
        c"* lua '%s' : payload_type '%s' satisfy filter\n"
    } else {
        c"* lua '%s' : payload_type '%s' does not satisfy filter\n"
    };
    unsafe {
        log(format.as_ptr(), instance, l7payload_str(cursor.payload));
        if accepts {
            log(c"* lua '%s' : desync\n".as_ptr(), instance);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_report_missing_function(name: *const c_char, log: LogSink) {
    unsafe { log(c"desync function '%s' does not exist\n".as_ptr(), name) };
}
