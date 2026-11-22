//! Shared validation, context metadata and error-reporting policy for the Lua VM.
use std::{
    ffi::{CStr, c_char},
    ptr,
};

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_lua_arity_error(
    actual: i32,
    minimum: i32,
    maximum: i32,
    ranged: bool,
) -> *const c_char {
    let error = if ranged {
        (actual < minimum || actual > maximum)
            .then_some(c"%s expect from %d to %d arguments, got %d")
    } else {
        (actual != minimum).then_some(c"%s expect exactly %d arguments, got %d")
    };
    error.map_or(ptr::null(), CStr::as_ptr)
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_context_vm(operation: u32, value: i32) -> u32 {
    match operation {
        0 => u32::from(value == 0), // nil context
        1 => u32::from(value >= 2), // optional direction argument
        2 => u32::from(value != 0), // nil uses the default direction
        3 => {
            if value == 0 {
                1
            } else {
                2
            }
        } // scripted outgoing flag
        4 => {
            if value == 0 {
                2
            } else {
                1
            }
        } // native incoming flag
        5 => u32::from(value != 5), // registry slot needs a table
        6 => u32::from(value == 0), // zero means no custom context reference
        7 => u32::from(value != 0), // negative Lua markers still reach luaL_unref
        _ => 0,
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_context_label(index: u32) -> *const c_char {
    let label = match index {
        0 => c"desync_ctx",
        1 => c"missing ctx",
        2 => c"ctx is invalid",
        3 => c"invalid cutoff state",
        4 => c"invalid execution context",
        5 => c"invalid raw packet view",
        6 => c"invalid execution plan state",
        7 => c"invalid context storage",
        8 => c"func",
        9 => c"func_n",
        10 => c"func_instance",
        11 => c"range",
        12 => c"payload",
        13 => c"payload_filter",
        14 => c"arg",
        15 => c"instance_cutoff",
        16 => c"lua_cutoff",
        17 => c"execution_plan_cancel",
        18 => c"raw_packet",
        _ => return ptr::null(),
    };
    label.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_context_report(event: u32, tracked: bool) -> *const c_char {
    let format = match (event, tracked) {
        (0, _) => c"instance cutoff not possible because missing ctx\n",
        (1, true) => c"instance cutoff for '%s' in=%u out=%u\n",
        (1, false) => {
            c"instance cutoff requested for '%s' in=%u out=%u but not possible without conntrack\n"
        }
        (2, true) => c"lua cutoff from '%s' in=%u out=%u\n",
        (2, false) => {
            c"lua cutoff requested from '%s' in=%u out=%u but not possible without conntrack\n"
        }
        (3, _) => c"execution plan cancel from '%s'\n",
        _ => return ptr::null(),
    };
    format.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_error_report_next(action: u32, string_like: bool, fatal: bool) -> u32 {
    match action {
        0 => 1,                // observe Lua's string predicate (which also accepts numbers)
        1 if string_like => 2, // coerce and borrow the error message
        1 => 4,
        2 => 3,
        3 => 4, // pop after logging, using the currently observed VM
        4 if fatal => 5,
        5 => 6,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_error_report_format(action: u32) -> *const c_char {
    match action {
        3 => c"LUA ERROR: %s\n".as_ptr(),
        5 => c"LUA PANIC: THIS IS FATAL. DYING.\n".as_ptr(),
        _ => ptr::null(),
    }
}
