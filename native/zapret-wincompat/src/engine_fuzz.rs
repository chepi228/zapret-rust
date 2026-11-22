//! Preserve the existing local diagnostic loop and its random consumption.
use std::{ffi::c_char, ptr};

const BUFFER_SIZE: usize = 65536 + 4096;

#[repr(C)]
#[derive(Default)]
struct Fuzz {
    stage: u32,
    iteration: u32,
    length: usize,
    modified: usize,
    first: u8,
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_fuzz_next(state: &mut Fuzz, count: u32, observed: usize) -> u32 {
    let next = match state.stage {
        0 if state.iteration < count => 1,
        1 if observed != 0 => 0,
        1 if state.iteration % 1000 == 0 => 2,
        1 | 2 => 3,
        3 => {
            state.length = observed % (BUFFER_SIZE + 1);
            4
        }
        4 if observed != 0 => 5,
        5 if state.length != 0 => 6,
        5 => 9,
        6 if observed == 0 => 7,
        6 => {
            let byte = observed as u8;
            state.first = if byte & 1 != 0 {
                0x40
            } else {
                0x60 | (byte & 0x0f)
            };
            8
        }
        7 => {
            state.first = observed as u8;
            8
        }
        8 => 9,
        9 => {
            state.modified = observed % (BUFFER_SIZE + 1);
            10
        }
        10 => 11,
        11 => {
            state.iteration += 1;
            u32::from(state.iteration < count)
        }
        _ => 0,
    };
    state.stage = next;
    next
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_fuzz_name(direction: u32, draw: u32) -> *const c_char {
    if draw & 1 == 0 {
        ptr::null()
    } else if direction == 0 {
        c"ifin".as_ptr()
    } else {
        c"ifout".as_ptr()
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_engine_fuzz_message(count: u32) -> *const c_char {
    if count == 0 {
        ptr::null()
    } else {
        c"fuzz packet data count=%u\n".as_ptr()
    }
}
