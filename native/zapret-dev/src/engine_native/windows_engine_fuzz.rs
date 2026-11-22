//! Run the existing local diagnostic loop against the engine entry.
use super::{DLOG_CONDUP, dpi_desync_packet, params};
use core::{
    ffi::{c_char, c_void},
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicI32, Ordering},
};

const MAXIMUM_PACKET: usize = 69_632;

#[derive(Default)]
#[repr(C)]
struct State {
    stage: u32,
    iteration: u32,
    length: usize,
    modified: usize,
    first: u8,
}

const _: () = assert!(size_of::<State>() == 8 + 3 * size_of::<usize>());

unsafe extern "C" {
    static bQuit: AtomicI32;
    fn zapret_random() -> i32;
    fn malloc(size: usize) -> *mut c_void;
    fn free(data: *mut c_void);
    fn zapret_helper_fill_random_bytes(output: *mut u8, length: usize);
    fn zapret_engine_fuzz_next(state: &mut State, count: u32, observed: usize) -> u32;
    fn zapret_engine_fuzz_name(direction: u32, draw: u32) -> *const c_char;
    fn zapret_engine_fuzz_message(count: u32) -> *const c_char;
}

pub(super) unsafe fn run() {
    let message = unsafe { zapret_engine_fuzz_message(params.fuzz) };
    if message.is_null() {
        return;
    }
    unsafe { DLOG_CONDUP(message, params.fuzz) };
    let count = unsafe { params.fuzz };
    let mut state = State::default();
    let mut packet: *mut u8 = ptr::null_mut();
    let mut modified = MaybeUninit::<[u8; MAXIMUM_PACKET]>::uninit();
    let mut observed = 0;
    unsafe {
        loop {
            match zapret_engine_fuzz_next(&mut state, count, observed) {
                1 => observed = (bQuit.load(Ordering::SeqCst) != 0) as usize,
                2 => {
                    DLOG_CONDUP(c"fuzz ct=%u\n".as_ptr(), state.iteration);
                }
                3 | 7 | 9 => observed = zapret_random() as usize,
                4 => {
                    packet = malloc(state.length).cast();
                    observed = usize::from(!packet.is_null());
                }
                5 => zapret_helper_fill_random_bytes(packet, state.length),
                6 => observed = usize::from(packet.read()),
                8 => packet.write(state.first),
                10 => {
                    let mut length = state.modified;
                    let inbound = zapret_engine_fuzz_name(0, zapret_random() as u32);
                    let outbound = zapret_engine_fuzz_name(1, zapret_random() as u32);
                    dpi_desync_packet(
                        0,
                        inbound,
                        outbound,
                        packet,
                        state.length,
                        modified.as_mut_ptr().cast(),
                        &mut length,
                    );
                }
                11 => free(packet.cast()),
                _ => return,
            }
        }
    }
}
