//! Windows clock, timer, and VM bindings for the existing idle scheduler.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_long},
    mem::{MaybeUninit, offset_of, size_of},
    ptr,
    sync::atomic::{AtomicI32, Ordering},
};

#[cfg(not(all(windows, any(target_arch = "x86", target_arch = "x86_64"))))]
compile_error!("The idle entry requires the Windows x86 or x64 ABI");

#[path = "windows_startup_params.rs"]
mod layout;
use layout::PARAMS;

#[repr(C)]
struct TimerPool {
    opaque: [u8; 0],
}

#[repr(C, align(8))]
struct Params {
    before_timers: [MaybeUninit<u8>; PARAMS.timers],
    timers: *mut TimerPool,
    timers_dirty: bool,
    after_dirty: [MaybeUninit<u8>; PARAMS.size - PARAMS.timers_dirty - size_of::<bool>()],
}

#[repr(C)]
struct Timespec64 {
    seconds: i64,
    nanoseconds: c_long,
}

#[repr(C)]
struct TimerOps {
    active: extern "C" fn() -> bool,
    dirty: extern "C" fn() -> bool,
    next: extern "C" fn() -> u64,
    now: extern "C" fn() -> u64,
    run: extern "C-unwind" fn(u64) -> u64,
}

const _: () = {
    assert!(size_of::<Params>() == PARAMS.size);
    assert!(offset_of!(Params, timers) == PARAMS.timers);
    assert!(offset_of!(Params, timers_dirty) == PARAMS.timers_dirty);
    assert!(size_of::<Timespec64>() == 16 && offset_of!(Timespec64, nanoseconds) == 8);
    let pointer = size_of::<usize>();
    assert!(size_of::<TimerOps>() == 5 * pointer && offset_of!(TimerOps, run) == 4 * pointer);
};

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

unsafe extern "C" {
    static mut params: Params;
    static bQuit: AtomicI32;
    safe fn boottime_ms() -> u64;
    fn zapret_timer_next_dirty(pool: *const TimerPool, dirty: *mut bool) -> u64;
    fn nanosleep64(request: *const Timespec64, remaining: *mut Timespec64) -> c_int;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_CONDUP(format: *const c_char, ...) -> c_int;
    fn zapret_capture_idle_report(quitting: bool, debug: Log, console: Log);
}

unsafe extern "C-unwind" {
    fn TimerPoolRun(pool: *mut *mut TimerPool, dirty: *mut bool, now: u64) -> u64;
    fn lua_do_gc();
    fn zapret_idle_loop(
        timers: *const TimerOps,
        quitting: extern "C" fn() -> bool,
        sleep: extern "C" fn(u64),
        prepare: extern "C-unwind" fn(),
        report: extern "C" fn(bool),
    );
}

#[unsafe(no_mangle)]
extern "C" fn loop_quitting() -> bool {
    unsafe { bQuit.load(Ordering::SeqCst) != 0 }
}

extern "C" fn timers_active() -> bool {
    unsafe { !(&raw const params.timers).read().is_null() }
}

extern "C" fn timers_dirty() -> bool {
    unsafe { (&raw const params.timers_dirty).read() }
}

extern "C" fn timers_next() -> u64 {
    unsafe {
        zapret_timer_next_dirty(
            (&raw const params.timers).read(),
            &raw mut params.timers_dirty,
        )
    }
}

extern "C-unwind" fn timers_run(now: u64) -> u64 {
    unsafe { TimerPoolRun(&raw mut params.timers, &raw mut params.timers_dirty, now) }
}

#[unsafe(export_name = "zapret_capture_timers")]
static CAPTURE_TIMERS: TimerOps = TimerOps {
    active: timers_active,
    dirty: timers_dirty,
    next: timers_next,
    now: boottime_ms,
    run: timers_run,
};

#[unsafe(no_mangle)]
extern "C" fn loop_sleep_ms(delay: u64) {
    let request = Timespec64 {
        seconds: (delay / 1_000) as i64,
        nanoseconds: ((delay % 1_000) * 1_000_000) as c_long,
    };
    unsafe { nanosleep64(&request, ptr::null_mut()) };
}

#[unsafe(no_mangle)]
extern "C-unwind" fn loop_prepare() {
    unsafe { lua_do_gc() };
}

extern "C" fn idle_report(quitting: bool) {
    unsafe { zapret_capture_idle_report(quitting, DLOG, DLOG_CONDUP) };
}

#[unsafe(export_name = "NoInterceptLoop")]
extern "C-unwind" fn no_intercept_loop() {
    unsafe {
        zapret_idle_loop(
            &CAPTURE_TIMERS,
            loop_quitting,
            loop_sleep_ms,
            loop_prepare,
            idle_report,
        )
    };
}
