//! Host timer scheduling across the pinned Win64 LuaJIT SEH ABI.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::offset_of,
    ptr,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("The host timer entry requires the Win64 LuaJIT SEH ABI");

const LUA_OFFSET: usize = 16_888;
const REGISTRY: c_int = -10_000;
const DESTROY: u32 = 1;
const RUN: u32 = 3;

const SAMPLE_CLOCK: u32 = 1;
const FIRE: u32 = 4;
const PUSH_REMOVED_NAME: u32 = 6;
const REPORT_REMOVAL: u32 = 7;
const POP_REMOVED_NAME: u32 = 8;
const RELEASE_REMOVED: u32 = 9;
const RELEASE_CURRENT: u32 = 14;

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct TimerPool {
    _opaque: [u8; 0],
}

#[repr(C)]
struct Params {
    _prefix: [u8; LUA_OFFSET],
    lua: *mut LuaState,
}

#[derive(Default)]
#[repr(C)]
struct Timer {
    id: u64,
    period: u64,
    fires: u32,
    name: c_int,
    function: c_int,
    data: c_int,
    oneshot: u32,
}

#[derive(Default)]
#[repr(C)]
struct State {
    entry: u32,
    stage: u32,
    status: u32,
    succeeded: u32,
    now: u64,
    after: u64,
    output: u64,
    current: Timer,
    removed: Timer,
}

#[repr(C)]
struct TimerLog {
    format: *const c_char,
    reason: *const c_char,
}

const _: () = {
    assert!(size_of::<Params>() == 16_896 && offset_of!(Params, lua) == LUA_OFFSET);
    assert!(size_of::<Timer>() == 40 && offset_of!(Timer, name) == 20);
    assert!(offset_of!(Timer, function) == 24 && offset_of!(Timer, data) == 28);
    assert!(offset_of!(Timer, oneshot) == 32);
    assert!(size_of::<State>() == 120 && offset_of!(State, now) == 16);
    assert!(offset_of!(State, current) == 40 && offset_of!(State, removed) == 80);
    assert!(size_of::<TimerLog>() == 16 && offset_of!(TimerLog, reason) == 8);
};

unsafe extern "C" {
    static mut params: Params;
    fn zapret_timer_lifecycle_native_step(
        state: &mut State,
        pool: *mut *mut TimerPool,
        dirty: *mut bool,
    ) -> u32;
    fn zapret_lua_timer_report(removed: bool, succeeded: bool) -> TimerLog;
    fn boottime_ms() -> u64;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn abort() -> !;
}

unsafe extern "C-unwind" {
    fn lua_rawgeti(lua: *mut LuaState, table: c_int, index: c_int);
    fn lua_tolstring(lua: *mut LuaState, index: c_int, size: *mut usize) -> *const c_char;
    fn lua_pcall(lua: *mut LuaState, nargs: c_int, results: c_int, handler: c_int) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_dlog_error();
    fn zapret_timer_unref(timer: *const Timer);
}

unsafe fn vm() -> *mut LuaState {
    unsafe { (&raw const params.lua).read() }
}

unsafe fn dispatch(entry: u32, pool: *mut *mut TimerPool, dirty: *mut bool, now: u64) -> u64 {
    let mut state = State {
        entry,
        now,
        ..State::default()
    };
    // The scheduler completes each native mutation before the VM is entered.
    // The callback may replace the pool or mark it dirty before the next step.
    unsafe {
        loop {
            match zapret_timer_lifecycle_native_step(&mut state, pool, dirty) {
                0 => return state.output,
                SAMPLE_CLOCK => state.now = boottime_ms(),
                FIRE => {
                    lua_rawgeti(vm(), REGISTRY, state.current.function);
                    lua_rawgeti(vm(), REGISTRY, state.current.name);
                    lua_rawgeti(vm(), REGISTRY, state.current.data);
                    let report = zapret_lua_timer_report(false, false);
                    let name = lua_tolstring(vm(), -2, ptr::null_mut());
                    DLOG(
                        report.format,
                        name,
                        state.current.period,
                        state.current.oneshot,
                        state.current.fires,
                    );
                    let succeeded = lua_pcall(vm(), 2, 0, 0) == 0;
                    if !succeeded {
                        lua_dlog_error();
                    }
                    state.status = u32::from(succeeded);
                }
                PUSH_REMOVED_NAME => lua_rawgeti(vm(), REGISTRY, state.removed.name),
                REPORT_REMOVAL => {
                    let report = zapret_lua_timer_report(true, state.succeeded != 0);
                    let name = lua_tolstring(vm(), -1, ptr::null_mut());
                    DLOG(report.format, name, report.reason);
                }
                POP_REMOVED_NAME => lua_settop(vm(), -2),
                RELEASE_REMOVED => zapret_timer_unref(&raw const state.removed),
                RELEASE_CURRENT => zapret_timer_unref(&raw const state.current),
                _ => abort(),
            }
        }
    }
}

/// # Safety
/// The pool slot belongs to the active LuaJIT engine on its owning thread.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn TimerPoolDestroy(pool: *mut *mut TimerPool) {
    unsafe { dispatch(DESTROY, pool, ptr::null_mut(), 0) };
}

/// # Safety
/// The pool and dirty slots remain valid across callbacks on the engine's LuaJIT thread.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn TimerPoolRun(
    pool: *mut *mut TimerPool,
    dirty: *mut bool,
    now: u64,
) -> u64 {
    unsafe { dispatch(RUN, pool, dirty, now) }
}
