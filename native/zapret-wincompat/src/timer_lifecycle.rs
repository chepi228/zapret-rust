//! The timer dispatcher releases every borrow before the engine calls Lua.
use crate::timers::{
    TimerInfo, TimerPool, zapret_timer_after, zapret_timer_due, zapret_timer_finish,
    zapret_timer_next, zapret_timer_remove,
};

#[repr(C)]
#[derive(Default)]
struct State {
    entry: u32,
    stage: u32,
    status: u32,
    succeeded: u32,
    now: u64,
    after: u64,
    output: u64,
    info: TimerInfo,
    removed: TimerInfo,
}
fn emit(s: &mut State, next: u32, op: u32) -> u32 {
    s.stage = next;
    op
}
fn step(s: &mut State) -> u32 {
    match s.entry {
        1 => match s.stage {
            0 => emit(s, 1, 12),
            1 => {
                if s.status != 0 {
                    emit(s, 2, 13)
                } else {
                    0
                }
            }
            2 => {
                if s.status != 0 {
                    emit(s, 3, 14)
                } else {
                    emit(s, 1, 12)
                }
            }
            3 => emit(s, 1, 12),
            _ => 0,
        },
        2 => match s.stage {
            0 => emit(s, 1, 2),
            1 => emit(s, 2, 11),
            _ => 0,
        },
        3 => match s.stage {
            0 => {
                if s.now == 0 {
                    emit(s, 1, 1)
                } else {
                    emit(s, 2, 2)
                }
            }
            1 => emit(s, 2, 2),
            2 => emit(s, 3, 3),
            3 => {
                if s.status != 0 {
                    s.after = s.info.id;
                    emit(s, 4, 4)
                } else {
                    emit(s, 11, 11)
                }
            }
            4 => {
                s.succeeded = u32::from(s.status != 0);
                emit(s, 5, 5)
            }
            5 => {
                if s.status != 0 {
                    emit(s, 6, 6)
                } else {
                    emit(s, 10, 10)
                }
            }
            6 => emit(s, 7, 7),
            7 => emit(s, 8, 8),
            8 => emit(s, 9, 9),
            9 => emit(s, 10, 10),
            10 => {
                if s.status != 0 {
                    s.after = 0;
                    emit(s, 2, 2)
                } else {
                    emit(s, 3, 3)
                }
            }
            _ => 0,
        },
        _ => 0,
    }
}
#[unsafe(no_mangle)]
extern "C" fn zapret_timer_lifecycle_step(state: &mut State) -> u32 {
    step(state)
}

// The slot and dirty flag remain in the engine, so a callback can replace
// the pool between calls. Destruction passes a null dirty flag.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_timer_lifecycle_native_step(
    state: &mut State,
    slot: *mut *mut TimerPool,
    dirty: *mut bool,
) -> u32 {
    loop {
        state.status = match step(state) {
            2 => {
                unsafe { dirty.write(false) };
                continue;
            }
            3 => unsafe {
                zapret_timer_due(slot.read(), state.after, state.now, &mut state.info) as u32
            },
            5 => unsafe {
                zapret_timer_finish(
                    slot,
                    state.info.id,
                    state.now,
                    state.succeeded as i32,
                    &mut state.removed,
                ) as u32
            },
            10 => u32::from(unsafe { dirty.read() }),
            11 => {
                state.output = unsafe { zapret_timer_next(slot.read()) };
                return 0;
            }
            12 => unsafe { zapret_timer_after(slot.read(), 0, &mut state.info) as u32 },
            13 => unsafe { zapret_timer_remove(slot, state.info.id, &mut state.info) as u32 },
            operation => return operation,
        };
    }
}

const _: () = {
    assert!(size_of::<TimerInfo>() == 40);
    assert!(size_of::<State>() == 120);
};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::timers::zapret_timer_set;
    use std::ptr;

    #[test]
    fn run_samples_time_then_releases_removed_refs_after_vm() {
        let mut s = State {
            entry: 3,
            ..State::default()
        };
        let mut ops = Vec::new();
        let mut due = 0;
        loop {
            let op = step(&mut s);
            if op == 0 {
                break;
            }
            ops.push(op);
            match op {
                1 => s.now = 100,
                3 => {
                    s.status = u32::from(due == 0);
                    due += 1;
                    s.info.id = 5;
                }
                4 => s.status = 0,
                5 => s.status = 1,
                10 => s.status = 0,
                11 => s.output = 150,
                _ => {}
            }
            assert!(ops.len() < 30);
        }
        assert_eq!(ops, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 3, 11]);
        assert_eq!(s.output, 150);
        assert_eq!(s.succeeded, 0);
        assert_eq!(s.after, 5);
    }
    #[test]
    fn callback_dirty_restart_resets_cursor_after_finish() {
        let mut s = State {
            entry: 3,
            now: 100,
            ..State::default()
        };
        let mut ops = Vec::new();
        let mut due = 0;
        loop {
            let op = step(&mut s);
            if op == 0 {
                break;
            }
            ops.push(op);
            match op {
                3 => {
                    if due > 0 {
                        assert_eq!(s.after, 0);
                    }
                    s.status = u32::from(due == 0);
                    s.info.id = 99;
                    due += 1;
                }
                4 => s.status = 1,
                5 => {
                    assert_eq!(s.succeeded, 1);
                    s.status = 0;
                }
                10 => s.status = 1,
                11 => s.output = 0,
                _ => {}
            }
            assert!(ops.len() < 30);
        }
        assert_eq!(ops, [2, 3, 4, 5, 10, 2, 3, 11]);
    }
    #[test]
    fn destruction_queries_current_pool_again_after_each_unref() {
        let mut s = State {
            entry: 1,
            ..State::default()
        };
        let mut ops = Vec::new();
        let mut visited = 0;
        loop {
            let op = step(&mut s);
            if op == 0 {
                break;
            }
            ops.push(op);
            match op {
                12 => {
                    s.status = u32::from(visited < 2);
                    visited += 1;
                }
                13 => s.status = u32::from(visited == 1),
                _ => {}
            }
            assert!(ops.len() < 20);
        }
        assert_eq!(ops, [12, 13, 14, 12, 13, 12]);
    }
    #[test]
    fn next_clears_dirty_before_scheduler_query() {
        let mut s = State {
            entry: 2,
            ..State::default()
        };
        assert_eq!(step(&mut s), 2);
        assert_eq!(step(&mut s), 11);
        s.output = 999;
        assert_eq!(step(&mut s), 0);
        assert_eq!(s.output, 999);
    }

    #[test]
    fn native_dispatch_reacquires_the_slot_after_a_lua_callback() {
        let mut slot = ptr::null_mut();
        let mut dirty = true;
        let mut info = TimerInfo::default();
        let name = c"timer".as_ptr();
        let mut dispatch = State {
            entry: 3,
            now: 20,
            ..State::default()
        };
        unsafe {
            assert_eq!(
                zapret_timer_set(&mut slot, name, &info, 20, &mut dispatch.info),
                0
            );
            assert_eq!(
                zapret_timer_lifecycle_native_step(&mut dispatch, &mut slot, &mut dirty),
                4
            );
            assert!(!dirty);

            // The callback removes the active timer and creates a replacement.
            assert_eq!(
                zapret_timer_remove(&mut slot, dispatch.info.id, &mut info),
                1
            );
            assert!(slot.is_null());
            assert_eq!(
                zapret_timer_set(&mut slot, name, &info, 31, &mut dispatch.removed),
                0
            );
            dirty = true;
            dispatch.status = 1;
            assert_eq!(
                zapret_timer_lifecycle_native_step(&mut dispatch, &mut slot, &mut dirty),
                0
            );
            assert!(!dirty);
            assert_eq!(dispatch.output, 31);

            let mut destroy = State {
                entry: 1,
                ..State::default()
            };
            assert_eq!(
                zapret_timer_lifecycle_native_step(&mut destroy, &mut slot, ptr::null_mut()),
                14
            );
            assert_ne!(destroy.info.id, dispatch.info.id);
            assert!(slot.is_null());
            assert_eq!(
                zapret_timer_lifecycle_native_step(&mut destroy, &mut slot, ptr::null_mut()),
                0
            );
        }
    }
}
