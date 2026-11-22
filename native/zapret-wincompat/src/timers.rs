//! Lua timer scheduling for the native Windows engine.
//!
//! The engine owns the Lua references. Every Rust call finishes before C invokes
//! Lua, which can re-enter the timer API and mutate the pool.

mod lua;

use std::{
    collections::{BTreeMap, HashMap},
    ffi::{CStr, c_char},
    ops::Bound::{Excluded, Unbounded},
    ptr,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TimerInfo {
    pub(super) id: u64,
    period: u64,
    fires: u32,
    name_ref: i32,
    func_ref: i32,
    data_ref: i32,
    oneshot: u32,
}

struct Timer {
    name: Rc<[u8]>,
    info: TimerInfo,
    due: u64,
}

#[derive(Default)]
pub(super) struct TimerPool {
    names: HashMap<Rc<[u8]>, u64>,
    timers: BTreeMap<u64, Timer>,
}

// The C pool pointer becomes null when its last timer is removed. Use a single
// counter so recreating a pool inside a callback cannot reuse a dispatched ID.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl TimerPool {
    fn set(&mut self, name: &[u8], mut info: TimerInfo, now: u64) -> Option<Option<TimerInfo>> {
        self.names.try_reserve(1).ok()?;
        info.id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        info.fires = 0;
        let name: Rc<[u8]> = Rc::from(name);
        let previous = self
            .names
            .insert(Rc::clone(&name), info.id)
            .and_then(|id| self.timers.remove(&id))
            .map(|timer| timer.info);
        self.timers.insert(
            info.id,
            Timer {
                name,
                info,
                due: now.wrapping_add(info.period),
            },
        );
        Some(previous)
    }

    fn get(&self, name: &[u8]) -> Option<TimerInfo> {
        let id = self.names.get(name)?;
        self.timers.get(id).map(|timer| timer.info)
    }

    fn remove(&mut self, id: u64) -> Option<TimerInfo> {
        let timer = self.timers.remove(&id)?;
        self.names.remove(timer.name.as_ref());
        Some(timer.info)
    }

    fn after(&self, id: u64) -> Option<TimerInfo> {
        self.timers
            .range((Excluded(id), Unbounded))
            .next()
            .map(|(_, timer)| timer.info)
    }

    fn due(&mut self, after: u64, now: u64) -> Option<TimerInfo> {
        let (_, timer) = self
            .timers
            .range_mut((Excluded(after), Unbounded))
            .find(|(_, timer)| timer.due <= now)?;
        timer.info.fires = timer.info.fires.wrapping_add(1);
        Some(timer.info)
    }

    fn finish(&mut self, id: u64, now: u64, succeeded: bool) -> Option<TimerInfo> {
        let timer = self.timers.get_mut(&id)?;
        if succeeded && timer.info.oneshot == 0 {
            // Base the next fire on this pass's time, even after a process pause.
            timer.due = now.wrapping_add(timer.info.period);
            None
        } else {
            self.remove(id)
        }
    }

    fn next(&self) -> u64 {
        self.timers
            .values()
            .map(|timer| timer.due)
            .min()
            .unwrap_or(0)
            .min(i64::MAX as u64)
    }
}

/// # Safety
/// C supplies a valid writable descriptor whenever the result is present.
unsafe fn output(info: Option<TimerInfo>, out: *mut TimerInfo) -> i32 {
    if let Some(info) = info {
        unsafe { out.write(info) };
        1
    } else {
        0
    }
}

/// # Safety
/// C passes the owning slot and writes through it only through this API.
unsafe fn drop_if_empty(slot: &mut *mut TimerPool) {
    if !(unsafe { &**slot }).timers.is_empty() {
        return;
    }
    let pool = std::mem::replace(slot, ptr::null_mut());
    drop(unsafe { Box::from_raw(pool) });
}

// Private ABI for timer_windows.h. Names are NUL-terminated at the boundary.
// TimerInfo values are copied, and no argument is borrowed by later calls.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_set(
    slot: *mut *mut TimerPool,
    name: *const c_char,
    info: *const TimerInfo,
    now: u64,
    previous: *mut TimerInfo,
) -> i32 {
    let slot = unsafe { &mut *slot };
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let info = unsafe { info.read() };
    let result = if slot.is_null() {
        let mut pool = Box::new(TimerPool::default());
        let result = pool.set(name, info, now);
        if result.is_some() {
            *slot = Box::into_raw(pool);
        }
        result
    } else {
        unsafe { &mut **slot }.set(name, info, now)
    };
    match result {
        Some(old) => unsafe { output(old, previous) },
        None => -1,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_timer_get(
    pool: *const TimerPool,
    name: *const c_char,
    out: *mut TimerInfo,
) -> i32 {
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    unsafe { output(pool.as_ref().and_then(|pool| pool.get(name)), out) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_after(
    pool: *const TimerPool,
    id: u64,
    out: *mut TimerInfo,
) -> i32 {
    unsafe { output(pool.as_ref().and_then(|pool| pool.after(id)), out) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_remove(
    slot: *mut *mut TimerPool,
    id: u64,
    out: *mut TimerInfo,
) -> i32 {
    let slot = unsafe { &mut *slot };
    let removed = unsafe { slot.as_mut() }.and_then(|pool| pool.remove(id));
    if removed.is_some() {
        unsafe { drop_if_empty(slot) };
    }
    unsafe { output(removed, out) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_due(
    pool: *mut TimerPool,
    after: u64,
    now: u64,
    out: *mut TimerInfo,
) -> i32 {
    unsafe { output(pool.as_mut().and_then(|pool| pool.due(after, now)), out) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_finish(
    slot: *mut *mut TimerPool,
    id: u64,
    now: u64,
    succeeded: i32,
    out: *mut TimerInfo,
) -> i32 {
    let slot = unsafe { &mut *slot };
    let removed = unsafe { slot.as_mut() }.and_then(|pool| pool.finish(id, now, succeeded != 0));
    if removed.is_some() {
        unsafe { drop_if_empty(slot) };
    }
    unsafe { output(removed, out) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_timer_next(pool: *const TimerPool) -> u64 {
    unsafe { pool.as_ref() }.map_or(0, TimerPool::next)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_timer_next_dirty(pool: *const TimerPool, dirty: &mut bool) -> u64 {
    *dirty = false;
    unsafe { zapret_timer_next(pool) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timer(period: u64, oneshot: bool) -> TimerInfo {
        TimerInfo {
            period,
            oneshot: u32::from(oneshot),
            ..TimerInfo::default()
        }
    }

    #[test]
    fn dispatches_due_timers_in_insertion_order_and_rearms_from_now() {
        let mut pool = TimerPool::default();
        assert_eq!(pool.set(b"first", timer(30, false), 100), Some(None));
        assert_eq!(pool.set(b"second", timer(10, true), 100), Some(None));
        assert_eq!(pool.next(), 110);
        assert!(pool.due(0, 109).is_none());
        let first = pool.due(0, 150).unwrap();
        assert_eq!(first.id, pool.get(b"first").unwrap().id);
        assert_eq!(first.fires, 1);
        assert_eq!(pool.finish(first.id, 150, true), None);
        let second = pool.due(first.id, 150).unwrap();
        assert_eq!(second.id, pool.get(b"second").unwrap().id);
        assert_eq!(pool.finish(second.id, 150, true), Some(second));
        assert_eq!(pool.next(), 180);
        assert_eq!(pool.due(0, 180).unwrap().fires, 2);
        assert!(pool.finish(first.id, 180, false).is_some());
        assert_eq!(pool.next(), 0);
    }

    #[test]
    fn completion_preserves_a_replacement_after_the_old_pool_is_freed() {
        let mut slot = ptr::null_mut();
        let mut info = TimerInfo::default();
        let name = c"timer".as_ptr();
        unsafe {
            assert_eq!(
                zapret_timer_set(&mut slot, name, &timer(10, true), 1, &mut info),
                0
            );
            assert_eq!(zapret_timer_due(slot, 0, 11, &mut info), 1);
            let old = info;
            assert_eq!(zapret_timer_remove(&mut slot, old.id, &mut info), 1);
            assert!(slot.is_null());
            assert_eq!(
                zapret_timer_set(&mut slot, name, &timer(25, false), 11, &mut info),
                0
            );
            assert_eq!(zapret_timer_finish(&mut slot, old.id, 11, 0, &mut info), 0);
            assert_eq!(zapret_timer_next(slot), 36);
            assert_eq!(zapret_timer_get(slot, name, &mut info), 1);
            assert_ne!(info.id, old.id);
            assert_eq!(info.fires, 0);
            assert_eq!(zapret_timer_remove(&mut slot, info.id, &mut info), 1);
            assert!(slot.is_null());
        }
    }

    #[test]
    fn replacement_is_last_in_enumeration() {
        let mut pool = TimerPool::default();
        pool.set(b"first", timer(10, false), 10).unwrap();
        pool.set(b"other", timer(10, false), 10).unwrap();
        let old = pool.get(b"first").unwrap();
        assert_eq!(pool.set(b"first", timer(10, true), 10), Some(Some(old)));
        let next = pool.after(0).unwrap();
        assert_eq!(Some(next), pool.get(b"other"));
        assert_eq!(pool.after(next.id), pool.get(b"first"));
    }
}
