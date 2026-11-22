use crate::{Context, Store};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

pub type SharedStore = Rc<RefCell<Store>>;

/// One pending queue per Lua VM. Store ownership stays rooted until the
/// callback succeeds, the store is discarded, or timer registration fails.
#[derive(Default)]
pub struct StoreScheduler {
    pending: BTreeMap<u64, SharedStore>,
    retired: Vec<u64>,
    scheduled: bool,
}

impl StoreScheduler {
    pub fn updated(
        &mut self,
        store: &SharedStore,
        legacy_file: bool,
        changed: bool,
    ) -> (bool, Option<u64>) {
        let plan = self.plan_update(store, legacy_file, changed);
        if let Some(serial) = plan.1 {
            self.pending.insert(serial, Rc::clone(store));
        }
        plan
    }

    pub fn plan_update(
        &self,
        store: &SharedStore,
        legacy_file: bool,
        changed: bool,
    ) -> (bool, Option<u64>) {
        let state = store.borrow();
        if legacy_file && changed {
            return (!state.disabled, None);
        }
        if !state.dirty || state.disabled {
            return (false, None);
        }
        (
            false,
            (!self.pending.contains_key(&state.serial)).then_some(state.serial),
        )
    }

    pub fn retain(&mut self, store: &SharedStore) -> bool {
        let state = store.borrow();
        if !state.dirty || state.disabled {
            return false;
        }
        self.pending
            .entry(state.serial)
            .or_insert_with(|| Rc::clone(store));
        true
    }

    pub fn discard(&mut self, store: &SharedStore) -> Option<u64> {
        let mut store = store.borrow_mut();
        store.discard();
        self.pending.remove(&store.serial).map(|_| store.serial)
    }

    pub fn finish(&mut self, store: &SharedStore) -> Option<u64> {
        let store = store.borrow();
        if store.dirty && !store.disabled {
            return None;
        }
        self.pending.remove(&store.serial).map(|_| store.serial)
    }

    pub fn wants_timer(&self) -> bool {
        !self.scheduled && !self.pending.is_empty()
    }

    pub fn prepare_timer(&mut self, context: &mut Context, now: f64) -> bool {
        let allowed = context.timer_gate(now, None);
        if !allowed {
            self.clear();
        }
        allowed
    }

    pub fn timer_result(&mut self, context: &mut Context, now: f64, success: bool) -> usize {
        context.timer_gate(now, Some(success));
        if success {
            self.scheduled = true;
            return 0;
        }
        let mut warnings = 0;
        for store in self.pending.values() {
            let mut store = store.borrow_mut();
            if !std::mem::replace(&mut store.timer_warned, true) {
                warnings += 1;
            }
        }
        self.clear();
        warnings
    }

    pub fn timer_fired(&mut self) {
        self.scheduled = false;
    }

    pub fn select(&mut self, now: f64) -> Option<u64> {
        let mut selected = None;
        self.pending.retain(|&serial, store| {
            let Some(due) = store.borrow_mut().due(now) else {
                self.retired.push(serial);
                return false;
            };
            if due <= now && selected.is_none_or(|previous| (due, serial) < previous) {
                selected = Some((due, serial));
            }
            true
        });
        selected.map(|(_, serial)| serial)
    }

    pub fn retired(&mut self) -> Option<u64> {
        self.retired.pop()
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.retired.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    fn dirty_at(time: f64) -> SharedStore {
        let mut store = Store::new(Limits::default(), true).unwrap();
        assert!(store.put("example", Some(2), 100, time));
        Rc::new(RefCell::new(store))
    }

    #[test]
    fn readiness_uses_deadline_then_serial_and_cleans_released_entries() {
        let mut scheduler = StoreScheduler::default();
        let first = dirty_at(1.);
        let second = dirty_at(1.);
        let earlier = dirty_at(0.);
        let first_serial = first.borrow().serial;
        let second_serial = second.borrow().serial;
        let earlier_serial = earlier.borrow().serial;
        assert_eq!(
            scheduler.updated(&second, false, true),
            (false, Some(second_serial))
        );
        assert_eq!(
            scheduler.updated(&first, false, true),
            (false, Some(first_serial))
        );
        assert_eq!(
            scheduler.updated(&earlier, false, true),
            (false, Some(earlier_serial))
        );
        assert_eq!(scheduler.updated(&first, false, true), (false, None));
        assert_eq!(Rc::strong_count(&first), 2);
        assert_eq!(scheduler.select(4.), None);
        assert_eq!(scheduler.select(5.), Some(earlier_serial));
        earlier.borrow_mut().commit(true, 5.);
        assert_eq!(scheduler.finish(&earlier), Some(earlier_serial));
        assert_eq!(scheduler.select(6.), Some(first_serial));
        first.borrow_mut().commit(true, 6.);
        assert_eq!(scheduler.select(6.), Some(second_serial));
        assert_eq!(scheduler.retired(), Some(first_serial));
        assert_eq!(Rc::strong_count(&first), 1);
        assert_eq!(scheduler.discard(&second), Some(second_serial));
        assert!(second.borrow().disabled);
        assert!(!scheduler.wants_timer());
    }

    #[test]
    fn timer_failures_share_retry_and_one_warning_per_store() {
        let mut scheduler = StoreScheduler::default();
        let mut context = Context::new(0);
        let store = dirty_at(1.);
        scheduler.updated(&store, false, true);
        assert!(scheduler.wants_timer());
        assert!(scheduler.prepare_timer(&mut context, 1.));
        assert_eq!(scheduler.timer_result(&mut context, 1., false), 1);
        assert!(store.borrow().dirty);
        assert_eq!(Rc::strong_count(&store), 1);

        scheduler.updated(&store, false, true);
        assert!(!scheduler.prepare_timer(&mut context, 30.));
        assert!(!scheduler.wants_timer());
        scheduler.updated(&store, false, true);
        assert!(scheduler.prepare_timer(&mut context, 31.));
        assert_eq!(scheduler.timer_result(&mut context, 31., false), 0);
        scheduler.updated(&store, false, true);
        assert!(!scheduler.prepare_timer(&mut context, 30.));
        scheduler.updated(&store, false, true);
        assert!(scheduler.prepare_timer(&mut context, 60.));
        assert_eq!(scheduler.timer_result(&mut context, 60., true), 0);
        assert!(!scheduler.wants_timer());
        scheduler.timer_fired();
        assert!(scheduler.wants_timer());
    }
}
