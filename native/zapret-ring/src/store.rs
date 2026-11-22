use crate::store_bounds::{MAX_BYTES, MAX_RECORDS, MIN_BYTES, TTL};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_SERIAL: AtomicU64 = AtomicU64::new(1);
pub const SAVE_DELAY: f64 = 5.;
pub const RETRY_DELAY: f64 = 30.;
const HEADER: &str = "# ring-store-v2\n";

#[derive(Clone, Debug)]
struct Record {
    key: String,
    n: u32,
    confirmed: u64,
    used: u64,
    previous: Option<usize>,
    next: Option<usize>,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub records: usize,
    pub bytes: usize,
    pub ttl: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS,
            bytes: MAX_BYTES,
            ttl: TTL,
        }
    }
}
impl Limits {
    pub fn valid(self) -> bool {
        (1..=MAX_RECORDS).contains(&self.records)
            && (MIN_BYTES..=MAX_BYTES).contains(&self.bytes)
            && (1..=TTL).contains(&self.ttl)
    }
}

pub struct Store {
    index: HashMap<String, usize>,
    records: Vec<Option<Record>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    pub limits: Limits,
    persistent: bool,
    pub disabled: bool,
    pub dirty: bool,
    pub serial: u64,
    pub legacy: bool,
    pub(crate) timer_warned: bool,
    since: f64,
    retry: Option<f64>,
}
impl Store {
    pub fn new(limits: Limits, persistent: bool) -> Option<Self> {
        if !limits.valid() {
            return None;
        }
        Some(Self {
            index: HashMap::with_capacity(limits.records),
            records: Vec::with_capacity(limits.records),
            free: Vec::new(),
            head: None,
            tail: None,
            limits,
            persistent,
            disabled: false,
            dirty: false,
            serial: NEXT_SERIAL.fetch_add(1, Ordering::Relaxed),
            legacy: false,
            timer_warned: false,
            since: 0.,
            retry: None,
        })
    }
    pub fn len(&self) -> usize {
        self.index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
    fn unlink(&mut self, index: usize) {
        let (previous, next) = {
            let r = self.records[index].as_ref().expect("live LRU record");
            (r.previous, r.next)
        };
        if let Some(p) = previous {
            self.records[p].as_mut().expect("previous LRU record").next = next
        } else {
            self.head = next
        }
        if let Some(n) = next {
            self.records[n].as_mut().expect("next LRU record").previous = previous
        } else {
            self.tail = previous
        }
    }
    fn remove(&mut self, index: usize) {
        self.unlink(index);
        let record = self.records[index].take().expect("live LRU record");
        self.index.remove(&record.key);
        self.free.push(index);
    }
    fn touch(&mut self, index: usize, now: u64) {
        if self.head != Some(index) {
            self.unlink(index);
            let head = self.head;
            let record = self.records[index].as_mut().expect("live LRU record");
            record.previous = None;
            record.next = head;
            if let Some(head) = head {
                self.records[head].as_mut().expect("LRU head").previous = Some(index)
            } else {
                self.tail = Some(index)
            }
            self.head = Some(index);
        }
        self.records[index].as_mut().expect("live LRU record").used = now;
    }
    fn expired(&self, index: usize, now: u64) -> bool {
        let record = self.records[index].as_ref().expect("live LRU record");
        !self.legacy && (record.confirmed > now || now - record.confirmed >= self.limits.ttl)
    }
    fn mark_dirty(&mut self, mono: f64) {
        if self.persistent && !self.disabled && !self.dirty {
            self.dirty = true;
            self.since = mono;
        }
    }
    pub fn get(&mut self, key: &str, now: u64, mono: f64) -> Option<u32> {
        let index = *self.index.get(key)?;
        if self.expired(index, now) {
            self.remove(index);
            self.mark_dirty(mono);
            return None;
        }
        self.touch(index, now);
        Some(self.records[index].as_ref()?.n)
    }
    pub fn put(&mut self, key: &str, n: Option<u32>, now: u64, mono: f64) -> bool {
        if key.is_empty()
            || key.len() > 255
            || key.bytes().any(|b| b.is_ascii_whitespace())
            || !mono.is_finite()
            || (!self.legacy && n.is_some_and(|n| !(2..=128).contains(&n)))
        {
            return false;
        }
        let index = self.index.get(key).copied();
        let Some(n) = n else {
            if let Some(index) = index {
                self.remove(index);
                self.mark_dirty(mono);
                return true;
            }
            return false;
        };
        if let Some(index) = index {
            let record = self.records[index].as_ref().expect("indexed LRU record");
            let changed = record.n != n
                || (!self.legacy && (now < record.confirmed || now - record.confirmed >= 60));
            self.touch(index, now);
            if changed {
                let record = self.records[index].as_mut().expect("indexed LRU record");
                record.n = n;
                record.confirmed = now;
                self.mark_dirty(mono);
            }
            return changed;
        }
        if self.len() >= self.limits.records {
            if self.legacy {
                self.index.clear();
                self.records.clear();
                self.free.clear();
                self.head = None;
                self.tail = None;
            } else if let Some(tail) = self.tail {
                self.remove(tail)
            }
        }
        let index = if let Some(index) = self.free.pop() {
            index
        } else {
            self.records.push(None);
            self.records.len() - 1
        };
        let owned = key.to_owned();
        self.records[index] = Some(Record {
            key: owned.clone(),
            n,
            confirmed: now,
            used: now,
            previous: None,
            next: self.head,
        });
        self.index.insert(owned, index);
        if let Some(head) = self.head {
            self.records[head].as_mut().expect("LRU head").previous = Some(index)
        } else {
            self.tail = Some(index)
        }
        self.head = Some(index);
        self.mark_dirty(mono);
        true
    }
    pub fn discard(&mut self) {
        self.disabled = true;
        self.dirty = false;
    }
    pub fn due(&mut self, mono: f64) -> Option<f64> {
        if !self.dirty || self.disabled || !mono.is_finite() {
            return None;
        }
        if mono < self.since {
            self.since = mono;
            self.retry = None;
        }
        Some((self.since + SAVE_DELAY).max(self.retry.unwrap_or(f64::NEG_INFINITY)))
    }
    pub fn commit(&mut self, ok: bool, mono: f64) {
        if ok {
            self.dirty = false;
            self.retry = None;
        } else if mono.is_finite() {
            self.retry = Some(mono + RETRY_DELAY);
        }
    }
    pub fn snapshot(&mut self, now: u64) -> Vec<u8> {
        let mut current = self.tail;
        while let Some(index) = current {
            current = self.records[index].as_ref().expect("LRU record").previous;
            if self.expired(index, now) {
                self.remove(index)
            }
        }
        let mut result = Vec::with_capacity(self.limits.bytes.min(self.len() * 64 + HEADER.len()));
        if !self.legacy {
            result.extend_from_slice(HEADER.as_bytes());
        }
        let mut current = self.head;
        while let Some(index) = current {
            let record = self.records[index].as_ref().expect("LRU record");
            let line = if self.legacy {
                format!("{} {}\n", record.key, record.n)
            } else {
                format!(
                    "{} {} {} {}\n",
                    record.key, record.n, record.confirmed, record.used
                )
            };
            if result.len() + line.len() <= self.limits.bytes {
                result.extend_from_slice(line.as_bytes());
            }
            current = record.next;
        }
        result
    }
    pub fn load(&mut self, text: &[u8], now: u64) {
        let Ok(text) = std::str::from_utf8(text) else {
            self.disabled = true;
            return;
        };
        if self.legacy {
            if text.len() > self.limits.bytes {
                return;
            }
            for line in text.lines() {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if self.len() >= self.limits.records {
                    break;
                }
                if parts.len() != 2 {
                    continue;
                }
                if let Ok(n) = parts[1].parse::<u32>() {
                    self.put(parts[0], Some(n), now, 0.);
                }
            }
            self.dirty = false;
            return;
        }
        if text.len() > self.limits.bytes || !text.starts_with(HEADER) {
            self.disabled = true;
            return;
        }
        for line in text[HEADER.len()..]
            .split(['\r', '\n'])
            .filter(|line| !line.is_empty())
        {
            let parts = line.split(' ').collect::<Vec<_>>();
            if parts.len() != 4
                || parts[0].is_empty()
                || parts[0].len() > 255
                || parts[0].bytes().any(|b| b.is_ascii_whitespace())
            {
                continue;
            }
            if !parts[1..]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            {
                continue;
            }
            let (Ok(n), Ok(confirmed), Ok(used)) = (
                parts[1].parse::<u32>(),
                parts[2].parse::<u64>(),
                parts[3].parse::<u64>(),
            ) else {
                continue;
            };
            if !(2..=128).contains(&n)
                || confirmed == 0
                || used < confirmed
                || used > now
                || confirmed > now
                || now - confirmed >= self.limits.ttl
                || self.index.contains_key(parts[0])
            {
                continue;
            }
            if self.len() >= self.limits.records {
                break;
            }
            let index = self.records.len();
            let key = parts[0].to_owned();
            self.records.push(Some(Record {
                key: key.clone(),
                n,
                confirmed,
                used,
                previous: self.tail,
                next: None,
            }));
            self.index.insert(key, index);
            if let Some(tail) = self.tail {
                self.records[tail].as_mut().expect("LRU tail").next = Some(index)
            } else {
                self.head = Some(index)
            }
            self.tail = Some(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ttl_lru_clock_reversal_bounds_and_deferred_retries() {
        let mut store = Store::new(
            Limits {
                records: 2,
                ..Limits::default()
            },
            true,
        )
        .unwrap();
        assert!(store.put("a", Some(2), 100, 0.));
        assert!(store.put("b", Some(3), 100, 0.));
        assert_eq!(store.get("a", 101, 1.), Some(2));
        assert!(store.put("c", Some(4), 102, 2.));
        assert_eq!(store.get("b", 102, 2.), None);
        assert_eq!(store.due(4.), Some(5.));
        store.commit(false, 5.);
        assert_eq!(store.due(6.), Some(35.));
        assert_eq!(store.due(-1.), Some(4.));
        let bytes = store.snapshot(102);
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .starts_with("# ring-store-v2\nc 4")
        );
        let mut restored = Store::new(Limits::default(), true).unwrap();
        restored.load(&bytes, 103);
        assert_eq!(restored.get("a", 103, 0.), Some(2));
        assert_eq!(restored.get("a", 100 + TTL, 1.), None);
        assert_eq!(store.get("a", 99, 3.), None);
        store.discard();
        assert_eq!(store.due(100.), None);
    }
    #[test]
    fn repeated_hits_do_not_extend_ttl_or_dirty_snapshots_until_reconfirmation() {
        let mut store = Store::new(Limits::default(), true).unwrap();
        store.put("host", Some(2), 100, 0.);
        store.commit(true, 5.);
        for now in 101..160 {
            assert_eq!(store.get("host", now, 6.), Some(2));
            assert!(!store.put("host", Some(2), now, 6.));
        }
        assert!(!store.dirty);
        assert!(store.put("host", Some(2), 160, 10.));
        assert!(store.dirty);
        let mut corrupt = Store::new(Limits::default(), true).unwrap();
        corrupt.load(b"host 2\n", 100);
        assert!(corrupt.disabled);
        for index in 0..10000 {
            corrupt.put(&format!("host{index}"), Some(2), 100, 0.);
        }
        assert_eq!(corrupt.len(), 2000);
        assert!(!corrupt.dirty);
        assert!(corrupt.snapshot(100).len() <= MAX_BYTES);
    }
}
