use std::{collections::HashMap, sync::Arc};

const MAX_HOSTS: usize = 4096;

pub fn host_capacity(default: bool, value: Option<f64>) -> Option<f64> {
    if default {
        return Some(MAX_HOSTS as f64);
    }
    value.filter(|capacity| (1. ..=MAX_HOSTS as f64).contains(capacity) && capacity.fract() == 0.)
}
struct Node {
    id: u64,
    group: Arc<str>,
    host: Arc<str>,
    previous: Option<usize>,
    next: Option<usize>,
}
pub struct HostIndex {
    capacity: usize,
    groups: HashMap<Arc<str>, HashMap<Arc<str>, usize>>,
    by_id: HashMap<u64, usize>,
    // LRU links use stable slots. Only the public connection IDs outlive eviction.
    nodes: Vec<Node>,
    head: Option<usize>,
    tail: Option<usize>,
    serial: u64,
}
impl HostIndex {
    pub fn new(capacity: usize) -> Option<Self> {
        (1..=MAX_HOSTS).contains(&capacity).then(|| Self {
            capacity,
            groups: HashMap::new(),
            by_id: HashMap::new(),
            nodes: Vec::new(),
            head: None,
            tail: None,
            serial: 0,
        })
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    fn unlink(&mut self, slot: usize) {
        let Node { previous, next, .. } = self.nodes[slot];
        if let Some(p) = previous {
            self.nodes[p].next = next;
        } else {
            self.head = next;
        }
        if let Some(n) = next {
            self.nodes[n].previous = previous;
        } else {
            self.tail = previous;
        }
    }
    fn link_head(&mut self, slot: usize) {
        self.nodes[slot].previous = None;
        self.nodes[slot].next = self.head;
        if let Some(head) = self.head {
            self.nodes[head].previous = Some(slot);
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
    }
    pub fn touch(&mut self, id: u64) -> bool {
        if self.head.is_some_and(|head| self.nodes[head].id == id) {
            return true;
        }
        let Some(&slot) = self.by_id.get(&id) else {
            return false;
        };
        self.unlink(slot);
        self.link_head(slot);
        true
    }
    pub fn access(&mut self, group: &str, host: &str) -> Option<(u64, Option<u64>, bool)> {
        if group.is_empty() || group.len() > 1024 || host.is_empty() || host.len() > 1024 {
            return None;
        }
        if let Some(&slot) = self.groups.get(group).and_then(|bucket| bucket.get(host)) {
            if self.head != Some(slot) {
                self.unlink(slot);
                self.link_head(slot);
            }
            return Some((self.nodes[slot].id, None, false));
        }
        let id = self.serial.checked_add(1)?;
        let group = self
            .groups
            .get_key_value(group)
            .map_or_else(|| Arc::from(group), |(key, _)| key.clone());
        let host = Arc::<str>::from(host);
        let node = Node {
            id,
            group: group.clone(),
            host: host.clone(),
            previous: None,
            next: None,
        };
        let (slot, evicted) = if self.nodes.len() == self.capacity {
            let slot = self.tail.expect("full host cache tail");
            self.unlink(slot);
            let old = std::mem::replace(&mut self.nodes[slot], node);
            self.by_id.remove(&old.id);
            let bucket = self.groups.get_mut(&old.group).expect("host bucket");
            bucket.remove(&old.host);
            if bucket.is_empty() && old.group != group {
                self.groups.remove(&old.group);
            }
            (slot, Some(old.id))
        } else {
            let slot = self.nodes.len();
            self.nodes.push(node);
            (slot, None)
        };
        self.groups.entry(group).or_default().insert(host, slot);
        self.by_id.insert(id, slot);
        self.link_head(slot);
        self.serial = id;
        Some((id, evicted, true))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn evicted_connection_ids_never_alias_new_records_and_empty_groups_are_removed() {
        let mut cache = HostIndex::new(2).unwrap();
        let (a, _, _) = cache.access("general", "a").unwrap();
        let (b, _, _) = cache.access("general", "b").unwrap();
        cache.touch(a);
        assert_eq!(cache.access("google", "c").unwrap().1, Some(b));
        assert!(!cache.touch(b));
        for i in 0..10000 {
            cache.access(&format!("group{i}"), "host").unwrap();
        }
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.groups.len(), 2);
        assert!(!cache.touch(a));
    }

    #[test]
    fn pinned_and_named_hits_keep_the_same_eviction_order_when_slots_are_reused() {
        for capacity in [1, 3, 8] {
            let mut cache = HostIndex::new(capacity).unwrap();
            let mut order = VecDeque::<(u64, usize, usize)>::new();
            let mut last_id = 0;
            for step in 0..1500 {
                let group = step % 5;
                let host = (step / 3 + step % 7) % 11;
                let key = (group.to_string(), host.to_string());
                let present = order.iter().position(|&(_, g, h)| (g, h) == (group, host));
                let expected = if let Some(position) = present {
                    let row = order.remove(position).unwrap();
                    order.push_front(row);
                    (row.0, None, false)
                } else {
                    let evicted = (order.len() == capacity).then(|| order.pop_back().unwrap().0);
                    last_id += 1;
                    order.push_front((last_id, group, host));
                    (last_id, evicted, true)
                };
                assert_eq!(cache.access(&key.0, &key.1), Some(expected));
                assert_eq!(
                    cache.access(&key.0, &key.1),
                    Some((expected.0, None, false))
                );
                let pin = last_id.saturating_sub((step % (capacity + 3)) as u64);
                let position = order.iter().position(|row| row.0 == pin);
                assert_eq!(cache.touch(pin), position.is_some());
                if let Some(position) = position {
                    let row = order.remove(position).unwrap();
                    order.push_front(row);
                }
            }
        }
    }

    #[test]
    fn exhausted_ids_leave_existing_pins_intact() {
        let mut cache = HostIndex::new(1).unwrap();
        let (id, _, _) = cache.access("group", "old").unwrap();
        cache.serial = u64::MAX;
        assert_eq!(cache.access("group", "new"), None);
        assert!(cache.touch(id));
        assert_eq!(cache.access("group", "old"), Some((id, None, false)));
    }
}
