use std::{collections::HashMap, sync::Arc};

const MAX_HOSTS: usize = 4096;

pub fn host_capacity(default: bool, value: Option<f64>) -> Option<f64> {
    if default {
        return Some(MAX_HOSTS as f64);
    }
    value.filter(|capacity| (1. ..=MAX_HOSTS as f64).contains(capacity) && capacity.fract() == 0.)
}
struct Node {
    group: Arc<str>,
    host: Arc<str>,
    previous: Option<u64>,
    next: Option<u64>,
}
pub struct HostIndex {
    capacity: usize,
    groups: HashMap<Arc<str>, HashMap<Arc<str>, u64>>,
    nodes: HashMap<u64, Node>,
    head: Option<u64>,
    tail: Option<u64>,
    serial: u64,
}
impl HostIndex {
    pub fn new(capacity: usize) -> Option<Self> {
        (1..=MAX_HOSTS).contains(&capacity).then(|| Self {
            capacity,
            groups: HashMap::new(),
            nodes: HashMap::with_capacity(capacity),
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
    fn unlink(&mut self, previous: Option<u64>, next: Option<u64>) {
        if let Some(p) = previous {
            self.nodes.get_mut(&p).expect("previous host").next = next
        } else {
            self.head = next
        }
        if let Some(n) = next {
            self.nodes.get_mut(&n).expect("next host").previous = previous
        } else {
            self.tail = previous
        }
    }
    pub fn touch(&mut self, id: u64) -> bool {
        if self.head == Some(id) {
            return true;
        }
        let Some(node) = self.nodes.get(&id) else {
            return false;
        };
        self.unlink(node.previous, node.next);
        let old = self.head;
        let node = self.nodes.get_mut(&id).expect("indexed host");
        node.previous = None;
        node.next = old;
        if let Some(old) = old {
            self.nodes.get_mut(&old).expect("host head").previous = Some(id)
        } else {
            self.tail = Some(id)
        }
        self.head = Some(id);
        true
    }
    pub fn access(&mut self, group: &str, host: &str) -> Option<(u64, Option<u64>, bool)> {
        if group.is_empty() || group.len() > 1024 || host.is_empty() || host.len() > 1024 {
            return None;
        }
        if let Some(id) = self
            .groups
            .get(group)
            .and_then(|bucket| bucket.get(host))
            .copied()
        {
            self.touch(id);
            return Some((id, None, false));
        }
        let mut evicted = None;
        if self.nodes.len() >= self.capacity {
            let id = self.tail.expect("full host cache tail");
            let node = self.nodes.remove(&id).expect("evicted host");
            self.unlink(node.previous, node.next);
            let bucket = self.groups.get_mut(&node.group).expect("host bucket");
            bucket.remove(&node.host);
            if bucket.is_empty() {
                self.groups.remove(&node.group);
            }
            evicted = Some(id);
        }
        self.serial = self.serial.checked_add(1)?;
        let id = self.serial;
        let group = self
            .groups
            .get_key_value(group)
            .map_or_else(|| Arc::from(group), |(key, _)| key.clone());
        let host = Arc::<str>::from(host);
        self.nodes.insert(
            id,
            Node {
                group: group.clone(),
                host: host.clone(),
                previous: None,
                next: self.head,
            },
        );
        self.groups.entry(group).or_default().insert(host, id);
        if let Some(old) = self.head {
            self.nodes.get_mut(&old).expect("host head").previous = Some(id)
        } else {
            self.tail = Some(id)
        }
        self.head = Some(id);
        Some((id, evicted, true))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
}
