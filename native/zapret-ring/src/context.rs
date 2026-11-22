#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub key: String,
    pub composition: String,
}
fn decimal(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}
fn hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn network_key(text: &str, now: u64, started: Option<u64>) -> Option<Network> {
    if text.len() > 128 || !text.ends_with('\n') {
        return None;
    }
    let parts = text.strip_suffix('\n')?.split(' ').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "3" {
        return None;
    }
    let stamp = decimal(parts[1])?;
    if stamp > now
        || now - stamp > 20
        || started.is_some_and(|started| stamp <= started)
        || !hex(parts[2], 64)
        || !hex(parts[3], 24)
    {
        return None;
    }
    Some(Network {
        key: parts[2].to_ascii_uppercase(),
        composition: parts[3].to_ascii_uppercase(),
    })
}
pub fn state_path(dir: &str, state: &str, key: &str) -> Option<String> {
    let stem = state.strip_suffix(".txt")?;
    if stem.is_empty()
        || !stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || !hex(key, 64)
        || key.bytes().any(|b| b.is_ascii_lowercase())
    {
        return None;
    }
    Some(format!("{dir}/{stem}-{key}.txt"))
}
pub fn legacy_state_path(dir: &str, state: &str) -> Option<String> {
    state_path(dir, state, &"A".repeat(64))?;
    Some(format!("{dir}/{state}"))
}
pub fn state_composition(state: &str) -> Option<&str> {
    let state = state.strip_prefix("ring-")?.strip_suffix(".txt")?;
    let mut parts = state.split('-');
    let group = parts.next()?;
    let composition = parts.next()?;
    let tail = parts.next()?;
    if parts.next().is_some()
        || group.is_empty()
        || !group
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || !hex(composition, 24)
        || composition.bytes().any(|b| b.is_ascii_uppercase())
        || tail.is_empty()
        || !tail
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(composition)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkLease {
    pub event: u64,
    pub until: u64,
    pub stamp: u64,
}
pub fn link_guard(text: &str, now: u64, started: Option<u64>) -> Option<LinkLease> {
    if text.len() > 64 || !text.ends_with('\n') {
        return None;
    }
    let parts = text.strip_suffix('\n')?.split(' ').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "1" {
        return None;
    }
    let stamp = decimal(parts[1])?;
    let event = decimal(parts[2])?;
    let until = decimal(parts[3])?;
    if stamp > now
        || now - stamp > 10
        || started.is_some_and(|started| stamp <= started)
        || event > stamp
        || ((event == 0) != (until == 0))
        || (until != 0 && until < event)
        || until > stamp.saturating_add(20)
    {
        return None;
    }
    Some(LinkLease {
        event,
        until,
        stamp,
    })
}

pub struct Context {
    pub started: u64,
    network: Option<Network>,
    pub network_revision: u64,
    checked: Option<f64>,
    pub epoch: u64,
    link_checked: Option<f64>,
    pub link_revision: u64,
    event: u64,
    deadline: f64,
    timer_failed: Option<f64>,
    timer_retry: Option<f64>,
}
impl Context {
    pub fn new(started: u64) -> Self {
        Self {
            started,
            network: None,
            network_revision: 0,
            checked: None,
            epoch: 0,
            link_checked: None,
            link_revision: 0,
            event: 0,
            deadline: 0.,
            timer_failed: None,
            timer_retry: None,
        }
    }
    pub fn network_due(&self, mono: f64, force: bool) -> bool {
        force
            || self
                .checked
                .is_none_or(|checked| mono < checked || mono - checked >= 1.)
    }
    pub fn observe_network(&mut self, text: Option<&str>, now: u64, mono: f64) {
        let current = text.and_then(|text| network_key(text, now, Some(self.started)));
        if current != self.network {
            self.network_revision = self.network_revision.saturating_add(1);
        }
        self.network = current;
        self.checked = Some(mono);
        self.epoch = now;
    }
    pub fn network_for(&self, state: &str) -> Option<&str> {
        let network = self.network.as_ref()?;
        (state_composition(state)?.eq_ignore_ascii_case(&network.composition))
            .then_some(network.key.as_str())
    }
    pub fn link_due(&self, mono: f64) -> bool {
        self.link_checked
            .is_none_or(|checked| mono < checked || mono - checked >= 1.)
    }
    pub fn observe_link(&mut self, text: Option<&str>, now: u64, mono: f64) {
        let lease = text.and_then(|text| link_guard(text, now, Some(self.started)));
        if let Some(lease) = lease {
            if lease.event != 0 && lease.event != self.event {
                self.link_revision = self.link_revision.saturating_add(1);
                self.event = lease.event;
            }
        }
        self.deadline = lease.map_or(0., |lease| {
            mono + lease
                .until
                .min(lease.stamp.saturating_add(10))
                .saturating_sub(now) as f64
        });
        self.link_checked = Some(mono);
    }
    pub fn paused(&self, mono: f64) -> bool {
        mono < self.deadline
    }
    pub fn timer_gate(&mut self, mono: f64, result: Option<bool>) -> bool {
        if let Some(ok) = result {
            if ok {
                self.timer_failed = None;
                self.timer_retry = None;
            } else {
                self.timer_failed = Some(mono);
                self.timer_retry = Some(mono + 30.);
            }
        }
        if self.timer_failed.is_some_and(|failed| mono < failed) {
            self.timer_failed = Some(mono);
            self.timer_retry = Some(mono + 30.);
        }
        self.timer_retry.is_none_or(|retry| mono >= retry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leases_are_fresh_strict_scoped_and_revisions_survive_expiry() {
        let key = "A".repeat(64);
        let composition = "C".repeat(24);
        let text = format!("3 101 {key} {composition}\n");
        assert!(network_key(&text, 101, Some(101)).is_none());
        assert!(network_key(&text, 122, None).is_none());
        let state = format!("ring-general-{}-abc.txt", composition.to_lowercase());
        let mut ctx = Context::new(100);
        ctx.observe_network(Some(&text), 101, 1.);
        assert_eq!(ctx.network_for(&state), Some(key.as_str()));
        assert_eq!(ctx.network_revision, 1);
        ctx.observe_network(None, 102, 2.);
        assert_eq!(ctx.network_for(&state), None);
        assert_eq!(ctx.network_revision, 2);
        ctx.observe_link(Some("1 103 102 110\n"), 103, 3.);
        assert!(ctx.paused(4.));
        assert_eq!(ctx.link_revision, 1);
        ctx.observe_link(None, 120, 20.);
        assert!(!ctx.paused(20.));
        assert_eq!(ctx.link_revision, 1);
        assert!(state_path("root", "../bad.txt", &key).is_none());
        assert!(state_path("root", "ring.txt", &key.to_lowercase()).is_none());
    }
}
