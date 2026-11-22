use std::net::{Ipv4Addr, Ipv6Addr};

pub fn subnet(raw: &[u8]) -> Option<String> {
    match raw {
        [a, b, c, _] => Some(format!("{}/24", Ipv4Addr::new(*a, *b, *c, 0))),
        _ if raw.len() == 16 => {
            let mut bytes = [0; 16];
            bytes[..6].copy_from_slice(&raw[..6]);
            Some(format!("{}/48", Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}
pub fn received_ack(reverse_seen: bool, ack_flag: bool, ack: u32, server_start: u32) -> u32 {
    if !reverse_seen || !ack_flag {
        return 0;
    }
    let got = ack.wrapping_sub(server_start);
    if got < 0x80000000 { got } else { 0 }
}
pub fn forged_rst(
    incoming: bool,
    tcp: bool,
    rst: bool,
    ttl: Option<f64>,
    server_ttl: Option<f64>,
    gap: Option<f64>,
) -> bool {
    incoming
        && tcp
        && rst
        && (ttl.zip(server_ttl).is_some_and(|(a, b)| (a - b).abs() > 2.)
            || gap.is_some_and(|gap| (0. ..0.010).contains(&gap)))
}
pub fn tls_refused(
    incoming: bool,
    tcp: bool,
    tracked_tls: bool,
    fin: bool,
    seq: f64,
    upper: f64,
    payload_len: f64,
) -> bool {
    incoming && tcp && tracked_tls && fin && seq >= 1. && (seq + payload_len).max(upper) <= 8.
}
pub fn success(
    standard: bool,
    outgoing: bool,
    tcp: bool,
    received: u32,
    threshold: Option<f64>,
) -> (bool, bool) {
    if standard {
        return (true, outgoing);
    }
    if outgoing && tcp && received as f64 > threshold.unwrap_or(28000.) {
        return (true, true);
    }
    (false, false)
}
pub fn failure(
    standard: bool,
    tls_refused: bool,
    unproven: bool,
    fails: Option<f64>,
) -> (bool, Option<f64>) {
    let failed = standard || tls_refused;
    (
        failed,
        (failed && unproven).then(|| fails.unwrap_or(3.) - 1.),
    )
}
pub fn initial_strategy(
    current: u32,
    total: Option<u32>,
    seen: bool,
    host_revision: Option<u64>,
    revision: u64,
    contextual: bool,
    hint: Option<u32>,
) -> (u32, bool) {
    let reset = contextual && host_revision != Some(revision);
    let current = if reset { 1 } else { current };
    let seen = seen && !reset;
    let selected = if !seen {
        hint.filter(|hint| total.is_some_and(|total| *hint <= total) && *hint != current)
            .unwrap_or(current)
    } else {
        current
    };
    (selected, reset)
}
#[derive(Clone, Copy, Default)]
pub struct Guard {
    pub link_revision: Option<u64>,
    pub link_tainted: bool,
}
#[derive(Clone, Copy)]
pub struct Observation {
    pub nocheck: bool,
    pub evicted: bool,
    pub link_revision: u64,
    pub paused: bool,
    pub revision: Option<u64>,
    pub current_revision: u64,
    pub strategy: Option<u32>,
    pub current_strategy: Option<u32>,
}
impl Guard {
    pub fn skip(&mut self, observed: Observation) -> bool {
        let Observation {
            nocheck,
            evicted,
            link_revision,
            paused,
            revision,
            current_revision,
            strategy,
            current_strategy,
        } = observed;
        if nocheck || evicted {
            return true;
        }
        if self.link_revision.is_none() {
            self.link_revision = Some(link_revision);
            self.link_tainted = paused;
        }
        paused
            || self.link_tainted
            || self.link_revision != Some(link_revision)
            || revision.is_some_and(|r| r != current_revision)
            || strategy.is_some_and(|s| Some(s) != current_strategy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_decisions_preserve_boundaries_and_ack_wraparound() {
        assert_eq!(received_ack(true, true, 10, u32::MAX - 9), 20);
        assert_eq!(received_ack(true, true, 0, 1), 0);
        assert!(!success(false, true, true, 28000, None).0);
        assert!(success(false, true, true, 28001, None).1);
        assert_eq!(success(true, false, true, 0, None), (true, false));
        assert!(!forged_rst(
            true,
            true,
            true,
            Some(64.),
            Some(62.),
            Some(0.010)
        ));
        assert!(forged_rst(true, true, true, Some(65.), Some(62.), None));
        assert!(tls_refused(true, true, true, true, 1., 0., 7.));
        assert!(!tls_refused(true, true, true, true, 1., 0., 8.));
        assert_eq!(failure(false, true, true, None), (true, Some(2.)));
        let mut guard = Guard::default();
        let observation = Observation {
            nocheck: false,
            evicted: false,
            link_revision: 0,
            paused: false,
            revision: Some(1),
            current_revision: 1,
            strategy: Some(2),
            current_strategy: Some(2),
        };
        assert!(!guard.skip(observation));
        assert!(guard.skip(Observation {
            link_revision: 1,
            ..observation
        }));
    }
}
