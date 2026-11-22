use crate::diagnostic as d;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr, path::Path, time::Duration};
use tokio::{
    net::TcpStream,
    task::JoinSet,
    time::{Instant, timeout},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LatencyOutcome {
    Success,
    Timeout,
    Error,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencySample {
    pub at: f64,
    pub outcome: LatencyOutcome,
    pub ms: Option<f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyStream {
    pub samples: Vec<LatencySample>,
    pub last_scheduled: Option<f64>,
    pub last_active: f64,
    pub touch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyStore {
    pub streams: BTreeMap<String, LatencyStream>,
    capacity: usize,
    max_samples: usize,
    window_seconds: f64,
    clock: Option<f64>,
    sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LatencySummary {
    pub count: usize,
    pub success_count: usize,
    pub timeouts: usize,
    pub errors: usize,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub last_ms: Option<f64>,
    pub last_success_age: Option<f64>,
    pub spikes: usize,
    pub consecutive_failures: usize,
    pub fresh: bool,
    pub last_scheduled: Option<f64>,
}
impl Default for LatencyStore {
    fn default() -> Self {
        Self::new(128, 120, 600.).expect("valid defaults")
    }
}
fn key(ip: &str, kind: &str, port: u16) -> Option<String> {
    let ip: IpAddr = ip.parse().ok()?;
    match kind {
        "icmp" => Some(format!("icmp|{ip}")),
        "tcp" if port > 0 => Some(format!("tcp|{ip}|{port}")),
        _ => None,
    }
}
impl LatencyStore {
    pub fn new(capacity: usize, max_samples: usize, window_seconds: f64) -> Result<Self> {
        if !(1..=512).contains(&capacity)
            || !(1..=1000).contains(&max_samples)
            || !window_seconds.is_finite()
            || !(1.0..=3600.).contains(&window_seconds)
        {
            bail!("invalid latency store limits")
        }
        Ok(Self {
            streams: BTreeMap::new(),
            capacity,
            max_samples,
            window_seconds,
            clock: None,
            sequence: 0,
        })
    }
    fn entry(&mut self, key: String, now: f64, create: bool) -> Option<&mut LatencyStream> {
        if !now.is_finite() || now < 0. || self.clock.is_some_and(|n| now < n) {
            return None;
        }
        self.clock = Some(now);
        let cutoff = now - self.window_seconds;
        if create {
            self.streams.retain(|_, v| v.last_active >= cutoff)
        }
        if self
            .streams
            .get(&key)
            .is_some_and(|v| v.last_active < cutoff)
        {
            self.streams.remove(&key);
        }
        if !self.streams.contains_key(&key) {
            if !create {
                return None;
            }
            if self.streams.len() >= self.capacity {
                let oldest = self
                    .streams
                    .iter()
                    .min_by_key(|(_, v)| v.touch)
                    .map(|(k, _)| k.clone())?;
                self.streams.remove(&oldest);
            }
            self.streams.insert(
                key.clone(),
                LatencyStream {
                    samples: vec![],
                    last_scheduled: None,
                    last_active: now,
                    touch: 0,
                },
            );
        }
        self.sequence = self.sequence.saturating_add(1);
        let entry = self.streams.get_mut(&key)?;
        entry.samples.retain(|s| s.at >= cutoff);
        entry.touch = self.sequence;
        Some(entry)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        ip: &str,
        kind: &str,
        port: u16,
        outcome: LatencyOutcome,
        ms: Option<f64>,
        now: f64,
        completed_at: Option<f64>,
    ) -> bool {
        if match outcome {
            LatencyOutcome::Success => ms.is_none_or(|n| !n.is_finite() || n < 0.),
            _ => ms.is_some(),
        } {
            return false;
        }
        let at = completed_at.unwrap_or(now);
        if !at.is_finite() || at < 0. || at > now || at < now - self.window_seconds {
            return false;
        }
        let max = self.max_samples;
        let Some(key) = key(ip, kind, port) else {
            return false;
        };
        let Some(entry) = self.entry(key, now, true) else {
            return false;
        };
        let index = entry.samples.partition_point(|s| s.at <= at);
        entry
            .samples
            .insert(index, LatencySample { at, outcome, ms });
        if entry.samples.len() > max {
            entry.samples.remove(0);
        }
        entry.last_active = entry
            .samples
            .last()
            .map_or(0., |s| s.at)
            .max(entry.last_scheduled.unwrap_or(0.));
        true
    }
    pub fn summary(&mut self, ip: &str, kind: &str, port: u16, now: f64) -> LatencySummary {
        let Some(key) = key(ip, kind, port) else {
            return LatencySummary::default();
        };
        let Some(entry) = self.entry(key, now, false) else {
            return LatencySummary::default();
        };
        let samples = &entry.samples;
        let success: Vec<_> = samples
            .iter()
            .filter(|s| s.outcome == LatencyOutcome::Success)
            .collect();
        let mut sorted: Vec<_> = success.iter().filter_map(|s| s.ms).collect();
        sorted.sort_by(f64::total_cmp);
        let mut summary = LatencySummary {
            count: samples.len(),
            success_count: success.len(),
            timeouts: samples
                .iter()
                .filter(|s| s.outcome == LatencyOutcome::Timeout)
                .count(),
            errors: samples
                .iter()
                .filter(|s| s.outcome == LatencyOutcome::Error)
                .count(),
            consecutive_failures: samples
                .iter()
                .rev()
                .take_while(|s| s.outcome != LatencyOutcome::Success)
                .count(),
            last_scheduled: entry.last_scheduled,
            ..Default::default()
        };
        if !sorted.is_empty() {
            let n = sorted.len();
            let median = if n % 2 == 1 {
                sorted[n / 2]
            } else {
                sorted[n / 2 - 1] / 2. + sorted[n / 2] / 2.
            };
            summary.min_ms = sorted.first().copied();
            summary.max_ms = sorted.last().copied();
            summary.median_ms = Some(median);
            if n >= 20 {
                summary.p95_ms = Some(sorted[(n as f64 * 0.95).ceil() as usize - 1]);
            }
            summary.last_ms = success.last().and_then(|s| s.ms);
            summary.last_success_age = success.last().map(|s| now - s.at);
            summary.fresh = summary.last_success_age.is_some_and(|age| age <= 60.);
            summary.spikes = sorted.iter().filter(|&&n| n >= median + 50.).count();
        }
        summary
    }
    pub fn due(&mut self, ip: &str, kind: &str, port: u16, now: f64) -> bool {
        let Some(key) = key(ip, kind, port) else {
            return false;
        };
        if !now.is_finite() || now < 0. || self.clock.is_some_and(|n| now < n) {
            return false;
        }
        let Some(entry) = self.entry(key, now, false) else {
            return true;
        };
        let failures = entry
            .samples
            .iter()
            .rev()
            .take(3)
            .take_while(|s| s.outcome != LatencyOutcome::Success)
            .count();
        let gap = if kind == "tcp" {
            20.
        } else if failures >= 3 {
            60.
        } else {
            5.
        };
        entry.last_scheduled.is_none_or(|n| now - n >= gap)
    }
    pub fn scheduled(&mut self, ip: &str, kind: &str, port: u16, now: f64) -> bool {
        let Some(key) = key(ip, kind, port) else {
            return false;
        };
        let Some(entry) = self.entry(key, now, true) else {
            return false;
        };
        entry.last_scheduled = Some(now);
        entry.last_active = now;
        true
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct ProbeRow {
    pub(crate) address: String,
    pub(crate) kind: String,
    pub(crate) port: u16,
    pub(crate) sample: u64,
    pub(crate) outcome: LatencyOutcome,
    pub(crate) ms: Option<f64>,
    pub(crate) error: String,
    pub(crate) completed_after_ms: f64,
    pub(crate) completed_at_seconds: f64,
    pub(crate) evidence: String,
}
pub(crate) async fn probe(
    address: IpAddr,
    kind: &str,
    port: u16,
    sample: u64,
    timeout_ms: u64,
    batch_start: Instant,
) -> ProbeRow {
    let start = Instant::now();
    let (outcome, ms, error) = if kind == "tcp" {
        match timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect((address, port)),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                let elapsed = start.elapsed().as_secs_f64() * 1000.;
                if elapsed <= timeout_ms as f64 {
                    (LatencyOutcome::Success, Some(elapsed), String::new())
                } else {
                    (
                        LatencyOutcome::Timeout,
                        None,
                        "TCP connect exceeded deadline".into(),
                    )
                }
            }
            Ok(Err(e)) => (LatencyOutcome::Error, None, e.to_string()),
            Err(_) => (LatencyOutcome::Timeout, None, "TCP connect timeout".into()),
        }
    } else {
        tokio::task::spawn_blocking(move || icmp(address, timeout_ms as u32))
            .await
            .unwrap_or_else(|e| (LatencyOutcome::Error, None, e.to_string()))
    };
    let elapsed = start.elapsed().as_secs_f64() * 1000.;
    ProbeRow {
        address: address.to_string(),
        kind: kind.into(),
        port: if kind == "icmp" { 0 } else { port },
        sample,
        outcome,
        ms,
        error,
        completed_after_ms: elapsed,
        completed_at_seconds: start.duration_since(batch_start).as_secs_f64()
            + elapsed.min(timeout_ms as f64) / 1000.,
        evidence: if kind == "icmp" {
            "IcmpEchoRtt"
        } else {
            "TcpHandshake"
        }
        .into(),
    }
}
#[cfg(windows)]
fn icmp(address: IpAddr, timeout_ms: u32) -> (LatencyOutcome, Option<f64>, String) {
    use std::{
        mem::size_of,
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::*,
        Networking::WinSock::*,
    };
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    // These synchronous IP Helper calls honor their OS timeout. No raw socket privilege is required.
    unsafe {
        let handle = if address.is_ipv4() {
            IcmpCreateFile()
        } else {
            Icmp6CreateFile()
        };
        if handle == INVALID_HANDLE_VALUE {
            return (
                LatencyOutcome::Error,
                None,
                std::io::Error::last_os_error().to_string(),
            );
        }
        let owner = Owned(handle);
        let payload = b"zapret-rust-native-latency-echo";
        let mut buffer = vec![0u64; 128];
        let count = match address {
            IpAddr::V4(ip) => IcmpSendEcho(
                owner.0,
                u32::from_ne_bytes(ip.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                null(),
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                timeout_ms,
            ),
            IpAddr::V6(ip) => {
                let source = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    ..Default::default()
                };
                let mut destination = source;
                destination.sin6_addr.u.Byte = ip.octets();
                Icmp6SendEcho2(
                    owner.0,
                    null_mut(),
                    None,
                    null(),
                    &source,
                    &destination,
                    payload.as_ptr().cast(),
                    payload.len() as u16,
                    null(),
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                    timeout_ms,
                )
            }
        };
        if count == 0 {
            let e = std::io::Error::last_os_error();
            return (
                if e.raw_os_error() == Some(11010) {
                    LatencyOutcome::Timeout
                } else {
                    LatencyOutcome::Error
                },
                None,
                e.to_string(),
            );
        }
        let (status, rtt) = if address.is_ipv4() {
            assert!(buffer.len() * 8 >= size_of::<ICMP_ECHO_REPLY>());
            let reply = &*buffer.as_ptr().cast::<ICMP_ECHO_REPLY>();
            (reply.Status, reply.RoundTripTime)
        } else {
            let reply = &*buffer.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>();
            (reply.Status, reply.RoundTripTime)
        };
        if status == 0 {
            (LatencyOutcome::Success, Some(rtt as f64), String::new())
        } else {
            (
                if status == 11010 {
                    LatencyOutcome::Timeout
                } else {
                    LatencyOutcome::Error
                },
                None,
                format!("ICMP status {status}"),
            )
        }
    }
}
#[cfg(not(windows))]
fn icmp(_: IpAddr, _: u32) -> (LatencyOutcome, Option<f64>, String) {
    (
        LatencyOutcome::Error,
        None,
        "native ICMP is supported on Windows only".into(),
    )
}
pub(crate) fn run(_root: &Path, kind: &str, args: &Value) -> Result<Value> {
    let timeout_ms = d::integer(args, "timeout_ms", 1000, 1, 5000)?;
    let count = d::integer(args, "count", 4, 1, 20)?;
    let interval = d::integer(args, "interval_ms", 250, 0, 60000)?;
    let budget = d::integer(args, "deadline_ms", 30000, 1, 60000)?;
    let port = d::integer(args, "port", 443, 1, 65535)? as u16;
    let protocol = args["protocol"].as_str().unwrap_or(match kind {
        "tcp-latency" => "tcp",
        "icmp-latency" => "icmp",
        _ => "both",
    });
    if !matches!(protocol, "tcp" | "icmp" | "both") {
        bail!("protocol must be tcp, icmp or both")
    }
    let mut addresses = Vec::new();
    if let Some(values) = args["addresses"]
        .as_array()
        .filter(|v| !v.is_empty())
        .or_else(|| args["ips"].as_array().filter(|v| !v.is_empty()))
        .or_else(|| args["urls"].as_array().filter(|v| !v.is_empty()))
    {
        for value in values {
            addresses.push(
                value
                    .as_str()
                    .context("literal IP address required")?
                    .parse::<IpAddr>()
                    .context("literal IP address required")?,
            )
        }
    } else {
        let text = args["ip"].as_str().context("latency requires an explicit literal ip or addresses; measured game peers must be selected by the controller")?;
        addresses.push(
            text.parse::<IpAddr>()
                .context("literal IP address required")?,
        )
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > 16 {
        bail!("expected 1..16 literal addresses")
    }
    crate::runtime(async {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(budget);
        let mut rows = Vec::new();
        let mut store = LatencyStore::default();
        let cancel = d::cancellation();
        for sample in 1..=count {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64;
            if remaining == 0 || *cancel.borrow() {
                break;
            }
            let mut pending = JoinSet::new();
            for &address in &addresses {
                for p in ["icmp", "tcp"] {
                    if protocol == "both" || protocol == p {
                        pending.spawn(probe(
                            address,
                            p,
                            port,
                            sample,
                            timeout_ms.min(remaining),
                            started,
                        ));
                    }
                }
            }
            while let Some(row) = pending.join_next().await {
                let row = row?;
                let now = started.elapsed().as_secs_f64();
                store.record(
                    &row.address,
                    &row.kind,
                    row.port,
                    row.outcome,
                    row.ms,
                    now,
                    Some(row.completed_at_seconds.min(now)),
                );
                rows.push(row);
            }
            if sample < count {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(Duration::from_millis(interval).min(remaining)).await;
            }
        }
        let now = started.elapsed().as_secs_f64();
        let mut summaries = Vec::new();
        for address in addresses {
            for p in ["icmp", "tcp"] {
                if protocol == "both" || protocol == p {
                    summaries.push(json!({"address":address,"kind":p,"port":if p=="icmp"{0}else{port},"summary":store.summary(&address.to_string(),p,if p=="icmp"{0}else{port},now)}));
                }
            }
        }
        Ok(
            json!({"schema":1,"kind":"Latency","rows":rows,"summaries":summaries,"completion":if *cancel.borrow(){"Interrupted"}else if Instant::now()>=deadline{"Deadline"}else{"Completed"},"elapsed_ms":now*1000.,"game_latency_measured":false}),
        )
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentile_requires_twenty_real_replies_and_old_success_is_not_fresh() {
        let mut s = LatencyStore::default();
        for i in 1..=19 {
            s.record(
                "127.0.0.1",
                "icmp",
                0,
                LatencyOutcome::Success,
                Some(i as f64),
                i as f64,
                None,
            );
        }
        assert_eq!(s.summary("127.0.0.1", "icmp", 0, 19.).p95_ms, None);
        s.record(
            "127.0.0.1",
            "icmp",
            0,
            LatencyOutcome::Success,
            Some(100.),
            20.,
            None,
        );
        assert_eq!(s.summary("127.0.0.1", "icmp", 0, 20.).p95_ms, Some(19.));
        assert!(!s.summary("127.0.0.1", "icmp", 0, 81.).fresh);
    }
    #[test]
    fn stale_delayed_result_never_becomes_fresh_on_resume() {
        let mut s = LatencyStore::default();
        assert!(s.record(
            "127.0.0.1",
            "tcp",
            443,
            LatencyOutcome::Success,
            Some(10.),
            100.,
            Some(1.)
        ));
        assert!(!s.summary("127.0.0.1", "tcp", 443, 100.).fresh);
        assert!(!s.record(
            "127.0.0.1",
            "tcp",
            443,
            LatencyOutcome::Success,
            Some(10.),
            101.,
            Some(102.)
        ));
    }
    #[test]
    fn three_icmp_failures_slow_down_probe_schedule() {
        let mut s = LatencyStore::default();
        for i in 0..3 {
            s.record(
                "127.0.0.1",
                "icmp",
                0,
                LatencyOutcome::Timeout,
                None,
                i as f64,
                None,
            );
        }
        s.scheduled("127.0.0.1", "icmp", 0, 2.);
        assert!(!s.due("127.0.0.1", "icmp", 0, 61.));
        assert!(s.due("127.0.0.1", "icmp", 0, 62.));
    }
}
