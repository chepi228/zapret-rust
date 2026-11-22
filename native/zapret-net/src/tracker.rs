//! Enrichment of a finished, bounded ETW capture. Active probes observe the network now;
//! they are never evidence of latency during an earlier recorded pause.
use crate::{diagnostic as d, http, latency};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
    path::Path,
    time::Duration,
};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout},
};

const FLOW_LIMIT: usize = 512;
const PEER_LIMIT: usize = 12;
const TCP_LIMIT: usize = 12;
const GEO_LIMIT: usize = 6;

#[derive(Clone, Debug)]
struct Options {
    probes: bool,
    tcp_fallback: bool,
    geo: bool,
    dns_names: bool,
    count: u64,
    timeout_ms: u64,
    interval_ms: u64,
    deadline_ms: u64,
}
fn boolean(args: &Value, name: &str, default: bool) -> Result<bool> {
    args.get(name)
        .map(|value| {
            value
                .as_bool()
                .with_context(|| format!("{name} must be boolean"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}
impl Options {
    fn parse(args: &Value) -> Result<Self> {
        ensure!(
            args.is_object(),
            "tracker diagnostic arguments must be an object"
        );
        Ok(Self {
            probes: boolean(args, "active_probes", true)?,
            tcp_fallback: boolean(args, "tcp_fallback", true)?,
            geo: boolean(args, "geo", false)?,
            dns_names: boolean(args, "dns_names", true)?,
            count: d::integer(args, "probe_count", 3, 1, 20)?,
            timeout_ms: d::integer(args, "probe_timeout_ms", 1000, 1, 2000)?,
            interval_ms: d::integer(args, "probe_interval_ms", 250, 0, 2000)?,
            deadline_ms: d::integer(args, "diagnostic_deadline_ms", 20000, 1, 30000)?,
        })
    }
}

/// A conservative active-probe policy, stricter than legacy passive ETW reporting.
/// Special-use/documentation, local and address-translation literals are not probed.
fn public_peer(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            !(b[0] == 0
                || b[0] == 10
                || b[0] == 127
                || b[0] >= 224
                || (b[0] == 100 && (64..=127).contains(&b[1]))
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && (16..=31).contains(&b[1]))
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && matches!(b[2], 0 | 2))
                || (b[0] == 192 && b[1] == 88 && b[2] == 99)
                || (b[0] == 198 && matches!(b[1], 18 | 19))
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113))
        }
        IpAddr::V6(ip) => {
            let b = ip.segments();
            b[0] & 0xe000 == 0x2000
                && !(b[0] == 0x2001
                    && (b[1] == 0
                        || b[1] == 0xdb8
                        || b[1] == 2
                        || b[1] & 0xfff0 == 0x10
                        || b[1] & 0xfff0 == 0x20))
                && b[0] != 0x2002
                && !(b[0] == 0x3fff && b[1] & 0xf000 == 0)
        }
    }
}
fn counter(flow: &Value, name: &str) -> u64 {
    flow[name].as_u64().unwrap_or(0)
}
fn weight(flow: &Value) -> (u64, u64) {
    (
        counter(flow, "out").saturating_add(counter(flow, "in")),
        counter(flow, "bytes_out").saturating_add(counter(flow, "bytes_in")),
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProbeTarget {
    address: IpAddr,
    kind: &'static str,
    port: u16,
}
#[derive(Debug)]
struct Selection {
    peers: Vec<IpAddr>,
    tcp: Vec<ProbeTarget>,
    public_peer_count: usize,
    tcp_endpoint_count: usize,
    rejected_flows: usize,
    flows_truncated: bool,
}
fn select(capture: &Value) -> Selection {
    let values = capture["flows"].as_array().map_or(&[][..], Vec::as_slice);
    let mut ips = BTreeMap::<IpAddr, (u64, u64)>::new();
    let mut tcp = BTreeMap::<(IpAddr, u16), (u64, u64)>::new();
    let mut rejected = 0;
    for flow in values.iter().take(FLOW_LIMIT) {
        let Some(address) = flow["address"].as_str().and_then(|s| s.parse().ok()) else {
            rejected += 1;
            continue;
        };
        let Some(port) = flow["port"].as_u64().filter(|p| (1..=65535).contains(p)) else {
            rejected += 1;
            continue;
        };
        if !public_peer(address) || !matches!(flow["protocol"].as_str(), Some("tcp" | "udp")) {
            rejected += 1;
            continue;
        }
        let w = weight(flow);
        let ip = ips.entry(address).or_default();
        ip.0 = ip.0.saturating_add(w.0);
        ip.1 = ip.1.saturating_add(w.1);
        if flow["protocol"] == "tcp" {
            let row = tcp.entry((address, port as u16)).or_default();
            row.0 = row.0.saturating_add(w.0);
            row.1 = row.1.saturating_add(w.1);
        }
    }
    let public_peer_count = ips.len();
    let mut ips: Vec<_> = ips.into_iter().collect();
    ips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let peers: Vec<_> = ips.into_iter().take(PEER_LIMIT).map(|(ip, _)| ip).collect();
    let mut tcp: Vec<_> = tcp
        .into_iter()
        .filter(|((ip, _), _)| peers.contains(ip))
        .collect();
    tcp.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let tcp_endpoint_count = tcp.len();
    Selection {
        peers,
        tcp: tcp
            .into_iter()
            .take(TCP_LIMIT)
            .map(|((address, port), _)| ProbeTarget {
                address,
                kind: "tcp",
                port,
            })
            .collect(),
        public_peer_count,
        tcp_endpoint_count,
        rejected_flows: rejected,
        flows_truncated: values.len() > FLOW_LIMIT,
    }
}

#[derive(Debug, Serialize)]
struct TimedSample {
    address: String,
    kind: String,
    port: u16,
    sample: u64,
    outcome: latency::LatencyOutcome,
    ms: Option<f64>,
    error: String,
    evidence: String,
    started_utc_ms: String,
    completed_utc_ms: String,
    started_after_ms: f64,
    completed_after_ms: f64,
    elapsed_ms: f64,
    operation_elapsed_ms: f64,
    phase: &'static str,
    clock_basis: &'static str,
    capture_correlation_not_measured: bool,
    game_latency_measured: bool,
}
async fn timed_probe(
    target: ProbeTarget,
    sample: u64,
    budget: u64,
    origin: Instant,
) -> TimedSample {
    let started_utc_ms = d::now();
    let start = Instant::now();
    let measured = latency::probe(
        target.address,
        target.kind,
        target.port,
        sample,
        budget,
        origin,
    )
    .await;
    let end = Instant::now();
    TimedSample {
        address: measured.address,
        kind: measured.kind,
        port: measured.port,
        sample: measured.sample,
        outcome: measured.outcome,
        ms: measured.ms,
        error: measured.error,
        evidence: measured.evidence,
        started_utc_ms,
        completed_utc_ms: d::now(),
        started_after_ms: start.duration_since(origin).as_secs_f64() * 1000.,
        completed_after_ms: end.duration_since(origin).as_secs_f64() * 1000.,
        elapsed_ms: end.duration_since(start).as_secs_f64() * 1000.,
        operation_elapsed_ms: measured.completed_after_ms,
        phase: "PostCapture",
        clock_basis: "UtcOperationBoundsAndMonotonicDuration",
        capture_correlation_not_measured: true,
        game_latency_measured: false,
    }
}
fn remaining_ms(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64
}
fn completion(deadline: Instant, cancel: &watch::Receiver<bool>) -> &'static str {
    if *cancel.borrow() {
        "Interrupted"
    } else if remaining_ms(deadline) == 0 {
        "Deadline"
    } else {
        "Completed"
    }
}
#[allow(clippy::too_many_arguments)]
async fn samples(
    targets: &[ProbeTarget],
    options: &Options,
    parallel: usize,
    origin: Instant,
    deadline: Instant,
    cancel: &watch::Receiver<bool>,
    store: &mut latency::LatencyStore,
) -> Result<Vec<TimedSample>> {
    let mut rows = Vec::new();
    let mut cancellation = cancel.clone();
    for sample in 1..=options.count {
        let mut queue: VecDeque<_> = targets.iter().copied().collect();
        let mut pending = JoinSet::new();
        loop {
            while pending.len() < parallel && !*cancel.borrow() {
                let budget = remaining_ms(deadline).min(options.timeout_ms);
                if budget == 0 {
                    break;
                }
                let Some(target) = queue.pop_front() else {
                    break;
                };
                store.scheduled(
                    &target.address.to_string(),
                    target.kind,
                    target.port,
                    origin.elapsed().as_secs_f64(),
                );
                pending.spawn(timed_probe(target, sample, budget, origin));
            }
            let Some(row) = pending.join_next().await else {
                break;
            };
            let row = row.context("tracker latency task failed")?;
            let now = origin.elapsed().as_secs_f64();
            store.record(
                &row.address,
                &row.kind,
                row.port,
                row.outcome,
                row.ms,
                now,
                Some((row.completed_after_ms / 1000.).min(now)),
            );
            rows.push(row);
        }
        if *cancel.borrow() || remaining_ms(deadline) == 0 {
            break;
        }
        if sample < options.count && !targets.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(options.interval_ms.min(remaining_ms(deadline)))) => {},
                _ = cancellation.changed() => {},
            }
        }
    }
    Ok(rows)
}
async fn latency_observations(
    selection: &Selection,
    options: &Options,
    origin: Instant,
    deadline: Instant,
    cancel: &watch::Receiver<bool>,
) -> Result<Value> {
    if !options.probes {
        return Ok(
            json!({"completion":"Skipped","reason":"ActiveProbesDisabled","rows":[],"summaries":[]}),
        );
    }
    let icmp: Vec<_> = selection
        .peers
        .iter()
        .map(|&address| ProbeTarget {
            address,
            kind: "icmp",
            port: 0,
        })
        .collect();
    let mut store = latency::LatencyStore::default();
    let mut rows = samples(&icmp, options, 6, origin, deadline, cancel, &mut store).await?;
    let now = origin.elapsed().as_secs_f64();
    let mut summaries = Vec::new();
    let mut icmp_available = BTreeSet::new();
    for ip in &selection.peers {
        let summary = store.summary(&ip.to_string(), "icmp", 0, now);
        if summary.fresh {
            icmp_available.insert(*ip);
        }
    }
    let fallback: Vec<_> = selection
        .tcp
        .iter()
        .copied()
        .filter(|t| !icmp_available.contains(&t.address))
        .collect();
    if options.tcp_fallback {
        rows.extend(samples(&fallback, options, 3, origin, deadline, cancel, &mut store).await?);
    }
    let now = origin.elapsed().as_secs_f64();
    for target in icmp
        .iter()
        .chain(fallback.iter().filter(|_| options.tcp_fallback))
    {
        summaries.push(json!({"address":target.address,"kind":target.kind,"port":target.port,"summary":store.summary(&target.address.to_string(),target.kind,target.port,now)}));
    }
    let not_probed: Vec<_> = selection.tcp.iter().filter(|t| !options.tcp_fallback || icmp_available.contains(&t.address)).map(|t| json!({"address":t.address,"port":t.port,"kind":"tcp","reason":if options.tcp_fallback{"FreshIcmpAvailable"}else{"TcpFallbackDisabled"}})).collect();
    Ok(
        json!({"phase":"PostCapture","capture_correlation_not_measured":true,"game_latency_measured":false,"completion":completion(deadline,cancel),"timeout_ms":options.timeout_ms,"requested_samples_per_stream":options.count,"rows":rows,"summaries":summaries,"tcp_not_probed":not_probed,"p95_minimum_successes":20,"summary_window_seconds":600,"summary_max_samples":120,"udp_loss_measured":false,"cause":"NotEstablished"}),
    )
}

fn clean(value: &Value) -> String {
    value
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}
fn parse_geo(value: &Value, address: IpAddr, primary: bool) -> Result<Value> {
    if primary {
        ensure!(
            value["success"] == true,
            "geolocation service did not return success"
        );
    }
    let received: IpAddr = value["ip"]
        .as_str()
        .context("geolocation response omitted IP")?
        .parse()
        .context("geolocation response contains invalid IP")?;
    ensure!(
        received == address,
        "geolocation response IP differs from observed peer"
    );
    let code = clean(&value[if primary { "country_code" } else { "country" }]);
    ensure!(
        code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()),
        "geolocation response omitted country code"
    );
    let coords = clean(&value["loc"]);
    let (lat, lon) = if primary {
        (value["latitude"].as_f64(), value["longitude"].as_f64())
    } else {
        coords
            .split_once(',')
            .map_or((None, None), |(a, b)| (a.parse().ok(), b.parse().ok()))
    };
    Ok(
        json!({"ip":address,"country_code":code.to_ascii_uppercase(),"country":if primary{clean(&value["country"])}else{code.clone()},"region":clean(&value["region"]),"city":clean(&value["city"]),"organization":if primary{clean(&value["connection"]["org"])}else{clean(&value["org"])},"isp":if primary{clean(&value["connection"]["isp"])}else{String::new()},"latitude":lat.filter(|n|n.is_finite()&&(-90.0..=90.).contains(n)),"longitude":lon.filter(|n|n.is_finite()&&(-180.0..=180.).contains(n)),"source":"ExternalProviderMetadata","peer_service_attribution":"NotConfirmed"}),
    )
}
async fn geo_peer(
    address: IpAddr,
    origin: Instant,
    deadline: Instant,
    cancel: watch::Receiver<bool>,
) -> Value {
    let mut observations = Vec::new();
    let mut metadata = None;
    for (primary, url) in [
        (true, format!("https://ipwho.is/{address}?lang=ru")),
        (false, format!("https://ipinfo.io/{address}/json")),
    ] {
        let budget = remaining_ms(deadline).min(1500);
        if budget == 0 || *cancel.borrow() {
            break;
        }
        let started_utc_ms = d::now();
        let start = Instant::now();
        let result = async {
            let body = http::fetch_async(&url, 65536, budget, None).await?;
            let value: Value = serde_json::from_slice(&body).context("invalid geolocation JSON")?;
            parse_geo(&value, address, primary)
        }
        .await;
        let mut row = json!({"url":url,"started_utc_ms":started_utc_ms,"completed_utc_ms":d::now(),"started_after_ms":start.duration_since(origin).as_secs_f64()*1000.,"completed_after_ms":origin.elapsed().as_secs_f64()*1000.,"elapsed_ms":start.elapsed().as_secs_f64()*1000.});
        match result {
            Ok(value) => {
                row["state"] = json!("Observed");
                metadata = Some(value);
                observations.push(row);
                break;
            }
            Err(error) => {
                row["state"] = json!("Unknown");
                row["error"] = json!(format!("{error:#}"));
                observations.push(row);
            }
        }
    }
    json!({"address":address,"state":if metadata.is_some(){"Observed"}else{"Unknown"},"metadata":metadata,"observations":observations,"completion":completion(deadline,&cancel),"capture_correlation_not_measured":true})
}
async fn geolocation(
    selection: &Selection,
    options: &Options,
    origin: Instant,
    deadline: Instant,
    cancel: &watch::Receiver<bool>,
) -> Result<Value> {
    if !options.geo {
        return Ok(
            json!({"requested":false,"completion":"Skipped","reason":"NotRequested","rows":[]}),
        );
    }
    let mut queue: VecDeque<_> = selection.peers.iter().take(GEO_LIMIT).copied().collect();
    let mut pending = JoinSet::new();
    let mut rows = Vec::new();
    loop {
        while pending.len() < 2 && !*cancel.borrow() && remaining_ms(deadline) > 0 {
            let Some(address) = queue.pop_front() else {
                break;
            };
            pending.spawn(geo_peer(address, origin, deadline, cancel.clone()));
        }
        let Some(row) = pending.join_next().await else {
            break;
        };
        rows.push(row.context("tracker geolocation task failed")?);
    }
    Ok(
        json!({"requested":true,"scope":"ObservedPublicPeersOnly","peer_limit":GEO_LIMIT,"completion":completion(deadline,cancel),"rows":rows,"not_started":queue,"approximate":true,"cause":"NotEstablished"}),
    )
}

#[cfg(any(windows, test))]
fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", b[3], b[2], b[1], b[0])
        }
        IpAddr::V6(ip) => {
            let text: String = ip.octets().iter().map(|b| format!("{b:02x}")).collect();
            let mut name = String::with_capacity(73);
            for c in text.chars().rev() {
                name.push(c);
                name.push('.');
            }
            name.push_str("ip6.arpa.");
            name
        }
    }
}
#[cfg(windows)]
fn cached_ptr(address: IpAddr) -> Value {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::NetworkManagement::Dns::*;
    let name: Vec<_> = reverse_name(address)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut records = null_mut();
    // Documented cache-only lookup; no DNS, LLMNR, NetBT, hosts or suffix expansion.
    // https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants
    let status = unsafe {
        DnsQuery_W(
            name.as_ptr(),
            DNS_TYPE_PTR,
            DNS_QUERY_CACHE_ONLY
                | DNS_QUERY_NO_HOSTS_FILE
                | DNS_QUERY_NO_NETBT
                | DNS_QUERY_NO_MULTICAST
                | DNS_QUERY_NO_LOCAL_NAME
                | DNS_QUERY_TREAT_AS_FQDN,
            null_mut(),
            &mut records,
            null_mut(),
        )
    };
    struct Records(*mut DNS_RECORDA);
    impl Drop for Records {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DnsFree(self.0.cast(), DnsFreeRecordList);
                }
            }
        }
    }
    let _owner = Records(records);
    if status != 0 {
        return json!({"state":"Unknown","reason":"CacheMissOrUnavailable","os_status":status,"names":[],"truncated":false});
    }
    let mut names = BTreeSet::new();
    let mut visited = 0;
    while !records.is_null() && visited < 64 && names.len() < 8 {
        // DnsQuery_W returns the Unicode record layout despite the SDK's generic pointer type.
        let record = unsafe { &*records.cast::<DNS_RECORDW>() };
        if record.wType == DNS_TYPE_PTR
            && usize::from(record.wDataLength) >= size_of::<DNS_PTR_DATAW>()
        {
            let pointer = unsafe { record.Data.PTR.pNameHost };
            if !pointer.is_null() {
                let mut length = 0;
                while length < 254 && unsafe { *pointer.add(length) } != 0 {
                    length += 1;
                }
                if length < 254 {
                    let name = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(pointer, length)
                    });
                    let name = name.trim_end_matches('.').to_ascii_lowercase();
                    if !name.is_empty()
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                    {
                        names.insert(name);
                    }
                }
            }
        }
        records = record.pNext.cast();
        visited += 1;
    }
    json!({"state":if names.is_empty(){"Unknown"}else{"Observed"},"reason":if names.is_empty(){"NoCachedPtr"}else{"CachedPtr"},"names":names,"truncated":!records.is_null()})
}
#[cfg(not(windows))]
fn cached_ptr(_address: IpAddr) -> Value {
    json!({"state":"Unknown","reason":"NativeDnsCacheUnavailable","names":[],"truncated":false})
}
async fn cache_peer(address: IpAddr, origin: Instant, deadline: Instant) -> Value {
    let started_utc_ms = d::now();
    let start = Instant::now();
    let budget = remaining_ms(deadline).min(500);
    let result = if budget == 0 {
        json!({"state":"Unknown","reason":"Deadline","names":[]})
    } else {
        match timeout(
            Duration::from_millis(budget),
            tokio::task::spawn_blocking(move || cached_ptr(address)),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                json!({"state":"Unknown","reason":"CacheReadFailed","error":error.to_string(),"names":[]})
            }
            Err(_) => json!({"state":"Unknown","reason":"CacheReadDeadline","names":[]}),
        }
    };
    let mut row = result;
    row["address"] = json!(address);
    row["started_utc_ms"] = json!(started_utc_ms);
    row["completed_utc_ms"] = json!(d::now());
    row["started_after_ms"] = json!(start.duration_since(origin).as_secs_f64() * 1000.);
    row["completed_after_ms"] = json!(origin.elapsed().as_secs_f64() * 1000.);
    row["elapsed_ms"] = json!(start.elapsed().as_secs_f64() * 1000.);
    row["clock_basis"] = json!("CallerObservedCompletionOrDeadline");
    row
}

#[cfg(windows)]
async fn forward_cache(
    peers: Vec<IpAddr>,
    deadline: Instant,
    mut cancel: watch::Receiver<bool>,
) -> (Value, BTreeMap<IpAddr, BTreeSet<String>>) {
    let budget = remaining_ms(deadline).min(1_000);
    if budget == 0 || *cancel.borrow() {
        return (
            json!({"state":"Skipped","reason":completion(deadline, &cancel)}),
            BTreeMap::new(),
        );
    }
    let duration = Duration::from_millis(budget);
    let mut worker =
        tokio::task::spawn_blocking(move || zapret_platform::forward_dns_cache(&peers, duration));
    let state = tokio::select! {
        biased;
        _ = cancel.changed() => json!({"state":"Skipped","reason":"Interrupted"}),
        result = timeout(duration, &mut worker) => match result {
            Ok(Ok(Ok(cache))) => {
                let state = if cache.enumerated && !cache.names_truncated { "Completed" } else { "Partial" };
                return (json!({"state":state,"enumerated":cache.enumerated,
                    "names_truncated":cache.names_truncated}), cache.names);
            }
            Ok(Ok(Err(error))) => json!({"state":"Unknown","reason":"CacheReadFailed","error":format!("{error:#}")}),
            Ok(Err(error)) => json!({"state":"Unknown","reason":"CacheReadFailed","error":error.to_string()}),
            Err(_) => json!({"state":"Unknown","reason":"CacheReadDeadline"}),
        }
    };
    worker.abort();
    (state, BTreeMap::new())
}

#[cfg(not(windows))]
async fn forward_cache(
    _peers: Vec<IpAddr>,
    _deadline: Instant,
    _cancel: watch::Receiver<bool>,
) -> (Value, BTreeMap<IpAddr, BTreeSet<String>>) {
    (
        json!({"state":"Unknown","reason":"NativeDnsCacheUnavailable"}),
        BTreeMap::new(),
    )
}

fn merge_cache_names(row: &mut Value, forward_names: &BTreeSet<String>) {
    let ptr_names = row["names"].clone();
    let mut names: BTreeSet<_> = ptr_names
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    names.extend(forward_names.iter().map(String::as_str));
    row["names"] = json!(names);
    row["ptr_names"] = ptr_names;
    row["forward_names"] = json!(forward_names);
    row["state"] = json!("Observed");
    row["reason"] = json!("CachedForwardAddress");
}

async fn dns_names(
    selection: &Selection,
    options: &Options,
    origin: Instant,
    deadline: Instant,
    cancel: &watch::Receiver<bool>,
) -> Result<Value> {
    if !options.dns_names {
        return Ok(json!({"completion":"Skipped","reason":"DnsNamesDisabled","rows":[]}));
    }
    let reverse = async {
        let mut queue: VecDeque<_> = selection.peers.iter().copied().collect();
        let mut pending = JoinSet::new();
        let mut rows = Vec::new();
        loop {
            while pending.len() < 4 && !*cancel.borrow() && remaining_ms(deadline) > 0 {
                let Some(address) = queue.pop_front() else {
                    break;
                };
                pending.spawn(cache_peer(address, origin, deadline));
            }
            let Some(row) = pending.join_next().await else {
                break;
            };
            rows.push(row.context("tracker DNS cache task failed")?);
        }
        Ok::<_, anyhow::Error>((rows, queue))
    };
    let (reverse, (forward, names)) = tokio::join!(
        reverse,
        forward_cache(selection.peers.clone(), deadline, cancel.clone())
    );
    let (mut rows, mut queue) = reverse?;
    for (address, names) in names {
        if let Some(row) = rows.iter_mut().find(|row| {
            row["address"]
                .as_str()
                .and_then(|value| value.parse::<IpAddr>().ok())
                == Some(address)
        }) {
            merge_cache_names(row, &names);
        } else {
            queue.retain(|peer| *peer != address);
            rows.push(
                json!({"address":address,"state":"Observed","reason":"CachedForwardAddress",
                "names":names,"forward_names":names}),
            );
        }
    }
    Ok(
        json!({"completion":completion(deadline,cancel),"mode":"WindowsDnsClientCache","external_queries":false,"scope":"MachineCacheNotProcessAttribution",
            "forward_cache_enumerated":forward["enumerated"] == true,"forward_cache":forward,"rows":rows,"not_started":queue,
            "caller_deadline_bounded":true,"pending_os_cache_read_may_outlive_deadline":true}),
    )
}

fn packet_timing(capture: &Value) -> Value {
    let flows = capture["flows"].as_array().map_or(&[][..], Vec::as_slice);
    let incomplete = capture["truncated"] == true
        || capture["identities_incomplete"] == true
        || counter(capture, "events_lost") > 0
        || counter(capture, "decode_errors") > 0
        || counter(&capture["trace"], "events_lost") > 0
        || counter(&capture["trace"], "decode_errors") > 0
        || flows.len() > FLOW_LIMIT;
    let duration = capture["duration_sec"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.);
    let mut rows = Vec::new();
    let mut retx = 0u64;
    let mut udp_no_reply = 0;
    let mut tcp_no_data = 0;
    let mut main_udp = None::<(u64, usize)>;
    for (index, flow) in flows.iter().take(FLOW_LIMIT).enumerate() {
        retx = retx.saturating_add(counter(flow, "retx"));
        let udp_no_incoming =
            flow["protocol"] == "udp" && counter(flow, "out") >= 20 && counter(flow, "in") == 0;
        let tcp_attempts = flow["protocol"] == "tcp"
            && counter(flow, "syn_attempts") > 0
            && counter(flow, "out") == 0
            && counter(flow, "in") == 0;
        udp_no_reply += usize::from(udp_no_incoming);
        tcp_no_data += usize::from(tcp_attempts);
        let w = weight(flow).0;
        if flow["protocol"] == "udp"
            && duration.is_some_and(|seconds| w as f64 / seconds >= 5.)
            && main_udp.is_none_or(|(best, _)| w > best)
        {
            main_udp = Some((w, index));
        }
        rows.push(json!({"flow_index":index,"address":flow["address"],"port":flow["port"],"protocol":flow["protocol"],"out":flow["out"],"in":flow["in"],"retx":flow["retx"],"syn_attempts":flow["syn_attempts"],"state":if flow["timing"].is_object(){"Observed"}else{"Unknown"},"timing":flow["timing"],"udp_outgoing_without_observed_reply":udp_no_incoming,"tcp_attempts_without_observed_data":tcp_attempts,"cause":"NotEstablished"}));
    }
    let main_udp = main_udp.map(|(_, index)| json!({"flow_index":index,"address":flows[index]["address"],"port":flows[index]["port"],"criterion":"HighestUdpObservedPacketCountAtLeast5PerSecondOverCapture","game_or_voice_attribution":"NotConfirmed"}));
    json!({"scope":"EtwObservedEvents","coverage_incomplete":incomplete,"cause":"NotEstablished","flows":rows,"context":capture["timing_context"],"retransmit_events":retx,"udp_flows_without_observed_reply":udp_no_reply,"tcp_attempt_flows_without_observed_data":tcp_no_data,"main_udp_candidate":main_udp,"gap_latency_correlation":"NotMeasured"})
}
fn millis(value: &Value) -> String {
    value
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.)
        .map_or_else(|| "—".into(), |n| format!("{n:.1}"))
}
fn summary_lines(value: &Value) -> Vec<String> {
    let mut lines = vec!["Пробы задержки относятся к периоду после записи ETW; задержка игры во время записанных пауз не измерена.".into()];
    if value["completion"] == "Skipped" {
        let reason = match value["reason"].as_str() {
            Some("OfflineReplay") => "разбор сохранённой записи без сетевых обращений",
            Some("CaptureUnavailable") => "захват сетевых событий недоступен",
            Some("CaptureCleanupUnconfirmed") => {
                "завершение захвата сетевых событий не подтверждено"
            }
            Some("NoObservedPublicPeers") => "в записи нет подходящих публичных адресов",
            _ => "данных недостаточно",
        };
        lines.push(format!(
            "Дополнительные обращения не выполнялись: {reason}."
        ));
    }
    if value["packet_timing"]["coverage_incomplete"] == true {
        lines.push(
            "Покрытие ETW неполное; отсутствие события не доказывает отсутствие пакета.".into(),
        );
    }
    let timing = &value["packet_timing"];
    if timing["context"].is_object() {
        let context = &timing["context"];
        lines.push(format!("Общая тишина между наблюдавшимися событиями данных: макс {} мс, >100 мс {}, >250 мс {}. Это интервалы ETW, причина не установлена.", millis(&context["max_gap_ms"]), counter(context,"over_100_ms"), counter(context,"over_250_ms")));
    }
    if counter(timing, "udp_flows_without_observed_reply") > 0
        || counter(timing, "tcp_attempt_flows_without_observed_data") > 0
    {
        lines.push(format!("Потоков UDP с >=20 исходящими событиями без наблюдавшихся входящих: {}; потоков TCP с попытками подключения без наблюдавшихся данных: {}. Причина не установлена.", counter(timing,"udp_flows_without_observed_reply"), counter(timing,"tcp_attempt_flows_without_observed_data")));
    }
    if timing["main_udp_candidate"].is_object() {
        let candidate = &timing["main_udp_candidate"];
        lines.push(format!("Наиболее активный UDP: {}:{}, не менее 5 событий/с в среднем по записи. Связь с матчем или голосом не подтверждена.", candidate["address"].as_str().unwrap_or("?"),counter(candidate,"port")));
    }
    if let Some(rows) = value["latency"]["summaries"].as_array() {
        for row in rows {
            let s = &row["summary"];
            lines.push(format!("После записи: {} {}:{} — медиана/P95 {}/{} мс, ответы/попытки {}/{}, timeout {}, ошибки {}.",row["kind"].as_str().unwrap_or("?"),row["address"].as_str().unwrap_or("?"),row["port"].as_u64().unwrap_or(0),millis(&s["median_ms"]),millis(&s["p95_ms"]),s["success_count"].as_u64().unwrap_or(0),s["count"].as_u64().unwrap_or(0),s["timeouts"].as_u64().unwrap_or(0),s["errors"].as_u64().unwrap_or(0)));
        }
        if !rows.is_empty() {
            lines.push("P95 требует 20 ответов. ICMP/TCP-пробы и их неответы не измеряют потери UDP; причина пауз не установлена.".into());
        }
    }
    if let Some(rows) = value["geolocation"]["rows"].as_array() {
        for row in rows.iter().filter(|r| r["state"] == "Observed") {
            let m = &row["metadata"];
            lines.push(format!(
                "География по внешнему справочнику: {} — {}, {}, {} (приблизительно).",
                row["address"].as_str().unwrap_or("?"),
                m["country"].as_str().unwrap_or("?"),
                m["city"].as_str().unwrap_or(""),
                m["organization"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(rows) = value["dns_names"]["rows"].as_array() {
        for row in rows {
            let names: Vec<_> = row["names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !names.is_empty() {
                lines.push(format!(
                    "Кэш DNS Windows: {} — {} (общий кэш, связь с процессом не доказана).",
                    row["address"].as_str().unwrap_or("?"),
                    names.join(", ")
                ));
            }
        }
    }
    if let Some(rows) = value["packet_timing"]["flows"].as_array() {
        for row in rows.iter().filter(|r| r["state"] == "Observed").take(32) {
            let t = &row["timing"];
            lines.push(format!("Паузы ETW {} {}:{}: макс вых/вх {}/{} мс, >100 мс {}/{}, retx {}. Причина не установлена.",row["protocol"].as_str().unwrap_or("?"),row["address"].as_str().unwrap_or("?"),row["port"].as_u64().unwrap_or(0),millis(&t["outgoing"]["max_gap_ms"]),millis(&t["incoming"]["max_gap_ms"]),t["outgoing"]["over_100_ms"].as_u64().unwrap_or(0),t["incoming"]["over_100_ms"].as_u64().unwrap_or(0),row["retx"].as_u64().unwrap_or(0)));
        }
    }
    lines
}

/// Add bounded observations to a completed capture without modifying the capture or system state.
///
/// At most 12 literal public peer IPs are selected from actual captured flows, with no hostname
/// or port expansion. ICMP is sampled first; observed TCP endpoints are sampled only if their IP
/// has no fresh ICMP answer. Optional `geo: true` queries at most six observed peer IPs.
/// `active_probes: false` disables ICMP/TCP, and `dns_names: false` disables local DNS cache reads.
/// Replay, failed capture and unconfirmed cleanup never trigger any enrichment network activity.
pub fn enrich_tracker(_root: &Path, capture: &Value, args: &Value) -> Result<Value> {
    let options = Options::parse(args)?;
    ensure!(capture.is_object(), "tracker capture must be an object");
    let origin = Instant::now();
    let started_utc_ms = d::now();
    let selection = select(capture);
    let skip = if capture["capture_kind"] == "OfflineReplay" || capture["status"] == "Replayed" {
        Some("OfflineReplay")
    } else if !matches!(capture["status"].as_str(), Some("Captured" | "Partial")) {
        Some("CaptureUnavailable")
    } else if capture["cleanup_confirmed"] != true {
        Some("CaptureCleanupUnconfirmed")
    } else if selection.peers.is_empty() {
        Some("NoObservedPublicPeers")
    } else {
        None
    };
    let packet_timing = packet_timing(capture);
    let mut result = if let Some(reason) = skip {
        json!({"completion":"Skipped","reason":reason,"latency":{"completion":"Skipped","reason":reason,"rows":[],"summaries":[]},"geolocation":{"requested":options.geo,"completion":"Skipped","reason":reason,"rows":[]},"dns_names":{"completion":"Skipped","reason":reason,"external_queries":false,"rows":[]}})
    } else {
        crate::runtime(async {
            let deadline = origin + Duration::from_millis(options.deadline_ms);
            let cancel = d::cancellation();
            let (latency, geolocation, dns_names) = tokio::join!(
                latency_observations(&selection, &options, origin, deadline, &cancel),
                geolocation(&selection, &options, origin, deadline, &cancel),
                dns_names(&selection, &options, origin, deadline, &cancel)
            );
            Ok(
                json!({"completion":completion(deadline,&cancel),"latency":latency?,"geolocation":geolocation?,"dns_names":dns_names?}),
            )
        })?
    };
    result["schema"] = json!(1);
    result["kind"] = json!("TrackerDiagnostics");
    result["phase"] = json!("PostCapture");
    result["capture_correlation_not_measured"] = json!(true);
    result["game_latency_measured"] = json!(false);
    result["started_utc_ms"] = json!(started_utc_ms);
    result["finished_utc_ms"] = json!(d::now());
    result["elapsed_ms"] = json!(origin.elapsed().as_secs_f64() * 1000.);
    result["deadline_ms"] = json!(options.deadline_ms);
    result["selection"] = json!({"scope":"ObservedLiteralPublicPeersOnly","addresses":selection.peers,"public_peers_observed":selection.public_peer_count,"peer_limit":PEER_LIMIT,"peer_limit_reached":selection.public_peer_count>PEER_LIMIT,"tcp_endpoint_limit":TCP_LIMIT,"tcp_endpoints_observed_for_selected_peers":selection.tcp_endpoint_count,"tcp_endpoint_limit_reached":selection.tcp_endpoint_count>TCP_LIMIT,"rejected_flow_count":selection.rejected_flows,"flow_input_truncated":selection.flows_truncated});
    result["packet_timing"] = packet_timing;
    result["cause"] = json!("NotEstablished");
    result["summary_lines"] = json!(summary_lines(&result));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow(address: &str, protocol: &str, port: u64, packets: u64) -> Value {
        json!({"address":address,"protocol":protocol,"port":port,"out":packets,"in":0,"bytes_out":packets*100,"bytes_in":0,"retx":0,"syn_attempts":0})
    }
    #[test]
    fn targets_are_bounded_public_literal_observed_endpoints() {
        let mut flows = vec![
            flow("127.0.0.1", "tcp", 443, 999),
            flow("::ffff:192.168.1.1", "tcp", 443, 999),
            flow("192.0.2.1", "tcp", 443, 999),
            flow("2001:db8::1", "udp", 53, 999),
            flow("host.example", "tcp", 443, 999),
            flow("8.8.8.8", "tcp", 0, 999),
            flow("8.8.8.8", "icmp", 443, 999),
        ];
        flows.extend((1..=20).map(|i| flow(&format!("9.0.0.{i}"), "tcp", 4000 + i, i)));
        flows.push(flow("9.0.0.20", "tcp", 4020, 20));
        let s = select(&json!({"flows":flows}));
        assert_eq!(s.peers.len(), 12);
        assert_eq!(s.peers[0].to_string(), "9.0.0.20");
        assert_eq!(s.public_peer_count, 20);
        assert_eq!(s.rejected_flows, 7);
        assert_eq!(s.tcp.len(), 12);
        assert!(s.tcp.iter().all(|t| t.port >= 4009 && t.port <= 4020));
    }
    #[test]
    fn public_filter_rejects_special_ranges_and_keeps_native_public_families() {
        for s in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.0.1",
            "192.168.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001:db8::1",
            "2001:2::1",
            "2002:808:808::",
            "3fff::1",
        ] {
            assert!(!public_peer(s.parse().unwrap()), "{s}");
        }
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_peer(s.parse().unwrap()), "{s}");
        }
    }
    #[test]
    fn replay_failed_capture_and_cleanup_unknown_never_start_network_enrichment() {
        for (capture, reason) in [
            (
                json!({"status":"Replayed","capture_kind":"OfflineReplay","flows":[flow("8.8.8.8","tcp",443,1)]}),
                "OfflineReplay",
            ),
            (
                json!({"status":"Unavailable","flows":[flow("8.8.8.8","tcp",443,1)]}),
                "CaptureUnavailable",
            ),
            (
                json!({"status":"Captured","cleanup_confirmed":false,"flows":[flow("8.8.8.8","tcp",443,1)]}),
                "CaptureCleanupUnconfirmed",
            ),
        ] {
            let row = enrich_tracker(Path::new("."), &capture, &json!({"geo":true})).unwrap();
            assert_eq!(row["completion"], "Skipped");
            assert_eq!(row["reason"], reason);
            assert_eq!(row["latency"]["rows"], json!([]));
            assert_eq!(row["geolocation"]["rows"], json!([]));
            assert_eq!(row["dns_names"]["rows"], json!([]));
            assert_eq!(row["capture_correlation_not_measured"], true);
        }
    }
    #[test]
    fn gap_counts_are_taken_only_from_observed_event_timing() {
        let mut udp = flow("8.8.8.8", "udp", 20000, 40);
        udp["timing"] = json!({"incoming":{"gap_count":0,"max_gap_ms":null,"over_100_ms":0},"outgoing":{"gap_count":2,"max_gap_ms":350.,"over_100_ms":2}});
        let mut tcp = flow("1.1.1.1", "tcp", 443, 0);
        tcp["syn_attempts"] = json!(3);
        tcp["retx"] = json!(2);
        let row = packet_timing(
            &json!({"duration_sec":5,"truncated":true,"flows":[udp,tcp],"timing_context":{"max_gap_ms":200.}}),
        );
        assert_eq!(row["udp_flows_without_observed_reply"], 1);
        assert_eq!(row["tcp_attempt_flows_without_observed_data"], 1);
        assert_eq!(row["retransmit_events"], 2);
        assert_eq!(row["flows"][0]["timing"]["outgoing"]["max_gap_ms"], 350.);
        assert_eq!(row["flows"][1]["state"], "Unknown");
        assert_eq!(row["flows"][1]["timing"], Value::Null);
        assert_eq!(row["coverage_incomplete"], true);
        assert_eq!(row["main_udp_candidate"]["flow_index"], 0);
        assert_eq!(row["cause"], "NotEstablished");
    }
    #[test]
    fn provider_ip_must_match_observed_peer_and_text_is_bounded() {
        let ip = "8.8.8.8".parse().unwrap();
        let mut value = json!({"success":true,"ip":"1.1.1.1","country_code":"US","country":"United States","city":"City\nInjected","latitude":91,"longitude":181,"connection":{"org":"o".repeat(1024)}});
        assert!(parse_geo(&value, ip, true).is_err());
        value["ip"] = json!("8.8.8.8");
        let row = parse_geo(&value, ip, true).unwrap();
        assert_eq!(row["city"], "CityInjected");
        assert_eq!(row["latitude"], Value::Null);
        assert_eq!(row["longitude"], Value::Null);
        assert_eq!(row["organization"].as_str().unwrap().len(), 256);
        let fallback = parse_geo(
            &json!({"ip":"8.8.8.8","country":"US","loc":"37.1,-122.2","org":"AS15169 Google"}),
            ip,
            false,
        )
        .unwrap();
        assert_eq!(fallback["latitude"], 37.1);
        assert_eq!(fallback["longitude"], -122.2);
    }
    #[test]
    fn cache_queries_use_absolute_reverse_names_without_external_resolution() {
        assert_eq!(
            reverse_name("8.8.4.4".parse().unwrap()),
            "4.4.8.8.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:4860:4860::8888".parse().unwrap()),
            "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn forward_names_merge_with_cached_ptr_names_without_duplicates() {
        let mut row = json!({"address":"8.8.8.8","state":"Observed","reason":"CachedPtr",
            "names":["ptr.example","shared.example"]});
        let forward = BTreeSet::from(["forward.example".into(), "shared.example".into()]);
        merge_cache_names(&mut row, &forward);
        assert_eq!(
            row["names"],
            json!(["forward.example", "ptr.example", "shared.example"])
        );
        assert_eq!(row["ptr_names"], json!(["ptr.example", "shared.example"]));
        assert_eq!(
            row["forward_names"],
            json!(["forward.example", "shared.example"])
        );
    }
    #[test]
    fn invalid_limits_and_boolean_options_are_rejected_before_network() {
        for args in [
            json!({"probe_count":21}),
            json!({"probe_timeout_ms":2001}),
            json!({"diagnostic_deadline_ms":30001}),
            json!({"geo":"yes"}),
            json!({"active_probes":1}),
        ] {
            assert!(enrich_tracker(Path::new("."), &json!({}), &args).is_err());
        }
    }
    #[test]
    fn real_local_tcp_samples_have_own_clocks_and_measured_summary() {
        crate::runtime(async {
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let target = ProbeTarget {
                address: listener.local_addr()?.ip(),
                kind: "tcp",
                port: listener.local_addr()?.port(),
            };
            let options = Options::parse(
                &json!({"probe_count":3,"probe_interval_ms":0,"probe_timeout_ms":500}),
            )?;
            let origin = Instant::now();
            let (_send, cancel) = watch::channel(false);
            let mut store = latency::LatencyStore::default();
            let rows = samples(
                &[target],
                &options,
                1,
                origin,
                origin + Duration::from_secs(2),
                &cancel,
                &mut store,
            )
            .await?;
            assert_eq!(rows.len(), 3);
            for row in &rows {
                assert_eq!(row.outcome, latency::LatencyOutcome::Success);
                assert!(row.ms.is_some_and(|n| n >= 0.));
                assert_eq!(row.evidence, "TcpHandshake");
                assert_eq!(row.phase, "PostCapture");
                assert!(row.capture_correlation_not_measured);
                assert!(!row.game_latency_measured);
                assert!(row.completed_after_ms >= row.started_after_ms);
                assert!(row.elapsed_ms >= row.ms.unwrap());
                assert!(row.started_utc_ms.parse::<u128>().is_ok());
                assert!(row.completed_utc_ms.parse::<u128>().is_ok());
            }
            let summary = store.summary(
                &target.address.to_string(),
                "tcp",
                target.port,
                origin.elapsed().as_secs_f64(),
            );
            assert_eq!(summary.success_count, 3);
            assert!(summary.median_ms.is_some());
            assert_eq!(summary.p95_ms, None);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn cancelled_or_expired_schedules_do_not_open_connections() {
        crate::runtime(async {
            let target = ProbeTarget {
                address: "127.0.0.1".parse()?,
                kind: "tcp",
                port: 1,
            };
            let options = Options::parse(&json!({}))?;
            let origin = Instant::now();
            let (_send, cancel) = watch::channel(true);
            let mut store = latency::LatencyStore::default();
            assert!(
                samples(
                    &[target],
                    &options,
                    1,
                    origin,
                    origin + Duration::from_secs(1),
                    &cancel,
                    &mut store
                )
                .await?
                .is_empty()
            );
            let (_send, cancel) = watch::channel(false);
            assert!(
                samples(&[target], &options, 1, origin, origin, &cancel, &mut store)
                    .await?
                    .is_empty()
            );
            assert!(store.streams.is_empty());
            Ok(())
        })
        .unwrap();
    }
}
