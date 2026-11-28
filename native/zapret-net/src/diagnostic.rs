use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::lookup_host,
    time::{Instant, timeout},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Target {
    #[serde(default = "default_group", alias = "Group")]
    pub group: String,
    #[serde(default = "default_name", alias = "Name")]
    pub name: String,
    #[serde(alias = "Url")]
    pub url: String,
}
fn default_group() -> String {
    "Custom".into()
}
fn default_name() -> String {
    "target".into()
}
pub(crate) fn targets(root: &Path, args: &Value, all: bool) -> Result<Vec<Target>> {
    let result = if let Some(value) = args
        .get("targets")
        .filter(|v| v.as_array().is_none_or(|a| !a.is_empty()))
    {
        serde_json::from_value::<Vec<Target>>(value.clone()).context("invalid targets")?
    } else if let Some(url) = args.get("url").and_then(Value::as_str) {
        vec![Target {
            group: default_group(),
            name: default_name(),
            url: url.into(),
        }]
    } else if let Some(urls) = args
        .get("urls")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    {
        urls.iter()
            .enumerate()
            .map(|(i, url)| {
                Ok(Target {
                    group: default_group(),
                    name: format!("target{}", i + 1),
                    url: url.as_str().context("invalid URL")?.into(),
                })
            })
            .collect::<Result<_>>()?
    } else {
        let text = std::fs::read_to_string(root.join("tools/targets.txt"))
            .context("read network targets")?;
        let mut values = Vec::new();
        for line in text.trim_start_matches('\u{feff}').lines() {
            let Some((key, url)) = line.split_once('=') else {
                continue;
            };
            let Some((group, name)) = key
                .split_ascii_whitespace()
                .next()
                .and_then(|id| id.split_once('.'))
            else {
                continue;
            };
            if group.is_empty()
                || name.is_empty()
                || !group.chars().all(|c| c.is_ascii_alphanumeric())
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            if all
                || matches!(
                    (group, name),
                    ("YouTube", "web") | ("Discord", "main") | ("Clean", "bing")
                )
            {
                values.push(Target {
                    group: group.into(),
                    name: name.into(),
                    url: url.trim().into(),
                });
            }
        }
        values
    };
    if result.is_empty() || result.len() > if all { 256 } else { 6 } {
        bail!("expected 1..{} targets", if all { 256 } else { 6 })
    }
    for target in &result {
        crate::http::checked_url(&target.url, false)?;
    }
    Ok(result)
}
pub(crate) fn integer(args: &Value, name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match args.get(name) {
        Some(v) => v
            .as_u64()
            .with_context(|| format!("{name} must be a positive integer"))?,
        None => default,
    };
    if !(min..=max).contains(&value) {
        bail!("{name} outside {min}..{max}")
    };
    Ok(value)
}
pub(crate) fn duration_ms(args: &Value, default: u64, max: u64) -> Result<u64> {
    if args.get("timeout_ms").is_some() {
        integer(args, "timeout_ms", default, 1, max)
    } else {
        integer(args, "timeout_sec", default.div_ceil(1000), 1, max / 1000).map(|n| n * 1000)
    }
}
pub(crate) fn ca_file(args: &Value) -> Result<Option<PathBuf>> {
    args.get("ca_file")
        .map(|v| {
            v.as_str()
                .context("ca_file must be a path")
                .map(PathBuf::from)
        })
        .transpose()
}
pub(crate) fn now() -> String {
    // UTC unix milliseconds are unambiguous, locale-independent and sortable.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}
pub(crate) fn context(root: &Path) -> Value {
    zapret_platform::command(root, "network-context", &json!({}))
        .unwrap_or_else(|e| json!({"known":false,"error":format!("{e:#}")}))
}
pub(crate) fn context_state(before: &Value, after: &Value) -> &'static str {
    if before["known"] != true || after["known"] != true {
        return "Unknown";
    }
    let a = before
        .get("stable_key")
        .or_else(|| before.get("context_key"))
        .or_else(|| before.get("key"))
        .unwrap_or(before);
    let b = after
        .get("stable_key")
        .or_else(|| after.get("context_key"))
        .or_else(|| after.get("key"))
        .unwrap_or(after);
    if a == b
        && before.get("processes") == after.get("processes")
        && before.get("settings_hash") == after.get("settings_hash")
    {
        "ObservedStable"
    } else {
        "Changed"
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Dns {
    pub state: String,
    pub reason: String,
    pub addresses: Vec<String>,
    pub error: String,
    pub elapsed_ms: f64,
    pub resolver: String,
}
pub(crate) async fn resolve(host: &str, timeout_ms: u64) -> Dns {
    let start = Instant::now();
    let mut row = Dns {
        state: "UNKNOWN".into(),
        reason: "Timeout".into(),
        addresses: vec![],
        error: String::new(),
        elapsed_ms: 0.,
        resolver: "system resolver; no application proxy".into(),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        row.state = "OK".into();
        row.reason = "AddressLiteral".into();
        row.addresses.push(ip.to_string());
    } else {
        match timeout(
            Duration::from_millis(timeout_ms.max(1)),
            lookup_host((host, 443)),
        )
        .await
        {
            Ok(Ok(values)) => {
                row.addresses = zapret_core::connection_addresses(values, 64)
                    .into_iter()
                    .map(|s| s.ip().to_string())
                    .collect();
                row.state = if row.addresses.is_empty() {
                    "FAIL"
                } else {
                    "OK"
                }
                .into();
                row.reason = if row.addresses.is_empty() {
                    "NoAddresses"
                } else {
                    "Resolved"
                }
                .into();
            }
            Ok(Err(error)) => {
                row.state = "FAIL".into();
                row.reason = "ResolveFailed".into();
                row.error = error.to_string();
            }
            Err(_) => {}
        }
    }
    row.elapsed_ms = start.elapsed().as_secs_f64() * 1000.;
    row
}
pub(crate) fn select_addresses(values: &[String]) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut first6 = false;
    let mut seen = HashSet::new();
    for value in values {
        let Ok(ip) = value.parse::<IpAddr>() else {
            continue;
        };
        if !seen.insert(ip) {
            continue;
        }
        if seen.len() == 1 {
            first6 = ip.is_ipv6()
        }
        let list = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
        if list.len() < 2 {
            list.push(ip);
        }
    }
    let lists = if first6 { [v6, v4] } else { [v4, v6] };
    let mut result = Vec::new();
    for i in 0..2 {
        for list in &lists {
            if let Some(ip) = list.get(i) {
                result.push(*ip);
            }
        }
    }
    result
}

/// Probe the selected DNS answers under one deadline. Keep the preferred
/// peer's observation if none confirm the protocol.
pub(crate) async fn first_confirmed<T, F: Future<Output = T>>(
    peers: &[IpAddr],
    budget_ms: u64,
    probe: impl Fn(IpAddr, u64) -> F,
    confirmed: impl Fn(&T) -> bool,
) -> Option<T> {
    let mut next = 0;
    let mut pending = FuturesUnordered::new();
    let mut primary = None;
    let mut launch_at = Instant::now();
    let deadline = launch_at + Duration::from_millis(budget_ms);
    let stagger = Duration::from_millis((budget_ms / (peers.len() as u64 + 1)).min(150));
    loop {
        let now = Instant::now();
        if now >= deadline && next > 0 {
            next = peers.len();
        }
        if (pending.is_empty() || now >= launch_at)
            && let Some(&address) = peers.get(next)
        {
            let index = next;
            next += 1;
            let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
            let request = probe(address, remaining.max(1));
            pending.push(async move { (index, request.await) });
            launch_at = Instant::now() + stagger;
        }
        if pending.is_empty() {
            return primary;
        }
        tokio::select! {
            biased;
            Some((index, row)) = pending.next() => {
                if confirmed(&row) {
                    return Some(row);
                }
                if index == 0 {
                    primary = Some(row);
                }
                launch_at = Instant::now();
            }
            _ = tokio::time::sleep_until(launch_at), if next < peers.len() => {}
        }
    }
}

pub(crate) fn host(args: &Value, default: &str) -> Result<String> {
    let value = args
        .get("host")
        .or_else(|| args.get("hostname"))
        .and_then(Value::as_str)
        .unwrap_or(default);
    if value.parse::<IpAddr>().is_ok() {
        return Ok(value.into());
    }
    let url = crate::http::checked_url(&format!("https://{value}/"), false)?;
    if url.path() != "/" || url.query().is_some() || url.port().is_some() {
        bail!("expected hostname or literal address")
    }
    Ok(crate::http::hostname(&url))
}
pub(crate) fn socket(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}
pub(crate) fn cancellation() -> tokio::sync::watch::Receiver<bool> {
    let (send, receive) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = send.send(true);
        }
    });
    receive
}

pub fn diagnostics(root: &Path, kind: &str, args: &Value) -> Result<Value> {
    if !args.is_object() {
        bail!("diagnostic arguments must be an object")
    }
    match kind {
        "dns" | "ipv6" => crate::dns::run(root, kind, args),
        "connection" | "connection-check" => crate::connection::run(root, args),
        "stun" | "voice" | "voice-control" => crate::stun::run(root, kind, args),
        "latency" | "tcp-latency" | "icmp-latency" => crate::latency::run(root, kind, args),
        "webcheck" | "web" | "browser" => crate::web::run(root, args),
        "provider" | "provider-check" | "ipinfo" => crate::provider::run(root, args),
        _ => bail!("unknown network diagnostic {kind}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[tokio::test]
    async fn diagnostic_fallback_keeps_the_preferred_result_and_one_round_budget() {
        let peers = ["::1", "127.0.0.1", "127.0.0.2"].map(|s| s.parse::<IpAddr>().unwrap());
        for usable in [Some(peers[0]), Some(peers[2]), None] {
            let calls = RefCell::new(Vec::new());
            let result = first_confirmed(
                &peers,
                500,
                |ip, ms| {
                    calls.borrow_mut().push((ip, ms));
                    std::future::ready(ip)
                },
                |ip| Some(*ip) == usable,
            )
            .await;
            assert_eq!(result, usable.or(Some(peers[0])));
            let calls = calls.into_inner();
            assert_eq!(
                calls.len(),
                if usable == Some(peers[0]) {
                    1
                } else {
                    peers.len()
                }
            );
            assert!(calls.iter().all(|&(_, ms)| (1..=500).contains(&ms)));
            assert!(calls.windows(2).all(|pair| pair[0].1 >= pair[1].1));
        }
    }
}
