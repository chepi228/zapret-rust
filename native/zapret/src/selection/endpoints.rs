//! Compare screening runs at the same server and distinguish a shared CDN edge failure
//! from a regression in the candidate. The ordinary final observation stays in the report.
use super::{Row, Target, probe_details};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

fn address(raw: &Value) -> Option<SocketAddr> {
    raw["remote_address"].as_str()?.parse().ok()
}

fn advertised(raw: &Value, peer: SocketAddr) -> bool {
    raw["resolved_addresses"]
        .as_array()
        .is_some_and(|addresses| {
            addresses
                .iter()
                .any(|v| v.as_str().and_then(|s| s.parse().ok()) == Some(peer))
        })
}

fn pin(target: &Target, peer: SocketAddr) -> Target {
    Target {
        peer: Some(peer),
        ..target.clone()
    }
}

fn multiple_tls_peers(raw: &Value) -> bool {
    raw["tcp_attempts"].as_array().is_some_and(|attempts| {
        attempts
            .iter()
            .filter(|attempt| attempt.get("error") == Some(&Value::Null))
            .nth(1)
            .is_some()
    })
}

pub(super) fn tls_peer_retry(raw: &Value) -> bool {
    if !multiple_tls_peers(raw) {
        return false;
    }
    // A speculative handshake on another address does not delay a successful
    // preferred peer. Older sequential retries have an error on their first attempt.
    let first = &raw["tcp_attempts"][0];
    !(raw["certificate_validated"] == true
        && first["address"].is_string()
        && first["address"] == raw["remote_address"]
        && first.get("error") == Some(&Value::Null)
        && first["tls_error"].is_null())
}

pub(super) fn for_round(targets: &[Target], baseline: &[Row]) -> Vec<Target> {
    let peers: BTreeMap<_, _> = baseline
        .iter()
        .filter(|row| {
            row.state == "OK" && !row.flaky && row.tries == 1 && row.code.starts_with('2')
        })
        .filter_map(|row| {
            let peer = address(&row.raw)?;
            advertised(&row.raw, peer).then(|| (row.key(), peer))
        })
        .collect();
    targets
        .iter()
        .map(|target| match peers.get(&target.key()) {
            Some(&peer) if target.probe_mode() != zapret_net::ProbeMode::RobloxIcon => {
                pin(target, peer)
            }
            _ => target.clone(),
        })
        .collect()
}

pub(super) fn verify_peer(row: &zapret_net::Observation, peer: SocketAddr) -> Result<()> {
    let socket = peer.to_string();
    ensure!(
        row.dns_source == "connect_ip override"
            && row.resolved_addresses == [socket.as_str()]
            && row
                .remote_address
                .as_deref()
                .is_none_or(|remote| remote == socket)
            && (row.status_code.is_none() || row.remote_address.is_some()),
        "Worker не подтвердил заданный адрес {peer}"
    );
    Ok(())
}

fn failed_handshake(raw: &Value) -> bool {
    !multiple_tls_peers(raw)
        && raw["status_code"].is_null()
        && raw["body_bytes"] == 0
        && matches!(raw["stage"].as_str(), Some("Tls" | "Tcp"))
        && matches!(
            raw["termination"].as_str(),
            Some("TlsFailure" | "TcpFailure" | "Timeout")
        )
}

struct Comparison<'a> {
    index: usize,
    target: &'a Target,
    failed: SocketAddr,
    earlier: Vec<SocketAddr>,
}

fn comparisons<'a>(targets: &'a [Target], expected: &[Row], actual: &[Row]) -> Vec<Comparison<'a>> {
    let by_key: BTreeMap<_, _> = targets.iter().map(|t| (t.key(), t)).collect();
    let mut good = BTreeMap::<String, BTreeSet<SocketAddr>>::new();
    for row in expected.iter().filter(|r| r.state == "OK") {
        if let Some(peer) = address(&row.raw) {
            good.entry(row.key()).or_default().insert(peer);
        }
    }
    actual
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            if row.state != "FAIL"
                || matches!(row.group.as_str(), "DPI" | "Clean")
                || !failed_handshake(&row.raw)
            {
                return None;
            }
            let failed = address(&row.raw)?;
            let key = row.key();
            if by_key.get(&key)?.probe_mode() == zapret_net::ProbeMode::RobloxIcon {
                return None;
            }
            let earlier = good.get(&key)?;
            // A failure on a previously successful peer must keep its veto. Do not
            // send requests to retired DNS addresses or erase two different failed attempts.
            if earlier.contains(&failed)
                || !earlier.iter().all(|&ip| advertised(&row.raw, ip))
                || row.failed_retry.as_ref().is_some_and(|retry| {
                    !failed_handshake(retry)
                        || address(retry) != Some(failed)
                        || !earlier.iter().all(|&ip| advertised(retry, ip))
                })
            {
                return None;
            }
            Some(Comparison {
                index,
                target: *by_key.get(&key)?,
                failed,
                earlier: earlier.iter().copied().collect(),
            })
        })
        .collect()
}

pub(super) fn validate_final(
    targets: &[Target],
    expected: &[Row],
    actual: &[Row],
    probe: impl FnMut(&[Target], bool) -> Result<Vec<Row>>,
) -> Result<crate::selection_decision::Check> {
    // CDN peer replays cannot change a clean-site veto. Retain the observations
    // for all sites, but only attribute a failure to a site we have established.
    let controls = expected
        .iter()
        .filter(|row| row.group == "Clean" && row.state == "OK");
    let veto = if controls.clone().next().is_some() {
        super::final_check(controls, actual).err()
    } else {
        None
    };
    let (error, details) = if let Some(error) = veto {
        (Some(error), probe_details(actual))
    } else {
        let (compared, details) = compare_final(targets, expected, actual, probe)?;
        (super::final_check(expected, &compared).err(), details)
    };
    Ok(crate::selection_decision::Check {
        confirmed: error.is_none(),
        error: error.map(|e| format!("{e:#}")),
        details,
    })
}

/// Reproduce all earlier successes on their peers under the candidate. Also require
/// two failures on the newly selected peer under the original working command.
pub(super) fn compare_final(
    targets: &[Target],
    expected: &[Row],
    actual: &[Row],
    mut probe: impl FnMut(&[Target], bool) -> Result<Vec<Row>>,
) -> Result<(Vec<Row>, Vec<Value>)> {
    let mut comparable = actual.to_vec();
    let mut details = probe_details(actual);
    let changes = comparisons(targets, expected, actual);
    if changes.is_empty() {
        return Ok((comparable, details));
    }
    let mut replay = BTreeMap::<String, Vec<Row>>::new();
    let count = changes
        .iter()
        .map(|change| change.earlier.len())
        .max()
        .unwrap_or(0);
    for slot in 0..count {
        // At most one job per URL/target identity per batch.
        let jobs: Vec<_> = changes
            .iter()
            .filter_map(|change| {
                change
                    .earlier
                    .get(slot)
                    .map(|&peer| pin(change.target, peer))
            })
            .collect();
        for row in probe(&jobs, false)? {
            replay.entry(row.key()).or_default().push(row);
        }
    }
    let matched = |change: &Comparison, rows: &[Row]| {
        change.earlier.iter().all(|&peer| {
            rows.iter()
                .any(|r| r.state == "OK" && address(&r.raw) == Some(peer))
        })
    };
    let controls: Vec<_> = changes
        .iter()
        .filter(|c| {
            replay
                .get(&c.target.key())
                .is_some_and(|rows| matched(c, rows))
        })
        .map(|c| pin(c.target, c.failed))
        .collect();
    let mut previous = BTreeMap::<String, Vec<Row>>::new();
    if !controls.is_empty() {
        for row in probe(&controls, true)? {
            previous.entry(row.key()).or_default().push(row);
        }
    }
    for change in &changes {
        let key = change.target.key();
        let replayed = replay.get(&key).map(Vec::as_slice).unwrap_or_default();
        let control = previous.get(&key).map(Vec::as_slice).unwrap_or_default();
        let shared = matched(change, replayed)
            && control.len() == 2
            && control.iter().all(|r| {
                r.state == "FAIL"
                    && failed_handshake(&r.raw)
                    && address(&r.raw) == Some(change.failed)
            });
        if shared {
            comparable[change.index] = replayed[0].clone();
        }
        details[change.index]["peer_comparison"] = json!({
            "shared_failure":shared, "dns_peer":change.failed,
            "candidate_replays":probe_details(replayed), "previous_controls":probe_details(control)
        });
    }
    Ok((comparable, details))
}
