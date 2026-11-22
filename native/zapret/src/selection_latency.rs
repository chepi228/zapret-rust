//! Compare complete test requests across all target groups at comparable quality.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use zapret_core::RankRow;

pub const POLICY: &str = "availability-then-working-request-latency-v3";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub scope: String,
    pub targets: usize,
    pub wins: usize,
    pub regressions: usize,
    pub gain_ms: f64,
    pub gain_percent: f64,
    pub reference_tcp_ms: f64,
    pub candidate_tcp_ms: f64,
    pub reference_tls_ms: f64,
    pub candidate_tls_ms: f64,
    pub reference_connect_ms: f64,
    pub candidate_connect_ms: f64,
    pub reference_total_ms: f64,
    pub candidate_total_ms: f64,
    pub reference_p95_ms: f64,
    pub candidate_p95_ms: f64,
    pub panel: Vec<String>,
}
impl Comparison {
    pub fn faster(&self) -> bool {
        self.candidate_total_ms < self.reference_total_ms
            && self.gain_ms > 0.
            && self.wins * 2 > self.targets
            && self.regressions == 0
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preference {
    pub reference: String,
    pub candidate: String,
    pub trial: Comparison,
    pub working: Option<Comparison>,
    pub confirmed: bool,
}

pub fn eligible(reference: &RankRow, candidate: &RankRow) -> bool {
    candidate.total == reference.total
        && reference.total > 0
        && candidate.score.is_finite()
        && reference.score.is_finite()
        && reference.ok >= reference.total as f64 * 0.80
        && candidate.ok >= candidate.total as f64 * 0.80
        && candidate.score >= reference.score - zapret_core::NEAR_BEST_SCORE_MARGIN
        && reference.harm == 0
        && candidate.harm == 0
        && candidate.freeze == 0
        && ["NBA2K", "EAC", "YouTube", "Discord", "SoundCloud"]
            .iter()
            .all(|group| {
                let total = reference.group_totals.get(*group).copied().unwrap_or(0);
                total == 0
                    || (candidate.group_totals.get(*group) == Some(&total)
                        && candidate.groups.get(*group).copied().unwrap_or(0.)
                            >= reference.groups.get(*group).copied().unwrap_or(0.))
            })
}

struct Sample {
    group: String,
    peer: String,
    code: String,
    termination: String,
    body_limit: u64,
    body_bytes: u64,
    post_bytes: u64,
    dns: f64,
    tcp: f64,
    connect: f64,
    first_byte: f64,
    total: f64,
}
#[derive(Serialize)]
pub struct Timing {
    pub total: usize,
    pub ok: usize,
    pub errors: usize,
    pub recovered: usize,
    pub samples: usize,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub first_byte_ms: Option<f64>,
    pub total_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}
#[derive(Serialize)]
pub struct OverallTiming {
    #[serde(flatten)]
    pub timing: Timing,
    pub groups: BTreeMap<String, Timing>,
}
pub fn timing(rows: &[Value]) -> Timing {
    let valid = samples(rows).unwrap_or_default();
    let med = |get: fn(&Sample) -> f64| {
        (!valid.is_empty()).then(|| median(valid.values().map(get).collect()))
    };
    let ok = rows.iter().filter(|row| row["state"] == "OK").count();
    Timing {
        total: rows.len(),
        ok,
        errors: rows.len() - ok,
        recovered: rows
            .iter()
            .filter(|row| row["state"] == "OK" && (row["flaky"] == true || row["tries"] != 1))
            .count(),
        samples: valid.len(),
        dns_ms: med(|row| row.dns),
        tcp_ms: med(|row| row.tcp),
        tls_ms: med(|row| row.connect - row.tcp),
        first_byte_ms: med(|row| row.first_byte),
        total_ms: med(|row| row.total),
        p95_ms: (!valid.is_empty()).then(|| p95(valid.values().map(|row| row.total).collect())),
    }
}
pub fn overall_timing(rows: &[Value]) -> OverallTiming {
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for row in rows {
        if let Some(group) = row["group"].as_str() {
            groups.entry(group.into()).or_default().push(row.clone());
        }
    }
    OverallTiming {
        timing: timing(rows),
        groups: groups
            .into_iter()
            .map(|(group, rows)| (group, timing(&rows)))
            .collect(),
    }
}

fn verified_response(row: &Value) -> bool {
    row["state"] == "OK"
        && row["url"].as_str().is_some_and(|url| {
            url.starts_with("http://")
                || (url.starts_with("https://") && row["certificate_validated"] == true)
        })
}
pub fn preserves_services(reference: &[Value], candidate: &[Value]) -> bool {
    reference
        .iter()
        .filter(|row| row["state"] == "OK")
        .all(|before| {
            candidate
                .iter()
                .find(|row| {
                    row["group"] == before["group"]
                        && row["name"] == before["name"]
                        && row["url"] == before["url"]
                })
                .is_some_and(|after| {
                    verified_response(after)
                        && (before["group"] != "Clean"
                            || before["tls_ms"]
                                .as_f64()
                                .zip(after["tls_ms"].as_f64())
                                .is_some_and(|(a, b)| b <= a + 500.))
                })
        })
        && candidate.iter().filter(|row| row["flaky"] == true).count()
            <= reference.iter().filter(|row| row["flaky"] == true).count()
        && candidate
            .iter()
            .filter(|row| row["state"] == "FREEZE")
            .count()
            <= reference
                .iter()
                .filter(|row| row["state"] == "FREEZE")
                .count()
}
fn sample(row: &Value) -> Option<(String, Sample)> {
    if !verified_response(row) || row["flaky"] == true || row["tries"] != 1 {
        return None;
    }
    let group = row["group"].as_str()?;
    let url = row["url"].as_str()?;
    let dns = row["dns_ms"].as_f64()?;
    let tcp = row["tcp_ms"].as_f64()? - dns;
    let connect = if url.starts_with("https://") {
        row["tls_ms"].as_f64()? - dns
    } else {
        tcp
    };
    let first_byte = row["first_byte_ms"].as_f64()?;
    let total = row["total_ms"].as_f64()?;
    if ![dns, tcp, connect, first_byte, total]
        .iter()
        .all(|value| value.is_finite() && *value >= 0.)
        || total <= 0.
        || connect < tcp
        || first_byte + 0.001 < dns + connect
        || total + 0.001 < first_byte
    {
        return None;
    }
    let termination = row["termination"].as_str()?;
    let body_limit = row["body_limit"].as_u64()?;
    let body_bytes = row["body_bytes"].as_u64()?;
    if !matches!(termination, "Complete" | "BodyLimit")
        || body_limit == 0
        || body_bytes > body_limit
        || (termination == "BodyLimit" && body_bytes != body_limit)
    {
        return None;
    }
    Some((
        format!("{group}|{}|{url}", row["name"].as_str()?),
        Sample {
            group: group.into(),
            peer: row["remote_address"]
                .as_str()
                .filter(|peer| !peer.is_empty())?
                .into(),
            code: row["code"].as_str()?.into(),
            termination: termination.into(),
            body_limit,
            body_bytes,
            post_bytes: row["post_bytes"].as_u64()?,
            dns,
            tcp,
            connect,
            first_byte,
            total,
        },
    ))
}
fn samples(rows: &[Value]) -> Option<BTreeMap<String, Sample>> {
    let mut result = BTreeMap::new();
    for row in rows {
        if let Some((key, sample)) = sample(row) {
            if result.insert(key, sample).is_some() {
                return None;
            }
        }
    }
    Some(result)
}
pub fn median_request_ms(rows: &[Value]) -> Option<f64> {
    let samples = samples(rows)?;
    (!samples.is_empty()).then(|| median(samples.values().map(|s| s.total).collect()))
}
fn p95(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[(values.len() * 95).div_ceil(100) - 1]
}
fn comparable(a: &Sample, b: &Sample) -> bool {
    a.peer == b.peer
        && a.code == b.code
        && a.body_limit == b.body_limit
        && a.post_bytes == b.post_bytes
        && a.termination == b.termination
        && a.body_bytes.abs_diff(b.body_bytes) <= 256.max(a.body_bytes.max(b.body_bytes) / 5)
}
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n % 2 == 0 {
        (values[n / 2 - 1] + values[n / 2]) / 2.
    } else {
        values[n / 2]
    }
}

pub fn compare(reference: &[Value], candidate: &[Value]) -> Option<Comparison> {
    let reference = samples(reference)?;
    let candidate = samples(candidate)?;
    let common: Vec<_> = reference
        .iter()
        .filter_map(|(key, a)| {
            candidate
                .get(key)
                .filter(|b| comparable(a, b))
                .map(|b| (key, a, b))
        })
        .collect();
    // A few fast endpoints cannot stand in for the whole tested target set.
    if common.len() < 5.max(reference.len().max(candidate.len()).div_ceil(2)) {
        return None;
    }
    let pairs = common;
    let gains: Vec<_> = pairs.iter().map(|(_, a, b)| a.total - b.total).collect();
    let reference_tcp_ms = median(pairs.iter().map(|(_, a, _)| a.tcp).collect());
    let candidate_tcp_ms = median(pairs.iter().map(|(_, _, b)| b.tcp).collect());
    let reference_p95_ms = p95(pairs.iter().map(|(_, a, _)| a.total).collect());
    let candidate_p95_ms = p95(pairs.iter().map(|(_, _, b)| b.total).collect());
    let mut groups = BTreeMap::<&str, (Vec<f64>, Vec<f64>)>::new();
    for (_, a, b) in &pairs {
        let (before, after) = groups.entry(&a.group).or_default();
        before.push(a.total);
        after.push(b.total);
    }
    let group_regressions = groups
        .into_values()
        .filter(|(a, b)| {
            let before = median(a.clone());
            median(b.clone()) - before > 20f64.max(before * 0.20)
        })
        .count();
    let regressions = pairs
        .iter()
        .filter(|(_, a, b)| b.total - a.total > 100f64.max(a.total * 0.50))
        .count()
        + group_regressions
        + usize::from(candidate_p95_ms - reference_p95_ms > 50f64.max(reference_p95_ms * 0.20));
    Some(Comparison {
        scope: "AllTargets".into(),
        targets: pairs.len(),
        wins: gains.iter().filter(|gain| **gain > 0.).count(),
        regressions,
        gain_ms: median(gains),
        gain_percent: median(
            pairs
                .iter()
                .map(|(_, a, b)| (a.total - b.total) / a.total * 100.)
                .collect(),
        ),
        reference_tcp_ms,
        candidate_tcp_ms,
        reference_tls_ms: median(pairs.iter().map(|(_, a, _)| a.connect - a.tcp).collect()),
        candidate_tls_ms: median(pairs.iter().map(|(_, _, b)| b.connect - b.tcp).collect()),
        reference_connect_ms: median(pairs.iter().map(|(_, a, _)| a.connect).collect()),
        candidate_connect_ms: median(pairs.iter().map(|(_, _, b)| b.connect).collect()),
        reference_total_ms: median(pairs.iter().map(|(_, a, _)| a.total).collect()),
        candidate_total_ms: median(pairs.iter().map(|(_, _, b)| b.total).collect()),
        reference_p95_ms,
        candidate_p95_ms,
        panel: pairs.iter().map(|(key, _, _)| (*key).clone()).collect(),
    })
}

pub fn confirm(
    preference: &Preference,
    reference: &[Value],
    candidate: &[Value],
) -> Option<Comparison> {
    let filter = |rows: &[Value]| {
        rows.iter()
            .filter(|row| {
                let key = format!(
                    "{}|{}|{}",
                    row["group"].as_str().unwrap_or(""),
                    row["name"].as_str().unwrap_or(""),
                    row["url"].as_str().unwrap_or("")
                );
                preference.trial.panel.contains(&key)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let comparison = compare(&filter(reference), &filter(candidate))?;
    (comparison.targets >= 5.max(preference.trial.targets.div_ceil(2))).then_some(comparison)
}

pub fn preference(
    reference: &RankRow,
    row: &RankRow,
    details: &BTreeMap<String, Vec<Value>>,
) -> Option<Preference> {
    if !eligible(reference, row) {
        return None;
    }
    let baseline = details.get(&reference.id)?;
    let candidate = details.get(&row.id)?;
    if !preserves_services(baseline, candidate) {
        return None;
    }
    let trial = compare(baseline, candidate)?;
    Some(Preference {
        reference: reference.id.clone(),
        candidate: row.id.clone(),
        trial,
        working: None,
        confirmed: false,
    })
}

pub fn recommend(rows: &[RankRow], details: &BTreeMap<String, Vec<Value>>) -> Option<Preference> {
    let reference = rows.first()?;
    rows.iter()
        .skip(1)
        .filter_map(|row| preference(reference, row, details))
        .filter(|preference| preference.trial.faster())
        .min_by(|a, b| {
            a.trial
                .candidate_total_ms
                .total_cmp(&b.trial.candidate_total_ms)
                .then(
                    a.trial
                        .candidate_p95_ms
                        .total_cmp(&b.trial.candidate_p95_ms),
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn samples(tcp: f64, tls: f64) -> Vec<Value> {
        (0..6).map(|n|json!({"group":"NBA2K","name":format!("service{n}"),"url":format!("https://s{n}.test/"),
            "state":"OK","tries":1,"flaky":false,"certificate_validated":true,
            "remote_address":format!("203.0.113.{}:443",n+1),"dns_ms":5.,"tcp_ms":5.+tcp,"tls_ms":5.+tcp+tls,
            "first_byte_ms":15.+tcp+tls,"total_ms":35.+tcp+tls,"code":"200","body_limit":65536,"body_bytes":1024,"post_bytes":0,"termination":"Complete"})).collect()
    }
    fn score(id: &str, points: f64) -> RankRow {
        RankRow {
            id: id.into(),
            score: points,
            ok: points,
            total: 54,
            groups: BTreeMap::from([("NBA2K".into(), 5.), ("EAC".into(), 3.)]),
            group_totals: BTreeMap::from([("NBA2K".into(), 5), ("EAC".into(), 3)]),
            ..Default::default()
        }
    }
    #[test]
    fn fast_near_winner_can_win_without_choosing_a_fast_broken_strategy() {
        let mut rows = vec![score("52", 49.), score("58", 48.5), score("13", 20.)];
        let details = BTreeMap::from([
            ("52".into(), samples(50., 100.)),
            ("58".into(), samples(35., 65.)),
            ("13".into(), samples(5., 5.)),
        ]);
        let choice = recommend(&rows, &details).unwrap();
        assert_eq!(choice.candidate, "58");
        assert_eq!(choice.trial.targets, 6);
        rows[1].groups.insert("EAC".into(), 2.);
        assert!(recommend(&rows, &details).is_none());
    }
    #[test]
    fn different_servers_missing_certificates_and_too_few_pairs_do_not_prove_speed() {
        let base = samples(50., 100.);
        let mut other = samples(10., 20.);
        for row in &mut other {
            row["remote_address"] = json!("198.51.100.1:443");
        }
        assert!(compare(&base, &other).is_none());
        let mut other = samples(10., 20.);
        for row in &mut other {
            row["certificate_validated"] = json!(false);
        }
        assert!(compare(&base, &other).is_none());
        assert!(compare(&base, &samples(10., 20.)[..2]).is_none());
    }
    #[test]
    fn timing_noise_one_fast_outlier_and_a_slow_game_endpoint_do_not_win() {
        let base = samples(50., 100.);
        let mut noise = samples(49., 99.);
        for row in noise.iter_mut().take(3) {
            row["total_ms"] = json!(187.);
        }
        assert!(!compare(&base, &noise).unwrap().faster());
        assert!(compare(&base, &samples(49., 99.)).unwrap().faster());
        let mut outlier = samples(50., 100.);
        outlier[0]["tls_ms"] = json!(65.);
        assert!(!compare(&base, &outlier).unwrap().faster());
        let mut fast = samples(30., 60.);
        fast[0]["tls_ms"] = json!(400.);
        fast[0]["first_byte_ms"] = json!(410.);
        fast[0]["total_ms"] = json!(430.);
        assert!(!compare(&base, &fast).unwrap().faster());
    }
    #[test]
    fn full_request_latency_includes_dns_and_does_not_add_tcp_or_tls_twice() {
        let base = samples(50., 100.);
        let mut candidate = samples(50., 100.);
        for row in &mut candidate {
            row["dns_ms"] = json!(105.);
            row["tcp_ms"] = json!(155.);
            row["tls_ms"] = json!(255.);
            row["first_byte_ms"] = json!(265.);
            row["total_ms"] = json!(285.);
        }
        let same = compare(&base, &candidate).unwrap();
        assert_eq!(same.gain_ms, -100.);
        let changed = compare(&base, &samples(35., 65.)).unwrap();
        assert_eq!(changed.gain_ms, 50.);
    }
    #[test]
    fn all_target_groups_and_the_response_transfer_influence_the_choice() {
        let mut base = samples(50., 100.);
        let mut candidate = samples(30., 60.);
        for (index, group) in ["NBA2K", "EAC", "Clean", "DPI", "Discord", "YouTube"]
            .iter()
            .enumerate()
        {
            base[index]["group"] = json!(group);
            candidate[index]["group"] = json!(group);
            if index >= 2 {
                candidate[index]["total_ms"] = json!(350.);
            }
        }
        let compared = compare(&base, &candidate).unwrap();
        assert_eq!(compared.scope, "AllTargets");
        assert_eq!(compared.targets, 6);
        assert!(!compared.faster());
        let mut body_slow = samples(30., 60.);
        for row in &mut body_slow {
            row["total_ms"] = json!(350.);
        }
        assert!(!compare(&samples(50., 100.), &body_slow).unwrap().faster());
    }
    #[test]
    fn a_missing_game_endpoint_or_an_unstable_fast_success_cannot_hide_behind_the_same_group_score()
    {
        let rows = vec![score("52", 49.), score("58", 49.)];
        let mut details = BTreeMap::from([
            ("52".into(), samples(50., 100.)),
            ("58".into(), samples(30., 60.)),
        ]);
        details.get_mut("58").unwrap().remove(0);
        assert!(recommend(&rows, &details).is_none());
        details.insert("58".into(), samples(30., 60.));
        details.get_mut("58").unwrap()[0]["flaky"] = json!(true);
        assert!(recommend(&rows, &details).is_none());
    }

    #[test]
    fn changed_responses_or_request_sizes_do_not_prove_lower_latency() {
        let baseline = samples(50., 100.);
        for (key, value) in [
            ("code", json!("403")),
            ("body_bytes", json!(1)),
            ("body_limit", json!(4096)),
            ("post_bytes", json!(65536)),
            ("total_ms", Value::Null),
            ("tries", json!(2)),
            ("termination", json!("Deadline")),
        ] {
            let mut candidate = samples(30., 60.);
            for row in &mut candidate {
                row[key] = value.clone();
            }
            assert!(compare(&baseline, &candidate).is_none(), "{key}");
        }
    }

    #[test]
    fn overall_summary_covers_every_group_without_treating_failures_or_retries_as_fast() {
        let mut rows = samples(50., 100.);
        for (row, group) in rows
            .iter_mut()
            .zip(["Clean", "DPI", "NBA2K", "EAC", "YouTube", "Discord"])
        {
            row["group"] = json!(group);
        }
        rows[4]["state"] = json!("FAIL");
        rows[4]["total_ms"] = json!(0.);
        rows[5]["flaky"] = json!(true);
        rows[5]["tries"] = json!(2);
        rows[5]["total_ms"] = json!(1.);
        let summary = overall_timing(&rows);
        assert_eq!(summary.timing.total, 6);
        assert_eq!(summary.timing.ok, 5);
        assert_eq!(summary.timing.errors, 1);
        assert_eq!(summary.timing.recovered, 1);
        assert_eq!(summary.timing.samples, 4);
        assert_eq!(summary.timing.total_ms, Some(185.));
        assert_eq!(summary.timing.first_byte_ms, Some(165.));
        assert_eq!(summary.timing.tcp_ms, Some(50.));
        assert_eq!(summary.timing.tls_ms, Some(100.));
        assert_eq!(summary.groups.len(), 6);
        assert_eq!(summary.groups["Clean"].samples, 1);
        assert_eq!(summary.groups["DPI"].samples, 1);
        assert_eq!(summary.groups["YouTube"].total_ms, None);
    }

    #[test]
    fn latency_preference_preserves_successful_dpi_targets_too() {
        let mut baseline = samples(50., 100.);
        let mut candidate = samples(30., 60.);
        baseline[0]["group"] = json!("DPI");
        candidate[0]["group"] = json!("DPI");
        candidate[0]["state"] = json!("FAIL");
        assert!(!preserves_services(&baseline, &candidate));
    }

    #[test]
    fn confirmation_cannot_shrink_a_large_panel_to_a_few_surviving_fast_addresses() {
        let baseline = samples(50., 100.);
        let candidate = samples(30., 60.);
        let mut trial = compare(&baseline, &candidate).unwrap();
        // Simulate a trial over a larger fixed panel, then only six surviving addresses.
        trial.targets = 30;
        let preference = Preference {
            reference: "52".into(),
            candidate: "58".into(),
            trial,
            working: None,
            confirmed: false,
        };
        assert!(confirm(&preference, &baseline, &candidate).is_none());
    }

    #[test]
    fn ordinary_http_does_not_require_or_fabricate_a_tls_handshake() {
        let mut baseline = samples(50., 100.);
        let mut candidate = samples(30., 60.);
        for rows in [&mut baseline, &mut candidate] {
            for row in rows {
                row["url"] = json!(row["url"].as_str().unwrap().replace("https://", "http://"));
                row["certificate_validated"] = json!(false);
                row["tls_ms"] = json!(0.);
            }
        }
        let comparison = compare(&baseline, &candidate).unwrap();
        assert!(comparison.faster());
        assert_eq!(comparison.candidate_tls_ms, 0.);
    }
}
