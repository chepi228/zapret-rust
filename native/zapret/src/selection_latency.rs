//! Compare paired, completed requests and keep service availability ahead of latency.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use zapret_core::RankRow;

pub const PREVIOUS_POLICY: &str = "availability-then-working-request-latency-v3";
pub const POLICY: &str = "repeatable-service-group-score-v8";
pub const SERVICE_SCOPE: &str = "ServiceTargets";
pub const MIN_WORKING_POINTS: f64 = 3.;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    All,
    Services,
}

pub(crate) fn steam_target(name: &str) -> bool {
    matches!(name, "steam" | "steamapi" | "steam_asset")
}

pub(crate) fn service(row: &Value) -> bool {
    match row["group"].as_str() {
        None | Some("DPI") => false,
        Some("Clean") => row["name"].as_str().is_some_and(steam_target),
        Some(_) => true,
    }
}

pub(crate) fn stable(row: &Value) -> bool {
    verified_response(row) && row["flaky"] != true && row["tries"] == 1
}

// Keep the incoming coverage/history order for otherwise equal candidates.
pub fn service_rank(row: &RankRow, details: &BTreeMap<String, Vec<Value>>) -> (bool, usize, usize) {
    let services = details
        .get(&row.id)
        .into_iter()
        .flatten()
        .filter(|v| service(v));
    (
        row.harm == 0,
        services.clone().filter(|v| stable(v)).count(),
        services.filter(|v| verified_response(v)).count(),
    )
}

// All profiles share a target panel. Each service contributes one vote to coverage.
pub(crate) fn availability_rank(rows: &[Value]) -> (usize, u64, u64) {
    let mut groups = BTreeMap::<&str, (u64, u64, u64)>::new();
    for row in rows.iter().filter(|row| service(row)) {
        let group = row["group"].as_str().expect("service group");
        let (total, reached, reliable) = groups.entry(group).or_default();
        *total += 1;
        *reached += u64::from(verified_response(row));
        *reliable += u64::from(stable(row));
    }
    let mut rank = (0, 0, 0);
    for (total, reached, reliable) in groups.into_values() {
        rank.0 += usize::from(reached > 0);
        rank.1 += 1_000_000 * reached / total;
        rank.2 += 1_000_000 * reliable / total;
    }
    rank
}

pub fn service_ready(row: &RankRow, details: &BTreeMap<String, Vec<Value>>) -> bool {
    let total = details
        .get(&row.id)
        .into_iter()
        .flatten()
        .filter(|v| service(v))
        .count();
    let (healthy, stable, _) = service_rank(row, details);
    healthy && stable >= Panel::Services.required_pairs(total)
}

pub fn complete_services(rows: &[Value]) -> bool {
    let services = rows.iter().filter(|row| service(row));
    services.clone().count() >= 5 && services.into_iter().all(stable)
}

impl Panel {
    fn required_pairs(self, total: usize) -> usize {
        5.max(match self {
            Self::Services => (total * 4).div_ceil(5),
            Self::All => total.div_ceil(2),
        })
    }

    pub fn for_trials(rows: &[RankRow], details: &BTreeMap<String, Vec<Value>>) -> Self {
        let Some(first) = rows.first().and_then(|r| details.get(&r.id)) else {
            return Self::All;
        };
        let keys = |records: &[Value]| -> BTreeSet<String> {
            records
                .iter()
                .filter(|v| service(v))
                .filter_map(target_key)
                .collect()
        };
        let expected = keys(first);
        if expected.len() < 5 || !first.iter().any(|v| v["group"] == "DPI") {
            return Self::All;
        }
        let same_panel = rows.iter().all(|r| {
            details.get(&r.id).is_some_and(|records| {
                records.iter().filter(|v| service(v)).count() == expected.len()
                    && keys(records) == expected
            })
        });
        let usable = rows.iter().any(|r| service_ready(r, details));
        if same_panel && usable {
            Self::Services
        } else {
            Self::All
        }
    }

    pub fn prioritize(
        self,
        rows: &mut [RankRow],
        details: &BTreeMap<String, Vec<Value>>,
        primary: &str,
    ) {
        if self == Self::Services {
            rows.sort_by_cached_key(|row| {
                Reverse((
                    row.harm == 0,
                    availability_rank(&details[&row.id]),
                    row.id == primary,
                ))
            });
        }
    }
}

fn target_key(row: &Value) -> Option<String> {
    Some(format!(
        "{}|{}|{}",
        row["group"].as_str()?,
        row["name"].as_str()?,
        row["url"].as_str()?
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceScore {
    pub points: f64,
    pub groups: BTreeMap<String, f64>,
}

impl ServiceScore {
    fn from_groups(times: &BTreeMap<&str, (Vec<f64>, Vec<f64>)>) -> Self {
        // Each address votes once within its group. Doubling and halving the
        // same request time have equal and opposite effects on the score.
        let groups: BTreeMap<_, _> = times
            .iter()
            .map(|(&name, (before, after))| {
                let sum: f64 = before
                    .iter()
                    .zip(after)
                    .map(|(&a, &b)| (a - b) / a.max(b) * 100.)
                    .sum();
                (name.to_owned(), sum / before.len() as f64)
            })
            .collect();
        Self {
            points: groups.values().sum::<f64>() / groups.len() as f64,
            groups,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_score: Option<ServiceScore>,
    pub targets: usize,
    pub wins: usize,
    pub regressions: usize,
    pub gain_ms: f64,
    pub gain_percent: f64,
    pub reference_tcp_ms: Option<f64>,
    pub candidate_tcp_ms: Option<f64>,
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
    pub fn screening_order(&self, other: &Self) -> std::cmp::Ordering {
        if let (Some(a), Some(b)) = (&self.service_score, &other.service_score) {
            return b.points.total_cmp(&a.points);
        }
        self.regressions
            .cmp(&other.regressions)
            .then_with(|| other.gain_ms.total_cmp(&self.gain_ms))
    }
    pub fn promising(&self) -> bool {
        self.service_score
            .as_ref()
            .is_some_and(|score| score.points > 0.)
    }

    pub fn service_rejection(&self) -> Option<String> {
        let Some(score) = &self.service_score else {
            return Some("Недостаточно сопоставимых замеров.".into());
        };
        if score.points < MIN_WORKING_POINTS {
            return Some(format!("Выигрыш меньше {MIN_WORKING_POINTS} баллов."));
        }
        if let Some((group, _)) = score.groups.iter().find(|(_, points)| **points < -20.) {
            return Some(format!("Группа {group} потеряла больше 20 баллов."));
        }
        if self.candidate_p95_ms - self.reference_p95_ms > 20f64.max(self.reference_p95_ms * 0.10) {
            return Some("Время самых медленных запросов (P95) заметно выросло.".into());
        }
        None
    }

    pub fn faster(&self) -> bool {
        if self.scope == SERVICE_SCOPE {
            return self.service_rejection().is_none();
        }
        self.regressions == 0
            && self.candidate_total_ms < self.reference_total_ms
            && self.gain_ms > 0.
            && self.wins * 2 > self.targets
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preference {
    pub reference: String,
    pub candidate: String,
    pub trial: Comparison,
    pub working: Option<Comparison>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat: Option<Comparison>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeatable_points: Option<f64>,
    pub confirmed: bool,
}

pub fn eligible(reference: &RankRow, candidate: &RankRow, panel: Panel) -> bool {
    candidate.score.is_finite()
        && reference.score.is_finite()
        && (panel == Panel::Services
            || (reference.total > 0
                && candidate.total == reference.total
                && reference.ok >= reference.total as f64 * 0.80
                && candidate.ok >= candidate.total as f64 * 0.80
                && candidate.score >= reference.score - zapret_core::NEAR_BEST_SCORE_MARGIN
                && candidate.freeze == 0))
        && reference.harm == 0
        && candidate.harm == 0
        && reference.group_totals.iter().all(|(group, total)| {
            matches!(group.as_str(), "DPI" | "Clean")
                || *total == 0
                || (candidate.group_totals.get(group) == Some(total)
                    && candidate.groups.get(group).copied().unwrap_or(0.)
                        >= reference.groups.get(group).copied().unwrap_or(0.))
        })
}

struct Sample {
    group: String,
    mode: Option<String>,
    media_url: Option<String>,
    peer: String,
    code: String,
    termination: String,
    body_limit: u64,
    body_bytes: u64,
    post_bytes: u64,
    dns: f64,
    tcp: Option<f64>,
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
    let valid = samples(rows, Panel::All).unwrap_or_default();
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
        tcp_ms: nonempty_median(valid.values().filter_map(|row| row.tcp).collect()),
        tls_ms: med(|row| row.connect - row.tcp.unwrap_or(0.)),
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
pub fn preserves_services(reference: &[Value], candidate: &[Value], panel: Panel) -> bool {
    let protected = |row: &&Value| panel == Panel::All || row["group"] != "DPI";
    reference
        .iter()
        .filter(protected)
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
                    let time = if before["url"]
                        .as_str()
                        .is_some_and(|url| url.starts_with("http://"))
                    {
                        "tcp_ms"
                    } else {
                        "tls_ms"
                    };
                    verified_response(after)
                        && (before["group"] != "Clean"
                            || !before["code"].as_str().is_some_and(|s| s.starts_with('2'))
                            || after["code"].as_str().is_some_and(|s| s.starts_with('2')))
                        && (panel == Panel::All
                            || !service(before)
                            || !stable(before)
                            || stable(after))
                        && (before["group"] != "Clean"
                            || before[time].as_f64().zip(after[time].as_f64()).is_some_and(
                                |(a, b)| {
                                    a.is_finite()
                                        && a > 0.
                                        && b.is_finite()
                                        && b > 0.
                                        && b <= a + 500.
                                },
                            ))
                })
        })
        && (panel == Panel::Services
            || candidate.iter().filter(|row| row["flaky"] == true).count()
                <= reference.iter().filter(|row| row["flaky"] == true).count())
        && candidate
            .iter()
            .filter(protected)
            .filter(|row| row["state"] == "FREEZE")
            .count()
            <= reference
                .iter()
                .filter(protected)
                .filter(|row| row["state"] == "FREEZE")
                .count()
}
fn sample(row: &Value) -> Option<(String, Sample)> {
    if !stable(row) || row["tls_peer_retry"] == true {
        return None;
    }
    let group = row["group"].as_str()?;
    let url = row["url"].as_str()?;
    let dns = row["dns_ms"].as_f64()?;
    let tcp = if row["mode"] == "http3_head" {
        None
    } else {
        Some(row["tcp_ms"].as_f64()? - dns)
    };
    let connect = if url.starts_with("https://") {
        row["tls_ms"].as_f64()? - dns
    } else {
        tcp?
    };
    let first_byte = row["first_byte_ms"].as_f64()?;
    let total = row["total_ms"].as_f64()?;
    if ![dns, tcp.unwrap_or(0.), connect, first_byte, total]
        .iter()
        .all(|value| value.is_finite() && *value >= 0.)
        || total <= 0.
        || connect < tcp.unwrap_or(0.)
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
        target_key(row)?,
        Sample {
            group: group.into(),
            mode: row["mode"].as_str().map(str::to_owned),
            media_url: row["media_url"].as_str().map(str::to_owned),
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
fn samples(rows: &[Value], panel: Panel) -> Option<BTreeMap<String, Sample>> {
    let mut result = BTreeMap::new();
    for row in rows.iter().filter(|r| panel == Panel::All || service(r)) {
        if let Some((key, sample)) = sample(row) {
            if result.insert(key, sample).is_some() {
                return None;
            }
        }
    }
    Some(result)
}
pub fn median_request_ms(rows: &[Value]) -> Option<f64> {
    let samples = samples(rows, Panel::All)?;
    (!samples.is_empty()).then(|| median(samples.values().map(|s| s.total).collect()))
}

fn p95(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[(values.len() * 95).div_ceil(100) - 1]
}
fn comparable(a: &Sample, b: &Sample) -> bool {
    a.peer == b.peer
        && a.media_url == b.media_url
        && a.mode == b.mode
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
fn nonempty_median(values: Vec<f64>) -> Option<f64> {
    (!values.is_empty()).then(|| median(values))
}

pub(crate) fn compare_panel(
    reference: &[Value],
    candidate: &[Value],
    panel: Panel,
) -> Option<Comparison> {
    let reference = samples(reference, panel)?;
    let candidate = samples(candidate, panel)?;
    compare_samples(&reference, &candidate, panel)
}

fn compare_samples(
    reference: &BTreeMap<String, Sample>,
    candidate: &BTreeMap<String, Sample>,
    panel: Panel,
) -> Option<Comparison> {
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
    if common.len() < panel.required_pairs(reference.len().max(candidate.len())) {
        return None;
    }
    let pairs = common;
    let gains: Vec<_> = pairs.iter().map(|(_, a, b)| a.total - b.total).collect();
    let reference_tcp_ms = nonempty_median(pairs.iter().filter_map(|(_, a, _)| a.tcp).collect());
    let candidate_tcp_ms = nonempty_median(pairs.iter().filter_map(|(_, _, b)| b.tcp).collect());
    let reference_p95_ms = p95(pairs.iter().map(|(_, a, _)| a.total).collect());
    let candidate_p95_ms = p95(pairs.iter().map(|(_, _, b)| b.total).collect());
    let mut groups = BTreeMap::<&str, (Vec<f64>, Vec<f64>)>::new();
    for (_, a, b) in &pairs {
        let (before, after) = groups.entry(&a.group).or_default();
        before.push(a.total);
        after.push(b.total);
    }
    let service_score = if panel == Panel::Services {
        if reference
            .values()
            .chain(candidate.values())
            .any(|s| !groups.contains_key(s.group.as_str()))
        {
            return None;
        }
        Some(ServiceScore::from_groups(&groups))
    } else {
        None
    };
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
        service_score,
        scope: if panel == Panel::Services {
            SERVICE_SCOPE
        } else {
            "AllTargets"
        }
        .into(),
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
        reference_tls_ms: median(
            pairs
                .iter()
                .map(|(_, a, _)| a.connect - a.tcp.unwrap_or(0.))
                .collect(),
        ),
        candidate_tls_ms: median(
            pairs
                .iter()
                .map(|(_, _, b)| b.connect - b.tcp.unwrap_or(0.))
                .collect(),
        ),
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
    panel: Panel,
    previous: Option<(&[Value], &[Value])>,
) -> Option<Comparison> {
    let required = preference.working.as_ref().unwrap_or(&preference.trial);
    let keys: BTreeSet<_> = required.panel.iter().collect();
    let on_panel = |rows: &[Value], first: Option<&[Value]>| {
        let mut current = samples(rows, panel)?;
        if let Some(first) = first {
            let previous = samples(first, panel)?;
            current.retain(|key, sample| {
                previous
                    .get(key)
                    .is_some_and(|before| comparable(before, sample))
            });
        }
        current.retain(|key, _| keys.contains(key));
        Some(current)
    };
    let before = on_panel(reference, previous.map(|(before, _)| before))?;
    let after = on_panel(candidate, previous.map(|(_, after)| after))?;
    let comparison = compare_samples(&before, &after, panel)?;
    if panel == Panel::Services
        && !comparison
            .service_score
            .as_ref()?
            .groups
            .keys()
            .eq(preference.trial.service_score.as_ref()?.groups.keys())
    {
        return None;
    }
    (comparison.targets >= panel.required_pairs(preference.trial.targets)).then_some(comparison)
}

// Score the first pair on the same addresses as the reversed run.
pub fn repeatable_points(
    first: &Comparison,
    repeat: &Comparison,
    reference: &[Value],
    candidate: &[Value],
) -> Option<f64> {
    let original = first.service_score.as_ref()?;
    let reverse = repeat.service_score.as_ref()?;
    let shared;
    let forward = if first.panel == repeat.panel {
        original
    } else {
        let keys: BTreeSet<_> = repeat.panel.iter().collect();
        let restrict = |rows: &[Value]| {
            let mut points = samples(rows, Panel::Services)?;
            points.retain(|key, _| keys.contains(key));
            Some(points)
        };
        let pair = compare_samples(
            &restrict(reference)?,
            &restrict(candidate)?,
            Panel::Services,
        )?;
        if pair.panel != repeat.panel {
            return None;
        }
        shared = pair.service_score?;
        &shared
    };
    if forward.groups.is_empty() || !forward.groups.keys().eq(reverse.groups.keys()) {
        return None;
    }
    let sum: f64 = forward
        .groups
        .iter()
        .map(|(g, a)| a.min(reverse.groups[g]))
        .sum();
    Some(original.points.min(sum / forward.groups.len() as f64))
}

pub fn preference(
    reference: &RankRow,
    row: &RankRow,
    details: &BTreeMap<String, Vec<Value>>,
    panel: Panel,
) -> Option<Preference> {
    if !eligible(reference, row, panel) {
        return None;
    }
    let baseline = details.get(&reference.id)?;
    let candidate = details.get(&row.id)?;
    if !preserves_services(baseline, candidate, panel) {
        return None;
    }
    let trial = compare_panel(baseline, candidate, panel)?;
    Some(Preference {
        reference: reference.id.clone(),
        candidate: row.id.clone(),
        trial,
        working: None,
        repeat: None,
        repeatable_points: None,
        confirmed: false,
    })
}

#[derive(Default)]
pub struct Screening {
    pub preference: Option<Preference>,
    pub service_scores: BTreeMap<String, f64>,
}

pub fn recommend(
    rows: &[RankRow],
    details: &BTreeMap<String, Vec<Value>>,
    panel: Panel,
) -> Screening {
    let mut screening = Screening::default();
    let Some(reference) = rows.first() else {
        return screening;
    };
    if panel == Panel::Services {
        screening.service_scores.insert(reference.id.clone(), 0.);
    }
    screening.preference = rows
        .iter()
        .skip(1)
        .filter_map(|row| preference(reference, row, details, panel))
        .inspect(|p| {
            if let Some(score) = &p.trial.service_score {
                screening
                    .service_scores
                    .insert(p.candidate.clone(), score.points);
            }
        })
        .filter(|p| {
            if panel == Panel::Services {
                p.trial.promising()
            } else {
                p.trial.faster()
            }
        })
        .min_by(|a, b| {
            if panel == Panel::Services {
                return a.trial.screening_order(&b.trial);
            }
            a.trial
                .candidate_total_ms
                .total_cmp(&b.trial.candidate_total_ms)
                .then(
                    a.trial
                        .candidate_p95_ms
                        .total_cmp(&b.trial.candidate_p95_ms),
                )
        });
    screening
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn compare(reference: &[Value], candidate: &[Value]) -> Option<Comparison> {
        compare_panel(reference, candidate, Panel::All)
    }
    fn recommend(rows: &[RankRow], details: &BTreeMap<String, Vec<Value>>) -> Option<Preference> {
        super::recommend(rows, details, Panel::for_trials(rows, details)).preference
    }
    fn samples(tcp: f64, tls: f64) -> Vec<Value> {
        (0..6).map(|n|json!({"group":"NBA2K","name":format!("service{n}"),"url":format!("https://s{n}.test/"),
            "state":"OK","tries":1,"flaky":false,"certificate_validated":true,
            "remote_address":format!("203.0.113.{}:443",n+1),"dns_ms":5.,"tcp_ms":5.+tcp,"tls_ms":5.+tcp+tls,
            "first_byte_ms":15.+tcp+tls,"total_ms":35.+tcp+tls,"code":"200","body_limit":65536,"body_bytes":1024,"post_bytes":0,"termination":"Complete"})).collect()
    }
    #[test]
    fn a_verified_alternate_tls_peer_counts_for_access_and_excludes_mixed_latency() {
        let mut row = samples(30., 60.).remove(0);
        assert!(sample(&row).is_some());
        row["tls_peer_retry"] = json!(true);
        assert!(stable(&row) && sample(&row).is_none());
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
    fn a_service_with_many_addresses_cannot_outvote_an_unreachable_group() {
        let mut many = samples(50., 100.);
        for r in &mut many {
            r["group"] = json!("Discord");
        }
        let mut icon = many[0].clone();
        icon["group"] = json!("Roblox");
        many.push(icon);
        let mut one_missing = many.clone();
        one_missing.last_mut().unwrap()["state"] = json!("FAIL");
        let mut both_reached = many.clone();
        for r in &mut both_reached[1..4] {
            r["state"] = json!("FAIL");
        }
        assert!(availability_rank(&both_reached) > availability_rank(&one_missing));
        let doubled: Vec<_> = many
            .iter()
            .chain(many.iter().filter(|r| r["group"] == "Discord"))
            .cloned()
            .collect();
        assert_eq!(availability_rank(&many), availability_rank(&doubled));
    }

    #[test]
    fn a_service_group_has_the_same_vote_regardless_of_its_number_of_targets() {
        let mut base = samples(50., 100.);
        let mut other = base.clone();
        for (i, (a, b)) in base.iter_mut().zip(&mut other).enumerate() {
            let group = if i == 0 { "Discord" } else { "NBA2K" };
            a["group"] = json!(group);
            b["group"] = json!(group);
            a["total_ms"] = json!(400.);
            b["total_ms"] = json!(if i == 0 { 800. } else { 200. });
        }
        let pair = compare_panel(&base, &other, Panel::Services).unwrap();
        let score = pair.service_score.as_ref().unwrap();
        assert_eq!(score.groups["Discord"], -50.);
        assert_eq!(score.groups["NBA2K"], 50.);
        assert_eq!(score.points, 0.);
        assert!(!pair.faster());
        other[0]["remote_address"] = json!("203.0.113.99:443");
        assert!(compare_panel(&base, &other, Panel::Services).is_none());
    }

    #[test]
    fn one_slow_endpoint_can_be_outweighed_but_noise_cannot_switch_the_profile() {
        let mut base = samples(50., 100.);
        for i in 6..32 {
            let mut extra = base[0].clone();
            extra["name"] = json!(format!("extra-{i}"));
            base.push(extra);
        }
        let mut other = base.clone();
        for row in &mut base {
            row["total_ms"] = json!(600.);
        }
        for row in &mut other {
            row["total_ms"] = json!(500.);
        }
        other[0]["total_ms"] = json!(1000.);
        let pair = compare_panel(&base, &other, Panel::Services).unwrap();
        assert_eq!(pair.regressions, 1);
        assert!(pair.faster());
        for row in &mut other {
            row["total_ms"] = json!(590.);
        }
        let noise = compare_panel(&base, &other, Panel::Services).unwrap();
        assert!(noise.promising() && !noise.faster());
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
        assert!(!preserves_services(&baseline, &candidate, Panel::All));
        assert!(preserves_services(&baseline, &candidate, Panel::Services));
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
            repeat: None,
            repeatable_points: None,
            confirmed: false,
        };
        assert!(confirm(&preference, &baseline, &candidate, Panel::All, None).is_none());
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

    #[test]
    fn a_control_retry_within_tolerance_is_distinct_from_a_steam_retry_or_a_control_loss() {
        let mut before = samples(30., 60.);
        before[0]["group"] = json!("Clean");
        before[0]["name"] = json!("adobe");
        before[1]["group"] = json!("Clean");
        before[1]["name"] = json!("steamapi");
        let mut after = before.clone();
        after[0]["tries"] = json!(2);
        assert!(preserves_services(&before, &after, Panel::Services));
        after[1]["tries"] = json!(2);
        assert!(!preserves_services(&before, &after, Panel::Services));
        after[1]["tries"] = json!(1);
        after[0]["state"] = json!("FAIL");
        assert!(!preserves_services(&before, &after, Panel::Services));
    }

    #[test]
    fn repeat_requires_the_same_servers_and_most_of_the_original_service_panel() {
        let before = samples(50., 100.);
        let after = samples(35., 65.);
        let trial = compare_panel(&before, &after, Panel::Services).unwrap();
        let speed = Preference {
            reference: "a".into(),
            candidate: "b".into(),
            working: Some(trial.clone()),
            trial,
            repeat: None,
            repeatable_points: None,
            confirmed: false,
        };
        let (mut next_a, mut next_b) = (before.clone(), after.clone());
        for changed in 0..3 {
            let repeat = confirm(
                &speed,
                &next_a,
                &next_b,
                Panel::Services,
                Some((&before, &after)),
            );
            assert_eq!(
                repeat.map(|p| p.targets),
                (changed < 2).then_some(6 - changed)
            );
            for rows in [&mut next_a, &mut next_b] {
                rows[changed]["remote_address"] = json!("198.51.100.10:443");
            }
        }
    }

    #[test]
    fn a_larger_dpi_score_cannot_displace_the_primary_or_an_extra_healthy_service() {
        let mut rows = vec![
            score("strong", 52.),
            score("current", 46.),
            score("slow", 50.),
        ];
        let mut panel = samples(45., 80.);
        let mut dpi = panel[0].clone();
        dpi["group"] = json!("DPI");
        panel.push(dpi);
        let mut details: BTreeMap<_, _> =
            rows.iter().map(|r| (r.id.clone(), panel.clone())).collect();
        details.get_mut("slow").unwrap()[0]["tries"] = json!(2);
        let selected = Panel::for_trials(&rows, &details);
        assert!(selected == Panel::Services);
        selected.prioritize(&mut rows, &details, "current");
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["current", "strong", "slow"]
        );
        details.get_mut("current").unwrap()[1]["state"] = json!("FAIL");
        selected.prioritize(&mut rows, &details, "current");
        assert_eq!(rows[0].id, "strong");
    }
}
