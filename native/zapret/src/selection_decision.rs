//! A measured winner is recommended only after its working configuration passes.
use crate::selection_latency::{self, Panel};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use zapret_core::RankRow;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub confirmed: bool,
    pub error: Option<String>,
    pub details: Vec<Value>,
}

#[derive(Default)]
pub struct Decision {
    pub recommended: Option<RankRow>,
    pub checks: BTreeMap<String, Check>,
    pub preference: Option<crate::selection_latency::Preference>,
    pub repeat_candidates: Vec<String>,
}

const QUICK_FINALISTS: usize = 3;
const MAX_REVERSED_PAIRS: usize = 2;

pub fn verified_preferred(
    rows: &[RankRow],
    full: bool,
    details: &BTreeMap<String, Vec<Value>>,
    panel: Panel,
    mut validate: impl FnMut(&str) -> Result<Check>,
) -> Result<Decision> {
    if panel == Panel::Services {
        return verified_services(rows, full, details, validate);
    }
    let mut decision = Decision::default();
    let Some(leader) = rows.first() else {
        return Ok(decision);
    };
    let mut peers: Vec<_> = rows
        .iter()
        .skip(1)
        .filter(|row| selection_latency::eligible(leader, row, panel))
        .map(|row| {
            let ms = details
                .get(&row.id)
                .and_then(|rows| selection_latency::median_request_ms(rows));
            (row, ms.unwrap_or(f64::INFINITY))
        })
        .collect();
    peers.sort_by(|a, b| a.1.total_cmp(&b.1));
    // Start with the coverage leader. Check comparable peers from fastest to
    // slowest, then use the original runners-up only if nobody passed.
    let order = std::iter::once(leader)
        .chain(peers.into_iter().map(|(row, _)| row))
        .chain(rows.iter().take(QUICK_FINALISTS).skip(1));
    for row in order {
        if !full && decision.checks.len() >= QUICK_FINALISTS {
            break;
        }
        if decision.checks.contains_key(&row.id) {
            continue;
        }
        if decision.recommended.is_some() && !selection_latency::eligible(leader, row, panel) {
            continue;
        }
        let mut preference = decision
            .recommended
            .as_ref()
            .and_then(|winner| selection_latency::preference(winner, row, details, panel));
        if decision.recommended.is_some() && preference.is_none() {
            continue;
        }
        let check = validate(&row.id)?;
        if check.confirmed {
            if let Some(speed) = &mut preference {
                let baseline = &decision.checks[&speed.reference].details;
                speed.working =
                    selection_latency::confirm(speed, baseline, &check.details, panel, None);
                speed.confirmed = speed
                    .working
                    .as_ref()
                    .is_some_and(|working| working.faster())
                    && selection_latency::preserves_services(baseline, &check.details, panel);
                if speed.confirmed {
                    decision.recommended = Some(row.clone());
                }
            } else {
                decision.recommended = Some(row.clone());
            }
        }
        if preference.as_ref().is_some_and(|speed| speed.confirmed) || decision.preference.is_none()
        {
            decision.preference = preference;
        }
        decision.checks.insert(row.id.clone(), check);
    }
    Ok(decision)
}
/// Use the first healthy working configuration as a fixed reference for every challenger.
fn verified_services(
    rows: &[RankRow],
    full: bool,
    details: &BTreeMap<String, Vec<Value>>,
    mut validate: impl FnMut(&str) -> Result<Check>,
) -> Result<Decision> {
    let mut decision = Decision::default();
    let limit = if full { usize::MAX } else { QUICK_FINALISTS };
    let mut reference = None;
    for row in rows
        .iter()
        .filter(|row| selection_latency::service_ready(row, details))
        .take(limit)
    {
        let check = validate(&row.id)?;
        let passed = check.confirmed;
        decision.checks.insert(row.id.clone(), check);
        if passed {
            reference = Some(row);
            break;
        }
    }
    let Some(reference) = reference else {
        return Ok(decision);
    };
    decision.recommended = Some(reference.clone());
    let mut peers: Vec<_> = rows
        .iter()
        .filter(|row| !decision.checks.contains_key(&row.id))
        .filter_map(|row| selection_latency::preference(reference, row, details, Panel::Services))
        .filter(|speed| speed.trial.promising())
        .collect();
    peers.sort_by(|a, b| a.trial.screening_order(&b.trial));
    let mut finalists = Vec::new();
    for mut speed in peers.into_iter().take(limit - decision.checks.len()) {
        let check = validate(&speed.candidate)?;
        let before = &decision.checks[&reference.id].details;
        if check.confirmed
            && selection_latency::preserves_services(before, &check.details, Panel::Services)
        {
            speed.working =
                selection_latency::confirm(&speed, before, &check.details, Panel::Services, None);
        }
        decision.checks.insert(speed.candidate.clone(), check);
        if let Some(working) = speed.working.as_ref().filter(|pair| pair.faster()) {
            finalists.push((working.gain_ms, speed));
        } else if decision.preference.is_none() {
            decision.preference = Some(speed);
        }
    }
    finalists.sort_by(|a, b| b.0.total_cmp(&a.0));
    // Preserve the original reference for the endpoint check of every reversed pair.
    let mut latest_reference = None;
    let mut recheck_fallback = false;
    for (_, mut speed) in finalists.into_iter().take(MAX_REVERSED_PAIRS) {
        let candidate_repeat = validate(&speed.candidate)?;
        recheck_fallback = !candidate_repeat.confirmed;
        if candidate_repeat.confirmed {
            let reference_repeat = validate(&reference.id)?;
            if reference_repeat.confirmed
                && selection_latency::preserves_services(
                    &reference_repeat.details,
                    &candidate_repeat.details,
                    Panel::Services,
                )
            {
                speed.repeat = selection_latency::confirm(
                    &speed,
                    &reference_repeat.details,
                    &candidate_repeat.details,
                    Panel::Services,
                    Some((
                        &decision.checks[&reference.id].details,
                        &decision.checks[&speed.candidate].details,
                    )),
                );
                speed.confirmed = speed.repeat.as_ref().is_some_and(|pair| pair.faster());
            }
            latest_reference = Some(reference_repeat);
        }
        let confirmed = speed.confirmed;
        decision
            .checks
            .insert(speed.candidate.clone(), candidate_repeat);
        decision.repeat_candidates.push(speed.candidate.clone());
        if confirmed || decision.repeat_candidates.len() == 1 {
            decision.preference = Some(speed);
        }
        if confirmed
            || latest_reference
                .as_ref()
                .is_some_and(|check| !check.confirmed)
        {
            break;
        }
    }
    if recheck_fallback {
        latest_reference = Some(validate(&reference.id)?);
    }
    if let Some(latest) = latest_reference {
        decision.checks.insert(reference.id.clone(), latest);
    }
    decision.recommended =
        if let Some(speed) = decision.preference.as_ref().filter(|p| p.confirmed) {
            rows.iter().find(|r| r.id == speed.candidate)
        } else if decision.checks[&reference.id].confirmed {
            Some(reference)
        } else {
            rows.iter().find(|r| {
                decision
                    .checks
                    .get(&r.id)
                    .is_some_and(|check| check.confirmed)
            })
        }
        .cloned();
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn verified_preferred(
        rows: &[RankRow],
        full: bool,
        details: &BTreeMap<String, Vec<Value>>,
        validate: impl FnMut(&str) -> Result<Check>,
    ) -> Result<Decision> {
        super::verified_preferred(
            rows,
            full,
            details,
            Panel::for_trials(rows, details),
            validate,
        )
    }
    fn sample(tls: f64) -> Vec<Value> {
        (0..6).map(|n|json!({"group":"NBA2K","name":format!("s{n}"),"url":format!("https://s{n}.test/"),"remote_address":"203.0.113.1:443",
            "state":"OK","certificate_validated":true,"flaky":false,"tries":1,"dns_ms":5.,"tcp_ms":35.,"tls_ms":tls+5.,
            "first_byte_ms":tls+15.,"total_ms":tls+35.,"code":"200","body_limit":65536,"body_bytes":1024,"post_bytes":0,"termination":"Complete"})).collect()
    }

    #[test]
    fn fast_services_can_win_despite_synthetic_losses_only_after_reversed_confirmation() {
        let observations = |tls, synthetic_ok: bool| {
            let mut v = sample(tls);
            for mut synthetic in sample(100.) {
                synthetic["group"] = json!("DPI");
                if !synthetic_ok {
                    synthetic["state"] = json!("FREEZE");
                }
                v.push(synthetic);
            }
            v
        };
        let rows: Vec<_> = [("heavy", 12.), ("light", 6.)]
            .into_iter()
            .map(|(id, ok)| RankRow {
                id: id.into(),
                ok,
                score: ok,
                total: 12,
                freeze: (12. - ok) as usize,
                groups: BTreeMap::from([("NBA2K".into(), 6.), ("DPI".into(), ok - 6.)]),
                group_totals: BTreeMap::from([("NBA2K".into(), 6), ("DPI".into(), 6)]),
                ..Default::default()
            })
            .collect();
        let details = BTreeMap::from([
            ("heavy".into(), observations(160., true)),
            ("light".into(), observations(80., false)),
        ]);
        for (last_ms, expected) in [(82., "light"), (180., "heavy")] {
            let mut calls = Vec::new();
            let decision = verified_preferred(&rows, true, &details, |id| {
                let repeat = calls.iter().any(|previous| previous == id);
                calls.push(id.to_owned());
                let ms = if id == "heavy" {
                    160.
                } else if repeat {
                    last_ms
                } else {
                    80.
                };
                Ok(Check {
                    confirmed: true,
                    error: None,
                    details: observations(ms, id == "heavy"),
                })
            })
            .unwrap();
            assert_eq!(calls, ["heavy", "light", "light", "heavy"]);
            assert_eq!(decision.recommended.unwrap().id, expected);
            assert_eq!(decision.preference.unwrap().confirmed, expected == "light");
        }
    }
    #[test]
    fn speed_preference_requires_a_second_success_in_the_working_mode() {
        let rows = vec![
            RankRow {
                id: "52".into(),
                score: 49.,
                ok: 49.,
                total: 54,
                ..Default::default()
            },
            RankRow {
                id: "58".into(),
                score: 49.,
                ok: 49.,
                total: 54,
                ..Default::default()
            },
        ];
        let details = BTreeMap::from([("52".into(), sample(150.)), ("58".into(), sample(100.))]);
        for (working_ms, expected) in [(100., "58"), (170., "52")] {
            let mut calls = Vec::new();
            let decision = verified_preferred(&rows, false, &details, |id| {
                calls.push(id.to_string());
                Ok(Check {
                    confirmed: true,
                    error: None,
                    details: sample(if id == "52" { 150. } else { working_ms }),
                })
            })
            .unwrap();
            assert_eq!(calls, ["52", "58"]);
            assert_eq!(decision.recommended.unwrap().id, expected);
            assert_eq!(decision.preference.unwrap().confirmed, expected == "58");
        }
    }

    fn service_fixture(items: &[(&str, f64)]) -> (Vec<RankRow>, BTreeMap<String, Vec<Value>>) {
        let mut rows = Vec::new();
        let mut details = BTreeMap::new();
        for &(id, tls) in items {
            rows.push(RankRow {
                id: id.into(),
                total: 12,
                ..Default::default()
            });
            let mut records = sample(tls);
            let mut synthetic = records[0].clone();
            synthetic["group"] = json!("DPI");
            records.push(synthetic);
            details.insert(id.to_owned(), records);
        }
        (rows, details)
    }

    #[test]
    fn a_failed_repeat_gives_the_next_working_finalist_an_independent_pair() {
        let (rows, details) =
            service_fixture(&[("failed", 60.), ("anchor", 230.), ("a", 180.), ("b", 80.)]);
        let mut order = Vec::new();
        let decision = verified_preferred(&rows, true, &details, |id| {
            let again = order.iter().any(|previous| previous == id);
            order.push(id.to_owned());
            Ok(Check {
                confirmed: id != "failed" && !(id == "b" && again),
                error: None,
                details: details[id].clone(),
            })
        })
        .unwrap();
        assert_eq!(order, ["failed", "anchor", "b", "a", "b", "a", "anchor"]);
        assert_eq!(decision.recommended.unwrap().id, "a");
        assert!(decision.preference.unwrap().confirmed);
        assert_eq!(decision.repeat_candidates, ["b", "a"]);
        assert!(!decision.checks["b"].confirmed);
    }

    #[test]
    fn a_shortlist_uses_at_most_two_reversed_pairs_and_refreshes_the_fallback() {
        let (rows, details) =
            service_fixture(&[("anchor", 230.), ("a", 80.), ("b", 100.), ("c", 120.)]);
        for full in [false, true] {
            let mut order = Vec::new();
            let decision = verified_preferred(&rows, full, &details, |id| {
                let repeated = order.iter().any(|old| old == id);
                order.push(id.to_string());
                Ok(Check {
                    confirmed: !repeated || id == "anchor",
                    error: None,
                    details: details[id].clone(),
                })
            })
            .unwrap();
            assert_eq!(decision.recommended.unwrap().id, "anchor");
            assert!(!decision.preference.unwrap().confirmed);
            assert_eq!(decision.repeat_candidates, ["a", "b"]);
            assert_eq!(order.last().unwrap(), "anchor");
            assert_eq!(order.len(), if full { 7 } else { 6 });
        }
    }

    #[test]
    fn a_runner_up_keeps_the_original_endpoint_reference_and_stops_if_the_anchor_fails() {
        let (rows, details) = service_fixture(&[("anchor", 230.), ("a", 80.), ("b", 100.)]);
        for anchor_healthy in [false, true] {
            let mut anchor_calls = 0;
            let decision = verified_preferred(&rows, false, &details, |id| {
                let mut records = details[id].clone();
                if id == "anchor" {
                    anchor_calls += 1;
                }
                if id == "anchor" && anchor_calls == 2 {
                    for row in &mut records {
                        row["remote_address"] = json!("203.0.113.55:443");
                    }
                }
                Ok(Check {
                    confirmed: id != "anchor" || anchor_calls != 2 || anchor_healthy,
                    error: None,
                    details: records,
                })
            })
            .unwrap();
            if anchor_healthy {
                assert_eq!(decision.recommended.unwrap().id, "b");
                assert!(decision.preference.unwrap().confirmed);
                assert_eq!(decision.repeat_candidates, ["a", "b"]);
            } else {
                assert!(!decision.checks["anchor"].confirmed);
                assert!(!decision.preference.unwrap().confirmed);
                assert_eq!(decision.repeat_candidates, ["a"]);
            }
        }
    }

    #[test]
    fn lowest_confirmed_working_latency_wins_even_if_trial_times_are_in_another_order() {
        let rows: Vec<_> = [
            ("31", 49.),
            ("58", 49.),
            ("60", 49.),
            ("52", 48.5),
            ("3", 21.),
        ]
        .into_iter()
        .map(|(id, score)| RankRow {
            id: id.into(),
            score,
            ok: score,
            total: 54,
            ..Default::default()
        })
        .collect();
        let details = BTreeMap::from([
            ("31".into(), sample(220.)),
            ("58".into(), sample(218.)),
            ("60".into(), sample(200.)),
            ("52".into(), sample(215.)),
            ("3".into(), sample(40.)),
        ]);
        for (full, expected) in [(false, "52"), (true, "58")] {
            let mut tried = Vec::new();
            let result = verified_preferred(&rows, full, &details, |id| {
                tried.push(id.to_owned());
                let ms = match id {
                    "31" => 220.,
                    "60" => 200.,
                    "52" => 190.,
                    "58" => 188.,
                    _ => panic!("poor coverage"),
                };
                Ok(Check {
                    confirmed: true,
                    error: None,
                    details: sample(ms),
                })
            })
            .unwrap();
            assert_eq!(
                tried,
                if full {
                    &["31", "60", "52", "58"][..]
                } else {
                    &["31", "60", "52"][..]
                }
            );
            assert_eq!(result.recommended.unwrap().id, expected);
            let winner = result.preference.unwrap();
            assert!(winner.confirmed);
            assert_eq!(winner.candidate, expected);
            assert_eq!(winner.working.unwrap().gain_ms, if full { 2. } else { 10. });
        }
    }
    fn rows() -> Vec<RankRow> {
        ["31", "51", "58", "50"]
            .iter()
            .map(|id| RankRow {
                id: (*id).into(),
                ..Default::default()
            })
            .collect()
    }
    #[test]
    fn rejected_hetzner_leader_is_replaced_only_by_a_confirmed_candidate() {
        let mut tried = Vec::new();
        let result = verified_preferred(&rows(), false, &BTreeMap::new(), |id| {
            tried.push(id.to_owned());
            Ok(Check {
                confirmed: id == "51",
                error: if id == "31" {
                    Some("DPI/FI.HE-03 Hetzner: TLS reset".into())
                } else {
                    None
                },
                details: Vec::new(),
            })
        })
        .unwrap();
        assert_eq!(tried, ["31", "51"]);
        assert_eq!(result.recommended.unwrap().id, "51");
        assert!(!result.checks["31"].confirmed);
    }
    #[test]
    fn current_primary_as_measured_leader_does_not_prevent_fallback_to_the_next_finalist() {
        let candidates: Vec<_> = ["50", "52", "31"]
            .into_iter()
            .map(|id| RankRow {
                id: id.into(),
                ..Default::default()
            })
            .collect();
        let mut tried = Vec::new();
        let result = verified_preferred(&candidates, false, &BTreeMap::new(), |id| {
            tried.push(id.to_owned());
            Ok(Check {
                confirmed: id == "52",
                error: (id == "50").then(|| "Working coverage regression".into()),
                details: Vec::new(),
            })
        })
        .unwrap();
        assert_eq!(tried, ["50", "52"]);
        assert_eq!(result.recommended.unwrap().id, "52");
        assert!(!result.checks["50"].confirmed);
        assert!(result.checks["52"].confirmed);
    }
    #[test]
    fn final_rechecks_are_bounded_and_a_context_error_never_becomes_a_recommendation() {
        let mut count = 0;
        let result = verified_preferred(&rows(), false, &BTreeMap::new(), |_| {
            count += 1;
            Ok(Check {
                confirmed: false,
                error: Some("failed".into()),
                details: Vec::new(),
            })
        })
        .unwrap();
        assert_eq!(count, 3);
        assert!(result.recommended.is_none());
        assert!(
            verified_preferred(&rows(), true, &BTreeMap::new(), |_| anyhow::bail!(
                "network changed"
            ))
            .is_err()
        );
    }

    #[test]
    fn full_selection_reaches_a_comparable_fourth_finalist_only_with_a_passing_final() {
        let rows: Vec<_> = [
            ("31", 49.),
            ("58", 49.),
            ("60", 49.),
            ("52", 48.5),
            ("61", 47.),
        ]
        .into_iter()
        .map(|(id, score)| RankRow {
            id: id.into(),
            score,
            ok: score,
            total: 54,
            ..Default::default()
        })
        .collect();
        for (full, passing, expected) in [
            (false, "52", None),
            (true, "52", Some("52")),
            (true, "61", None),
        ] {
            let mut tried = Vec::new();
            let result = verified_preferred(&rows, full, &BTreeMap::new(), |id| {
                tried.push(id.to_owned());
                Ok(Check {
                    confirmed: id == passing,
                    error: None,
                    details: Vec::new(),
                })
            })
            .unwrap();
            assert_eq!(
                tried,
                if full {
                    &["31", "58", "60", "52"][..]
                } else {
                    &["31", "58", "60"][..]
                }
            );
            assert_eq!(result.recommended.as_ref().map(|r| r.id.as_str()), expected);
        }
    }
}
