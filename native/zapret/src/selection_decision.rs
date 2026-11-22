//! A measured winner is recommended only after its working configuration passes.
use crate::selection_latency;
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

pub struct Decision {
    pub recommended: Option<RankRow>,
    pub checks: BTreeMap<String, Check>,
    pub preference: Option<crate::selection_latency::Preference>,
}

const QUICK_FINALISTS: usize = 3;

pub fn verified_preferred(
    rows: &[RankRow],
    full: bool,
    details: &BTreeMap<String, Vec<Value>>,
    mut validate: impl FnMut(&str) -> Result<Check>,
) -> Result<Decision> {
    let mut decision = Decision {
        recommended: None,
        checks: BTreeMap::new(),
        preference: None,
    };
    let Some(leader) = rows.first() else {
        return Ok(decision);
    };
    let mut peers: Vec<_> = rows
        .iter()
        .skip(1)
        .filter(|row| selection_latency::eligible(leader, row))
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
        if decision.recommended.is_some() && !selection_latency::eligible(leader, row) {
            continue;
        }
        let mut preference = decision
            .recommended
            .as_ref()
            .and_then(|winner| selection_latency::preference(winner, row, details));
        if decision.recommended.is_some() && preference.is_none() {
            continue;
        }
        let check = validate(&row.id)?;
        if check.confirmed {
            if let Some(speed) = &mut preference {
                let baseline = &decision.checks[&speed.reference].details;
                speed.working = selection_latency::confirm(speed, baseline, &check.details);
                speed.confirmed = speed
                    .working
                    .as_ref()
                    .is_some_and(|working| working.faster())
                    && selection_latency::preserves_services(baseline, &check.details);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sample(tls: f64) -> Vec<Value> {
        (0..6).map(|n|json!({"group":"NBA2K","name":format!("s{n}"),"url":format!("https://s{n}.test/"),"remote_address":"203.0.113.1:443",
            "state":"OK","certificate_validated":true,"flaky":false,"tries":1,"dns_ms":5.,"tcp_ms":35.,"tls_ms":tls+5.,
            "first_byte_ms":tls+15.,"total_ms":tls+35.,"code":"200","body_limit":65536,"body_bytes":1024,"post_bytes":0,"termination":"Complete"})).collect()
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
