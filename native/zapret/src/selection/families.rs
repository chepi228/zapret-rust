use crate::selection_latency::{self, Panel};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zapret_core::{Coverage, RankRow, Strategy, TestRank};

pub(crate) fn signature(strategy: &Strategy) -> String {
    use std::sync::LazyLock;
    static TUNING: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r":(pos|repeats|blob|host|seqovl|seqovl_pattern)=[^:]+").expect("constant regex")
    });
    static SNI: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([=,])sni=[^,:]+").expect("constant regex"));
    let mut parts = vec!["family-http-v2".to_owned()];
    for section in ["general", "google", "discord_media", "ipset_tcp", "quic"] {
        let actual = if strategy.sections.contains_key(section) {
            section
        } else {
            "general"
        };
        parts.push(format!(
            "{section}@{}",
            strategy.section_family(actual, "general")
        ));
        let mut previous = None;
        for line in strategy.section(actual, "general") {
            if line.starts_with("--lua-desync=") {
                let normalized = TUNING.replace_all(line, ":${1}=*");
                let normalized = SNI.replace_all(&normalized, "${1}sni=*").into_owned();
                if previous.as_ref() != Some(&normalized) {
                    parts.push(normalized.clone());
                }
                previous = Some(normalized);
            } else {
                parts.push(line.clone());
                previous = None;
            }
        }
    }
    zapret_core::sha256(parts.join("\n").as_bytes())
}

// A family describes the general TCP method. The detailed signature also accounts
// for service-specific sections, QUIC and IPv4/IPv6 variants inside that family.
pub(crate) fn method(strategy: &Strategy) -> String {
    let mut names = Vec::new();
    for line in strategy.section("general", "general") {
        if let Some(name) = line
            .strip_prefix("--lua-desync=")
            .and_then(|args| args.split(':').next())
        {
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        return format!("Другой режим {}", &signature(strategy)[..12]);
    }
    names.join(" + ")
}

pub(super) fn catalog(strategies: &[Strategy]) -> BTreeMap<String, Vec<&str>> {
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for strategy in strategies {
        groups
            .entry(method(strategy))
            .or_default()
            .push(strategy.id.as_str());
    }
    groups
}

pub(super) fn schedule(
    pool: &[Strategy],
    all: &[Strategy],
    primary: &str,
    rank: Option<&TestRank>,
    cover: Option<&Coverage>,
    priority: impl Iterator<Item = String>,
) -> (Vec<Strategy>, Vec<Strategy>) {
    let mut required: BTreeSet<_> = priority.collect();
    required.insert(primary.to_owned());
    for section in ["general", "google", "discord_media", "game_tcp"] {
        required.extend(
            zapret_core::rotation_order(all, primary, section, rank, cover)
                .into_iter()
                .map(|s| s.id),
        );
    }
    representatives(pool, &required)
}

fn representatives(
    pool: &[Strategy],
    required: &BTreeSet<String>,
) -> (Vec<Strategy>, Vec<Strategy>) {
    let mut selected = required.clone();
    let mut groups = BTreeMap::<_, Vec<&Strategy>>::new();
    for strategy in pool {
        groups.entry(method(strategy)).or_default().push(strategy);
    }
    for group in groups.values() {
        if !group.iter().any(|s| selected.contains(&s.id)) {
            selected.insert(group[0].id.clone());
        }
        if group.len() >= 4 {
            let mut picked = group.iter().filter(|s| selected.contains(&s.id));
            let already = picked.next().expect("nonempty family");
            if picked.next().is_none() {
                let first_signature = signature(already);
                if let Some(other) = group.iter().find(|s| signature(s) != first_signature) {
                    selected.insert(other.id.clone());
                }
            }
        }
    }
    pool.iter().cloned().partition(|s| selected.contains(&s.id))
}

#[derive(Serialize)]
pub(super) struct Leader {
    pub family: String,
    pub strategy: String,
}

#[derive(Serialize)]
pub(super) struct Refinement {
    pub representatives: Vec<String>,
    pub leaders: Vec<Leader>,
    pub followups: Vec<String>,
    pub reason: &'static str,
}

pub(super) struct Evidence<'a> {
    pub rows: Vec<RankRow>,
    pub details: &'a BTreeMap<String, Vec<Value>>,
    pub primary: &'a str,
    pub controls_stable: bool,
    pub perfect: BTreeSet<String>,
}

pub(super) fn refine(
    initial: &[Strategy],
    mut remaining: Vec<Strategy>,
    mut evidence: Evidence<'_>,
) -> (Vec<Strategy>, Vec<String>, Refinement) {
    let profiles: BTreeMap<_, _> = initial.iter().map(|s| (s.id.as_str(), s)).collect();
    let details = evidence.details;
    let rows = &mut evidence.rows;
    // Resolve ties independently of the randomized measurement order.
    rows.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    let panel = Panel::for_trials(rows, details);
    panel.prioritize(rows, details, evidence.primary);
    let mut ranked = Vec::new();
    let mut clear_family_gain = false;
    let mut coverage_family = false;
    if let Some(anchor) = rows
        .iter()
        .find(|r| panel == Panel::Services && selection_latency::service_ready(r, details))
    {
        let mut gains = Vec::new();
        let mut comparable = Vec::new();
        let complete = |row: &RankRow| {
            selection_latency::complete_services(&details[&row.id])
                && details.get("0").is_some_and(|base| {
                    selection_latency::preserves_services(base, &details[&row.id], panel)
                })
        };
        let anchor_complete = complete(anchor);
        let anchor_method = method(profiles[anchor.id.as_str()]);
        let mut another_working_variant = false;
        for row in rows.iter() {
            if row.id == anchor.id {
                continue;
            }
            let Some(pair) = selection_latency::preference(anchor, row, details, panel) else {
                continue;
            };
            let faster = pair.trial.faster();
            if evidence.controls_stable && anchor_complete && complete(row) {
                let profile = profiles[row.id.as_str()];
                let active = profiles[anchor.id.as_str()];
                if method(profile) == anchor_method {
                    another_working_variant |=
                        profile.sections != active.sections || profile.match_l3 != active.match_l3;
                } else if !clear_family_gain {
                    clear_family_gain = faster
                        || (pair.trial.gain_ms <= -1.
                            && selection_latency::preference(row, anchor, details, panel)
                                .is_some_and(|p| p.trial.faster()));
                }
            }
            if faster {
                gains.push((row, pair.trial));
            } else {
                comparable.push((row, pair.trial));
            }
        }
        gains.sort_by(|a, b| a.1.screening_order(&b.1));
        ranked.extend(gains.into_iter().map(|(r, _)| r));
        ranked.push(anchor);
        comparable.sort_by(|a, b| a.1.screening_order(&b.1));
        ranked.extend(comparable.into_iter().map(|(r, _)| r));
        if another_working_variant {
            let (_, stable, _) = selection_latency::service_rank(anchor, details);
            let mut other_methods = rows
                .iter()
                .filter(|r| method(profiles[r.id.as_str()]) != anchor_method)
                .peekable();
            coverage_family = other_methods.peek().is_some()
                && other_methods.all(|r| {
                    r.harm > 0 || selection_latency::service_rank(r, details).1 + 2 <= stable
                });
        }
        if !clear_family_gain || !evidence.controls_stable {
            ranked.extend(
                rows.iter()
                    .filter(|r| selection_latency::service_ready(r, details)),
            );
        }
    } else {
        ranked.extend(rows.iter().filter(|r| evidence.perfect.contains(&r.id)));
    }
    let reason = if evidence.controls_stable && clear_family_gain {
        "complete_services"
    } else if evidence.controls_stable && coverage_family {
        "coverage_family"
    } else if panel == Panel::All && !evidence.perfect.is_empty() {
        "complete_coverage"
    } else {
        "explore_all"
    };
    let mut leaders = Vec::new();
    for row in ranked {
        let family = method(profiles[row.id.as_str()]);
        if leaders.iter().any(|l: &Leader| l.family == family)
            || !remaining.iter().any(|s| method(s) == family)
        {
            continue;
        }
        leaders.push(Leader {
            family,
            strategy: row.id.clone(),
        });
        if leaders.len() == 2 {
            break;
        }
    }
    // Sample one sibling per leading method before trying a second sibling of the same one.
    let mut followups = Vec::new();
    let mut signatures: BTreeSet<_> = initial.iter().map(signature).collect();
    for leader in leaders.iter().cycle().take(2) {
        let next = remaining
            .iter()
            .enumerate()
            .filter(|(_, s)| method(s) == leader.family)
            .min_by_key(|(_, s)| signatures.contains(&signature(s)))
            .map(|(i, _)| i);
        if let Some(index) = next {
            let next = remaining.remove(index);
            signatures.insert(signature(&next));
            followups.push(next);
        }
    }
    let refinement = Refinement {
        representatives: initial.iter().map(|s| s.id.clone()).collect(),
        leaders,
        followups: followups.iter().map(|s| s.id.clone()).collect(),
        reason,
    };
    let skipped = if reason == "explore_all" {
        followups.append(&mut remaining);
        Vec::new()
    } else {
        remaining.into_iter().map(|s| s.id).collect()
    };
    (followups, skipped, refinement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(id: &str, op: &str) -> Strategy {
        Strategy {
            id: id.into(),
            sections: BTreeMap::from([("general".into(), vec![format!("--lua-desync={op}")])]),
            ..Default::default()
        }
    }

    #[test]
    fn groups_follow_the_general_method_and_retain_protected_and_distinct_variants() {
        let mut variant = profile("3", "fake:repeats=2");
        variant
            .sections
            .insert("quic".into(), vec!["different UDP variant".into()]);
        let pool = vec![
            profile("1", "fake:repeats=1"),
            profile("2", "fake:repeats=3"),
            variant,
            profile("4", "fake:repeats=8"),
            profile("5", "multisplit"),
        ];
        assert_eq!(catalog(&pool)["fake"], ["1", "2", "3", "4"]);
        let (first, rest) = representatives(&pool, &BTreeSet::from(["4".to_owned()]));
        assert_eq!(
            first.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["3", "4", "5"]
        );
        assert_eq!(rest.len(), 2);
    }

    fn observations(ms: f64) -> Vec<Value> {
        (0..7).map(|n| json!({"group":if n == 6 {"DPI"} else {"NBA2K"}, "name":format!("s{n}"),
            "url":format!("https://s{n}.test/"),"remote_address":"203.0.113.1:443","state":"OK","tries":1,"flaky":false,
            "certificate_validated":true,"code":"200","dns_ms":1.,"tcp_ms":5.,"tls_ms":10.,"first_byte_ms":15.,
            "total_ms":ms,"termination":"Complete","body_limit":65536,"body_bytes":1000,"post_bytes":0})).collect()
    }

    #[test]
    fn one_superior_family_needs_two_distinct_profiles_and_a_clear_coverage_gap() {
        for (other_action, drop_count, expected) in [
            ("fake:repeats=4", 2, "coverage_family"),
            ("fake:repeats=8", 2, "explore_all"),
            ("fake:repeats=4", 1, "explore_all"),
        ] {
            let first = [
                profile("a", "fake:repeats=8"),
                profile("v", other_action),
                profile("b", "multisplit"),
            ];
            let rows = first
                .iter()
                .map(|s| RankRow {
                    id: s.id.clone(),
                    total: 7,
                    ..Default::default()
                })
                .collect();
            let mut details: BTreeMap<_, _> = ["0", "a", "v", "b"]
                .into_iter()
                .map(|id| (id.to_owned(), observations(150.)))
                .collect();
            for row in &mut details.get_mut("b").unwrap()[..drop_count] {
                row["state"] = json!("FAIL");
            }
            let (next, _, result) = refine(
                &first,
                vec![
                    profile("a1", "fake"),
                    profile("a2", "fake"),
                    profile("b1", "multisplit"),
                ],
                Evidence {
                    rows,
                    details: &details,
                    primary: "a",
                    controls_stable: true,
                    perfect: BTreeSet::new(),
                },
            );
            assert_eq!(result.reason, expected);
            assert_eq!(
                next.len(),
                if expected == "coverage_family" { 2 } else { 3 }
            );
        }
    }

    #[test]
    fn equal_latency_or_a_lost_steam_target_keeps_sibling_families_in_play() {
        let first = [profile("a", "fake"), profile("b", "multisplit")];
        for loses_steam in [false, true] {
            let mut details: BTreeMap<_, _> = [
                ("0", 200.),
                ("a", 200.),
                ("b", if loses_steam { 90. } else { 200. }),
            ]
            .into_iter()
            .map(|(id, ms)| (id.to_owned(), observations(ms)))
            .collect();
            for (id, records) in &mut details {
                records[0]["group"] = json!("Clean");
                records[0]["name"] = json!("steam");
                if loses_steam && id == "b" {
                    records[0]["state"] = json!("FAIL");
                }
            }
            let rows = first
                .iter()
                .map(|s| RankRow {
                    id: s.id.clone(),
                    total: 7,
                    ..Default::default()
                })
                .collect();
            let remaining = vec![
                profile("a1", "fake"),
                profile("b1", "multisplit"),
                profile("b2", "multisplit"),
            ];
            let (next, skipped, result) = refine(
                &first,
                remaining,
                Evidence {
                    rows,
                    details: &details,
                    primary: "a",
                    controls_stable: true,
                    perfect: BTreeSet::from(["a".into()]),
                },
            );
            assert_eq!(result.reason, "explore_all");
            assert!(skipped.is_empty());
            assert_eq!(next.len(), 3);
        }
    }

    #[test]
    fn quick_followups_use_two_measured_methods_and_widen_on_noise_or_endpoint_changes() {
        let mut selected = vec![
            profile("a", "fake"),
            profile("b", "multisplit"),
            profile("c", "fakedsplit"),
        ];
        let deferred = vec![
            profile("a1", "fake"),
            profile("b1", "multisplit"),
            profile("b2", "multisplit"),
            profile("c1", "fakedsplit"),
        ];
        for (stable, common_peers, expected_reason) in [
            (true, true, "complete_services"),
            (false, true, "explore_all"),
            (true, false, "explore_all"),
        ] {
            selected.reverse();
            let rows = selected
                .iter()
                .map(|s| RankRow {
                    id: s.id.clone(),
                    total: 7,
                    ..Default::default()
                })
                .collect();
            let mut details: BTreeMap<_, _> = [("0", 240.), ("a", 220.), ("b", 90.), ("c", 120.)]
                .into_iter()
                .map(|(id, ms)| (id.to_owned(), observations(ms)))
                .collect();
            if !common_peers {
                for id in ["b", "c"] {
                    for row in details.get_mut(id).unwrap() {
                        row["remote_address"] = json!("203.0.113.2:443");
                    }
                }
            }
            let (next, skipped, result) = refine(
                &selected,
                deferred.clone(),
                Evidence {
                    rows,
                    details: &details,
                    primary: "a",
                    controls_stable: stable,
                    perfect: BTreeSet::new(),
                },
            );
            assert_eq!(result.reason, expected_reason);
            if common_peers {
                assert_eq!(result.followups, ["b1", "c1"]);
            }
            if expected_reason == "explore_all" {
                assert_eq!(next.len(), deferred.len());
                assert!(skipped.is_empty());
            } else {
                assert_eq!(next.len(), 2);
                assert_eq!(skipped, ["a1", "b2"]);
            }
        }
    }
}
