//! Local quick-test learning. Complete/manual pools never lose a strategy.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use zapret_core::{RankRow, Strategy};

pub const FILE: &str = "runtime/test-selection-cache.json";
pub(crate) const QUICK_STRATEGY_LIMIT: usize = 18;
const PRIORITY_SLOTS: usize = 6;
const MAX_AGE: i64 = 7 * 24 * 60 * 60;
const CACHE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONTEXTS: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    fingerprint: String,
    observed_at: i64,
    generation: u64,
    samples: Vec<RankRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cache {
    schema: u32,
    context: String,
    generation: u64,
    entries: BTreeMap<String, Entry>,
}

pub struct Plan {
    pub strategies: Vec<Strategy>,
    pub deferred: Vec<String>,
    pub queued: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct ContextHistory {
    contexts: Vec<Cache>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum SavedHistory {
    Contexts(ContextHistory),
    Legacy(Cache),
}

fn read_history(root: &Path) -> Vec<Cache> {
    let history = zapret_core::read_bounded(&root.join(FILE), CACHE_BYTES as u64)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let mut contexts = match history {
        Some(SavedHistory::Contexts(history)) if history.contexts.len() <= MAX_CONTEXTS => {
            history.contexts
        }
        Some(SavedHistory::Legacy(cache)) => vec![cache],
        _ => Vec::new(),
    };
    contexts.retain(|cache| {
        cache.schema == 1
            && cache.entries.len() <= 512
            && cache.entries.values().all(|entry| entry.samples.len() <= 3)
    });
    contexts
}

impl Cache {
    pub fn new(context: &str) -> Self {
        Self {
            schema: 1,
            context: context.into(),
            generation: 0,
            entries: BTreeMap::new(),
        }
    }
    pub fn load(root: &Path, context: &str) -> Self {
        read_history(root)
            .into_iter()
            .find(|cache| cache.context == context)
            .unwrap_or_else(|| Self::new(context))
    }
    pub fn save(&self, root: &Path) -> Result<()> {
        let mut contexts = read_history(root);
        contexts.retain(|cache| cache.context != self.context);
        contexts.insert(0, self.clone());
        contexts.truncate(MAX_CONTEXTS);
        let mut history = ContextHistory { contexts };
        loop {
            let bytes = serde_json::to_vec(&history)?;
            if bytes.len() <= CACHE_BYTES {
                return zapret_core::atomic_write(&root.join(FILE), &bytes);
            }
            ensure!(
                history.contexts.len() > 1,
                "История подключения превышает лимит файла"
            );
            history.contexts.pop();
        }
    }
    pub fn observe(
        &mut self,
        rows: &[RankRow],
        quality: &BTreeMap<String, bool>,
        hashes: &BTreeMap<String, String>,
        now: i64,
    ) {
        self.generation = self.generation.saturating_add(1);
        for row in rows {
            if quality.get(&row.id) != Some(&true)
                || !row.score.is_finite()
                || !row.ok.is_finite()
                || row.total == 0
            {
                self.entries.remove(&row.id);
                continue;
            }
            let Some(hash) = hashes.get(&row.id) else {
                continue;
            };
            let entry = self.entries.entry(row.id.clone()).or_insert_with(|| Entry {
                fingerprint: hash.clone(),
                observed_at: now,
                generation: self.generation,
                samples: Vec::new(),
            });
            if entry.fingerprint != *hash {
                entry.samples.clear();
                entry.fingerprint = hash.clone();
            }
            entry.observed_at = now;
            entry.generation = self.generation;
            entry.samples.push(row.clone());
            if entry.samples.len() > 3 {
                entry.samples.remove(0);
            }
        }
    }
    pub fn plan(
        &self,
        pool: &[Strategy],
        all: &[Strategy],
        primary: &str,
        full: bool,
        hashes: &BTreeMap<String, String>,
        now: i64,
    ) -> Plan {
        if full {
            return Plan {
                strategies: pool.to_vec(),
                deferred: Vec::new(),
                queued: Vec::new(),
            };
        }
        let valid = |id: &str, entry: &Entry| {
            hashes.get(id) == Some(&entry.fingerprint)
                && now >= entry.observed_at - 60
                && now.saturating_sub(entry.observed_at) <= MAX_AGE
                && !entry.samples.is_empty()
                && entry.samples.iter().all(|row| {
                    row.total > 0
                        && row.total <= 256
                        && row.score.is_finite()
                        && row.ok.is_finite()
                        && row.ok >= 0.
                        && row.ok <= row.total as f64
                        && row.harm <= 256
                        && row.groups.values().all(|v| v.is_finite() && *v >= 0.)
                })
        };
        let mut known: Vec<_> = self
            .entries
            .iter()
            .filter(|(id, entry)| valid(id, entry))
            .collect();
        known.sort_by(|(_, a), (_, b)| {
            b.samples
                .last()
                .unwrap()
                .score
                .total_cmp(&a.samples.last().unwrap().score)
        });
        let mut pool = pool.to_vec();
        for (id, _) in known.iter().take(2) {
            if !pool.iter().any(|strategy| strategy.id == **id) {
                if let Some(strategy) = all.iter().find(|strategy| strategy.id == **id) {
                    pool.push(strategy.clone());
                }
            }
        }
        let Some((_, leader)) = known.first() else {
            return self.bounded(pool, Vec::new(), primary, &known);
        };
        let best = leader.samples.last().unwrap();
        if best.ok / (best.total as f64) < 0.65 {
            return self.bounded(pool, Vec::new(), primary, &known);
        }
        let mut deferred = Vec::new();
        pool.retain(|strategy| {
            let Some(entry) = self
                .entries
                .get(&strategy.id)
                .filter(|entry| valid(&strategy.id, entry))
            else {
                return true;
            };
            let row = entry.samples.last().unwrap();
            if strategy.id == primary
                || self.generation.saturating_sub(entry.generation) >= 5
                || row.total != best.total
            {
                return true;
            }
            let specialist = row
                .groups
                .iter()
                .filter(|(group, _)| group.as_str() != "Clean")
                .any(|(group, points)| {
                    let total = row.group_totals.get(group).copied().unwrap_or(0);
                    let other = best.group_totals.get(group).copied().unwrap_or(0);
                    total > 0
                        && other > 0
                        && *points / (total as f64)
                            > best.groups.get(group).copied().unwrap_or(0.) / (other as f64) + 0.05
                });
            if specialist {
                return true;
            }
            let gap = best.score - row.score;
            let severe = gap >= 10f64.max(row.total as f64 * 0.20)
                && (best.ok - row.ok >= row.total as f64 * 0.15 || row.harm >= best.harm + 4);
            let repeated = entry.samples.len() >= 2
                && entry.samples.iter().rev().take(2).all(|sample| {
                    sample.total == best.total
                        && best.score - sample.score >= 5.
                        && (best.ok - sample.ok >= 5. || sample.harm >= best.harm + 3)
                });
            if severe || repeated {
                deferred.push(strategy.id.clone());
                false
            } else {
                true
            }
        });
        self.bounded(pool, deferred, primary, &known)
    }

    fn bounded(
        &self,
        pool: Vec<Strategy>,
        deferred: Vec<String>,
        primary: &str,
        known: &[(&String, &Entry)],
    ) -> Plan {
        if pool.len() <= QUICK_STRATEGY_LIMIT {
            return Plan {
                strategies: pool,
                deferred,
                queued: Vec::new(),
            };
        }
        let mut ids = Vec::<String>::new();
        let add = |ids: &mut Vec<String>, id: &str| {
            if pool.iter().any(|s| s.id == id) && !ids.iter().any(|saved| saved == id) {
                ids.push(id.into());
            }
        };
        add(&mut ids, primary);
        for (id, _) in known.iter().take(3) {
            add(&mut ids, id);
        }
        if let Some((_, best)) = known.first() {
            let best = best.samples.last().unwrap();
            for group in [
                "YouTube",
                "Discord",
                "NBA2K",
                "QUIC",
                "CDN",
                "EAC",
                "SoundCloud",
            ] {
                if ids.len() >= PRIORITY_SLOTS {
                    break;
                }
                let fraction = |row: &RankRow| {
                    row.groups.get(group).copied().unwrap_or(0.)
                        / row.group_totals.get(group).copied().unwrap_or(1).max(1) as f64
                };
                if let Some((id, _)) = known
                    .iter()
                    .filter(|(_, entry)| {
                        fraction(entry.samples.last().unwrap()) > fraction(best) + 0.05
                    })
                    .max_by(|(_, a), (_, b)| {
                        fraction(a.samples.last().unwrap())
                            .total_cmp(&fraction(b.samples.last().unwrap()))
                    })
                {
                    add(&mut ids, id);
                }
            }
        }
        for (id, _) in known {
            if ids.len() >= PRIORITY_SLOTS {
                break;
            }
            add(&mut ids, id);
        }
        let families: BTreeMap<_, _> = pool
            .iter()
            .map(|s| (&s.id, crate::selection::family(s)))
            .collect();
        let generations: BTreeMap<_, _> = known
            .iter()
            .map(|(id, entry)| (id.as_str(), entry.generation.saturating_add(1)))
            .collect();
        let mut represented = BTreeMap::<&str, usize>::new();
        for id in &ids {
            *represented.entry(&families[id]).or_default() += 1;
        }
        // Visit unmeasured and older profiles first. Within that cohort spread the slots across
        // families, then prefer the profile differing in the most sections from its closest peer.
        let mut exploration: Vec<_> = pool.iter().filter(|s| !ids.contains(&s.id)).collect();
        let mut selected: Vec<_> = pool.iter().filter(|s| ids.contains(&s.id)).collect();
        while ids.len() < QUICK_STRATEGY_LIMIT {
            let Some((index, _)) = exploration.iter().enumerate().min_by_key(|(_, strategy)| {
                let distance = selected
                    .iter()
                    .map(|other| section_distance(strategy, other))
                    .min()
                    .unwrap_or(0);
                (
                    generations.get(strategy.id.as_str()).copied().unwrap_or(0),
                    represented
                        .get(families[&strategy.id].as_str())
                        .copied()
                        .unwrap_or(0),
                    std::cmp::Reverse(distance),
                )
            }) else {
                break;
            };
            let next = exploration.remove(index);
            *represented.entry(&families[&next.id]).or_default() += 1;
            ids.push(next.id.clone());
            selected.push(next);
        }
        let queued = pool
            .iter()
            .filter(|s| !ids.contains(&s.id))
            .map(|s| s.id.clone())
            .collect();
        let strategies = ids
            .iter()
            .filter_map(|id| pool.iter().find(|s| s.id == *id).cloned())
            .collect();
        Plan {
            strategies,
            deferred,
            queued,
        }
    }
}

fn section_distance(a: &Strategy, b: &Strategy) -> usize {
    zapret_core::SECTIONS
        .iter()
        .copied()
        .chain(["ipset_tcp", "ipset_udp"])
        .filter(|section| {
            a.sections.get(*section) != b.sections.get(*section)
                || a.match_l3.get(*section) != b.match_l3.get(*section)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 2_000_000_000;
    #[test]
    fn late_distinct_families_and_udp_variants_enter_a_cold_pick_before_duplicates() {
        let mut all: Vec<_> = (1..=30)
            .map(|id| Strategy {
                id: id.to_string(),
                ..Default::default()
            })
            .collect();
        all[28]
            .sections
            .insert("general".into(), vec!["distinct TCP section".into()]);
        all[29]
            .sections
            .insert("quic".into(), vec!["distinct UDP section".into()]);
        let plan = Cache::new("new").plan(&all, &all, "1", false, &BTreeMap::new(), NOW);
        assert_eq!(plan.strategies[0].id, "1");
        let first: Vec<_> = plan.strategies[..3].iter().map(|s| s.id.as_str()).collect();
        assert!(first.contains(&"29") && first.contains(&"30"));
    }

    #[test]
    fn returning_to_a_network_restores_its_own_history_including_legacy_data() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime")).unwrap();
        let a = learned();
        std::fs::write(root.path().join(FILE), serde_json::to_vec(&a).unwrap()).unwrap();
        let mut b = Cache::new("mobile");
        b.generation = 2;
        b.save(root.path()).unwrap();
        assert_eq!(Cache::load(root.path(), "mobile").generation, 2);
        assert_eq!(
            Cache::load(root.path(), &a.context).entries.len(),
            a.entries.len()
        );
        assert!(Cache::load(root.path(), "new").entries.is_empty());
    }
    #[test]
    fn ordinary_pick_is_bounded_even_without_history_while_full_keeps_all_41() {
        let all: Vec<_> = (1..=41)
            .map(|id| Strategy {
                id: id.to_string(),
                ..Default::default()
            })
            .collect();
        let hashes = all.iter().map(|s| (s.id.clone(), s.id.clone())).collect();
        let cache = Cache::new("cold-network");
        let quick = cache.plan(&all, &all, "40", false, &hashes, NOW);
        assert_eq!(quick.strategies.len(), QUICK_STRATEGY_LIMIT);
        assert_eq!(quick.queued.len(), all.len() - quick.strategies.len());
        assert!(quick.strategies.iter().any(|s| s.id == "40"));
        let full = cache.plan(&all, &all, "40", true, &hashes, NOW);
        assert_eq!(full.strategies.len(), 41);
        assert!(full.queued.is_empty());
    }

    #[test]
    fn next_quick_pick_keeps_the_winner_and_explores_other_candidates() {
        let all: Vec<_> = (1..=41)
            .map(|id| Strategy {
                id: id.to_string(),
                ..Default::default()
            })
            .collect();
        let hashes = all.iter().map(|s| (s.id.clone(), s.id.clone())).collect();
        let mut cache = Cache::new("cold-network");
        let first = cache.plan(&all, &all, "40", false, &hashes, NOW);
        let scores: Vec<_> = first
            .strategies
            .iter()
            .map(|s| RankRow {
                id: s.id.clone(),
                score: 48.,
                ok: 48.,
                total: 54,
                ..Default::default()
            })
            .collect();
        cache.observe(
            &scores,
            &first
                .strategies
                .iter()
                .map(|s| (s.id.clone(), true))
                .collect(),
            &hashes,
            NOW,
        );
        let next = cache.plan(&all, &all, "40", false, &hashes, NOW + 1);
        assert!(next.strategies.iter().any(|s| s.id == "40"));
        assert!(
            next.strategies
                .iter()
                .filter(|s| first.queued.contains(&s.id))
                .count()
                >= QUICK_STRATEGY_LIMIT - PRIORITY_SLOTS
        );
    }
    fn strategies() -> Vec<Strategy> {
        ["50", "53", "58", "61"]
            .iter()
            .map(|id| Strategy {
                id: (*id).into(),
                name: format!("strategy {id}"),
                ..Default::default()
            })
            .collect()
    }
    fn hashes() -> BTreeMap<String, String> {
        strategies()
            .iter()
            .map(|s| (s.id.clone(), format!("hash-{}", s.id)))
            .collect()
    }
    fn rows() -> Vec<RankRow> {
        [
            ("50", 48., 49., 0),
            ("53", 4., 6., 8),
            ("58", 49., 50., 0),
            ("61", 46., 48., 0),
        ]
        .iter()
        .map(|(id, score, ok, harm)| RankRow {
            id: (*id).into(),
            score: *score,
            ok: *ok,
            total: 54,
            harm: *harm,
            groups: BTreeMap::from([("YouTube".into(), 3.), ("DPI".into(), *ok - 3.)]),
            group_totals: BTreeMap::from([("YouTube".into(), 3), ("DPI".into(), 51)]),
            ..Default::default()
        })
        .collect()
    }
    fn learned() -> Cache {
        let mut cache = Cache::new("network-and-inputs");
        cache.observe(
            &rows(),
            &strategies().iter().map(|s| (s.id.clone(), true)).collect(),
            &hashes(),
            NOW,
        );
        cache
    }
    #[test]
    fn second_quick_test_defers_a_clear_loser_but_retains_near_winners_and_primary() {
        let cache = learned();
        let all = strategies();
        let plan = cache.plan(&all, &all, "50", false, &hashes(), NOW + 1);
        assert_eq!(plan.deferred, ["53"]);
        assert_eq!(
            plan.strategies
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            ["50", "58", "61"]
        );
        let plan = cache.plan(&all, &all, "53", false, &hashes(), NOW + 1);
        assert!(plan.strategies.iter().any(|s| s.id == "53"));
    }
    #[test]
    fn full_test_expiry_changed_file_and_changed_network_restore_exploration() {
        let cache = learned();
        let all = strategies();
        for (full, time, hashes) in [
            (true, NOW + 1, hashes()),
            (false, NOW + MAX_AGE + 1, hashes()),
            (false, NOW + 1, {
                let mut h = hashes();
                h.insert("53".into(), "changed".into());
                h
            }),
        ] {
            assert!(
                cache
                    .plan(&all, &all, "50", full, &hashes, time)
                    .deferred
                    .is_empty()
            );
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime")).unwrap();
        cache.save(root.path()).unwrap();
        assert!(
            Cache::load(root.path(), "another-network")
                .plan(&all, &all, "50", false, &hashes(), NOW)
                .deferred
                .is_empty()
        );
    }
    #[test]
    fn a_service_specialist_is_kept_even_with_a_low_total_score() {
        let mut cache = learned();
        for id in ["50", "58", "61"] {
            cache
                .entries
                .get_mut(id)
                .unwrap()
                .samples
                .last_mut()
                .unwrap()
                .groups
                .insert("YouTube".into(), 1.);
        }
        assert!(
            cache
                .plan(&strategies(), &strategies(), "50", false, &hashes(), NOW)
                .deferred
                .is_empty()
        );
    }
    #[test]
    fn an_uncertain_retest_cannot_leave_a_previous_bad_verdict_in_force() {
        let mut cache = learned();
        cache.observe(
            &[rows()[1].clone()],
            &BTreeMap::from([("53".into(), false)]),
            &hashes(),
            NOW + 1,
        );
        assert!(
            cache
                .plan(
                    &strategies(),
                    &strategies(),
                    "50",
                    false,
                    &hashes(),
                    NOW + 1
                )
                .deferred
                .is_empty()
        );
    }
    #[test]
    fn old_poor_strategies_return_for_a_periodic_check() {
        let mut cache = learned();
        cache.generation += 5;
        assert!(
            cache
                .plan(
                    &strategies(),
                    &strategies(),
                    "50",
                    false,
                    &hashes(),
                    NOW + 1
                )
                .deferred
                .is_empty()
        );
    }
}
