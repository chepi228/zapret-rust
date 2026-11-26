use crate::{
    selection_decision::Check,
    selection_latency::{self, Panel},
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, time::Duration};
use zapret_core::{RankRow, TestResultContext};

pub(super) const SLOTS: usize = 2;

pub(crate) fn next_candidates(
    rows: &[RankRow],
    details: &BTreeMap<String, Vec<Value>>,
    checks: &BTreeMap<String, Check>,
    primary: &str,
) -> Vec<String> {
    let Some(reference) = rows.iter().find(|row| row.id == primary) else {
        return Vec::new();
    };
    let Some(anchor) = checks.get(primary).filter(|check| check.confirmed) else {
        return Vec::new();
    };
    if Panel::for_trials(rows, details) != Panel::Services
        || !selection_latency::service_ready(reference, details)
    {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    for row in rows.iter().filter(|row| row.id != primary) {
        let checked = checks.get(&row.id);
        if checked.is_some_and(|check| !check.confirmed) {
            continue;
        }
        let Some(speed) = selection_latency::preference(reference, row, details, Panel::Services)
        else {
            continue;
        };
        if !speed.trial.promising() {
            continue;
        }
        let measured = if let Some(check) = checked {
            if !selection_latency::preserves_services(
                &anchor.details,
                &check.details,
                Panel::Services,
            ) {
                continue;
            }
            let Some(pair) = selection_latency::confirm(
                &speed,
                &anchor.details,
                &check.details,
                Panel::Services,
                None,
            )
            .filter(|pair| pair.faster()) else {
                continue;
            };
            pair
        } else {
            speed.trial
        };
        candidates.push((checked.is_some(), measured, row.id.clone()));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.screening_order(&b.1)));
    candidates
        .into_iter()
        .take(SLOTS)
        .map(|(_, _, id)| id)
        .collect()
}

#[derive(Deserialize)]
struct SavedRun {
    schema: u32,
    context: TestResultContext,
    primary: String,
    timeout_ms: u64,
    accepted: bool,
    quality_eligible: bool,
    primary_requested: Option<String>,
    startup: Option<Startup>,
    startup_error: Option<String>,
    next_quick_latency: Option<Vec<String>>,
    selection_policy: Option<String>,
}

#[derive(Deserialize)]
struct Startup {
    #[serde(default)]
    restored: bool,
}

// Older reports contain all observations but no compact shortlist.
#[derive(Deserialize)]
struct SavedTrials {
    rows: Vec<RankRow>,
    details: BTreeMap<String, Vec<Value>>,
    strategy_quality: BTreeMap<String, bool>,
    final_checks: BTreeMap<String, Check>,
}

fn from_report(
    bytes: &[u8],
    current: &TestResultContext,
    primary: &str,
    timeout_ms: u64,
) -> Option<Vec<String>> {
    let run: SavedRun = serde_json::from_slice(bytes).ok()?;
    if run.schema != 1
        || !run.accepted
        || !run.quality_eligible
        || run.primary != primary
        || run
            .primary_requested
            .as_deref()
            .is_some_and(|id| id != primary)
        || run.startup.is_some_and(|state| state.restored)
        || run.startup_error.is_some()
        || run.timeout_ms != timeout_ms
        || !current.compatible(&run.context)
    {
        return None;
    }
    if run.selection_policy.as_deref() == Some(selection_latency::POLICY)
        && let Some(ids) = run.next_quick_latency
    {
        return (ids.len() <= SLOTS).then_some(ids);
    }
    let mut trials: SavedTrials = serde_json::from_slice(bytes).ok()?;
    trials
        .rows
        .retain(|row| trials.strategy_quality.get(&row.id) == Some(&true));
    Some(next_candidates(
        &trials.rows,
        &trials.details,
        &trials.final_checks,
        primary,
    ))
}

pub(crate) fn recent_candidates(
    root: &Path,
    current: &TestResultContext,
    primary: &str,
    timeout_ms: u64,
) -> Vec<String> {
    let read = || {
        let path = crate::runtime_file(root, "test-native-last.json").ok()?;
        let age = path.metadata().ok()?.modified().ok()?.elapsed().ok()?;
        if age > Duration::from_secs(super::MAX_AGE as u64) {
            return None;
        }
        let bytes = zapret_core::read_bounded(&path, 16 * 1024 * 1024).ok()?;
        from_report(&bytes, current, primary, timeout_ms)
    };
    read().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, time::SystemTime};

    #[test]
    fn only_a_recent_accepted_run_on_the_same_network_inputs_primary_and_timeout_nominates_peers() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("runtime")).unwrap();
        let path = root.path().join("runtime/test-native-last.json");
        let context = TestResultContext {
            schema: 2,
            network_key: "A".repeat(64),
            inputs_hash: "B".repeat(64),
            run_id: "c".repeat(32),
        };
        let source = json!({"schema":1,"context":context,"primary":"50","timeout_ms":5000,"accepted":true,"quality_eligible":true,
            "selection_policy":selection_latency::POLICY,
            "parallel":8,"next_quick_latency":["70","71"]});
        let mut current = context.clone();
        current.run_id = "d".repeat(32);
        let load = |context, primary: &str, timeout| {
            recent_candidates(root.path(), context, primary, timeout)
        };
        fs::write(&path, serde_json::to_vec(&source).unwrap()).unwrap();
        assert_eq!(load(&current, "50", 5000), ["70", "71"]);
        assert!(load(&current, "31", 5000).is_empty());
        assert!(load(&current, "50", 2500).is_empty());
        for field in ["NetworkKey", "InputsHash"] {
            let mut other = source.clone();
            other["context"][field] = json!("E".repeat(64));
            fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
            assert!(load(&current, "50", 5000).is_empty());
        }
        for field in ["accepted", "quality_eligible"] {
            let mut other = source.clone();
            other[field] = json!(false);
            fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
            assert!(load(&current, "50", 5000).is_empty());
        }
        for (field, value) in [
            ("primary_requested", json!("31")),
            ("startup", json!({"restored":true})),
            ("startup_error", json!("failed")),
        ] {
            let mut other = source.clone();
            other[field] = value;
            fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
            assert!(load(&current, "50", 5000).is_empty());
        }
        fs::write(&path, serde_json::to_vec(&source).unwrap()).unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(
                SystemTime::now() - Duration::from_secs((super::super::MAX_AGE + 60) as u64),
            )
            .unwrap();
        assert!(load(&current, "50", 5000).is_empty());
    }
}
