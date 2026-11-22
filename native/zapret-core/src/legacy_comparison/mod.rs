//! Exact offline replay of historical finalists-v1/v2 evidence. No process or network control.
mod canonical;
mod resources;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
type Evidence<T> = Result<T, &'static str>;

fn require(condition: bool, reason: &'static str) -> Evidence<()> {
    if condition { Ok(()) } else { Err(reason) }
}
fn metric(row: &Value, key: &str) -> Option<f64> {
    let value = match &row[key] {
        Value::Number(value) if value.is_f64() => value
            .as_f64()
            .filter(|v| v.is_finite())
            .and_then(|value| canonical::general(value, 15).parse().ok()),
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        _ => None,
    }?;
    value.is_finite().then_some(value)
}
fn number(row: &Value, key: &str) -> Evidence<f64> {
    metric(row, key).ok_or("missing-number")
}
fn string(row: &Value, key: &str) -> String {
    match &row[key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => other.to_string(),
    }
}
fn ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn slots(plan: &Value) -> Evidence<Vec<Value>> {
    let seed = number(plan, "Seed")?;
    let blocks = number(plan, "Blocks")?;
    require(
        seed >= 0.
            && seed <= i32::MAX as f64
            && seed.fract() == 0.
            && (4. ..=12.).contains(&blocks)
            && blocks % 2. == 0.,
        "invalid-comparison-size",
    )?;
    let mut random = canonical::DotNetRandom::new(seed as i32);
    let mut pattern = "ABBA";
    let mut result = Vec::new();
    for block in 1..=blocks as usize + 2 {
        let kind = if block == 1 || block == blocks as usize + 2 {
            "Calibration"
        } else {
            "Compare"
        };
        if kind == "Compare" {
            pattern = if block % 2 == 0 {
                if random.bit() { "ABBA" } else { "BAAB" }
            } else if pattern == "ABBA" {
                "BAAB"
            } else {
                "ABBA"
            };
        } else {
            pattern = "ABBA"
        }
        for (position, arm) in pattern.chars().enumerate() {
            let a = kind == "Calibration" || arm == 'A';
            result.push(json!({"Index":result.len()+1,"Block":block,"Position":position+1,"Kind":kind,"Arm":arm.to_string(),
                "StrategyId":plan[if a{"AId"}else{"BId"}],"StrategyHash":plan[if a{"AHash"}else{"BHash"}]}));
        }
    }
    Ok(result)
}

fn same_context(plan: &Value, row: &Value) -> bool {
    metric(row, "Schema") == Some(1.)
        && ["RunId", "CapturedNetworkKey", "CapturedInputsHash"]
            .iter()
            .all(|key| string(row, key) == string(plan, key))
        && metric(row, "Seed") == metric(plan, "Seed")
}
fn same_slot(row: &Value, slot: &Value) -> bool {
    [
        ("ComparisonBlock", "Block"),
        ("ComparisonKind", "Kind"),
        ("ComparisonArm", "Arm"),
        ("StrategyId", "StrategyId"),
        ("StrategyHash", "StrategyHash"),
    ]
    .iter()
    .all(|(left, right)| string(row, left) == string(slot, right))
}
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        values[mid - 1] + (values[mid] - values[mid - 1]) / 2.
    } else {
        values[mid]
    }
}

fn checked(plan: &Value, rows: &[Value]) -> Evidence<Value> {
    let protocol = string(plan, "Protocol");
    require(
        metric(plan, "Schema") == Some(1.)
            && matches!(protocol.as_str(), "finalists-v1" | "finalists-v2")
            && ascii_digits(&string(plan, "AId"))
            && ascii_digits(&string(plan, "BId"))
            && string(plan, "AId") != string(plan, "BId")
            && hex(&string(plan, "RunId"), 32),
        "invalid-plan",
    )?;
    require(
        protocol != "finalists-v2" || plan["ResourcePolicy"] == "process-v1",
        "invalid-resource-policy",
    )?;
    require(
        ["AHash", "BHash", "CapturedNetworkKey", "CapturedInputsHash"]
            .iter()
            .all(|key| hex(&string(plan, key), 64)),
        "invalid-plan",
    )?;
    let slots = slots(plan)?;
    let supplied = plan["Slots"].as_array().ok_or("invalid-plan")?;
    require(
        supplied.len() == slots.len()
            && supplied.iter().zip(&slots).all(|(a, b)| {
                [
                    "Index",
                    "Block",
                    "Position",
                    "Kind",
                    "Arm",
                    "StrategyId",
                    "StrategyHash",
                ]
                .iter()
                .all(|key| string(a, key) == string(b, key))
            }),
        "invalid-plan",
    )?;
    let targets = plan["Targets"].as_array().ok_or("invalid-target")?;
    let mut identities = BTreeMap::new();
    let mut required = BTreeSet::new();
    for target in targets {
        require(
            hex(&string(target, "Key"), 64)
                && !string(target, "Group").is_empty()
                && !string(target, "Name").is_empty(),
            "invalid-target",
        )?;
        require(
            identities
                .insert(string(target, "Key").to_ascii_lowercase(), target)
                .is_none(),
            "invalid-target",
        )?;
        required.insert(string(target, "Group"));
    }
    let declared = plan["RequiredGroups"]
        .as_array()
        .ok_or("invalid-required-groups")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_owned())
        .collect::<BTreeSet<_>>();
    require(
        !identities.is_empty() && required == declared,
        "invalid-required-groups",
    )?;
    let completions = rows
        .iter()
        .filter(|row| row["Stage"] == "comparison-complete")
        .collect::<Vec<_>>();
    require(completions.len() <= 1, "duplicate-completion")?;
    let completion = completions.first().copied();
    if let Some(completion) = completion {
        require(
            same_context(plan, completion)
                && metric(completion, "ValidatedSlots") == Some(slots.len() as f64)
                && string(completion, "EvidenceHash") == canonical::digest(rows)?,
            "invalid-completion",
        )?;
    }
    let resource_count = rows
        .iter()
        .filter(|row| row["Stage"] == "comparison-resource")
        .count();
    require(
        protocol != "finalists-v1" || resource_count == 0,
        "unexpected-resource-records",
    )?;
    let mut resources = json!({"Schema":1,"Status":"NotRequested","Scope":"CompareMeasured","A":null,"B":null,"Windows":[]});
    if protocol == "finalists-v2" {
        if let Some(completion) = completion {
            require(
                metric(completion, "ResourceSamples") == Some(resource_count as f64),
                "invalid-resource-count",
            )?;
            resources = resources::assess(plan, &slots, rows)?;
        } else {
            resources["Status"] = json!("NotFinalized")
        }
    }
    let mut index = BTreeMap::new();
    let mut first_count = 0;
    let mut retry_count = 0;
    for row in rows.iter().filter(|row| row["Stage"] == "comparison") {
        let slot = number(row, "ComparisonSlot")?;
        let attempt = number(row, "Attempt")?;
        require(
            slot >= 1.
                && slot <= slots.len() as f64
                && slot.fract() == 0.
                && matches!(attempt, 1. | 2.),
            "invalid-slot",
        )?;
        require(same_context(plan, row), "mixed-context")?;
        require(
            same_slot(row, &slots[slot as usize - 1]),
            "mixed-slot-identity",
        )?;
        let key = string(row, "TargetKey").to_ascii_lowercase();
        let target = identities.get(&key).ok_or("invalid-target-row")?;
        require(
            row["Group"] == target["Group"]
                && row["Name"] == target["Name"]
                && ["OK", "FAIL", "FREEZE", "NA"].contains(&string(row, "State").as_str()),
            "invalid-target-row",
        )?;
        require(
            index
                .insert((slot as usize, key, attempt as usize), row)
                .is_none(),
            "duplicate-attempt",
        )?;
        if attempt == 1. {
            first_count += 1
        } else {
            retry_count += 1
        }
    }
    let mut reasons = BTreeSet::new();
    if let Some(completion) = completion {
        require(
            metric(completion, "FirstAttempts") == Some(first_count as f64)
                && metric(completion, "RetryAttempts") == Some(retry_count as f64),
            "invalid-completion-counts",
        )?;
    } else {
        reasons.insert("collection-not-finalized");
    }
    if first_count != slots.len() * targets.len() {
        reasons.insert("incomplete-first-attempts");
    }
    let blocks = number(plan, "Blocks")? as usize;
    let mut details = Vec::new();
    for target in targets {
        let key = string(target, "Key").to_ascii_lowercase();
        let mut values = BTreeMap::new();
        let mut times = BTreeMap::new();
        let mut complete = true;
        let (
            mut a_count,
            mut b_count,
            mut a_ok,
            mut b_ok,
            mut a_recovered,
            mut b_recovered,
            mut calibration_count,
            mut calibration_ok,
        ) = (0, 0, 0, 0, 0, 0, 0, 0);
        let mut previous = None;
        for (i, slot) in slots.iter().enumerate() {
            let first = index.get(&(i + 1, key.clone(), 1)).copied();
            let retry = index.get(&(i + 1, key.clone(), 2)).copied();
            require(retry.is_none() || first.is_some(), "retry-without-first")?;
            let ok = first.is_some_and(|row| row["State"] == "OK");
            require(retry.is_none() || !ok, "unexpected-success-retry")?;
            let recovered = !ok && retry.is_some_and(|row| row["State"] == "OK");
            if slot["Kind"] == "Calibration" {
                calibration_count += usize::from(first.is_some());
                calibration_ok += usize::from(ok);
            } else if slot["Arm"] == "A" {
                a_count += usize::from(first.is_some());
                a_ok += usize::from(ok);
                a_recovered += usize::from(recovered);
            } else {
                b_count += usize::from(first.is_some());
                b_ok += usize::from(ok);
                b_recovered += usize::from(recovered);
            }
            for row in [first, retry].into_iter().flatten() {
                let (Some(start), Some(end)) =
                    (metric(row, "StartedMs"), metric(row, "ObservedMs"))
                else {
                    complete = false;
                    continue;
                };
                require(
                    start >= 0. && end >= start && previous.is_none_or(|p| start > p),
                    "invalid-monotonic-order",
                )?;
                previous = Some(end);
            }
            if let Some(row) = first {
                if let (true, Some(tls), Some(start), Some(end)) = (
                    ok,
                    metric(row, "TlsMs").filter(|v| *v > 0.),
                    metric(row, "StartedMs"),
                    metric(row, "ObservedMs"),
                ) {
                    values.insert(i + 1, tls);
                    times.insert(i + 1, (start + end) / 2.);
                    continue;
                }
            }
            complete = false;
        }
        let mut deltas = Vec::new();
        let mut noise = None;
        let mut threshold = None;
        let mut conclusion = "Insufficient";
        if complete {
            let mut max_noise: f64 = 0.;
            for (block, members) in slots.chunks_exact(4).enumerate() {
                let at = block * 4 + 1;
                let start = times[&at];
                let end = times[&(at + 3)];
                require(end > start, "invalid-block")?;
                let pattern = members
                    .iter()
                    .map(|row| string(row, "Arm"))
                    .collect::<String>();
                require(matches!(pattern.as_str(), "ABBA" | "BAAB"), "invalid-block")?;
                let residuals = [1, 2].map(|i| {
                    let estimate = values[&at]
                        + (values[&(at + 3)] - values[&at]) * (times[&(at + i)] - start)
                            / (end - start);
                    if pattern == "ABBA" {
                        values[&(at + i)] - estimate
                    } else {
                        estimate - values[&(at + i)]
                    }
                });
                require(residuals.iter().all(|v| v.is_finite()), "invalid-block")?;
                if members[0]["Kind"] == "Calibration" {
                    max_noise = max_noise.max(residuals[0].abs().max(residuals[1].abs()));
                } else {
                    deltas.push((residuals[0] + residuals[1]) / 2.);
                }
            }
            let a = slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| slot["Kind"] == "Compare" && slot["Arm"] == "A")
                .map(|(i, _)| values[&(i + 1)])
                .collect();
            let raw = (0.05 * median(a)).max(max_noise);
            // The historical outer Math.Max starts with integer literal 10.
            // PowerShell selects the Int32 overload and rounds ties to even.
            require(
                raw.is_finite() && raw.round_ties_even() <= i32::MAX as f64,
                "invalid-threshold",
            )?;
            let limit = 10f64.max(raw.round_ties_even());
            noise = Some(max_noise);
            threshold = Some(limit);
            conclusion = if deltas.iter().any(|delta| *delta > limit) {
                "Regressed"
            } else if deltas.iter().all(|delta| *delta < -limit) {
                "Improved"
            } else {
                "Uncertain"
            };
        }
        let preserved = a_ok != 2 * blocks || b_ok == 2 * blocks;
        if !preserved {
            reasons.insert("reference-endpoint-not-preserved");
        }
        if b_ok < a_ok {
            reasons.insert("first-attempt-availability-decreased");
        }
        if a_ok == 2 * blocks && !complete {
            reasons.insert("incomplete-reference-evidence");
        }
        if conclusion == "Regressed" {
            reasons.insert("observed-latency-regression");
        }
        details.push(json!({"Key":target["Key"],"Group":target["Group"],"Name":target["Name"],"Conclusion":conclusion,"Comparable":complete,"ReferencePreserved":preserved,
            "AFirstCount":a_count,"BFirstCount":b_count,"AFirstSuccess":a_ok,"BFirstSuccess":b_ok,"ARecovered":a_recovered,"BRecovered":b_recovered,
            "CalibrationCount":calibration_count,"CalibrationSuccess":calibration_ok,"NoiseMs":noise,"ThresholdMs":threshold,"BlockDeltas":deltas}));
    }
    let groups=required.iter().map(|group|json!({"Group":group,"Comparable":details.iter().any(|row|row["Group"]==*group && row["Comparable"]==true)})).collect::<Vec<_>>();
    if groups.iter().any(|row| row["Comparable"] != true) {
        reasons.insert("required-group-not-comparable");
    }
    let status = if !reasons.is_empty() {
        "Inconclusive"
    } else if details.iter().any(|row| row["Conclusion"] == "Improved") {
        "ConsistentImprovement"
    } else {
        "NoClearDifference"
    };
    Ok(
        json!({"Schema":1,"RunId":plan["RunId"],"Status":status,"CanRecommend":status=="ConsistentImprovement","ShadowOnly":true,"Reasons":reasons,
        "FirstAttempts":first_count,"RetryAttempts":retry_count,"Groups":groups,"Targets":details,"Resources":resources}),
    )
}

pub fn assess(plan: &Value, rows: &[Value]) -> Value {
    checked(plan,rows).unwrap_or_else(|_|json!({"Schema":1,"Status":"Invalid","CanRecommend":false,"ShadowOnly":true,"Reasons":["invalid-plan-or-evidence"],"FirstAttempts":null,"RetryAttempts":null,"Groups":[],"Targets":[],"Resources":{"Schema":1,"Status":"Invalid","Scope":"CompareMeasured","A":null,"B":null,"Windows":[]}}))
}

pub fn replay(
    plan_file: &Path,
    journal_file: &Path,
    output: Option<&Path>,
) -> anyhow::Result<Value> {
    let plan_file = std::path::absolute(plan_file)?;
    let journal_file = std::path::absolute(journal_file)?;
    if let Some(output) = output {
        let output = std::path::absolute(output)?;
        anyhow::ensure!(
            output != plan_file && output != journal_file,
            "Output must not overwrite evidence"
        );
        // Resolved path aliases are also refused when the destination exists.
        if output.exists() {
            anyhow::ensure!(
                std::fs::canonicalize(&output)? != std::fs::canonicalize(&plan_file)?
                    && std::fs::canonicalize(&output)? != std::fs::canonicalize(&journal_file)?,
                "Output must not overwrite evidence"
            );
        }
    }
    let plan: Value = serde_json::from_str(&crate::read_text(&plan_file, 64 * 1024 * 1024)?)?;
    let rows = crate::read_text(&journal_file, 64 * 1024 * 1024)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    anyhow::ensure!(rows.len() <= 250000, "Too many journal rows");
    let result = assess(&plan, &rows);
    if let Some(output) = output {
        crate::atomic_write(
            &std::path::absolute(output)?,
            &serde_json::to_vec_pretty(&result)?,
        )?;
    }
    Ok(result)
}
