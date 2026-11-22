//! Pure assessment of complete ABBA/BAAB observations. It never chooses or starts a strategy.
//!
//! The thresholds below are conservative decision rules, not confidence intervals or
//! evidence of causal attribution. HTTPS observations do not measure game latency.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde_json::{Value, json};

const ABSOLUTE_FLOOR_MS: f64 = 10.0;
const RELATIVE_FLOOR: f64 = 0.05;
const NOISE_MULTIPLIER: f64 = 2.0;

pub fn seal_record(record: &mut Value) -> Result<()> {
    record
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Comparison record must be an object"))?
        .remove("completion_hash");
    record["completion_hash"] = json!(zapret_core::sha256(&serde_json::to_vec(record)?));
    Ok(())
}

pub fn assess_saved(record: &Value) -> Result<Value> {
    ensure!(
        record["protocol"] == "finalists-native-v1" && record["complete"] == true,
        "Нет завершённого нативного сравнения"
    );
    let expected = record["completion_hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Нет подтверждения завершения сравнения"))?;
    let mut checked = record.clone();
    checked
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Comparison record must be an object"))?
        .remove("completion_hash");
    ensure!(
        expected == zapret_core::sha256(&serde_json::to_vec(&checked)?),
        "Состав завершённого сравнения изменён"
    );
    let rows = record["rows"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Нет строк сравнения"))?;
    let blocks = record["blocks"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| anyhow::anyhow!("Нет числа блоков сравнения"))?;
    assess(rows, blocks)
}

type Evidence<T> = std::result::Result<T, &'static str>;
type Target = (String, String, String);

#[derive(Clone, Copy)]
struct Probe {
    tls: Option<f64>,
    midpoint: f64,
    first_ok: bool,
    tries: Option<u64>,
    flaky: bool,
    clean: bool,
}

struct Observation {
    block: usize,
    arm: char,
    calibration: bool,
    probes: BTreeMap<Target, Probe>,
}

#[derive(Clone, Copy)]
struct Fit {
    delta: f64,
    slope: f64,
    residual: f64,
    delta_noise: f64,
}

fn metric(value: &Value, field: &str) -> Evidence<f64> {
    value[field]
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0)
        .ok_or("invalid-numeric-measurement")
}

fn text_field<'a>(value: &'a Value, field: &str) -> Evidence<&'a str> {
    value[field]
        .as_str()
        .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
        .ok_or("missing-evidence-identity")
}

fn require(condition: bool, reason: &'static str) -> Evidence<()> {
    if condition { Ok(()) } else { Err(reason) }
}

fn median(values: &[f64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        values[middle]
    } else {
        values[middle - 1] + (values[middle] - values[middle - 1]) / 2.0
    }
}

/// OLS: TLS = intercept + elapsed time + B indicator. Centering and scaling
/// time prevents cancellation when the monotonic clock has a large origin.
fn fit_block(times: [f64; 4], values: [f64; 4], arms: [char; 4]) -> Evidence<Fit> {
    require(
        times.iter().chain(&values).all(|value| value.is_finite())
            && times.windows(2).all(|pair| pair[0] < pair[1]),
        "invalid-block-clock",
    )?;
    require(
        arms == ['A', 'B', 'B', 'A'] || arms == ['B', 'A', 'A', 'B'],
        "invalid-block-pattern",
    )?;
    let span = times[3] - times[0];
    require(span.is_finite() && span > 0.0, "invalid-block-clock")?;
    let time = times.map(|time| (time - times[0]) / span);
    let mean_time = time.iter().sum::<f64>() / 4.0;
    // Scale the response too: malformed, huge finite values must not overflow
    // into JSON nulls that could look like a valid zero-noise comparison.
    let scale = values.iter().copied().map(f64::abs).fold(1.0, f64::max);
    let response = values.map(|value| value / scale);
    let mean_value = response.iter().sum::<f64>() / 4.0;
    let mut tt = 0.0;
    let mut ta = 0.0;
    let mut ty = 0.0;
    let mut ay = 0.0;
    for i in 0..4 {
        let t = time[i] - mean_time;
        let arm = if arms[i] == 'B' { 0.5 } else { -0.5 };
        tt += t * t;
        ta += t * arm;
        ty += t * (response[i] - mean_value);
        ay += arm * (response[i] - mean_value);
    }
    // The centered indicator has sum of squares 1 (two A and two B).
    let determinant = tt - ta * ta;
    require(
        determinant.is_finite() && determinant > f64::EPSILON * tt * 32.0,
        "singular-block-design",
    )?;
    let delta = (tt * ay - ta * ty) / determinant;
    let slope = (ty - ta * ay) / determinant;
    let mut squared = 0.0;
    let mut residual: f64 = 0.0;
    for i in 0..4 {
        let arm = if arms[i] == 'B' { 0.5 } else { -0.5 };
        let error = response[i] - mean_value - slope * (time[i] - mean_time) - delta * arm;
        squared += error * error;
        residual = residual.max(error.abs());
    }
    // Four observations and three fitted parameters leave one residual degree
    // of freedom. This noise scale is descriptive, not a significance test.
    let fit = Fit {
        delta: delta * scale,
        slope: slope * scale / span,
        residual: residual * scale,
        delta_noise: (squared * tt / determinant).sqrt() * scale,
    };
    require(
        [fit.delta, fit.slope, fit.residual, fit.delta_noise]
            .iter()
            .all(|value| value.is_finite()),
        "block-fit-overflow",
    )?;
    Ok(fit)
}

fn validate_rows(rows: &[Value], blocks: usize) -> Evidence<Vec<Observation>> {
    require(
        (4..=12).contains(&blocks) && blocks % 2 == 0,
        "invalid-comparison-size",
    )?;
    require(rows.len() == (blocks + 2) * 4, "incomplete-slot-matrix")?;
    let mut observations = Vec::with_capacity(rows.len());
    let mut context: Option<(&str, &str, &str)> = None;
    let mut candidates: [Option<(&str, &str)>; 2] = [None, None];
    let mut previous_end: Option<f64> = None;
    let mut expected_targets = None;
    for (slot, row) in rows.iter().enumerate() {
        let block = slot / 4;
        let position = slot % 4;
        require(
            row["block"].as_u64() == Some(block as u64)
                && row["position"].as_u64() == Some(position as u64),
            "invalid-slot-order",
        )?;
        let calibration = block == 0 || block == blocks + 1;
        require(
            row["calibration"].as_bool() == Some(calibration),
            "invalid-calibration-slot",
        )?;
        let arm = match row["arm"].as_str() {
            Some("A") => 'A',
            Some("B") => 'B',
            _ => return Err("invalid-block-pattern"),
        };
        require(
            row["context_validated"].as_bool() == Some(true),
            "unvalidated-context",
        )?;
        let row_context = (
            text_field(row, "network_key")?,
            text_field(row, "inputs_hash")?,
            text_field(row, "native_hash")?,
        );
        if let Some(expected) = context {
            require(expected == row_context, "mixed-comparison-context")?;
        } else {
            context = Some(row_context);
        }
        let strategy = (
            text_field(row, "strategy_id")?,
            text_field(row, "strategy_hash")?,
        );
        let candidate = usize::from(!calibration && arm == 'B');
        if let Some(expected) = candidates[candidate] {
            require(expected == strategy, "mixed-strategy-identity")?;
        } else {
            candidates[candidate] = Some(strategy);
        }
        let start = metric(row, "started_ms").map_err(|_| "invalid-monotonic-clock")?;
        let end = metric(row, "finished_ms").map_err(|_| "invalid-monotonic-clock")?;
        require(
            end > start
                && (end - start).is_finite()
                && previous_end.is_none_or(|previous| start >= previous),
            "invalid-monotonic-order",
        )?;
        previous_end = Some(end);
        let probes = row["probes"].as_array().ok_or("missing-targets")?;
        require(
            !probes.is_empty() && probes.len() <= 256,
            "invalid-target-count",
        )?;
        let mut targets = BTreeMap::new();
        for probe in probes {
            let group = text_field(probe, "Group").map_err(|_| "invalid-target-identity")?;
            let name = text_field(probe, "Name").map_err(|_| "invalid-target-identity")?;
            let url = text_field(probe, "Url").map_err(|_| "invalid-target-identity")?;
            let authority = url
                .strip_prefix("https://")
                .and_then(|rest| rest.split(['/', '?', '#']).next());
            require(
                authority.is_some_and(|host| !host.is_empty())
                    && !url.chars().any(char::is_whitespace),
                "target-has-no-meaningful-tls",
            )?;
            let probe_start = metric(probe, "StartedMs").map_err(|_| "invalid-probe-clock")?;
            let probe_end = metric(probe, "ObservedMs").map_err(|_| "invalid-probe-clock")?;
            require(
                probe_end > probe_start && (probe_end - probe_start).is_finite(),
                "invalid-probe-clock",
            )?;
            require(
                start <= probe_start && probe_end <= end,
                "probe-outside-slot",
            )?;
            let tls = metric(probe, "TlsMs").ok().filter(|tls| *tls > 0.0);
            let tries = probe["Tries"].as_u64();
            let flaky = probe["Flaky"].as_bool() != Some(false);
            let first_ok = probe["State"].as_str() == Some("OK") && tries == Some(1) && !flaky;
            let clean = first_ok && tls.is_some();
            require(
                targets
                    .insert(
                        (group.into(), name.into(), url.into()),
                        Probe {
                            tls,
                            midpoint: probe_start + (probe_end - probe_start) / 2.0,
                            first_ok,
                            tries,
                            flaky,
                            clean,
                        },
                    )
                    .is_none(),
                "duplicate-target",
            )?;
        }
        let keys = targets.keys().cloned().collect::<BTreeSet<_>>();
        if let Some(expected) = &expected_targets {
            require(*expected == keys, "incomplete-target-matrix")?;
        } else {
            expected_targets = Some(keys);
        }
        observations.push(Observation {
            block,
            arm,
            calibration,
            probes: targets,
        });
    }
    let (Some(a), Some(b)) = (candidates[0], candidates[1]) else {
        return Err("missing-candidate");
    };
    require(
        a.0 != b.0 && a.1 != b.1,
        "indistinguishable-candidate-identity",
    )?;
    let mut previous_pattern = None;
    for block in observations.chunks_exact(4) {
        let pattern = [block[0].arm, block[1].arm, block[2].arm, block[3].arm];
        require(
            pattern == ['A', 'B', 'B', 'A'] || pattern == ['B', 'A', 'A', 'B'],
            "invalid-block-pattern",
        )?;
        if !block[0].calibration {
            require(
                previous_pattern != Some(pattern),
                "unbalanced-block-sequence",
            )?;
            previous_pattern = Some(pattern);
        }
    }
    Ok(observations)
}

#[derive(Clone)]
struct ResourceSample {
    identity: Value,
    at: f64,
    cpu: f64,
    private: f64,
    working: f64,
    peak_working: f64,
}

fn resource_sample(sample: &Value) -> Evidence<ResourceSample> {
    require(
        sample["ready"].as_bool() == Some(true) && sample["status"] == "Ready",
        "resource-snapshot-unavailable",
    )?;
    let identity = &sample["identity"];
    let pid = identity["pid"]
        .as_u64()
        .filter(|pid| *pid > 0 && *pid <= u32::MAX as u64);
    let created = identity["created_filetime"]
        .as_u64()
        .filter(|created| *created > 0);
    require(
        pid.is_some()
            && created.is_some()
            && sample["pid"].as_u64() == pid
            && sample["created_filetime"].as_u64() == created
            && text_field(identity, "executable").is_ok(),
        "invalid-resource-process-identity",
    )?;
    let at = metric(sample, "observed_monotonic_ms").map_err(|_| "invalid-resource-clock")?;
    metric(sample, "read_duration_ms").map_err(|_| "invalid-resource-clock")?;
    let cpu = metric(sample, "cpu_total_ms").map_err(|_| "invalid-resource-counter")?;
    let private = metric(sample, "private_bytes").map_err(|_| "invalid-resource-counter")?;
    let working = metric(sample, "working_set_bytes").map_err(|_| "invalid-resource-counter")?;
    let peak_working =
        metric(sample, "peak_working_set_bytes").map_err(|_| "invalid-resource-counter")?;
    require(peak_working >= working, "invalid-resource-counter")?;
    Ok(ResourceSample {
        identity: identity.clone(),
        at,
        cpu,
        private,
        working,
        peak_working,
    })
}

fn resource_window(row: &Value) -> Evidence<Value> {
    let ready = resource_sample(&row["resources"]["ready"])?;
    let warm = resource_sample(&row["resources"]["warm"])?;
    let end = resource_sample(&row["resources"]["end"])?;
    require(
        ready.identity == warm.identity && warm.identity == end.identity,
        "mixed-resource-process-identity",
    )?;
    let start = metric(row, "started_ms").map_err(|_| "invalid-resource-clock")?;
    let finish = metric(row, "finished_ms").map_err(|_| "invalid-resource-clock")?;
    require(
        ready.at < warm.at && warm.at <= start && start < finish && finish <= end.at,
        "probe-outside-resource-window",
    )?;
    require(
        ready.cpu <= warm.cpu
            && warm.cpu <= end.cpu
            && ready.peak_working <= warm.peak_working
            && warm.peak_working <= end.peak_working,
        "reversed-resource-counter",
    )?;
    let elapsed = end.at - warm.at;
    let cpu = end.cpu - warm.cpu;
    let percent = 100.0 * (cpu / elapsed);
    require(
        elapsed.is_finite() && elapsed > 0.0 && cpu.is_finite() && percent.is_finite(),
        "resource-window-overflow",
    )?;
    Ok(json!({
        "status":"Ready", "identity":end.identity,
        "ready_monotonic_ms":ready.at, "warm_monotonic_ms":warm.at, "end_monotonic_ms":end.at,
        "warmup_cpu_time_ms":warm.cpu-ready.cpu, "warmup_elapsed_ms":warm.at-ready.at,
        "cpu_time_ms":cpu, "elapsed_ms":elapsed, "cpu_percent_one_core":percent,
        "private_bytes_end":end.private, "observed_max_private_bytes":warm.private.max(end.private),
        "working_set_bytes_end":end.working, "observed_max_working_set_bytes":warm.working.max(end.working),
        "os_peak_working_set_bytes_end":end.peak_working
    }))
}

fn resource_summary(windows: &[Value], blocks: usize, arm: &str) -> Evidence<Value> {
    let expected = blocks * 2;
    let known = windows
        .iter()
        .filter(|window| {
            window["calibration"] == false && window["arm"] == arm && window["status"] == "Ready"
        })
        .collect::<Vec<_>>();
    let mut summary = json!({
        "windows_known":known.len(), "windows_expected":expected,
        "cpu_time_ms_sum":null, "elapsed_ms_sum":null, "cpu_percent_one_core_weighted":null,
        "private_bytes_end_median":null, "observed_max_private_bytes":null,
        "working_set_bytes_end_median":null, "observed_max_working_set_bytes":null,
        "os_peak_working_set_bytes_max":null
    });
    if !known.is_empty() {
        let cpu = known
            .iter()
            .map(|window| window["cpu_time_ms"].as_f64().unwrap_or(f64::NAN))
            .sum::<f64>();
        let elapsed = known
            .iter()
            .map(|window| window["elapsed_ms"].as_f64().unwrap_or(f64::NAN))
            .sum::<f64>();
        let percent = 100.0 * (cpu / elapsed);
        require(
            [cpu, elapsed, percent]
                .iter()
                .all(|value| value.is_finite())
                && elapsed > 0.0,
            "resource-aggregate-overflow",
        )?;
        summary["cpu_time_ms_sum"] = json!(cpu);
        summary["elapsed_ms_sum"] = json!(elapsed);
        summary["cpu_percent_one_core_weighted"] = json!(percent);
        for (input, output) in [
            ("private_bytes_end", "private_bytes_end_median"),
            ("working_set_bytes_end", "working_set_bytes_end_median"),
        ] {
            let values = known
                .iter()
                .map(|window| window[input].as_f64().unwrap_or(f64::NAN))
                .collect::<Vec<_>>();
            let middle = median(&values);
            require(middle.is_finite(), "resource-aggregate-overflow")?;
            summary[output] = json!(middle);
        }
        for (input, output) in [
            ("observed_max_private_bytes", "observed_max_private_bytes"),
            (
                "observed_max_working_set_bytes",
                "observed_max_working_set_bytes",
            ),
            (
                "os_peak_working_set_bytes_end",
                "os_peak_working_set_bytes_max",
            ),
        ] {
            let maximum = known
                .iter()
                .map(|window| window[input].as_f64().unwrap_or(f64::NAN))
                .fold(0.0, f64::max);
            require(maximum.is_finite(), "resource-aggregate-overflow")?;
            summary[output] = json!(maximum);
        }
    }
    Ok(summary)
}

fn assess_resources(rows: &[Value], blocks: usize, reasons: &mut BTreeSet<String>) -> Value {
    let mut windows = Vec::with_capacity(rows.len());
    let mut previous_end = None;
    let mut identities = BTreeSet::new();
    let mut invalid = false;
    for (slot, row) in rows.iter().enumerate() {
        let window = resource_window(row).and_then(|window| {
            let ready = window["ready_monotonic_ms"]
                .as_f64()
                .ok_or("invalid-resource-clock")?;
            let end = window["end_monotonic_ms"]
                .as_f64()
                .ok_or("invalid-resource-clock")?;
            require(
                previous_end.is_none_or(|previous| ready >= previous),
                "overlapping-resource-windows",
            )?;
            let identity = &window["identity"];
            let process = (
                identity["pid"]
                    .as_u64()
                    .ok_or("invalid-resource-process-identity")?,
                identity["created_filetime"]
                    .as_u64()
                    .ok_or("invalid-resource-process-identity")?,
                text_field(identity, "executable")?.to_owned(),
            );
            require(
                identities.insert(process),
                "reused-resource-process-identity",
            )?;
            previous_end = Some(end);
            Ok(window)
        });
        let mut window = match window {
            Ok(window) => window,
            Err(reason) => {
                invalid = true;
                reasons.insert(reason.into());
                // Preserve the clock boundary of an invalid window as well, so
                // that its neighbour cannot silently overlap an unknown launch.
                if let Ok(end) = metric(&row["resources"]["end"], "observed_monotonic_ms") {
                    previous_end =
                        Some(previous_end.map_or(end, |previous: f64| previous.max(end)));
                }
                json!({"status":"Unavailable", "reason":reason})
            }
        };
        window["slot"] = json!(slot);
        window["block"] = row["block"].clone();
        window["position"] = row["position"].clone();
        window["arm"] = row["arm"].clone();
        window["calibration"] = row["calibration"].clone();
        windows.push(window);
    }
    let a = resource_summary(&windows, blocks, "A");
    let b = resource_summary(&windows, blocks, "B");
    let (a, b) = match (a, b) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            for reason in [a.err(), b.err()].into_iter().flatten() {
                reasons.insert(reason.into());
            }
            invalid = true;
            (Value::Null, Value::Null)
        }
    };
    let known = a["windows_known"].as_u64().unwrap_or(0) + b["windows_known"].as_u64().unwrap_or(0);
    let complete = !invalid && windows.len() == (blocks + 2) * 4 && known == (blocks * 4) as u64;
    let status = if complete {
        "Ready"
    } else if known > 0 {
        "Partial"
    } else {
        "Unavailable"
    };
    if !complete {
        reasons.insert("resources-not-comparable".into());
    }
    let differences = if complete {
        json!({
            "cpu_percent_one_core_b_minus_a":b["cpu_percent_one_core_weighted"].as_f64().unwrap_or(0.0)-a["cpu_percent_one_core_weighted"].as_f64().unwrap_or(0.0),
            "private_bytes_end_median_b_minus_a":b["private_bytes_end_median"].as_f64().unwrap_or(0.0)-a["private_bytes_end_median"].as_f64().unwrap_or(0.0),
            "interpretation":"descriptive; no resource budget was supplied"
        })
    } else {
        Value::Null
    };
    json!({
        "status":status, "scope":"CompareMeasured", "cpu_basis":"warm-to-end counter delta; elapsed-weighted one-core percent",
        "memory_basis":"sampled endpoints; OS peak is lifetime, not a measured-window peak",
        "a":a, "b":b, "differences":differences, "windows":windows
    })
}

fn target_assessment(
    observations: &[Observation],
    target: &Target,
    blocks: usize,
    reasons: &mut BTreeSet<String>,
) -> Value {
    let samples = observations
        .iter()
        .map(|row| row.probes[target])
        .collect::<Vec<_>>();
    let mut detail = json!({
        "group":target.0, "name":target.1, "url":target.2,
        "conclusion":"Insufficient", "comparable":false,
        "a_first_success":0, "b_first_success":0, "calibration_success":0,
        "a_expected":2*blocks, "b_expected":2*blocks, "calibration_expected":8,
        "retry_samples":samples.iter().filter(|sample| sample.tries.is_some_and(|tries| tries>1)).count(),
        "flaky_samples":samples.iter().filter(|sample| sample.flaky).count(),
        "missing_tls_samples":samples.iter().filter(|sample| sample.tls.is_none()).count(),
        "noise_ms":null, "practical_floor_ms":null, "threshold_ms":null,
        "median_b_minus_a_ms":null, "block_deltas_ms":[], "blocks":[], "calibration":[], "reasons":[]
    });
    let mut local = BTreeSet::new();
    for (field, arm) in [("a_first_success", 'A'), ("b_first_success", 'B')] {
        detail[field] = json!(
            observations
                .iter()
                .zip(&samples)
                .filter(|(row, sample)| !row.calibration && row.arm == arm && sample.first_ok)
                .count()
        );
    }
    detail["calibration_success"] = json!(
        observations
            .iter()
            .zip(&samples)
            .filter(|(row, sample)| row.calibration && sample.first_ok)
            .count()
    );
    if samples.iter().any(|sample| !sample.first_ok) {
        local.insert("unclean-first-attempt");
    }
    if samples.iter().any(|sample| sample.tls.is_none()) {
        local.insert("missing-meaningful-tls");
    }
    if samples.iter().any(|sample| !sample.clean) {
        reasons.extend(local.iter().map(|reason| (*reason).into()));
        detail["reasons"] = json!(local);
        return detail;
    }
    let a_values = observations
        .iter()
        .zip(&samples)
        .filter(|(row, _)| !row.calibration && row.arm == 'A')
        .map(|(_, sample)| sample.tls.unwrap_or(0.0))
        .collect::<Vec<_>>();
    let baseline = median(&a_values);
    let floor = ABSOLUTE_FLOOR_MS.max(RELATIVE_FLOOR * baseline);
    let mut calibration = Vec::new();
    let mut measured = Vec::new();
    let mut deltas = Vec::new();
    let mut noise: f64 = 0.0;
    let mut measured_noise: f64 = 0.0;
    for block in observations.chunks_exact(4) {
        let times = std::array::from_fn(|index| block[index].probes[target].midpoint);
        let values = std::array::from_fn(|index| block[index].probes[target].tls.unwrap_or(0.0));
        let arms = std::array::from_fn(|index| block[index].arm);
        let fit = match fit_block(times, values, arms) {
            Ok(fit) => fit,
            Err(reason) => {
                reasons.insert(reason.into());
                detail["reasons"] = json!([reason]);
                return detail;
            }
        };
        let block_detail = json!({
            "block":block[0].block, "pattern":arms.iter().collect::<String>(),
            "midpoints_ms":times, "b_minus_a_ms":fit.delta, "linear_drift_ms_per_ms":fit.slope,
            "max_residual_ms":fit.residual, "delta_noise_scale_ms":fit.delta_noise
        });
        if block[0].calibration {
            noise = noise
                .max(fit.delta.abs())
                .max(fit.residual)
                .max(fit.delta_noise);
            calibration.push(block_detail);
        } else {
            measured_noise = measured_noise.max(fit.residual).max(fit.delta_noise);
            deltas.push(fit.delta);
            measured.push(block_detail);
        }
    }
    let threshold = floor + NOISE_MULTIPLIER * noise;
    let effect = median(&deltas);
    let max_deviation = deltas
        .iter()
        .map(|delta| (delta - effect).abs())
        .fold(0.0, f64::max);
    let consistency_limit = (2.0 * threshold).max(effect.abs() * 0.5);
    if ![floor, threshold, effect, max_deviation, consistency_limit]
        .iter()
        .all(|value| value.is_finite())
    {
        reasons.insert("assessment-overflow".into());
        detail["reasons"] = json!(["assessment-overflow"]);
        return detail;
    }
    if noise > floor {
        local.insert("calibration-noise");
    }
    if measured_noise > floor {
        local.insert("noisy-comparison-block");
    }
    if max_deviation > consistency_limit {
        local.insert("inconsistent-block-effects");
    }
    if deltas.iter().any(|delta| *delta > threshold) {
        local.insert("observed-latency-regression");
    }
    let improved = deltas.iter().all(|delta| *delta < -threshold);
    let unchanged = deltas.iter().all(|delta| delta.abs() <= threshold);
    if !improved && !unchanged && !local.contains("observed-latency-regression") {
        local.insert("inconsistent-block-effects");
    }
    let conclusion = if local.contains("observed-latency-regression") {
        "Regressed"
    } else if !local.is_empty() {
        "Uncertain"
    } else if improved {
        "Improved"
    } else {
        "NoClearDifference"
    };
    detail["conclusion"] = json!(conclusion);
    detail["comparable"] = json!(local.is_empty());
    detail["a_tls_ms_median"] = json!(baseline);
    detail["noise_ms"] = json!(noise);
    detail["comparison_noise_ms"] = json!(measured_noise);
    detail["practical_floor_ms"] = json!(floor);
    detail["threshold_ms"] = json!(threshold);
    detail["median_b_minus_a_ms"] = json!(effect);
    detail["max_block_deviation_ms"] = json!(max_deviation);
    detail["block_consistency_limit_ms"] = json!(consistency_limit);
    detail["block_deltas_ms"] = json!(deltas);
    detail["blocks"] = json!(measured);
    detail["calibration"] = json!(calibration);
    detail["reasons"] = json!(local);
    reasons.extend(local.into_iter().map(str::to_owned));
    detail
}

/// Fail closed for incomplete or contradictory evidence. A recommendation is
/// observational and stays in the report; it never applies a strategy.
pub fn assess(rows: &[Value], blocks: usize) -> Result<Value> {
    let mut reasons = BTreeSet::new();
    let observations = match validate_rows(rows, blocks) {
        Ok(observations) => Some(observations),
        Err(reason) => {
            reasons.insert(reason.into());
            None
        }
    };
    let mut targets = Vec::new();
    if let Some(observations) = &observations {
        for target in observations[0].probes.keys() {
            targets.push(target_assessment(
                observations,
                target,
                blocks,
                &mut reasons,
            ));
        }
    }
    // An invalid block count is not allowed to overflow expected resource sizes.
    let resources = if observations.is_some() {
        assess_resources(rows, blocks, &mut reasons)
    } else {
        json!({"status":"Unavailable", "scope":"CompareMeasured", "reason":"comparison-context-invalid", "a":null, "b":null, "windows":[]})
    };
    let status = if !reasons.is_empty() {
        "Inconclusive"
    } else if targets
        .iter()
        .any(|target| target["conclusion"] == "Improved")
    {
        "ConsistentImprovement"
    } else {
        "NoClearDifference"
    };
    let can_recommend = status == "ConsistentImprovement";
    let mut text = match status {
        "ConsistentImprovement" => "Теневое сравнение: B стабильно улучшил TLS на части проверенных адресов; регрессий не обнаружено.".to_owned(),
        "NoClearDifference" => "Теневое сравнение: устойчивой разницы TLS между A и B не обнаружено.".to_owned(),
        _ => "Теневое сравнение: данных недостаточно для рекомендации.".to_owned(),
    };
    if !reasons.is_empty() {
        text.push_str(&format!(
            "\nПричины: {}.",
            reasons.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    for target in &targets {
        if let (Some(effect), Some(threshold)) = (
            target["median_b_minus_a_ms"].as_f64(),
            target["threshold_ms"].as_f64(),
        ) {
            text.push_str(&format!(
                "\n{} / {}: B−A {effect:+.2} мс; порог {threshold:.2} мс; {}.",
                target["group"].as_str().unwrap_or(""),
                target["name"].as_str().unwrap_or(""),
                target["conclusion"].as_str().unwrap_or("Insufficient")
            ));
        }
    }
    if resources["status"] == "Ready" {
        for arm in ["a", "b"] {
            let cost = &resources[arm];
            if let (Some(cpu), Some(percent), Some(known)) = (
                cost["cpu_time_ms_sum"].as_f64(),
                cost["cpu_percent_one_core_weighted"].as_f64(),
                cost["windows_known"].as_u64(),
            ) {
                text.push_str(&format!("\nДвижок {}: CPU {cpu:.2} мс, {percent:.2}% одного ядра с весом по времени; окон {known}/{}.", arm.to_uppercase(), blocks * 2));
            }
        }
    } else {
        text.push_str("\nРесурсы движка: нет полного набора сопоставимых окон.");
    }
    text.push_str("\nЭто наблюдения HTTPS в данном запуске с поправкой на линейный дрейф, без доказательства причинной связи и без измерения задержки игры. Стратегия автоматически не применяется.");
    let groups = targets.iter().filter_map(|target| target["group"].as_str()).collect::<BTreeSet<_>>().into_iter().map(|group| {
        json!({"group":group, "comparable":targets.iter().filter(|target| target["group"] == group).all(|target| target["comparable"] == true)})
    }).collect::<Vec<_>>();
    Ok(json!({
        "schema":1, "status":status, "shadow_only":true, "can_recommend":can_recommend,
        "scope":"observed-https-tls", "attribution":"observational; no causal proof",
        "blocks_expected":blocks, "slots_expected":blocks.checked_add(2).and_then(|count| count.checked_mul(4)), "slots_observed":rows.len(),
        "reasons":reasons, "targets":targets, "groups":groups, "resources":resources,
        "policy":{"absolute_floor_ms":ABSOLUTE_FLOOR_MS, "relative_floor":RELATIVE_FLOOR,
            "calibration_noise_multiplier":NOISE_MULTIPLIER, "all_blocks_must_agree":true,
            "resource_budget":null},
        "text":text
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_seal_binds_target_clocks_and_resource_windows() {
        let mut record = json!({"protocol":"finalists-native-v1","complete":true,"blocks":4,"rows":fixture(-40.)});
        record["rows"][0]["resources"]["start"]["read_duration_ms"] =
            json!(0.00016342830000000002_f64);
        seal_record(&mut record).unwrap();
        let saved = serde_json::to_vec_pretty(&record).unwrap();
        let mut record: Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(assess_saved(&record).unwrap()["can_recommend"], true);
        for key in ["probes", "resources"] {
            let mut edited = record.clone();
            if key == "probes" {
                edited["rows"][5]["probes"][0]["StartedMs"] = json!(1.);
            } else {
                edited["rows"][5]["resources"]["end"]["cpu_total_ms"] = json!(999.);
            }
            assert!(assess_saved(&edited).is_err());
        }
        record["complete"] = json!(false);
        seal_record(&mut record).unwrap();
        assert!(assess_saved(&record).is_err());
    }
    fn fixture(effect: f64) -> Vec<Value> {
        let mut rows = Vec::new();
        for block in 0..6 {
            let calibration = block == 0 || block == 5;
            let pattern = if calibration || block % 2 == 0 {
                ['A', 'B', 'B', 'A']
            } else {
                ['B', 'A', 'A', 'B']
            };
            for (position, arm) in pattern.into_iter().enumerate() {
                let slot = block * 4 + position;
                let start = block as f64 * 10000. + [200., 700., 2700., 5700.][position];
                let end = start + 100.;
                let midpoint = (start + end) / 2.;
                let measured_b = !calibration && arm == 'B';
                let identity = json!({"pid":1000+slot,"created_filetime":137000000000000000u64+slot as u64*100000,"executable":"C:\\fixture\\winws2.exe"});
                let sample = |at: f64, cpu: f64| json!({"ready":true,"status":"Ready","identity":identity,"pid":1000+slot,"created_filetime":137000000000000000u64+slot as u64*100000,"observed_monotonic_ms":at,"observed_ms":13700000000000f64+at,"read_duration_ms":0.01,"cpu_total_ms":cpu,"private_bytes":100000+slot,"working_set_bytes":200000+slot,"peak_working_set_bytes":300000+slot});
                rows.push(json!({"block":block,"position":position,"arm":arm.to_string(),"calibration":calibration,"strategy_id":if measured_b{"2"}else{"1"},"started_ms":start,"finished_ms":end,
                    "network_key":"stable-network","inputs_hash":"stable-inputs","native_hash":"stable-native","strategy_hash":if measured_b{"b-hash"}else{"a-hash"},"context_validated":true,
                    "probes":[{"Group":"Clean","Name":"control","Url":"https://control.invalid/","State":"OK","TlsMs":100.+0.002*midpoint,"Tries":1,"Flaky":false,"StartedMs":start+10.,"ObservedMs":end-10.},
                              {"Group":"DPI","Name":"endpoint","Url":"https://endpoint.invalid/","State":"OK","TlsMs":200.+0.002*midpoint+if measured_b{effect}else{0.},"Tries":1,"Flaky":false,"StartedMs":start+10.,"ObservedMs":end-10.}],
                    "resources":{"ready":sample(start-150.,0.),"warm":sample(start-50.,1.),"end":sample(end+20.,if measured_b{3.}else{2.})}}));
            }
        }
        rows
    }
    #[test]
    fn consistent_improvement_requires_complete_calibrated_groups() {
        let result = assess(&fixture(-40.), 4).unwrap();
        assert_eq!(result["status"], "ConsistentImprovement");
        assert_eq!(result["can_recommend"], true);
        assert_eq!(result["shadow_only"], true);
        assert_eq!(result["targets"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn linear_drift_with_irregular_spacing_is_not_strategy_improvement() {
        let result = assess(&fixture(0.), 4).unwrap();
        assert_eq!(result["status"], "NoClearDifference");
        assert_eq!(result["can_recommend"], false);
    }
    #[test]
    fn per_target_clocks_remove_drift_when_queue_positions_differ_between_arms() {
        let mut rows = fixture(0.);
        for row in &mut rows {
            let block = row["block"].as_u64().unwrap() as f64;
            let position = row["position"].as_u64().unwrap() as f64;
            let start = 200. + block * 300_000. + position * 65_000.;
            let end = start + 60_000.;
            let midpoint = (start + end) / 2.;
            let measured_b = row["calibration"] == false && row["arm"] == "B";
            let target_midpoint = midpoint - if measured_b { 20_000. } else { 0. };
            row["started_ms"] = json!(start);
            row["finished_ms"] = json!(end);
            row["probes"][0]["TlsMs"] = json!(100.);
            row["probes"][0]["StartedMs"] = json!(midpoint - 1.);
            row["probes"][0]["ObservedMs"] = json!(midpoint + 1.);
            // Both strategies observe the same linear latency curve. Other
            // requests in the batch only change this target's queue position.
            row["probes"][1]["TlsMs"] = json!(200. + 0.002 * (target_midpoint - block * 300_000.));
            row["probes"][1]["StartedMs"] = json!(target_midpoint - 1.);
            row["probes"][1]["ObservedMs"] = json!(target_midpoint + 1.);
            for (sample, at) in [
                ("ready", start - 150.),
                ("warm", start - 50.),
                ("end", end + 20.),
            ] {
                row["resources"][sample]["observed_monotonic_ms"] = json!(at);
                row["resources"][sample]["observed_ms"] = json!(13_700_000_000_000. + at);
            }
        }
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "NoClearDifference");
        assert_eq!(result["can_recommend"], false);
        assert!(
            result["targets"][1]["median_b_minus_a_ms"]
                .as_f64()
                .unwrap()
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn target_clocks_are_required_and_must_be_ordered_inside_their_slot() {
        for field in ["StartedMs", "ObservedMs"] {
            let mut rows = fixture(-40.);
            rows[4]["probes"][1].as_object_mut().unwrap().remove(field);
            assert!(has_reason(
                &assess(&rows, 4).unwrap(),
                "invalid-probe-clock"
            ));
            for invalid in [Value::Null, json!(-1)] {
                let mut rows = fixture(-40.);
                rows[4]["probes"][1][field] = invalid;
                assert!(has_reason(
                    &assess(&rows, 4).unwrap(),
                    "invalid-probe-clock"
                ));
            }
        }
        for (start, end, reason) in [
            (10_250., 10_250., "invalid-probe-clock"),
            (10_260., 10_240., "invalid-probe-clock"),
            (10_190., 10_250., "probe-outside-slot"),
            (10_250., 10_310., "probe-outside-slot"),
        ] {
            let mut rows = fixture(-40.);
            rows[4]["probes"][1]["StartedMs"] = json!(start);
            rows[4]["probes"][1]["ObservedMs"] = json!(end);
            let result = assess(&rows, 4).unwrap();
            assert_eq!(result["status"], "Inconclusive");
            assert_eq!(result["can_recommend"], false);
            assert!(has_reason(&result, reason));
        }
    }
    #[test]
    fn missing_slot_and_missing_target_block_recommendation() {
        let mut rows = fixture(-40.);
        rows.pop();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
        let mut rows = fixture(-40.);
        rows[3]["probes"].as_array_mut().unwrap().pop();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
    }
    #[test]
    fn retries_and_calibration_noise_remain_inconclusive() {
        let mut rows = fixture(-40.);
        rows[8]["probes"][1]["Tries"] = 2.into();
        rows[8]["probes"][1]["Flaky"] = true.into();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
        let mut rows = fixture(-40.);
        let value = rows[1]["probes"][1]["TlsMs"].as_f64().unwrap();
        rows[1]["probes"][1]["TlsMs"] = (value + 80.).into();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
    }
    #[test]
    fn mixed_context_and_process_identity_never_form_resource_deltas() {
        let mut rows = fixture(-40.);
        rows[8]["network_key"] = "changed".into();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
        let mut rows = fixture(-40.);
        rows[8]["resources"]["end"]["identity"]["created_filetime"] = 3.into();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "Inconclusive");
    }
    #[test]
    fn resource_aggregation_uses_measured_cpu_deltas_and_elapsed_weight() {
        let result = assess(&fixture(-40.), 4).unwrap();
        assert_eq!(result["resources"]["status"], "Ready");
        assert_eq!(result["resources"]["a"]["cpu_time_ms_sum"], 8.);
        assert_eq!(result["resources"]["b"]["cpu_time_ms_sum"], 16.);
        assert_eq!(result["resources"]["a"]["windows_known"], 8);
    }
    #[test]
    fn observed_latency_regression_is_a_blocking_reason() {
        let result = assess(&fixture(40.), 4).unwrap();
        assert_eq!(result["status"], "Inconclusive");
        assert_eq!(result["can_recommend"], false);
        assert!(
            result["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "observed-latency-regression")
        );
    }

    fn has_reason(result: &Value, reason: &str) -> bool {
        result["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == reason)
    }

    #[test]
    fn ols_recovers_both_patterns_at_irregular_midpoints() {
        let times = [
            1_000_000_000_000.0,
            1_000_000_000_031.0,
            1_000_000_000_707.0,
            1_000_000_004_997.0,
        ];
        for arms in [['A', 'B', 'B', 'A'], ['B', 'A', 'A', 'B']] {
            let values = std::array::from_fn(|index| {
                300.0 + 0.017 * (times[index] - times[0])
                    - if arms[index] == 'B' { 42.0 } else { 0.0 }
            });
            let fit = fit_block(times, values, arms).unwrap();
            assert!((fit.delta + 42.0).abs() < 1e-9);
            assert!((fit.slope - 0.017).abs() < 1e-12);
            assert!(fit.delta_noise < 1e-9);
        }
    }

    #[test]
    fn per_block_and_per_target_drift_are_independent_nuisance_terms() {
        let mut rows = fixture(-40.0);
        for row in &mut rows {
            let block = row["block"].as_u64().unwrap();
            let time =
                (row["started_ms"].as_f64().unwrap() + row["finished_ms"].as_f64().unwrap()) / 2.0;
            let local_time = time - block as f64 * 10_000.0;
            let b = row["calibration"] == false && row["arm"] == "B";
            let drift = if block % 2 == 0 { 0.003 } else { -0.012 };
            row["probes"][0]["TlsMs"] = json!(180.0 + 0.025 * local_time);
            row["probes"][1]["TlsMs"] =
                json!(250.0 + drift * local_time - if b { 40.0 } else { 0.0 });
        }
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "ConsistentImprovement");
        assert!(
            (result["targets"][1]["median_b_minus_a_ms"]
                .as_f64()
                .unwrap()
                + 40.0)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn slots_patterns_and_candidate_identity_are_checked() {
        let cases = [
            ("block", json!(0), "invalid-slot-order"),
            ("position", json!(1), "invalid-slot-order"),
            ("arm", json!("A"), "mixed-strategy-identity"),
            ("calibration", json!(true), "invalid-calibration-slot"),
            ("strategy_hash", json!("changed"), "mixed-strategy-identity"),
            ("strategy_id", json!("changed"), "mixed-strategy-identity"),
            ("context_validated", json!(false), "unvalidated-context"),
        ];
        for (field, value, reason) in cases {
            let mut rows = fixture(-40.0);
            rows[4][field] = value;
            let result = assess(&rows, 4).unwrap();
            assert_eq!(result["status"], "Inconclusive", "{field}");
            assert!(has_reason(&result, reason), "{field}: {result}");
        }
        for blocks in [0, 3, 5, 13, usize::MAX] {
            assert!(has_reason(
                &assess(&fixture(-40.0), blocks).unwrap(),
                "invalid-comparison-size"
            ));
        }
        let mut rows = fixture(-40.0);
        // Calibration B labels still run A. Changing one to B must be rejected.
        rows[1]["strategy_id"] = json!("2");
        rows[1]["strategy_hash"] = json!("b-hash");
        assert!(has_reason(
            &assess(&rows, 4).unwrap(),
            "mixed-strategy-identity"
        ));
    }

    #[test]
    fn target_sets_are_exact_and_duplicates_are_not_extra_evidence() {
        let mut rows = fixture(-40.0);
        let duplicate = rows[4]["probes"][0].clone();
        rows[4]["probes"].as_array_mut().unwrap().push(duplicate);
        assert!(has_reason(&assess(&rows, 4).unwrap(), "duplicate-target"));
        let mut rows = fixture(-40.0);
        rows[9]["probes"][1]["Url"] = json!("https://different.invalid/");
        assert!(has_reason(
            &assess(&rows, 4).unwrap(),
            "incomplete-target-matrix"
        ));
        let mut rows = fixture(-40.0);
        rows[9]["probes"].as_array_mut().unwrap().reverse();
        assert_eq!(assess(&rows, 4).unwrap()["status"], "ConsistentImprovement");
    }

    #[test]
    fn failed_first_attempts_and_unknown_tls_cannot_be_recovered_into_comparability() {
        for (field, value) in [
            ("State", json!("FAIL")),
            ("Tries", json!(2)),
            ("Tries", Value::Null),
            ("Flaky", Value::Null),
            ("TlsMs", json!(0)),
            ("TlsMs", json!(-1)),
            ("TlsMs", Value::Null),
        ] {
            let mut rows = fixture(-40.0);
            rows[4]["probes"][1][field] = value;
            let result = assess(&rows, 4).unwrap();
            assert_eq!(result["status"], "Inconclusive", "{field}");
            assert_eq!(result["targets"][1]["comparable"], false);
        }
    }

    #[test]
    fn one_regression_or_inconsistent_block_blocks_an_overall_improvement() {
        for replacement_effect in [0.0, 40.0, -160.0] {
            let mut rows = fixture(-40.0);
            for row in &mut rows[8..12] {
                if row["arm"] == "B" {
                    let tls = row["probes"][1]["TlsMs"].as_f64().unwrap();
                    row["probes"][1]["TlsMs"] = json!(tls + 40.0 + replacement_effect);
                }
            }
            let result = assess(&rows, 4).unwrap();
            assert_eq!(
                result["status"], "Inconclusive",
                "{replacement_effect}: {result}"
            );
            assert_eq!(result["can_recommend"], false);
            assert!(has_reason(
                &result,
                if replacement_effect > 0.0 {
                    "observed-latency-regression"
                } else {
                    "inconsistent-block-effects"
                }
            ));
        }
    }

    #[test]
    fn noise_in_a_measured_block_also_blocks_recommendation() {
        let mut rows = fixture(-40.0);
        let tls = rows[9]["probes"][1]["TlsMs"].as_f64().unwrap();
        rows[9]["probes"][1]["TlsMs"] = json!(tls + 80.0);
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "Inconclusive");
        assert!(has_reason(&result, "noisy-comparison-block"));
    }

    #[test]
    fn incomplete_resources_and_reversed_counters_are_not_zero_cost() {
        let mut rows = fixture(-40.0);
        rows[8]["resources"]["end"] = Value::Null;
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "Inconclusive");
        assert_eq!(result["resources"]["status"], "Partial");
        assert_eq!(
            result["resources"]["windows"][8]["cpu_time_ms"],
            Value::Null
        );
        assert_eq!(result["resources"]["a"]["windows_known"], 7);
        let mut rows = fixture(-40.0);
        rows[8]["resources"]["end"]["cpu_total_ms"] = json!(0.5);
        let result = assess(&rows, 4).unwrap();
        assert!(has_reason(&result, "reversed-resource-counter"));
        assert_eq!(
            result["resources"]["windows"][8]["cpu_time_ms"],
            Value::Null
        );
    }

    #[test]
    fn counter_windows_must_enclose_probes_and_not_overlap_other_launches() {
        let mut rows = fixture(-40.0);
        rows[8]["resources"]["end"]["observed_monotonic_ms"] = rows[8]["started_ms"].clone();
        assert!(has_reason(
            &assess(&rows, 4).unwrap(),
            "probe-outside-resource-window"
        ));
        let mut rows = fixture(-40.0);
        rows[8]["resources"]["ready"]["observed_monotonic_ms"] =
            rows[7]["resources"]["end"]["observed_monotonic_ms"]
                .as_f64()
                .map(|time| json!(time - 1.0))
                .unwrap();
        assert!(has_reason(
            &assess(&rows, 4).unwrap(),
            "overlapping-resource-windows"
        ));
        let mut rows = fixture(-40.0);
        rows[8]["started_ms"] = rows[7]["finished_ms"]
            .as_f64()
            .map(|time| json!(time - 1.0))
            .unwrap();
        assert!(has_reason(
            &assess(&rows, 4).unwrap(),
            "invalid-monotonic-order"
        ));
    }

    #[test]
    fn context_drift_prevents_aggregation_even_when_individual_counters_are_valid() {
        let mut rows = fixture(-40.0);
        rows[8]["inputs_hash"] = json!("changed");
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "Inconclusive");
        assert_eq!(result["resources"]["status"], "Unavailable");
        assert_eq!(result["resources"]["a"], Value::Null);
        assert!(has_reason(&result, "mixed-comparison-context"));
    }

    #[test]
    fn cpu_percent_is_weighted_by_actual_window_time_and_ignores_calibration() {
        let mut rows = fixture(-40.0);
        let end = rows[5]["resources"]["end"]["observed_monotonic_ms"]
            .as_f64()
            .unwrap();
        rows[5]["resources"]["end"]["observed_monotonic_ms"] = json!(end + 100.0);
        // Large calibration costs must not leak into measured A totals.
        rows[0]["resources"]["end"]["cpu_total_ms"] = json!(900.0);
        let result = assess(&rows, 4).unwrap();
        assert_eq!(result["status"], "ConsistentImprovement");
        let a = &result["resources"]["a"];
        assert_eq!(a["cpu_time_ms_sum"], 8.0);
        assert_eq!(a["elapsed_ms_sum"], 1460.0);
        assert!(
            (a["cpu_percent_one_core_weighted"].as_f64().unwrap() - 100.0 * 8.0 / 1460.0).abs()
                < 1e-12
        );
    }

    #[test]
    fn resource_identity_uses_exact_filetime_and_executable_as_well_as_pid() {
        for field in ["created_filetime", "executable"] {
            let mut rows = fixture(-40.0);
            let value = if field == "created_filetime" {
                json!(137000000000800001u64)
            } else {
                json!("C:\\other\\winws2.exe")
            };
            rows[8]["resources"]["end"]["identity"][field] = value.clone();
            if field == "created_filetime" {
                rows[8]["resources"]["end"][field] = value;
            }
            let result = assess(&rows, 4).unwrap();
            assert_eq!(result["status"], "Inconclusive");
            assert!(has_reason(&result, "mixed-resource-process-identity"));
        }
    }

    #[test]
    fn report_explicitly_limits_attribution_and_does_not_apply_a_strategy() {
        let result = assess(&fixture(-40.0), 4).unwrap();
        assert_eq!(result["shadow_only"], true);
        assert_eq!(result["scope"], "observed-https-tls");
        assert!(
            result["text"]
                .as_str()
                .unwrap()
                .contains("без доказательства причинной связи")
        );
        assert!(
            result["text"]
                .as_str()
                .unwrap()
                .contains("Стратегия автоматически не применяется")
        );
        serde_json::to_string(&result).unwrap();
    }
}
