//! Pure Schema-1 process resource windows shared by replay and sampling.
use serde_json::{Value, json};

pub fn resource_window(samples: &[Value]) -> Value {
    let mut result = json!({
        "Schema":1,"Status":"Unavailable","Reasons":["insufficient-samples"],"SampleCount":samples.len(),
        "ProcessId":null,"ProcessStartKey":null,"CpuTimeMs":null,"ElapsedMs":null,"CpuPercentOneCore":null,
        "PrivateBytesStart":null,"PrivateBytesEnd":null,"ObservedMaxPrivateBytes":null,
        "WorkingSetBytesEnd":null,"ObservedMaxWorkingSetBytes":null,"OsPeakWorkingSetBytesEnd":null,
        "ReadDurationMsSum":null,
    });
    if samples.len() < 2 {
        return result;
    }
    match checked_window(samples) {
        Ok(values) => {
            for (key, value) in values.as_object().expect("resource window object") {
                result[key] = value.clone();
            }
        }
        Err((status, reason)) => {
            result["Status"] = json!(status);
            result["Reasons"] = json!([reason]);
        }
    }
    result
}

fn checked_window(samples: &[Value]) -> std::result::Result<Value, (&'static str, &'static str)> {
    let first = &samples[0];
    let last = &samples[samples.len() - 1];
    let mut previous_time = -1.;
    let mut previous_cpu = -1.;
    let mut max_private: f64 = 0.;
    let mut max_working: f64 = 0.;
    let mut read_sum = 0.;
    for row in samples {
        if row["Schema"] != 1 {
            return Err(("Invalid", "invalid-schema"));
        }
        if row["ResourceStatus"] != "Ready" {
            return Err(("Unavailable", "counter-unavailable"));
        }
        let pid = row["ProcessId"]
            .as_u64()
            .filter(|pid| (1..=i32::MAX as u64).contains(pid));
        let key = row["ProcessStartKey"].as_str().unwrap_or("");
        if pid.is_none() || key.len() != 18 || !key.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(("Invalid", "invalid-identity"));
        }
        if row["ProcessId"] != first["ProcessId"]
            || row["ProcessStartKey"] != first["ProcessStartKey"]
        {
            return Err(("Invalid", "process-identity-changed"));
        }
        for name in [
            "ObservedMs",
            "ReadDurationMs",
            "CpuTotalMs",
            "PrivateBytes",
            "WorkingSetBytes",
            "OsPeakWorkingSetBytes",
        ] {
            let value = row[name]
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or(("Unavailable", "missing-or-nonfinite-counter"))?;
            if value < 0. {
                return Err(("Invalid", "negative-counter"));
            }
        }
        let time = row["ObservedMs"].as_f64().unwrap();
        let cpu = row["CpuTotalMs"].as_f64().unwrap();
        if time <= previous_time || cpu < previous_cpu {
            return Err(("Invalid", "nonmonotonic-counters"));
        }
        previous_time = time;
        previous_cpu = cpu;
        max_private = max_private.max(row["PrivateBytes"].as_f64().unwrap());
        max_working = max_working.max(row["WorkingSetBytes"].as_f64().unwrap());
        read_sum += row["ReadDurationMs"].as_f64().unwrap();
    }
    let cpu = last["CpuTotalMs"].as_f64().unwrap() - first["CpuTotalMs"].as_f64().unwrap();
    let elapsed = last["ObservedMs"].as_f64().unwrap() - first["ObservedMs"].as_f64().unwrap();
    let percentage = 100. * cpu / elapsed;
    if ![cpu, elapsed, percentage, read_sum]
        .iter()
        .all(|value| value.is_finite())
    {
        return Err(("Invalid", "derived-counter-overflow"));
    }
    Ok(json!({
        "Status":"Ready","Reasons":[],"ProcessId":first["ProcessId"],"ProcessStartKey":first["ProcessStartKey"],
        "CpuTimeMs":cpu,"ElapsedMs":elapsed,"CpuPercentOneCore":percentage,
        "PrivateBytesStart":first["PrivateBytes"],"PrivateBytesEnd":last["PrivateBytes"],
        "ObservedMaxPrivateBytes":max_private,"WorkingSetBytesEnd":last["WorkingSetBytes"],
        "ObservedMaxWorkingSetBytes":max_working,"OsPeakWorkingSetBytesEnd":last["OsPeakWorkingSetBytes"],
        "ReadDurationMsSum":read_sum,
    }))
}
