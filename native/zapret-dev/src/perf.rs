use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use zapret_platform::{ProcessMetrics, monotonic_ms, process_identity};

pub(crate) fn sample(process: Option<&ProcessMetrics>, pid: u32) -> Value {
    let begin = monotonic_ms().unwrap_or(0.);
    let mut result = json!({
        "Schema":1,"ResourceStatus":"Unavailable","ResourceReason":"counter-unavailable",
        "ProcessId":pid,"ProcessStartKey":null,"ObservedMs":null,"ReadDurationMs":null,
        "CpuTotalMs":null,"PrivateBytes":null,"WorkingSetBytes":null,"OsPeakWorkingSetBytes":null,
    });
    match process {
        None => result["ResourceReason"] = json!("no-process"),
        Some(process) => match process.sample() {
            Ok(metrics) => {
                let start = metrics["created_filetime"].as_u64().unwrap_or(0);
                result["ProcessStartKey"] = json!((start + 504_911_232_000_000_000).to_string());
                result["CpuTotalMs"] = metrics["cpu_total_ms"].clone();
                result["PrivateBytes"] = metrics["private_bytes"].clone();
                result["WorkingSetBytes"] = metrics["working_set_bytes"].clone();
                result["OsPeakWorkingSetBytes"] = metrics["peak_working_set_bytes"].clone();
                result["ResourceStatus"] = json!("Ready");
                result["ResourceReason"] = json!("");
            }
            Err(error) => {
                if process.is_running().is_ok_and(|running| !running) {
                    result["ResourceStatus"] = json!("Exited");
                    result["ResourceReason"] = json!("process-exited");
                }
                result["error"] = json!(format!("{error:#}"));
            }
        },
    }
    let end = monotonic_ms().unwrap_or(begin);
    result["ObservedMs"] = json!((begin + end) / 2.);
    result["ReadDurationMs"] = json!(end - begin);
    result
}

pub(crate) fn window(samples: &[Value]) -> Value {
    zapret_core::resource_window(samples)
}

pub(crate) fn run(pid: u32, duration_sec: u64, interval_ms: u64, output: &Path) -> Result<()> {
    ensure!(
        (1..=i32::MAX as u32).contains(&pid)
            && (1..=30).contains(&duration_sec)
            && (100..=5000).contains(&interval_ms),
        "Invalid resource sampling limits"
    );
    // Reserve the output before sampling so an invalid destination has no side effects.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| format!("Create {}", output.display()))?;
    let result = (|| {
        let observer = process_identity(pid).and_then(ProcessMetrics::open).ok();
        let deadline = Instant::now() + Duration::from_secs(duration_sec);
        let mut samples = Vec::new();
        loop {
            let row = sample(observer.as_ref(), pid);
            let ready = row["ResourceStatus"] == "Ready";
            samples.push(row);
            if !ready || Instant::now() >= deadline {
                break;
            }
            thread::sleep(
                Duration::from_millis(interval_ms)
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        let window = window(&samples);
        let report = json!({"Schema":1,"Scope":"ProcessOnly","RequestedProcessId":pid,"Samples":samples,"Window":window});
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        println!(
            "{}",
            report["Window"]["Status"].as_str().unwrap_or("Unavailable")
        );
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(output);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_exited_or_reused_process_cannot_form_a_valid_resource_window() {
        let row = |time, cpu| {
            json!({"Schema":1,"ResourceStatus":"Ready","ProcessId":1,
            "ProcessStartKey":"638000000000000000","ObservedMs":time,"ReadDurationMs":1.,
            "CpuTotalMs":cpu,"PrivateBytes":10.,"WorkingSetBytes":20.,"OsPeakWorkingSetBytes":30.})
        };
        let first = row(100., 10.);
        let second = row(200., 20.);
        assert_eq!(
            window(&[first.clone(), second.clone()])["CpuPercentOneCore"],
            10.
        );
        let mut exited = second.clone();
        exited["ResourceStatus"] = json!("Exited");
        assert_eq!(window(&[first.clone(), exited])["Status"], "Unavailable");
        let mut reused = second;
        reused["ProcessStartKey"] = json!("638000000000000001");
        assert_eq!(window(&[first, reused])["Status"], "Invalid");
    }
}
