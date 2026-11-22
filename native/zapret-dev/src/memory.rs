use anyhow::{Context, Result, ensure};
use mlua::{Function, Lua};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};
use zapret_platform::{ProcessMetrics, process_identity};

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.
    } else {
        values[middle]
    }
}

fn measure<T>(process: &ProcessMetrics, work: impl FnOnce() -> Result<T>) -> Result<(T, f64, f64)> {
    let before = process.sample()?["cpu_total_ms"]
        .as_f64()
        .context("Process CPU counter missing")?;
    let wall = Instant::now();
    let result = work()?;
    let elapsed = wall.elapsed().as_secs_f64() * 1000.;
    let after = process.sample()?["cpu_total_ms"]
        .as_f64()
        .context("Process CPU counter missing")?;
    Ok((result, after - before, elapsed))
}

fn benchmark(
    source: &str,
    helper: Option<&str>,
    hosts: usize,
    rounds: usize,
    warm: usize,
) -> Result<Value> {
    let process = ProcessMetrics::open(process_identity(std::process::id())?)?;
    let mut samples = Vec::new();
    let mut version = String::new();
    for _ in 0..rounds {
        let lua = Lua::new();
        if source.contains("zapret_ring_native")
            || helper.is_some_and(|helper| helper.contains("zapret_ring_native"))
        {
            crate::ring::register(&lua)?;
        }
        if let Some(helper) = helper {
            lua.load(helper).set_name("ring-store.lua").exec()?;
        }
        lua.load(source).set_name("autoring.lua").exec()?;
        lua.load(include_str!("fixtures/memorybench.lua"))
            .set_name("memory benchmark fixture")
            .exec()?;
        version = lua.globals().get("_VERSION")?;
        let heap: Function = lua
            .load("return function() collectgarbage('collect'); return collectgarbage('count') end")
            .eval()?;
        let heap_before: f64 = heap.call(())?;
        let burst: Function = lua.globals().get("run_burst")?;
        let (burst, burst_cpu, burst_wall) =
            measure(&process, || Ok(burst.call::<(u64, u64)>(hosts)?))?;
        let flush: Function = lua.globals().get("run_flush")?;
        let (flush, flush_cpu, flush_wall) =
            measure(&process, || Ok(flush.call::<(u64, u64, u64)>(hosts)?))?;
        let steady: Function = lua.globals().get("run_steady")?;
        let (_, warm_cpu, warm_wall) = measure(&process, || Ok(steady.call::<()>(warm)?))?;
        let heap_after: f64 = heap.call(())?;
        samples.push(json!({
            "burst_cpu_ms":burst_cpu,"flush_cpu_ms":flush_cpu,"burst_wall_ms":burst_wall,
            "flush_wall_ms":flush_wall,"warm_cpu_ms":warm_cpu,"warm_wall_ms":warm_wall,
            "lua_heap_before_kib":heap_before,"lua_heap_after_kib":heap_after,"lua_heap_growth_kib":heap_after-heap_before,
            "burst_write_calls":burst.0,"burst_bytes":burst.1,"total_write_calls":flush.0,
            "total_bytes":flush.1,"snapshot_bytes":flush.2,
        }));
    }
    let mut result = json!({"lua_version":version,"samples":samples});
    for field in [
        "burst_cpu_ms",
        "flush_cpu_ms",
        "burst_wall_ms",
        "flush_wall_ms",
        "warm_wall_ms",
        "lua_heap_growth_kib",
    ] {
        let values = samples
            .iter()
            .map(|row| row[field].as_f64().unwrap())
            .collect();
        result[format!("median_{field}")] = json!(median(values));
    }
    Ok(result)
}

pub(crate) fn run(
    pkg: &Path,
    baseline: &Path,
    baseline_ref: Option<&str>,
    output: &Path,
    hosts: usize,
    rounds: usize,
    warm: usize,
) -> Result<()> {
    ensure!(
        (1..=2000).contains(&hosts) && (1..=30).contains(&rounds) && (1..=100000).contains(&warm),
        "Invalid memory benchmark limits"
    );
    let baseline_text = zapret_core::read_text(baseline, 1024 * 1024)?;
    let current = zapret_core::read_text(&pkg.join("lua/autoring.lua"), 1024 * 1024)?;
    let store = zapret_core::read_text(&pkg.join("lua/ring-store.lua"), 1024 * 1024)?;
    let old = benchmark(&baseline_text, None, hosts, rounds, warm)?;
    let new = benchmark(&current, Some(&store), hosts, rounds, warm)?;
    ensure!(
        old["samples"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["burst_write_calls"] == hosts),
        "Baseline memory write count changed"
    );
    ensure!(
        new["samples"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["burst_write_calls"] == 0 && row["total_write_calls"] == 1),
        "Current memory batching changed"
    );
    let result = json!({
        "kind":"synthetic virtual filesystem; no packets, network, or physical disk","hosts":hosts,"rounds":rounds,"warm":warm,
        "lua_runtime":"mlua Lua 5.4","lupa_version":null,"baseline_ref":baseline_ref,
        "native_policy_profile":if current.contains("zapret_ring_native"){Some(if cfg!(debug_assertions){"debug linked developer policy"}else{"release linked developer policy"})}else{None},
        "lua_heap_note":"Lua heap excludes memory allocated by the Rust policy; real-engine release DLL checks are reported separately.",
        "cpu_note":"Windows process CPU accounting is quantized; zero does not mean zero work.",
        "baseline_sha256":zapret_core::sha256_file(baseline)?.to_ascii_lowercase(),
        "current_sha256":{"autoring.lua":zapret_core::sha256_file(&pkg.join("lua/autoring.lua"))?.to_ascii_lowercase(),
            "ring-store.lua":zapret_core::sha256_file(&pkg.join("lua/ring-store.lua"))?.to_ascii_lowercase()},
        "baseline":old,"current":new,
    });
    zapret_core::atomic_write(output, &serde_json::to_vec_pretty(&result)?)?;
    for name in ["baseline", "current"] {
        let row = &result[name];
        println!(
            "{name}: burst {:.3} ms; flush {:.3} ms; warm {:.3} ms; heap +{:.1} KiB; writes {} -> {}",
            row["median_burst_wall_ms"].as_f64().unwrap(),
            row["median_flush_wall_ms"].as_f64().unwrap(),
            row["median_warm_wall_ms"].as_f64().unwrap(),
            row["median_lua_heap_growth_kib"].as_f64().unwrap(),
            row["samples"][0]["burst_write_calls"],
            row["samples"][0]["total_write_calls"]
        );
    }
    Ok(())
}
