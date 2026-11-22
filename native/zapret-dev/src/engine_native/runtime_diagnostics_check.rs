//! Verify native log calls before selecting their Rust implementations.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const REPORT_ABI: &str = "#include \"windows_engine_reports_abi.h\"\n\n";
const LOG_SINK_ABI: &str = "#include \"runtime_log_windows.h\"\n";

fn replace(source: &mut String, start: &str, next: &str, selected: &str) -> Result<String> {
    let first = source
        .find(start)
        .with_context(|| format!("Pinned log start: {start}"))?;
    let last = first
        + source[first..]
            .find(next)
            .with_context(|| format!("Pinned log end: {next}"))?;
    let previous = source[first..last].to_owned();
    source.replace_range(first..last, selected);
    Ok(previous)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    objects: [&Path; 2],
    output: &Path,
) -> Result<()> {
    let [idle_object, reports_object] = objects;
    let directory = nfq
        .parent()
        .context("Runtime diagnostics parent")?
        .join("runtime-diagnostics-check");
    fs::create_dir(&directory)?;
    let auto_path = shim.join("auto_hostlist_windows.inc");
    let loop_path = shim.join("engine_loop_windows.inc");
    let prep_path = shim.join("capture_preflight_windows.inc");
    let cache_path = shim.join("packet_cache_windows.inc");
    let reassembly_path = shim.join("reassembly_windows.inc");
    let mut auto = fs::read_to_string(&auto_path)?;
    let mut capture = fs::read_to_string(&loop_path)?;
    let mut prepare = fs::read_to_string(&prep_path)?;
    let mut cache = fs::read_to_string(&cache_path)?;
    let mut reassembly = fs::read_to_string(&reassembly_path)?;

    let idle_start = capture
        .find("static bool loop_quitting(void)")
        .context("Pinned idle start")?;
    let idle_entry = capture[idle_start..]
        .find("void NoInterceptLoop(")
        .context("Pinned idle entry")?
        + idle_start;
    let idle_end = capture[idle_entry..]
        .find("\n}\n")
        .context("Pinned idle entry end")?
        + idle_entry
        + 3;
    fs::write(
        directory.join("engine_idle_reference.inc"),
        &capture[idle_start..idle_end],
    )?;

    let context_end = "} zapret_autolist_context;";
    let context = auto
        .find(context_end)
        .context("Pinned autohostlist context")?
        + context_end.len();
    let mut reference = auto[..context].to_owned();
    reference.push_str("\n\n");
    reference.push_str(&replace(
        &mut auto,
        "static void autolist_report(",
        "static const zapret_autolist_ops autolist_ops",
        REPORT_ABI,
    )?);
    reference.push_str(&replace(
        &mut capture,
        "static void loop_idle_report(",
        "void NoInterceptLoop(",
        REPORT_ABI,
    )?);
    reference.push_str(&replace(
        &mut capture,
        "static void loop_report(",
        "static const zapret_capture_ops capture_ops",
        "",
    )?);
    reference.push_str(&replace(
        &mut prepare,
        "static void native_capture_prepare_report(",
        "static zapret_capture_prepare_result native_capture_prepare(",
        REPORT_ABI,
    )?);
    let status = replace(
        &mut prepare,
        "    switch(result.status){",
        "    return result;",
        "    native_capture_prepare_status(result.status,result.error,save);\n",
    )?;
    reference.push_str("static void capture_prepare_status(uint32_t status, uint32_t error, const char *save)\n{\n");
    reference.push_str("    const struct { uint32_t status, error; } result = {status, error};\n");
    reference.push_str(&status);
    reference.push_str("}\n");

    let cache_context_end = "} zapret_packet_cache_context;";
    let cache_context = cache
        .find(cache_context_end)
        .context("Pinned packet cache report context")?
        + cache_context_end.len();
    reference.push_str(&cache[..cache_context]);
    reference.push_str("\n\n");
    reference.push_str(LOG_SINK_ABI);
    reference.push_str(&replace(
        &mut cache,
        "void zapret_packet_cache_report(",
        "static const zapret_packet_cache_ops packet_cache_ops",
        REPORT_ABI,
    )?);
    ensure!(
        cache.matches(LOG_SINK_ABI).count() == 1,
        "Pinned cache log ABI include"
    );
    cache = cache.replacen(LOG_SINK_ABI, "", 1);
    reference.push_str(&replace(
        &mut reassembly,
        LOG_SINK_ABI,
        "static const zapret_reassembly_ops reassembly_ops",
        REPORT_ABI,
    )?);
    fs::write(
        directory.join("runtime_diagnostics_reference.inc"),
        reference,
    )?;

    let mut results = String::new();
    for direct in [false, true] {
        let (fixture, executable, marker, object) = if direct {
            (
                "windows_engine_idle_oracle.c",
                "windows-engine-idle-check.exe",
                "PASS windows_engine_idle ",
                idle_object,
            )
        } else {
            (
                "runtime_diagnostics_oracle.c",
                "runtime-diagnostics-check.exe",
                "PASS runtime_diagnostics ",
                reports_object,
            )
        };
        let exe = directory.join(executable);
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_FILE_OFFSET_BITS=64",
            "-D_POSIX_C_SOURCE=200809L",
            "-DLUAJIT",
            "-Wno-macro-redefined",
        ]);
        for include in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            lua,
            nfq,
        ] {
            command.arg(format!("-I{}", include.display()));
        }
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join(fixture));
        if direct {
            command.args([
                "-fexceptions",
                "-Wl,--wrap=nanosleep64,--wrap=zapret_timer_next_dirty",
            ]);
        } else {
            command.arg("-Wl,--wrap=wf_error");
        }
        command
            .arg(object)
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(
            &command,
            &directory,
            "Compile pinned C and Rust runtime diagnostics",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare live report callbacks, log output and native error order",
        )?;
        ensure!(
            result.starts_with(marker),
            "Incomplete runtime diagnostic comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    fs::write(auto_path, auto)?;
    fs::write(loop_path, capture)?;
    fs::write(prep_path, prepare)?;
    fs::write(cache_path, cache)?;
    fs::write(reassembly_path, reassembly)?;
    Ok(())
}
