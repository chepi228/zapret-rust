//! Mixed option categories and final startup exits through the real CLI.
use super::engine_case;
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, fs, path::Path};
fn run(bin: &Path, logs: &Path, name: &str, args: &[OsString], code: u32) -> Result<String> {
    let text =
        engine_case(bin, args, code, &[]).with_context(|| format!("Main entry fixture {name}"))?;
    zapret_core::atomic_write(
        &logs.join(format!("engine-entry-{name}.log")),
        text.as_bytes(),
    )?;
    Ok(text)
}
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let directory = temporary.join("engine-entry-данные");
    fs::create_dir(&directory)?;
    let export = directory.join("фильтр.txt");
    let text = run(
        bin,
        logs,
        "export-before-dry",
        &[
            "--dry-run".into(),
            "--debug".into(),
            "--wf-dup-check=0".into(),
            "--wf-tcp-out=443".into(),
            format!("--wf-save={}", export.display()).into(),
            "--lua-init=error('entry must stay unused')".into(),
        ],
        0,
    )?;
    ensure!(
        fs::read_to_string(&export)?.contains("tcp.DstPort == 443"),
        "Main entry did not export its filter"
    );
    ensure!(
        !text.contains("command line parameters verified") && !text.contains("LUA INIT DONE"),
        "Filter export reached later startup phases"
    );
    let missing = directory.join("отсутствует.lua");
    let text = run(
        bin,
        logs,
        "validate-before-export",
        &[
            "--dry-run".into(),
            "--debug".into(),
            "--wf-dup-check=0".into(),
            "--wf-tcp-out=443".into(),
            format!("--wf-save={}", directory.display()).into(),
            format!("--lua-init=@{}", missing.display()).into(),
        ],
        1,
    )?;
    ensure!(
        text.contains("not accessible") && !text.contains("could not save raw filter"),
        "Capture preparation ran before Lua file validation"
    );
    for (name, options, expected, absent) in [
        (
            "numeric-first",
            ["--ipcache-lifetime=bad", "--import=entry_missing"],
            "invalid numeric value for --ipcache-lifetime",
            "template 'entry_missing' not found",
        ),
        (
            "control-first",
            ["--import=entry_missing", "--ipcache-lifetime=bad"],
            "template 'entry_missing' not found",
            "invalid numeric value for --ipcache-lifetime",
        ),
    ] {
        let mut args: Vec<OsString> = vec!["--intercept=0".into(), "--wf-dup-check=0".into()];
        args.extend(options.into_iter().map(Into::into));
        let text = run(bin, logs, name, &args, 1)?;
        ensure!(
            text.contains(expected) && !text.contains(absent),
            "Main entry changed argument error order for {name}"
        );
    }
    let text = run(
        bin,
        logs,
        "negative-network-flags",
        &[
            "--dry-run".into(),
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            "--ssid-filter-neg".into(),
            "--nlm-filter-neg=1".into(),
            "--comment=данные".into(),
        ],
        0,
    )?;
    ensure!(
        text.contains("command line parameters verified"),
        "Negative network flags reached the numeric validator"
    );
    const SCRIPT: &str = "assert(entry_payload==string.char(0,65,255)); function entry_one()end; function entry_two()end; ENTRY_KEEP=newproxy(true); getmetatable(ENTRY_KEEP).__gc=function() print('ok mixed entry closed'); io.stdout:flush() end; print('ok mixed entry ready'); io.stdout:flush()";
    let text = run(
        bin,
        logs,
        "mixed-normal",
        &[
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            "--debug".into(),
            "--ipcache-lifetime=321".into(),
            "--name=entry-first".into(),
            "--lua-desync=entry_one".into(),
            "--new=entry-second".into(),
            "--lua-desync=entry_two".into(),
            "--blob=entry_payload:0x0041ff".into(),
            format!("--lua-init={SCRIPT}").into(),
        ],
        0,
    )?;
    for expected in [
        "profile 1 (entry-first) lua entry_one(",
        "profile 2 (entry-second) lua entry_two(",
        "ipcache lifetime 321s",
        "LUA INIT DONE",
        "LUA SHUTDOWN",
    ] {
        ensure!(text.contains(expected), "Mixed main entry lost {expected}");
    }
    for marker in ["ok mixed entry ready", "ok mixed entry closed"] {
        ensure!(
            text.lines().any(|line| line.trim() == marker),
            "Mixed main entry lost {marker}"
        );
    }
    println!(
        "ok real engine: mixed option routing, first-error order, negative flags, filter/dry exits and final VM cleanup"
    );
    Ok(6)
}
