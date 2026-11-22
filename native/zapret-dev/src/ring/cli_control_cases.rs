//! Exercise common control parameters through the actual engine and owned arguments.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};
fn run(bin: &Path, logs: &Path, name: &str, args: &[&str], expected: u32) -> Result<String> {
    let mut options: Vec<OsString> = vec!["--intercept=0".into(), "--wf-dup-check=0".into()];
    options.extend(args.iter().map(OsString::from));
    let text = engine_case(bin, &options, expected, &[])?;
    zapret_core::atomic_write(
        &logs.join(format!("cli-control-{name}.log")),
        text.as_bytes(),
    )?;
    Ok(text)
}
pub(super) fn check(bin: &Path, logs: &Path) -> Result<usize> {
    let text = run(
        bin,
        logs,
        "templates",
        &[
            "--dry-run",
            "--debug",
            "--template=shared",
            "--cookie=template-cookie",
            "--payload=http_req",
            "--out-range=n1-n2",
            "--lua-desync=template_func",
            "--new=first",
            "--cookie=first-cookie",
            "--hostlist-domains=first.example",
            "--import=shared",
            "--new=second",
            "--import=shared",
            "--name=renamed",
            "--hostlist-domains=second.example",
            "--lua-desync=local_func",
        ],
        0,
    )?;
    for part in [
        "profile 1 (first) lua template_func( range_in=x0-x0 range_out=n1-n2 payload_type= http_req)",
        "profile 2 (renamed) lua template_func( range_in=x0-x0 range_out=n1-n2 payload_type= http_req)",
        "profile 2 (renamed) lua local_func( range_in=x0-x0 range_out=a0-a0 payload_type= all)",
    ] {
        ensure!(text.contains(part), "Profile control lost {part}");
    }
    for profile in [
        "profile 1 (first) include fixed hostlist",
        "profile 2 (renamed) include fixed hostlist",
    ] {
        ensure!(
            text.lines()
                .filter(|line| line.starts_with(profile))
                .count()
                == 1,
            "Anonymous profile state leaked across new"
        );
    }
    let text = run(
        bin,
        logs,
        "skipped",
        &[
            "--dry-run",
            "--debug",
            "--name=discarded",
            "--skip",
            "--new=kept",
            "--lua-desync=kept_func",
        ],
        0,
    )?;
    ensure!(
        text.contains("we have 1 user defined desync profile(s)")
            && text.contains("profile 1 (kept) lua kept_func("),
        "Skipped profile was retained or renumbered"
    );
    let text = run(bin, logs, "version", &["--version"], 0)?;
    ensure!(
        text.contains("lua_compat_ver"),
        "Version request did not print build identity"
    );
    let text = run(
        bin,
        logs,
        "comment-dry",
        &["--comment=данные-é-中", "--dry-run"],
        0,
    )?;
    ensure!(
        text.contains("command line parameters verified"),
        "Comment or dry-run flow failed"
    );
    let text = run(
        bin,
        logs,
        "duplicate-template",
        &[
            "--dry-run",
            "--template=duplicate",
            "--new",
            "--template=duplicate",
            "--new",
        ],
        1,
    )?;
    ensure!(
        text.contains("template 'duplicate' already present"),
        "Duplicate template diagnostic lost"
    );
    let text = run(
        bin,
        logs,
        "missing-import",
        &["--dry-run", "--import=missing-template"],
        1,
    )?;
    ensure!(
        text.contains("template 'missing-template' not found"),
        "Missing template diagnostic lost"
    );
    println!("ok real engine: profile control, templates, reset, version and dry-run");
    Ok(6)
}
