//! Native exports exercise post-parse capture decisions without opening WinDivert.
use super::{cli_capture_cases::export, engine_case};
use anyhow::{Result, ensure};
use std::path::Path;
pub(super) fn check(bin: &Path, stock: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let text = export(
        bin,
        stock,
        temporary,
        logs,
        "server-final",
        &[
            "--server".into(),
            "--wf-tcp-in=80".into(),
            "--wf-tcp-out=443".into(),
            "--wf-udp-in=53".into(),
            "--wf-udp-out=4444".into(),
        ],
    )?;
    for part in [
        "tcp.SrcPort == 443",
        "tcp.DstPort == 80",
        "udp.DstPort == 53",
        "udp.SrcPort == 4444",
    ] {
        ensure!(text.contains(part), "Server capture mapping lost {part}");
    }
    let text = export(
        bin,
        stock,
        temporary,
        logs,
        "disabled-final",
        &["--intercept=0".into(), "--wf-raw=tcp".into()],
    )?;
    ensure!(
        text.trim() == "false",
        "Disabled capture retained the raw filter"
    );
    let large = temporary.join("preflight-large-extra.txt");
    std::fs::write(&large, vec![b'x'; 65535])?;
    let directory = temporary.join("preflight-export-directory");
    std::fs::create_dir(&directory)?;
    let invalid = [
        (
            "empty",
            vec![],
            "must specify port or/and partial raw filter",
        ),
        (
            "overflow",
            vec![
                "--wf-tcp-out=443".into(),
                format!("--wf-raw-filter=@{}", large.display()).into(),
            ],
            "could not make filter",
        ),
        (
            "save-directory",
            vec![
                "--wf-tcp-out=443".into(),
                format!("--wf-save={}", directory.display()).into(),
            ],
            "could not save raw filter",
        ),
    ];
    for (name, arguments, diagnostic) in invalid {
        let mut options = vec!["--dry-run".into(), "--wf-dup-check=0".into()];
        options.extend(arguments);
        let text = engine_case(bin, &options, 1, &[])?;
        ensure!(
            text.contains(diagnostic),
            "Capture failure {name} lost its diagnostic"
        );
        zapret_core::atomic_write(
            &logs.join(format!("capture-preflight-{name}.log")),
            text.as_bytes(),
        )?;
    }
    ensure!(
        directory.is_dir() && std::fs::read_dir(&directory)?.next().is_none(),
        "Failed export changed the directory"
    );
    println!(
        "ok real engine: final server/disabled capture, expression overflow and export failures"
    );
    let text = engine_case(
        bin,
        &["--dry-run".into(), "--wf-tcp-out=443".into()],
        0,
        &[],
    )?;
    ensure!(
        text.contains("command line parameters verified"),
        "Dry-run still requires an argument mutex"
    );
    zapret_core::atomic_write(
        &logs.join("capture-preflight-dry-duplicate-default.log"),
        text.as_bytes(),
    )?;
    Ok(6)
}
