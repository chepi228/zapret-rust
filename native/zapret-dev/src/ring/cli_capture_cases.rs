//! Capture filter exports compiled by the real WinDivert helper, without interception.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};

pub(super) fn export(
    bin: &Path,
    stock: &Path,
    temporary: &Path,
    logs: &Path,
    name: &str,
    args: &[OsString],
) -> Result<String> {
    let path = temporary.join(format!("capture-{name}.txt"));
    let mut arguments = vec![
        "--dry-run".into(),
        "--wf-dup-check=0".into(),
        format!("--wf-save={}", path.display()).into(),
    ];
    arguments.extend_from_slice(args);
    let text = engine_case(bin, &arguments, 0, &[])?;
    let bytes = std::fs::read(&path)?;
    zapret_platform::validate_capture_filter(stock, &bytes)?;
    zapret_core::atomic_write(
        &logs.join(format!("cli-capture-{name}.log")),
        text.as_bytes(),
    )?;
    Ok(String::from_utf8(bytes)?)
}
pub(super) fn check(bin: &Path, stock: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let args: Vec<OsString> = [
        "--wf-iface=12.34",
        "--wf-l3=ipv4",
        "--wf-tcp-in=80,443",
        "--wf-tcp-out=1-65535",
        "--wf-udp-in=53",
        "--wf-udp-out=443",
        "--wf-icmp-in=8",
        "--wf-icmp-out=0",
        "--wf-ipp-in=17",
        "--wf-ipp-out=6",
        "--wf-tcp-empty",
        "--wf-filter-lan=0",
        "--wf-filter-loopback=0",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let text = export(bin, stock, temporary, logs, "generated", &args)?;
    for part in [
        "ifIdx=12",
        "subIfIdx=34",
        "tcp.SrcPort",
        "tcp.DstPort",
        "udp.SrcPort",
        "udp.DstPort",
    ] {
        ensure!(text.contains(part), "Capture option lost {part}");
    }

    let raw = temporary.join("capture-данные-é-中.txt");
    std::fs::write(&raw, b"ip and tcp")?;
    let text = export(
        bin,
        stock,
        temporary,
        logs,
        "raw-file",
        &[format!("--wf-raw=@{}", raw.display()).into()],
    )?;
    ensure!(text.trim() == "ip and tcp", "Raw file was changed");
    let part = temporary.join("capture-part-данные-é-中.txt");
    std::fs::write(&part, b"tcp.DstPort==443")?;
    let filter = temporary.join("capture-extra-данные-é-中.txt");
    std::fs::write(&filter, b"ip")?;
    let text = export(
        bin,
        stock,
        temporary,
        logs,
        "part-file",
        &[
            "--wf-tcp-out=80".into(),
            format!("--wf-raw-part=@{}", part.display()).into(),
            format!("--wf-raw-filter=@{}", filter.display()).into(),
        ],
    )?;
    ensure!(
        text.contains("tcp.DstPort==443"),
        "Raw part was not retained"
    );
    let mut count = 3;
    let large = temporary.join("capture-oversized.txt");
    std::fs::write(&large, vec![b'x'; 65536])?;
    let failures: Vec<(&str, OsString, &str)> = vec![
        (
            "empty-iface",
            "--wf-iface=".into(),
            "bad value for --wf-iface",
        ),
        (
            "space-iface",
            "--wf-iface= \t".into(),
            "bad value for --wf-iface",
        ),
        (
            "large-raw",
            format!("--wf-raw=@{}", large.display()).into(),
            "is too long",
        ),
        (
            "large-part",
            format!("--wf-raw-part=@{}", large.display()).into(),
            "is too long",
        ),
        (
            "large-filter",
            format!("--wf-raw-filter=@{}", large.display()).into(),
            "is too long",
        ),
        (
            "long-save",
            format!("--wf-save={}", "x".repeat(256)).into(),
            "is too long",
        ),
        (
            "ssid-number",
            "--ssid-filter-neg=invalid".into(),
            "bad value for --ssid-filter-neg",
        ),
        (
            "nlm-number",
            "--nlm-filter-neg=2147483648".into(),
            "bad value for --nlm-filter-neg",
        ),
    ];
    for (name, option, diagnostic) in failures {
        let text = engine_case(
            bin,
            &[
                "--dry-run".into(),
                "--intercept=0".into(),
                "--wf-dup-check=0".into(),
                option,
            ],
            1,
            &[],
        )?;
        ensure!(
            text.contains(diagnostic),
            "Rejected capture option {name} lost its diagnostic"
        );
        zapret_core::atomic_write(
            &logs.join(format!("cli-capture-{name}.log")),
            text.as_bytes(),
        )?;
        count += 1;
    }
    let text = engine_case(
        bin,
        &[
            "--dry-run".into(),
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            "--ssid-filter=данные-é-中,café".into(),
            "--ssid-filter-neg".into(),
            "--nlm-filter=fixture-one,fixture-two".into(),
            "--nlm-filter-neg=0".into(),
        ],
        0,
        &[],
    )?;
    zapret_core::atomic_write(
        &logs.join("cli-capture-network-filters.log"),
        text.as_bytes(),
    )?;
    println!("ok real engine: capture option exports, private Unicode files and size rejection");
    Ok(count + 1)
}
