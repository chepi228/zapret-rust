//! Actual list option I/O and anonymous entry reuse in private engine processes.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, io::Write, path::Path};

fn run(bin: &Path, args: &[OsString], expected: u32, logs: &Path, name: &str) -> Result<String> {
    let mut arguments = vec![
        "--dry-run".into(),
        "--intercept=0".into(),
        "--wf-dup-check=0".into(),
    ];
    arguments.extend_from_slice(args);
    let text = engine_case(bin, &arguments, expected, &[])?;
    zapret_core::atomic_write(&logs.join(format!("cli-list-{name}.log")), text.as_bytes())?;
    Ok(text)
}

pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    const CONTENT: &[u8] = b"example.test\n";
    let plain = temporary.join("auto-existing-данные-é-中.txt");
    std::fs::write(&plain, CONTENT)?;
    let text = run(
        bin,
        &[format!("--hostlist-auto={}", plain.display()).into()],
        0,
        logs,
        "auto-existing",
    )?;
    ensure!(
        std::fs::read(&plain)? == CONTENT && text.contains("Loaded 1 hosts"),
        "Automatic hostlist did not preserve existing data"
    );

    let created = temporary.join("auto-new-данные-é-中.txt");
    run(
        bin,
        &[format!("--hostlist-auto={}", created.display()).into()],
        0,
        logs,
        "auto-new",
    )?;
    ensure!(
        std::fs::metadata(&created)?.len() == 0,
        "New automatic hostlist was not empty"
    );

    let zipped = temporary.join("auto-zipped.txt.gz");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(CONTENT)?;
    let bytes = encoder.finish()?;
    std::fs::write(&zipped, &bytes)?;
    let text = run(
        bin,
        &[format!("--hostlist-auto={}", zipped.display()).into()],
        1,
        logs,
        "auto-gzip",
    )?;
    ensure!(
        text.contains("gzipped auto hostlists are not supported")
            && std::fs::read(&zipped)? == bytes,
        "Gzip automatic hostlist was accepted or changed"
    );

    let second = temporary.join("auto-duplicate-must-not-exist.txt");
    let text = run(
        bin,
        &[
            format!("--hostlist-auto={}", plain.display()).into(),
            format!("--hostlist-auto={}", second.display()).into(),
        ],
        1,
        logs,
        "auto-duplicate",
    )?;
    ensure!(
        text.contains("only one auto hostlist per profile")
            && !second.exists()
            && std::fs::read(&plain)? == CONTENT,
        "Duplicate automatic hostlist performed I/O"
    );

    let skipped = temporary.join("skipped-list-must-not-exist.txt");
    let mut args = vec!["--skip".into()];
    for option in [
        "hostlist",
        "hostlist-exclude",
        "hostlist-auto",
        "ipset",
        "ipset-exclude",
    ] {
        args.push(format!("--{option}={}", skipped.display()).into());
    }
    for option in [
        "hostlist-domains",
        "hostlist-exclude-domains",
        "ipset-ip",
        "ipset-exclude-ip",
    ] {
        args.push(format!("--{option}=invalid::value").into());
    }
    args.extend([
        "--new=kept".into(),
        "--hostlist-domains=kept.example".into(),
    ]);
    run(bin, &args, 0, logs, "skipped")?;
    ensure!(!skipped.exists(), "Skipped list options touched a file");

    let text = run(
        bin,
        &[
            "--debug".into(),
            "--name=repeated".into(),
            "--hostlist-domains=first.example".into(),
            "--hostlist-domains=second.example".into(),
            "--hostlist-exclude-domains=blocked.example".into(),
            "--hostlist-exclude-domains=blocked2.example".into(),
            "--ipset-ip=192.0.2.0/24".into(),
            "--ipset-ip=2001:db8::/32".into(),
            "--ipset-exclude-ip=198.51.100.0/24".into(),
            "--ipset-exclude-ip=2001:db8:1::/48".into(),
        ],
        0,
        logs,
        "anonymous-repeated",
    )?;
    for role in [
        "include fixed hostlist",
        "exclude fixed hostlist",
        "include fixed ipset",
        "exclude fixed ipset",
    ] {
        let prefix = format!("profile 1 (repeated) {role}");
        ensure!(
            text.lines()
                .filter(|line| line.starts_with(&prefix))
                .count()
                == 1,
            "Anonymous cache role was lost or duplicated: {role}"
        );
    }
    println!(
        "ok real engine: automatic and skipped lists, duplicate rejection and anonymous reuse"
    );
    Ok(6)
}
