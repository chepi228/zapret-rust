//! Real startup rejection and list-load diagnostics, using private files and jobs.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, io::Write, path::Path};
fn run(bin: &Path, logs: &Path, name: &str, args: &[OsString], expected: u32) -> Result<String> {
    let mut options = vec![
        "--dry-run".into(),
        "--intercept=0".into(),
        "--wf-dup-check=0".into(),
    ];
    options.extend_from_slice(args);
    let text = engine_case(bin, &options, expected, &[])?;
    zapret_core::atomic_write(
        &logs.join(format!("startup-validation-{name}.log")),
        text.as_bytes(),
    )?;
    Ok(text)
}
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let auto = temporary.join("startup-auto-данные-é-中.txt");
    const CONTENT: &[u8] = b"example.test\n";
    std::fs::write(&auto, CONTENT)?;
    let text = run(
        bin,
        logs,
        "server-auto",
        &[
            "--server".into(),
            format!("--hostlist-auto={}", auto.display()).into(),
        ],
        1,
    )?;
    ensure!(
        text.contains("autohostlists not supported in server mode")
            && std::fs::read(&auto)? == CONTENT,
        "Server autolist rejection changed"
    );
    let missing = temporary.join("startup-missing.txt");
    let lua = temporary.join("startup-missing.lua");
    for (option, name, diagnostic) in [
        ("hostlist", "missing-hosts", "hostlist"),
        ("ipset", "missing-ips", "ipset"),
    ] {
        let text = run(
            bin,
            logs,
            name,
            &[format!("--{option}={}", missing.display()).into()],
            1,
        )?;
        ensure!(
            text.contains(diagnostic) && text.contains("startup-missing.txt"),
            "Missing {option} lost path evidence"
        );
    }
    let text = run(
        bin,
        logs,
        "missing-script",
        &[format!("--lua-init=@{}", lua.display()).into()],
        1,
    )?;
    ensure!(
        text.contains("LUA file '") && text.contains("not accessible"),
        "Missing Lua script bypassed file validation"
    );
    for (option, name, content, diagnostic) in [
        (
            "hostlist",
            "corrupt-hosts",
            &b"example.test\n"[..],
            "hostlists load failed",
        ),
        (
            "ipset",
            "corrupt-ips",
            &b"192.0.2.0/24\n"[..],
            "ipset load failed",
        ),
    ] {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(content)?;
        let mut bytes = encoder.finish()?;
        let crc = bytes.len() - 8;
        bytes[crc] ^= 1;
        let path = temporary.join(format!("startup-{name}.gz"));
        std::fs::write(&path, &bytes)?;
        let text = run(
            bin,
            logs,
            name,
            &[format!("--{option}={}", path.display()).into()],
            1,
        )?;
        ensure!(
            text.contains(diagnostic) && text.contains("zlib decompression failed"),
            "Corrupt {option} load was not rejected at startup"
        );
    }
    let file = temporary.join("startup-writable-file");
    std::fs::write(&file, b"must remain")?;
    let text = run(
        bin,
        logs,
        "writable-file",
        &[format!("--writable={}", file.display()).into()],
        1,
    )?;
    ensure!(
        text.contains("could not make writable dir for LUA")
            && std::fs::read(&file)? == b"must remain",
        "Writable failure changed the existing file"
    );
    let text = run(bin, logs, "default-profile", &["--debug".into()], 0)?;
    ensure!(
        text.contains("adding low-priority default empty desync profile")
            && text.contains(
                "we have 1 user defined desync profile(s) and default low priority profile 0"
            )
            && text.contains("command line parameters verified"),
        "Default startup profile or count changed"
    );
    println!("ok real engine: startup state validation, list-load failures and default profile");
    Ok(8)
}
