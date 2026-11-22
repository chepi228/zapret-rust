//! Exercise config ownership through the real native executable without capture.
use super::engine_case;
use anyhow::{Result, ensure};
use std::path::Path;

pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let basic = b"--dry-run --intercept=0 --wf-dup-check=0";
    let mut exact = basic.to_vec();
    exact.resize(16_381, b' ');
    let mut oversized = exact.clone();
    oversized.push(b' ');
    for (name, data, exit, expected) in [
        (
            "plain",
            basic.to_vec(),
            0,
            "command line parameters verified",
        ),
        (
            "unicode-multiline",
            "--dry-run\r\n--intercept=0\t--wf-dup-check=0 --comment=\"русский é 中\""
                .as_bytes()
                .to_vec(),
            0,
            "command line parameters verified",
        ),
        (
            "embedded-nul",
            [basic.as_slice(), b"\0 ignored 'broken"].concat(),
            0,
            "command line parameters verified",
        ),
        (
            "exact-boundary",
            exact,
            0,
            "command line parameters verified",
        ),
        ("oversized", oversized, 1, "exceeds 16381 bytes"),
        (
            "broken-quote",
            [basic.as_slice(), b" 'broken"].concat(),
            1,
            "failed to split command line options from file",
        ),
    ] {
        let path = temporary.join(format!("config-{name}-данные-é-中.txt"));
        std::fs::write(&path, &data)?;
        let text = engine_case(bin, &[format!("@{}", path.display()).into()], exit, &[])?;
        ensure!(
            text.contains(expected),
            "Native config case did not finish as expected: {name}"
        );
        zapret_core::atomic_write(&logs.join(format!("config-{name}.log")), text.as_bytes())?;
    }
    for (name, path) in [
        ("missing", temporary.join("missing-config.txt")),
        ("directory", temporary.to_owned()),
    ] {
        let text = engine_case(bin, &[format!("@{}", path.display()).into()], 1, &[])?;
        ensure!(
            text.contains("could not load config file"),
            "Native config read failure was not reported: {name}"
        );
        zapret_core::atomic_write(&logs.join(format!("config-{name}.log")), text.as_bytes())?;
    }
    println!("ok real engine: native config ownership and size boundaries");
    Ok(8)
}
