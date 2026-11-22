//! Check writable setup through actual CLI parsing before any capture is opened.
use super::engine_case;
use anyhow::{Result, ensure};
use std::path::Path;
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let unicode = temporary.join("writable-данные-é-中");
    let occupied = temporary.join("writable-occupied.bin");
    const SENTINEL: &[u8] = b"native-writable-medium-sentinel\n";
    std::fs::write(&occupied, SENTINEL)?;
    let mut parent = temporary.to_owned();
    for _ in 0..4 {
        parent = parent.join("long-writable-parent-0123456789-abcdefghijklmnop");
        std::fs::create_dir(&parent)?;
    }
    let long = parent.join("длинный-каталог-é-中");
    ensure!(
        long.as_os_str().len() > 260,
        "Short writable long-path fixture"
    );
    for (name, path, exit, expected) in [
        (
            "unicode-new",
            &unicode,
            0,
            "command line parameters verified",
        ),
        (
            "unicode-existing",
            &unicode,
            0,
            "command line parameters verified",
        ),
        (
            "occupied-file",
            &occupied,
            1,
            "could not make writable dir for LUA",
        ),
        ("long-new", &long, 0, "command line parameters verified"),
    ] {
        let text = engine_case(
            bin,
            &[
                "--dry-run".into(),
                "--intercept=0".into(),
                "--wf-dup-check=0".into(),
                format!("--writable={}", path.display()).into(),
            ],
            exit,
            &[],
        )?;
        ensure!(
            text.contains(expected),
            "Incomplete native writable case: {name}"
        );
        zapret_core::atomic_write(&logs.join(format!("writable-{name}.log")), text.as_bytes())?;
    }
    ensure!(
        unicode.is_dir() && long.is_dir() && std::fs::read(&occupied)? == SENTINEL,
        "Writable setup changed a file or omitted a directory"
    );
    println!("ok real engine: native writable setup and existing-file rejection");
    Ok(4)
}
