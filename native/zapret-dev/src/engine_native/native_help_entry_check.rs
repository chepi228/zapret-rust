//! Complete original/new help gate; no selected source is published before PASS.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Help entry parent")?
        .join("native-help-entry-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let original = fs::read_to_string(&path)?;
    let start = original
        .find("static void exithelp(")
        .context("Original help entry")?;
    let end = start
        + original[start..]
            .find("\n}\n")
            .context("Original help end")?
        + 3;
    fs::write(
        directory.join("native_help_reference.inc"),
        &original[start..end],
    )?;
    let exe = directory.join("native-help-entry-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
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
        nfq,
        &nfq.join("windows"),
        lua,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("native_help_entry_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile complete Windows help entry oracle",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare full help bytes/defaults/bounded aggregation and native exits",
    )?;
    ensure!(
        result.starts_with("PASS native_help_entry "),
        "Incomplete help entry comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let mut selected = original;
    selected.replace_range(start..end, "#include \"native_help_entry_windows.inc\"\n");
    fs::write(path, selected)?;
    Ok(())
}
