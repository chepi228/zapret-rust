//! Compare Windows entry ordering through the original C and its new adapter.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Engine bootstrap parent")?
        .join("engine-bootstrap-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("static int win_main(")
        .context("Pinned Windows engine entry")?;
    let end = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Windows entry end")?
        + 3;
    fs::write(
        directory.join("engine_bootstrap_reference.inc"),
        &source[first..end],
    )?;
    let exe = directory.join("engine-bootstrap-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("engine_bootstrap_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lole32",
            "-lshell32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile Windows entry and cleanup comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check bootstrap transitions, failures and C adapter",
    )?;
    ensure!(
        result.starts_with("PASS engine_bootstrap "),
        "Incomplete bootstrap comparison"
    );
    let direct = directory.join("windows-engine-bootstrap-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
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
        .arg(shim.join("windows_engine_bootstrap_oracle.c"))
        .arg(object)
        .arg(library)
        .args([
            "-Wl,--gc-sections,--wrap=daemonize",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lole32",
            "-lshell32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&direct);
    tools.run_command(
        &command,
        &directory,
        "Compile the Rust bootstrap entry comparison",
    )?;
    let native = tools.run_command(
        &Command::new(direct),
        &directory,
        "Compare entry snapshots, late callbacks and cleanup order",
    )?;
    ensure!(
        native.starts_with("PASS windows_engine_bootstrap "),
        "Incomplete Rust entry comparison"
    );
    fs::write(output, format!("{result}{native}"))?;
    print!("{result}{native}");
    source.replace_range(first..end, "#include \"engine_bootstrap_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
