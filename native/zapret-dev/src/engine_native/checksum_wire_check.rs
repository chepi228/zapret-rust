//! Compare final wire bytes through the direct Rust checksum header.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Wire checksum parent")?
        .join("checksum-wire-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("checksum.c");
    fs::copy(&path, directory.join("checksum_wire_reference.inc"))?;
    let exe = directory.join("checksum-wire-check.exe");
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
        .arg(shim.join("checksum_wire_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile direct Rust checksum ABI comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check final IPv4 TCP UDP and ICMP checksums",
    )?;
    ensure!(
        result.starts_with("PASS checksum_wire "),
        "Incomplete wire checksum comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, "#include \"checksum_bridge_fixture.inc\"\n")?;
    Ok(())
}
