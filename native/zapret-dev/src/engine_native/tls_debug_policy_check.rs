//! Gate complete TLS diagnostic decoding before replacing the pinned C bodies.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    diagnostics: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let parent = nfq.parent().context("TLS diagnostics parent")?;
    let directory = parent.join("tls-debug-policy-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("static void TLSDebugHandshake(")
        .context("Pinned TLS debug start")?;
    let last = first
        + source[first..]
            .find("static void packet_debug(")
            .context("Pinned TLS debug end")?;
    fs::write(
        directory.join("tls_debug_reference.inc"),
        &source[first..last],
    )?;
    let exe = directory.join("tls-debug-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
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
        .arg(shim.join("tls_debug_policy_oracle.c"))
        .arg(diagnostics)
        .arg(library)
        .args([
            "-Wl,--gc-sections,--wrap=IsTLSHandshakeServerHello,--wrap=TLSFindExtInHandshake",
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
        "Compile complete TLS diagnostics comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Compare TLS diagnostics and deferred borrowed reads",
    )?;
    ensure!(
        result.starts_with("PASS tls_debug "),
        "Incomplete TLS diagnostic comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(first..last, "#include \"tls_debug_policy_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
