//! Compare native identity and calendar conversion, and exercise private event-log handles.
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
        .context("System diagnostic parent")?
        .join("system-diagnostics-check");
    fs::create_dir(&directory)?;
    let exe = directory.join("system-diagnostics-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [&directory, shim, &shim.join("include")] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("system_diagnostics_oracle.c"))
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
        "Compile system identity, calendar and event ownership fixture",
    )?;
    let result = tools.run_command(&Command::new(exe), &directory, "Check system diagnostics")?;
    ensure!(
        result.starts_with("PASS system_identity ")
            && result.contains("PASS system_eventlog ")
            && result.contains("PASS system_calendar "),
        "Incomplete system diagnostic fixture"
    );
    fs::write(output, &result)?;
    print!("{result}");
    Ok(())
}
