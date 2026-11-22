//! Check CSV token order, pool callbacks and atomic string-list failures.
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
        .context("Config list parent")?
        .join("config-lists-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static bool parse_domain_list(")
        .context("Pinned domain-list parser")?;
    let end = source[start..]
        .find("static void BlobDebug(")
        .context("Pinned comma list end")?
        + start;
    fs::write(
        directory.join("config_lists_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("config-lists-check.exe");
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
        .arg(shim.join("config_lists_oracle.c"))
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
        "Compile startup comma-list comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check immutable comma-list inputs",
    )?;
    ensure!(
        result.starts_with("PASS config_lists "),
        "Incomplete comma-list comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"config_lists_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
