//! Compare the actual main validation block before routing its decisions to Rust.
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
        .context("Startup validation source parent")?
        .join("startup-validation-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("\tDLOG(\"adding low-priority default empty desync profile")
        .context("Pinned startup validation start")?;
    let end = start
        + source[start..]
            .find("\n#ifdef ZAPRET_WINDOWS\n\tif (params.intercept)")
            .context("Pinned startup validation end")?;
    fs::write(
        directory.join("startup_validation_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("startup-validation-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
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
        .arg(shim.join("startup_validation_oracle.c"))
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
        "Compile startup validation order and ownership comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare startup defaults, file failures, template lifetimes and C adapter",
    )?;
    ensure!(
        result.starts_with("PASS startup_validation "),
        "Incomplete startup validation comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end,"\tif(!native_startup_validate(profile_flow.count,profile_flow.template_count))exit_clean(1);\n");
    let include = "#include \"cli_control_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned startup validation include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"startup_validation_windows.inc\""),
    );
    fs::write(path, source)?;
    Ok(())
}
