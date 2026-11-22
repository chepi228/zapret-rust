//! Check writable setup failures before publishing the path to Lua.
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
        .context("Writable check parent")?
        .join("writable-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("bool make_writable_dir(")
        .context("Pinned writable directory helper")?;
    let end = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned writable helper end")?
        + 3;
    fs::write(
        directory.join("writable_reference.inc"),
        &source[first..end],
    )?;
    let exe = directory.join("writable-check.exe");
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
        .arg(shim.join("writable_oracle.c"))
        .arg(shim.join("win_files.c"))
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
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(&command, &directory, "Compile writable setup comparison")?;
    let mut result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check writable truncation, type and publication failures",
    )?;
    ensure!(
        result.starts_with("PASS writable "),
        "Incomplete writable comparison"
    );
    let mut run = Command::new(&exe);
    run.arg("--real");
    let checked = tools.run_command(
        &run,
        &directory,
        "Check only private Unicode and long writable directories",
    )?;
    ensure!(
        checked.starts_with("PASS writable_real "),
        "Incomplete real writable check"
    );
    result.push_str(&checked);
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(first..end, "#include \"writable_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
