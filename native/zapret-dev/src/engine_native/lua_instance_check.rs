//! Compare raw instance formatting and prove caller-buffer boundaries.
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
        .context("Lua instance parent")?
        .join("lua-instance-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("void desync_instance(")
        .context("Pinned instance formatter")?;
    let end = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned instance formatter end")?
        + 3;
    fs::write(
        directory.join("lua_instance_reference.inc"),
        &source[first..end],
    )?;
    let exe = directory.join("lua-instance-check.exe");
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
        .arg(shim.join("lua_instance_oracle.c"))
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
        "Compile Lua instance bytes and guard-page comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare instance names and guarded C buffer boundaries",
    )?;
    ensure!(
        result.starts_with("PASS lua_instance "),
        "Incomplete instance comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(first..end, "#include \"lua_instance_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
