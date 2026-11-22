//! Check UCRT argv ownership and config-file boundaries before replacing C.
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
        .context("Config ownership parent")?
        .join("config-ownership-check");
    fs::create_dir(&directory)?;
    fs::copy(
        shim.join("wordexp.c"),
        directory.join("wordexp_reference.inc"),
    )?;
    let main = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&main)?;
    let start = source
        .find("void config_from_file(")
        .context("Pinned config loader")?;
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("Pinned config loader end")?
        + 3;
    fs::write(
        directory.join("config_file_reference.inc"),
        &source[start..end],
    )?;
    source.replace_range(start..end, "#include \"config_file_windows.inc\"\n");
    let exe = directory.join("config-ownership-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("config_ownership_oracle.c"))
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
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile argv ownership and config boundary comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check native argv allocation and config files",
    )?;
    ensure!(
        result.starts_with("PASS config_ownership "),
        "Incomplete config ownership comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(main, source)?;
    Ok(())
}
