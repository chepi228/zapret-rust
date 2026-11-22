//! Check retry/error behavior against pinned C and actual UCRT files and pipes.
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
        .context("Stdio comparison parent")?
        .join("stdio-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("helpers.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for name in [
        "read_intr",
        "fread_safe",
        "fgets_safe",
        "fill_crypto_random_bytes",
    ] {
        let start = source
            .find(&format!(" {name}("))
            .context("Pinned stream helper")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned stream helper end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("stdio_reference.inc"), reference)?;
    let exe = directory.join("stdio-check.exe");
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
        .arg(shim.join("stdio_oracle.c"))
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
        "Compile UCRT retry and boundary comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check engine stream and RNG helpers",
    )?;
    ensure!(
        result.starts_with("PASS engine_stdio "),
        "Incomplete engine stream comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.push_str("\n#include \"stdio_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
