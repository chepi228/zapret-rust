//! Compile the pinned batch dispatcher together with the Rust and Win32 checks.
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
        .context("Pinned engine source parent")?
        .join("engine-loop-check");
    fs::create_dir(&directory)?;
    let main = fs::read_to_string(nfq.join("nfqws.c"))?;
    let start = main
        .find("\t\t\tfor (n=0, packet=packets, left = len")
        .context("Missing pinned WinDivert batch loop")?;
    let end = main[start..]
        .find("\n\t\t}\n\t}\nex:")
        .context("Missing pinned WinDivert batch boundary")?;
    fs::write(
        directory.join("engine_loop_reference.inc"),
        &main[start..start + end],
    )?;

    let executable = directory.join("engine-loop-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wno-macro-redefined",
    ]);
    for path in [
        &directory,
        shim,
        &shim.join("include"),
        nfq,
        &nfq.join("windows"),
    ] {
        command.arg(format!("-I{}", path.display()));
    }
    tools.run_command(
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("engine_loop_oracle.c"))
            .arg(shim.join("windivert_receive_oracle.c"))
            .arg(library)
            .args([
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&executable),
        &directory,
        "Compile packet dispatch and overlapped receive checks",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare pinned packet dispatch and exercise local overlapped reads",
    )?;
    ensure!(
        result.lines().count() == 2 && result.lines().all(|line| line.starts_with("PASS ")),
        "Engine loop checks did not finish"
    );
    fs::write(output, &result)?;
    print!("{result}");
    Ok(())
}
