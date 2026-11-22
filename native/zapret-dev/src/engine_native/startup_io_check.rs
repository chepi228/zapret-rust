//! Compare startup output, then use only private PID files and a private window.
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
        .context("Startup IO parent")?
        .join("startup-io-check");
    fs::create_dir(&directory)?;
    let mut sources = Vec::new();
    for (file, anchor, reference, include) in [
        ("sec.c", "bool writepid(", "startup_pid_reference.inc", None),
        (
            "nfqws.c",
            "static void WinSetIcon(",
            "startup_icon_reference.inc",
            Some("startup_icon_windows.inc"),
        ),
    ] {
        let path = nfq.join(file);
        let mut source = fs::read_to_string(&path)?;
        let first = source.find(anchor).context("Pinned startup IO helper")?;
        let end = first
            + source[first..]
                .find("\n}\n")
                .context("Pinned startup IO helper end")?
            + 3;
        fs::write(directory.join(reference), &source[first..end])?;
        if let Some(include) = include {
            source.replace_range(first..end, &format!("#include \"{include}\"\n"));
            sources.push((path, source));
        }
    }
    let exe = directory.join("startup-io-check.exe");
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
        .arg(shim.join("startup_io_oracle.c"))
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
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile PID output and shared icon comparison",
    )?;
    let mut result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check PID IO failures and bounded icon requests",
    )?;
    ensure!(
        result.starts_with("PASS startup_io "),
        "Incomplete startup IO comparison"
    );
    for (argument, prefix, step) in [
        (
            "--real-pid",
            "PASS startup_pid_real ",
            "Check only private Unicode PID file and held handle",
        ),
        (
            "--real-icon",
            "PASS startup_icon_real ",
            "Check responsive and blocked private message-only window",
        ),
    ] {
        let mut run = Command::new(&exe);
        run.arg(argument);
        let checked = tools.run_command(&run, &directory, step)?;
        ensure!(
            checked.starts_with(prefix),
            "Incomplete real startup IO check"
        );
        result.push_str(&checked);
    }
    fs::write(output, &result)?;
    print!("{result}");
    for (path, source) in sources {
        fs::write(path, source)?;
    }
    Ok(())
}
