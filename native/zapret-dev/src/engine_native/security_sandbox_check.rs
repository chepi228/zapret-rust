//! Check Job ownership and process transition ordering without a live driver.
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
        .context("Security sandbox parent")?
        .join("security-sandbox-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("BOOL JobSandbox(")
        .context("Pinned Job sandbox")?;
    for (anchor, file) in [
        ("BOOL JobSandbox(", "security_job_reference.inc"),
        ("bool win_sandbox(", "security_sandbox_reference.inc"),
    ] {
        let start = source
            .find(anchor)
            .context("Pinned process sandbox helper")?;
        let end = start
            + source[start..]
                .find("\n}\n")
                .context("Pinned sandbox helper end")?
            + 3;
        fs::write(directory.join(file), &source[start..end])?;
        source.replace_range(start..end, "");
    }
    let exe = directory.join("security-sandbox-check.exe");
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
        .arg(shim.join("security_sandbox_oracle.c"))
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
    tools.run_command(
        &command,
        &directory,
        "Compile Job limits and sandbox transition comparison",
    )?;
    let mut result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check sandbox ordering, resource ownership and concurrency",
    )?;
    ensure!(
        result.starts_with("PASS security_sandbox "),
        "Incomplete sandbox comparison"
    );
    for (argument, prefix, step) in [
        (
            "--real",
            "PASS security_sandbox_real ",
            "Check only private process Job and rejected child",
        ),
        (
            "--real-transition",
            "PASS security_sandbox_transition ",
            "Restrict only the private fixture process and check repeated calls",
        ),
    ] {
        let mut run = Command::new(&exe);
        run.arg(argument);
        let checked = tools.run_command(&run, &directory, step)?;
        ensure!(
            checked.starts_with(prefix),
            "Incomplete real private sandbox check"
        );
        result.push_str(&checked);
    }
    fs::write(output, &result)?;
    print!("{result}");
    source.insert_str(first, "#include \"security_sandbox_windows.inc\"\n");
    source = source
        .replace("#define WINDIVERT_DEVICE_NAME \"WinDivert\"\n", "")
        .replace("static bool b_sandbox_set = false;\n", "");
    fs::write(path, source)?;
    Ok(())
}
