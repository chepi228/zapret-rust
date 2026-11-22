//! Compare token transitions with C, then exercise only isolated child tokens.
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
        .context("Security token parent")?
        .join("security-token-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    let first = source
        .find("BOOL AdjustPrivileges(")
        .context("Pinned token start")?;
    for name in [
        "AdjustPrivileges",
        "AdjustPrivilegesForCurrentProcess",
        "RemoveTokenPrivs",
        "LowMandatoryLevel",
    ] {
        let start = source
            .find(&format!(" {name}("))
            .context("Pinned token transition")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = start
            + source[start..]
                .find("\n}\n")
                .context("Pinned token transition end")?
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("security_token_reference.inc"), reference)?;
    let exe = directory.join("security-token-check.exe");
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
        .arg(shim.join("security_token_oracle.c"))
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
        "Compile token snapshot and failure comparison",
    )?;
    let mut result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare native token transitions and rejected snapshots",
    )?;
    ensure!(
        result.starts_with("PASS security_token "),
        "Incomplete token comparison"
    );
    for mode in ["--real-duplicate", "--real-low"] {
        let mut command = Command::new(&exe);
        command.arg(mode);
        let real = tools.run_command(&command, &directory, "Check owned isolated Windows token")?;
        ensure!(
            real.starts_with("PASS security_token_real "),
            "Incomplete isolated token check"
        );
        result.push_str(&real);
    }
    for wide in [false, true] {
        let bridge = directory.join(if wide {
            "token-bridge-wide.exe"
        } else {
            "token-bridge-ansi.exe"
        });
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
        ]);
        if wide {
            command.args(["-municode", "-DUNICODE=1", "-D_UNICODE=1"]);
        }
        command
            .arg(format!("-I{}", shim.display()))
            .arg(shim.join("security_token_bridge.c"))
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
            .arg(&bridge);
        tools.run_command(
            &command,
            &directory,
            "Compile actual ANSI/Unicode token adapter",
        )?;
        let checked = tools.run_command(
            &Command::new(bridge),
            &directory,
            "Check actual token adapter on owned duplicate",
        )?;
        ensure!(
            checked.starts_with("PASS security_token_bridge "),
            "Incomplete TCHAR token check"
        );
        result.push_str(&checked);
    }
    fs::write(output, &result)?;
    print!("{result}");
    source.insert_str(first, "#include \"security_token_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
