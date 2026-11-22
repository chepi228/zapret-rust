//! Compare label policy and COM ownership, then label only private fixtures.
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
        .context("Security label parent")?
        .join("security-label-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let forward = "BOOL SetMandatoryLabelFileW(LPCWSTR, DWORD, DWORD);";
    let first = source
        .find(forward)
        .context("Pinned wide label declaration")?;
    source = source.replacen(forward, "", 1);
    let mut reference = String::new();
    for anchor in [
        "BOOL SetMandatoryLabelFileW(LPCWSTR lpFileNameW,",
        "BOOL SetMandatoryLabelFile(LPCSTR ",
        "BOOL SetMandatoryLabelObject(",
        "bool ensure_file_access(",
        "bool ensure_dir_access(",
        "bool prepare_low_appdata(",
    ] {
        let start = source.find(anchor).context("Pinned label helper")?;
        let end = start
            + source[start..]
                .find("\n}\n")
                .context("Pinned label helper end")?
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("security_label_reference.inc"), reference)?;
    let exe = directory.join("security-label-check.exe");
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
        .arg(shim.join("security_label_oracle.c"))
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
    tools.run_command(
        &command,
        &directory,
        "Compile integrity label and COM ownership comparison",
    )?;
    let mut result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check label policy and failed folder cleanup",
    )?;
    ensure!(
        result.starts_with("PASS security_label "),
        "Incomplete label comparison"
    );
    let mut real = Command::new(&exe);
    real.arg("--real");
    let checked = tools.run_command(
        &real,
        &directory,
        "Check only owned private file and object labels",
    )?;
    ensure!(
        checked.starts_with("PASS security_label_real "),
        "Incomplete real private label check"
    );
    result.push_str(&checked);
    fs::write(output, &result)?;
    print!("{result}");
    source.insert_str(first, "#include \"security_label_windows.inc\"\n");
    source = source.replace(
        "static SID_IDENTIFIER_AUTHORITY label_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;\n",
        "",
    );
    fs::write(path, source)?;
    Ok(())
}
