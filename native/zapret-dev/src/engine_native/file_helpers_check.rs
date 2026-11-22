//! Compare owned-handle engine I/O with its pinned UCRT helper behavior.
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
        .context("File helper parent")?
        .join("file-helpers-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("helpers.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for name in ["load_file", "save_file", "append_to_list_file"] {
        let start = source
            .find(&format!(" {name}("))
            .context("Pinned file helper")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned file helper end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("file_helpers_reference.inc"), reference)?;
    let exe = directory.join("file-helpers-check.exe");
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
        .arg(shim.join("file_helpers_oracle.c"))
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
        "Compile engine native file helper comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check native engine binary and text I/O",
    )?;
    ensure!(
        result.starts_with("PASS engine_file_helpers "),
        "Incomplete native file helper comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.push_str("\n#include \"file_helpers_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
