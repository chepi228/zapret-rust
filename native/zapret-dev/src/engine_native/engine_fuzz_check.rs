//! Compare the two versions of the local diagnostic loop with a mock processor.
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
        .context("Diagnostic loop parent")?
        .join("engine-fuzz-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static void fuzzPacketData(")
        .context("Pinned local diagnostic loop")?;
    let entry = source
        .find("static void do_fuzz(")
        .context("Pinned diagnostic entry")?;
    let end = entry
        + source[entry..]
            .find("\n}\n")
            .context("Diagnostic loop end")?
        + 3;
    ensure!(start < entry, "Diagnostic loop source order");
    fs::write(
        directory.join("engine_fuzz_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("engine-fuzz-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [&directory, shim] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("engine_fuzz_oracle.c"))
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
        "Compile complete diagnostic loop comparison",
    )?;
    let text = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare local diagnostic loop allocations, RNG order and stop conditions",
    )?;
    ensure!(
        text.starts_with("PASS engine_fuzz "),
        "Incomplete diagnostic loop comparison"
    );
    fs::write(output, &text)?;
    print!("{text}");
    source.replace_range(start..end, "#include \"engine_fuzz_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
