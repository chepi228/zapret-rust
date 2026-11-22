//! Check list ownership and atomic copies before replacing the C implementations.
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
        .context("Collection source parent")?
        .join("collections-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("pools.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static struct str_list *strlist_entry_alloc(")
        .context("Pinned string collections")?;
    let end = source[start..]
        .find("#include \"params.h\"\n#include \"list_registry_windows.c\"")
        .context("Pinned string collection end")?
        + start;
    fs::write(
        directory.join("collections_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("collections-check.exe");
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
        .arg(shim.join("collections_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile engine collection comparison")?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check collection ownership and copy failures",
    )?;
    ensure!(
        result.starts_with("PASS engine_collections "),
        "Incomplete collection comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"collections_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
