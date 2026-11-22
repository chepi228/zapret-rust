//! Compare complete pinned loaders and exercise real Win32 file pinning.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    dll: &[u8],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Ring loader parent")?
        .join("ring-loader-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("rust_ring.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static const rr_api *rr_backend;")
        .context("Pinned ring loader state")?;
    let end = source
        .find("#include \"ring_gc_windows.inc\"")
        .context("Pinned ring finalizer")?;
    ensure!(
        start < end && source[start..end].contains("BCryptFinishHash"),
        "Pinned loader body"
    );
    fs::write(directory.join("ring_loader_types.inc"), &source[..start])?;
    fs::write(
        directory.join("ring_loader_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("ring-loader-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [&directory, shim, lua, nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("ring_loader_oracle.c"))
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
        "Compile the original and Rust ring loaders",
    )?;
    let unicode = directory.join("Проверка DLL");
    fs::create_dir(&unicode)?;
    let child = unicode.join("ring-loader-check.exe");
    fs::copy(exe, &child)?;
    fs::write(unicode.join("zapret-ring.dll"), dll)?;
    let result = tools.run_command(
        &Command::new(child),
        &unicode,
        "Compare loader failures, last errors, trusted SHA256 and the held DLL pin",
    )?;
    ensure!(
        result.starts_with("PASS ring_loader "),
        "Incomplete trusted loader comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"ring_loader_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
