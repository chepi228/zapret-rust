//! Gate complete cache facades independently of the already migrated indexes.
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
        .context("Cache lifecycle parent")?
        .join("cache-lifecycle-check");
    fs::create_dir(&directory)?;
    let path = shim.join("cache_windows.c");
    let original = fs::read_to_string(&path)?;
    ensure!(
        original.contains("static void cache_family_destroy(")
            && original.contains("free(item->hostname)"),
        "Pinned complete cache facade changed"
    );
    fs::write(directory.join("cache_lifecycle_before.inc"), &original)?;
    let mut candidate = original;
    for name in [
        "HostFailPoolPurge",
        "HostFailPoolPurgeRateLimited",
        "cache_family_destroy",
        "ipcacheDestroy",
        "ipcacheFind",
        "ipcacheTouch",
        "cache_family_purge",
        "ipcachePurgeRateLimited",
    ] {
        let at = candidate
            .find(&format!("{name}("))
            .with_context(|| format!("Pinned cache lifecycle {name}"))?;
        let start = candidate[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = start
            + candidate[start..]
                .find("\n}\n")
                .context("Pinned cache lifecycle end")?
            + 3;
        candidate.replace_range(start..end, "");
    }
    candidate.push_str("\n#include \"cache_lifecycle_windows.inc\"\n");
    let actual = directory.join("actual.c");
    fs::write(
        &actual,
        format!(
            "#include \"cache_fixture.h\"\n#include \"helpers.h\"\n#define printf cache_oracle_printf\n{candidate}"
        ),
    )?;
    let command = || {
        let mut c = Command::new(tools.compiler);
        c.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_FILE_OFFSET_BITS=64",
            "-D_POSIX_C_SOURCE=200809L",
        ]);
        for p in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            nfq,
        ] {
            c.arg(format!("-I{}", p.display()));
        }
        c.arg("-include").arg(shim.join("win_platform.h"));
        c
    };
    let object = directory.join("reference.o");
    let mut c = command();
    for name in [
        "HostFailPoolDestroy",
        "HostFailPoolAdd",
        "HostFailPoolFind",
        "HostFailPoolDel",
        "HostFailPoolPurge",
        "HostFailPoolPurgeRateLimited",
        "HostFailPoolDump",
        "ipcacheTouch",
        "ipcacheFind",
        "ipcachePurgeRateLimited",
        "ipcacheDestroy",
        "ipcachePrint",
    ] {
        c.arg(format!("-D{name}=reference_{name}"));
    }
    tools.run_command(
        c.arg("-c")
            .arg(shim.join("cache_lifecycle_reference.c"))
            .arg("-o")
            .arg(&object),
        &directory,
        "Compile complete old cache facade",
    )?;
    let exe = directory.join("cache-lifecycle-check.exe");
    let mut c = command();
    c.arg(actual)
        .arg(shim.join("cache_lifecycle_oracle.c"))
        .arg(object)
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &c,
        &directory,
        "Compile complete cache lifecycle comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare full cache entries, clocks, snapshots and diagnostic order",
    )?;
    ensure!(
        result.starts_with("PASS ") && result.contains("clock calls match pinned C"),
        "Incomplete cache lifecycle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, candidate)?;
    Ok(())
}
