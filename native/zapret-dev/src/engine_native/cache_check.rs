//! Compile pinned auxiliary caches and compare their public APIs to Rust.
use super::{cache_patch, tools::Tools};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let source = fs::read_to_string(nfq.join("pools.c"))?;
    let oom = between(
        &source,
        "#undef uthash_nonfatal_oom",
        "#include \"host_pool_windows.c\"",
    )?;
    let failure = between(
        &source,
        "void HostFailPoolDestroy(",
        "static struct str_list *strlist_entry_alloc(",
    )?;
    let ip = source
        .find("static void ipcache_item_touch(")
        .context("Pinned IP cache implementation")?;
    let directory = nfq
        .parent()
        .context("Cache source parent")?
        .join("cache-check");
    fs::create_dir(&directory)?;
    let reference = directory.join("reference.c");
    fs::write(
        &reference,
        format!(
            "#include \"cache_fixture.h\"\n#define printf cache_oracle_printf\n{oom}{failure}{}\n#include \"cache_reference.c\"\n",
            &source[ip..]
        ),
    )?;
    let command = || {
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
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
            &nfq.join("windows"),
            nfq,
        ] {
            command.arg(format!("-I{}", path.display()));
        }
        command.arg("-include").arg(shim.join("win_platform.h"));
        command
    };
    let object = directory.join("reference.o");
    let mut compile = command();
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
        compile.arg(format!("-D{name}=reference_{name}"));
    }
    tools.run_command(
        compile.args(["-c", "-o"]).arg(&object).arg(reference),
        &directory,
        "Compile pinned C auxiliary caches",
    )?;
    cache_patch::apply(nfq)?;
    let actual = directory.join("actual.c");
    fs::write(
        &actual,
        "#include \"cache_fixture.h\"\n#define printf cache_oracle_printf\n#include \"cache_windows.c\"\n",
    )?;
    let executable = directory.join("cache-check.exe");
    tools.run_command(
        command()
            .arg(actual)
            .arg(shim.join("cache_oracle.c"))
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
            .arg(&executable),
        &directory,
        "Compile C and Rust auxiliary cache conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust auxiliary caches",
    )?;
    ensure!(result.starts_with("PASS "), "Cache conformance incomplete");
    fs::write(output, &result)?;
    println!("{}", result.trim());
    Ok(())
}

fn between<'a>(source: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing pinned cache anchor: {first}"))?;
    let end = source
        .find(last)
        .with_context(|| format!("Missing pinned cache anchor: {last}"))?;
    ensure!(start < end, "Pinned cache boundaries changed");
    Ok(&source[start..end])
}
