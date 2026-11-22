//! Compare registration and reload against the pinned C routines.
use super::{list_registry_patch, tools::Tools};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let header = fs::read_to_string(nfq.join("pools.h"))?;
    let pools = fs::read_to_string(nfq.join("pools.c"))?;
    let hosts = fs::read_to_string(nfq.join("hostlist.c"))?;
    let ips = fs::read_to_string(nfq.join("ipset.c"))?;
    let directory = nfq
        .parent()
        .context("List registry source parent")?
        .join("list-registry-check");
    fs::create_dir(&directory)?;
    let reference = [
        between(&header, "struct hostlist_file {", "struct kavl_bit_elem")?,
        between(&header, "struct ipset_file {", "struct port_filter_item {")?,
        between(
            &pools,
            "struct hostlist_file *hostlist_files_add(",
            "static int kavl_bit_cmp(",
        )?,
        between(
            &pools,
            "struct ipset_file *ipset_files_add(",
            "static struct port_filter_item *port_filter_entry_alloc(",
        )?,
        between(
            &hosts,
            "static struct hostlist_file *RegisterHostlist_(",
            "struct hostlist_file *RegisterHostlist(",
        )?,
        between(
            &ips,
            "static struct ipset_file *RegisterIpset_(",
            "struct ipset_file *RegisterIpset(",
        )?,
        between(
            &hosts,
            "static bool LoadHostList(",
            "static bool LoadHostLists(",
        )?,
        between(&ips, "static bool LoadIpset(", "static bool LoadIpsets(")?,
    ]
    .concat();
    fs::write(directory.join("list_registry_reference.inc"), reference)?;
    list_registry_patch::apply(nfq)?;

    let executable = directory.join("list-registry-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
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
    tools.run_command(
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("list_registry_oracle.c"))
            .arg(library)
            .args([
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
        "Compile C and Rust list registration and reload conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust list registration and reload",
    )?;
    ensure!(
        result.starts_with("PASS "),
        "List registry conformance incomplete"
    );
    fs::write(output, &result)?;
    println!("{}", result.trim());
    Ok(())
}

fn between<'a>(source: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let (_, rest) = source
        .split_once(first)
        .with_context(|| format!("Missing pinned list anchor {first}"))?;
    let end = rest
        .find(last)
        .with_context(|| format!("Missing pinned list boundary {last}"))?;
    let start = source.len() - rest.len() - first.len();
    Ok(&source[start..start + first.len() + end])
}
