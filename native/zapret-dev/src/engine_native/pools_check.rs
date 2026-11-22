//! Compile the pinned C pool oracle and compare the Rust C ABI without a driver.
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
    let source = fs::read_to_string(nfq.join("pools.c"))?;
    let header = fs::read_to_string(nfq.join("pools.h"))?;
    let helpers = fs::read_to_string(nfq.join("helpers.c"))?;
    let search = fs::read_to_string(nfq.join("hostlist.c"))?;
    let mut reference = String::new();
    for fragment in [
        between(
            &header,
            "typedef struct hostlist_pool {",
            "void HostlistPoolDestroy",
        )?,
        between(
            &header,
            "#define DESTROY_STR_POOL",
            "typedef struct hostlist_pool {",
        )?,
        between(
            &source,
            "#define ADD_HOSTLIST_POOL",
            "void HostFailPoolDestroy(",
        )?,
        between(&source, "static int kavl_bit_cmp(", "bool ipset4Check(")?,
        between(&helpers, "void expand_bits(", "// \"       [fd00::1]\"")?,
        between(
            &search,
            "static bool SearchHostList(",
            "static bool HostlistsReloadCheck(",
        )?,
    ] {
        reference.push_str(fragment);
    }
    let reference = reference
        .replace("hostlist_pool", "reference_host_pool")
        .replace("HostlistPool", "reference_HostlistPool")
        .replace("SearchHostList", "reference_SearchHostList");

    let directory = nfq
        .parent()
        .context("Pinned engine source parent")?
        .join("pool-check");
    fs::create_dir(&directory)?;
    fs::write(directory.join("reference.inc"), reference)?;
    let executable = directory.join("pool-check.exe");
    tools.run_command(
        Command::new(tools.compiler)
            .args([
                "-O2",
                "-std=gnu99",
                "-ffunction-sections",
                "-fdata-sections",
            ])
            .arg(format!("-I{}", directory.display()))
            .arg(format!("-I{}", nfq.display()))
            .arg(format!("-I{}", shim.display()))
            .arg(shim.join("pools_oracle.c"))
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
        "Compile C and Rust pool conformance",
    )?;
    let result = tools.run_command(
        &Command::new(&executable),
        &directory,
        "Compare C and Rust pool semantics",
    )?;
    ensure!(
        result.starts_with("PASS "),
        "Pool oracle did not confirm completion"
    );
    fs::write(output, &result)?;
    println!("{}", result.trim());
    Ok(())
}

fn between<'a>(text: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let start = text
        .find(first)
        .with_context(|| format!("Missing pinned pool anchor: {first}"))?;
    let end = text
        .find(last)
        .with_context(|| format!("Missing pinned pool anchor: {last}"))?;
    ensure!(start < end, "Pinned pool reference boundaries changed");
    Ok(&text[start..end])
}
