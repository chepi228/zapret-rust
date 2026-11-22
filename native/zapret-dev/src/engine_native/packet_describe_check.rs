//! Exact diagnostic labels, buffer boundaries and print capture against C.
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
        .context("Packet describe parent")?
        .join("packet-describe-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for name in [
        "proto_name",
        "str_proto_name",
        "icmp_type_name",
        "str_icmp_type_name",
        "str_srcdst_ip",
        "str_ip",
        "print_ip",
        "str_srcdst_ip6",
        "str_ip6hdr",
        "print_ip6hdr",
        "str_tcphdr",
        "print_tcphdr",
        "str_udphdr",
        "print_udphdr",
        "str_icmphdr",
        "print_icmphdr",
    ] {
        let needle = if matches!(name, "proto_name" | "icmp_type_name") {
            format!("*{name}(")
        } else {
            format!(" {name}(")
        };
        let start = source.find(&needle).context("Pinned packet description")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = start
            + source[start..]
                .find("\n}\n")
                .context("Pinned packet description end")?
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("packet_describe_reference.inc"), reference)?;
    let exe = directory.join("packet-describe-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        nfq,
        &nfq.join("windows"),
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("packet_describe_oracle.c"))
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
        "Compile exact packet diagnostic comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check packet labels formatting and bounded printing",
    )?;
    ensure!(
        result.starts_with("PASS packet_describe "),
        "Incomplete packet diagnostic comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.push_str("\n#include \"packet_describe_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
