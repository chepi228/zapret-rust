//! Compare packet helper mutations, options and endpoint bytes with pinned C.
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
        .context("Packet helper parent")?
        .join("packet-helpers-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for name in [
        "net32_add",
        "net16_add",
        "tcp_find_option",
        "tcp_find_scale_factor",
        "tcp_find_mss",
        "tcp_synack_segment",
        "tcp_syn_segment",
        "extract_ports",
        "extract_dst",
        "extract_endpoints",
        "reverse_ip",
        "reverse_tcp",
        "ttl46",
        "family_from_proto",
    ] {
        let needle = if name == "tcp_find_option" {
            format!("*{name}(")
        } else {
            format!(" {name}(")
        };
        let start = source.find(&needle).context("Pinned packet helper")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = start
            + source[start..]
                .find("\n}\n")
                .context("Pinned packet helper end")?
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("packet_helpers_reference.inc"), reference)?;
    let exe = directory.join("packet-helpers-check.exe");
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
        .arg(shim.join("packet_helpers_oracle.c"))
        .arg(nfq.join("checksum.c"))
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
        "Compile direct packet helper comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check packet options and endpoint mutations",
    )?;
    ensure!(
        result.starts_with("PASS packet_helpers "),
        "Incomplete packet helper comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.push_str("\n#include \"packet_helpers_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
