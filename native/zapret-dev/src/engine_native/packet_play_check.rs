//! Compare TCP and QUIC preparation with the previously wired handlers.
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
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let parent = nfq.parent().context("Packet preparation source parent")?;
    let directory = parent.join("packet-play-check");
    fs::create_dir(&directory)?;
    let start = source
        .find("static uint8_t dpi_desync_tcp_packet_play(")
        .context("TCP preparation entry")?;
    let length = source[start..]
        .find("// conntrack is supported only for RELATED icmp")
        .context("End of UDP preparation")?;
    let end = start + length;
    let dns = "#include \"dns_response_windows.inc\"";
    ensure!(
        source[start..end].matches(dns).count() == 1,
        "Pinned DNS adapter location changed"
    );
    fs::write(
        directory.join("packet_play_reference.inc"),
        source[start..end].replace(dns, ""),
    )?;
    let state_start = source
        .find("struct play_state\n{")
        .context("Pinned play state")?;
    let state_end = source[state_start..]
        .find("\n};")
        .context("Pinned play state end")?
        + state_start
        + "\n};".len();
    fs::write(
        directory.join("packet_play_state.inc"),
        &source[state_start..state_end],
    )?;
    source.replace_range(
        start..end,
        &format!("{dns}\n#include \"packet_play_windows.inc\"\n\n"),
    );
    let descriptor_end = source
        .find("} t_protocol_probe;")
        .context("Pinned probe descriptor end")?;
    let descriptor_start = source[..descriptor_end]
        .rfind("typedef")
        .context("Pinned probe descriptor")?;
    let debug_start = source[descriptor_end..]
        .find("static void TLSDebugHandshake(")
        .context("Pinned TLS diagnostic start")?
        + descriptor_end;
    source.replace_range(descriptor_start..debug_start, "");
    let route_start = source
        .find("// conntrack is supported only for RELATED icmp")
        .context("Pinned ICMP route start")?;
    let route_end = route_start
        + source[route_start..]
            .find("\nuint8_t dpi_desync_packet(")
            .context("Pinned packet route end")?;
    fs::write(
        directory.join("packet_route_reference.inc"),
        &source[route_start..route_end],
    )?;
    source.replace_range(
        route_start..route_end,
        "#include \"packet_route_windows.inc\"\n",
    );
    let utilities = fs::read_to_string(nfq.join("darkmagic.c"))?;
    let checksum_start = utilities
        .find("void verdict_tcp_csum_fix(")
        .context("Pinned checksum policy start")?;
    let icmp_checksum = checksum_start
        + utilities[checksum_start..]
            .find("void verdict_icmp_csum_fix(")
            .context("Pinned ICMP checksum policy")?;
    let checksum_end = icmp_checksum
        + utilities[icmp_checksum..]
            .find("\n}\n")
            .context("Pinned checksum policy end")?
        + "\n}\n".len();
    fs::write(
        directory.join("packet_checksum_reference.inc"),
        &utilities[checksum_start..checksum_end],
    )?;
    let luajit = parent
        .parent()
        .context("Lua source parent")?
        .join("luajit2-2.1-20250826/src");
    let executable = directory.join("packet-play-check.exe");
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
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    for include in [
        directory.clone(),
        parent.join("protocol-check"),
        parent.join("packet-input-check"),
        shim.to_owned(),
        shim.join("include"),
        nfq.join("windows"),
        luajit,
        nfq.to_owned(),
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("packet_play_oracle.c"))
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
        .arg(&executable);
    tools.run_command(
        &command,
        &directory,
        "Compile packet preparation comparison",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare TCP and UDP preparation",
    )?;
    ensure!(
        result.starts_with("PASS packet_play ")
            && result
                .lines()
                .any(|line| line.starts_with("PASS packet_route "))
            && result
                .lines()
                .any(|line| line.starts_with("PASS lua_rules ")),
        "Packet preparation comparison incomplete"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    Ok(())
}
