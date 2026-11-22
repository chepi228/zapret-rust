//! Compare the new packet input policies to the pinned C implementation.
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
    let parent = nfq.parent().context("Packet input source parent")?;
    let directory = parent.join("packet-input-check");
    fs::create_dir(&directory)?;
    let sections = [
        (
            "static void protocol_probe(",
            "static void TLSDebugHandshake(",
            "protocol_probe",
        ),
        (
            "static bool ipcache_put_hostname(",
            "static bool desync_get_result(",
            "packet_cache",
        ),
        (
            "static const uint8_t *dns_extract_name(",
            "static uint8_t dpi_desync_udp_packet_play(",
            "dns_response",
        ),
        (
            "static bool pos_overflow(",
            "static bool replay_queue(struct rawpacket_queue *q);",
            "packet_range",
        ),
        (
            "static uint8_t verdict_aggregate(",
            "static uint8_t desync(",
            "packet_verdict",
        ),
    ];
    for (first, last, name) in sections {
        let start = source
            .find(first)
            .with_context(|| format!("Missing {first}"))?;
        let end = start
            + source[start..]
                .find(last)
                .with_context(|| format!("Missing {last}"))?;
        ensure!(start < end, "Empty packet input section {name}");
        fs::write(
            directory.join(format!("{name}_reference.inc")),
            &source[start..end],
        )?;
        source.replace_range(start..end, &format!("#include \"{name}_windows.inc\"\n\n"));
    }
    let typedef_end = source
        .find("} t_protocol_probe;")
        .context("Pinned detector descriptor")?
        + "} t_protocol_probe;".len();
    let typedef_start = source[..typedef_end]
        .rfind("typedef")
        .context("Pinned detector descriptor start")?;
    fs::write(
        directory.join("protocol_probe_descriptor.inc"),
        &source[typedef_start..typedef_end],
    )?;
    // The detectors in each call site are fixed and the dispatch treats them
    // as read-only. Avoid filling out the arrays on every incoming packet.
    ensure!(
        source.matches("t_protocol_probe testers[]").count() == 4,
        "Pinned detector tables changed"
    );
    source = source.replace(
        "t_protocol_probe testers[]",
        "static const t_protocol_probe testers[]",
    );
    let luajit = parent
        .parent()
        .context("Pinned LuaJIT parent")?
        .join("luajit2-2.1-20250826/src");
    let executable = directory.join("packet-input-check.exe");
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
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        &luajit,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("packet_input_oracle.c"))
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
        "Compile C and Rust packet input conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust packet input",
    )?;
    for section in [
        "protocol_probe",
        "dns_response",
        "packet_cache",
        "packet_range",
        "packet_verdict",
    ] {
        ensure!(
            result
                .lines()
                .any(|line| line.starts_with(&format!("PASS {section} "))),
            "Missing packet input comparison: {section}"
        );
    }
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    Ok(())
}
