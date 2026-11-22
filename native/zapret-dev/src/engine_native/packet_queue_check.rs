//! Compare the native FIFO and replay with the pinned C implementation before linking.
use super::tools::Tools;
use crate::ring_build::patch;
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
        .context("Pinned packet queue source parent")?
        .join("packet-queue-check");
    fs::create_dir(&directory)?;
    let header = nfq.join("packet_queue.h");
    let source = nfq.join("packet_queue.c");
    let original_header = fs::read_to_string(&header)?;
    let original_source = fs::read_to_string(&source)?;
    let (includes, functions) = original_source
        .split_once("#include \"packet_queue.h\"\n")
        .context("Missing pinned packet queue include")?;
    let reference = format!("{original_header}\n{includes}{functions}")
        .replace("rawpacket", "reference_rawpacket");
    fs::write(directory.join("packet_queue_reference.inc"), reference)?;

    let desync = nfq.join("desync.c");
    let pinned = fs::read_to_string(&desync)?;
    let replay_anchor = "static bool replay_queue(struct rawpacket_queue *q)\n{";
    let (before, replay_body) = pinned
        .split_once(replay_anchor)
        .context("Missing pinned replay implementation")?;
    let (replay_body, after) = replay_body
        .split_once("\n}\n")
        .context("Missing pinned replay function boundary")?;
    fs::write(
        directory.join("packet_replay_reference.inc"),
        format!("{replay_anchor}{replay_body}\n}}\n")
            .replace("replay_queue(", "reference_replay_queue("),
    )?;

    patch(&header, "\tTAILQ_ENTRY(rawpacket) next;\n", "")?;
    patch(
        &header,
        "TAILQ_HEAD(rawpacket_tailhead, rawpacket);",
        "struct zapret_packet_entries;",
    )?;
    patch(
        &header,
        "\tstruct rawpacket_tailhead q;",
        "\tstruct zapret_packet_entries *entries;",
    )?;

    let executable = directory.join("packet-queue-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
    ]);
    for path in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", path.display()));
    }
    tools.run_command(
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("packet_queue_oracle.c"))
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
        "Compile C and Rust packet queue and replay conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust packet queues and replay",
    )?;
    ensure!(
        result.lines().count() == 2 && result.lines().all(|line| line.starts_with("PASS ")),
        "Packet queue or replay comparison did not finish"
    );
    fs::write(output, &result)?;
    println!("{}", result.trim());
    fs::write(
        desync,
        format!("{before}#include \"replay_windows.inc\"\n{after}"),
    )?;
    fs::remove_file(&source).context("Remove the replaced C queue from the private build tree")?;
    Ok(())
}
