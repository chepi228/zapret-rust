//! Select per-packet/poll adapters only after native old/new behavior compares.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn body(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(anchor)
        .with_context(|| format!("Missing capture policy {anchor}"))?;
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("Capture policy function end")?
        + 3;
    Ok(start..end)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    host: &Path,
    output: &Path,
) -> Result<()> {
    let parent = nfq.parent().context("Capture packet parent")?;
    let directory = parent.join("capture-packet-policy-check");
    fs::create_dir(&directory)?;
    let path = shim.join("engine_loop_windows.inc");
    let mut capture = fs::read_to_string(&path)?;
    let range = body(&capture, "static uint8_t loop_process(")?;
    fs::write(
        directory.join("capture_packet_reference.inc"),
        &capture[range.clone()],
    )?;
    capture.replace_range(range, "#include \"capture_packet_policy_windows.inc\"\n");
    fs::write(directory.join("engine_loop_windows.inc"), &capture)?;
    let contract = fs::read_to_string(shim.join("engine_loop_oracle.c"))?;
    // Keep the native observation's owning type, including the atomic quit flag.
    let contract = contract.replace("volatile sig_atomic_t bQuit;", "__typeof__(bQuit) bQuit;");
    fs::write(directory.join("capture_loop_contract.c"), contract)?;
    fs::copy(
        parent.join("engine-loop-check/engine_loop_reference.inc"),
        directory.join("engine_loop_reference.inc"),
    )?;
    let receive_path = shim.join("windivert_receive_windows.inc");
    let mut receive = fs::read_to_string(&receive_path)?;
    let range = body(&receive, "static uint32_t receive_poll(")?;
    fs::write(
        directory.join("capture_poll_reference.inc"),
        &receive[range.clone()],
    )?;
    receive.replace_range(range, "#include \"capture_poll_policy_windows.inc\"\n");
    let mut log = String::new();
    for (domain, prefix) in [
        ("loop", "PASS "),
        ("poll", "PASS capture_poll "),
        ("packet", "PASS capture_packet "),
    ] {
        let exe = directory.join(format!("capture-{domain}-check.exe"));
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
        for include in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            lua,
            nfq,
        ] {
            command.arg(format!("-I{}", include.display()));
        }
        command.arg("-include").arg(shim.join("win_platform.h"));
        if domain == "loop" {
            command
                .arg(directory.join("capture_loop_contract.c"))
                .arg(shim.join("windivert_receive_oracle.c"));
        } else if domain == "poll" {
            command.arg(shim.join("capture_poll_policy_oracle.c"));
        } else {
            command
                .arg(shim.join("capture_packet_policy_oracle.c"))
                .arg(host);
        }
        command
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
            "Compile native capture policy conformance",
        )?;
        let text = tools.run_command(
            &Command::new(exe),
            &directory,
            "Compare capture batches, interfaces and poll observation order",
        )?;
        ensure!(
            text.starts_with(prefix),
            "Incomplete capture {domain} comparison"
        );
        if domain == "loop" {
            ensure!(
                text.lines()
                    .filter(|line| line.starts_with("PASS "))
                    .count()
                    == 2,
                "Missing private receive comparison"
            );
        }
        log.push_str(&text);
    }
    fs::write(output, &log)?;
    print!("{log}");
    fs::write(path, capture)?;
    fs::write(receive_path, receive)?;
    Ok(())
}
