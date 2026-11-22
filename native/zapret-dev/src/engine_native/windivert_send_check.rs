//! Check driver submissions without opening a driver handle.
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
        .context("WinDivert send source parent")?
        .join("windivert-send-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static HANDLE windivert_init_filter(")
        .context("Pinned driver open")?;
    let end = start
        + source[start..]
            .find("#include \"windivert_receive_windows.inc\"")
            .context("Pinned driver open end")?;
    let handle_reference = &source[start..end];
    let mutex = "\"Global\\\\winws_windivert_mutex\"";
    ensure!(
        handle_reference.matches(mutex).count() == 1,
        "Pinned driver mutex name changed"
    );
    // The comparison uses only an unnamed Windows mutex and a mock driver.
    fs::write(
        directory.join("handle_reference.inc"),
        handle_reference.replace(mutex, "NULL"),
    )?;
    source.replace_range(start..end, &format!(
        "#define ZAPRET_WINDIVERT_MUTEX {mutex}\n#include \"windivert_handles_windows.inc\"\n#undef ZAPRET_WINDIVERT_MUTEX\n\n"
    ));
    let gate = source
        .find("bool logical_net_filter_match(void)")
        .context("Pinned logical network gate")?;
    let gate_end = gate
        + source[gate..]
            .find("#define ZAPRET_WINDIVERT_MUTEX")
            .context("Pinned logical network gate end")?;
    source.replace_range(gate..gate_end, "#include \"network_gate_windows.inc\"\n\n");
    let old = "static DWORD logical_net_filter_tick=0;";
    ensure!(
        source.matches(old).count() == 1,
        "Pinned logical network timer changed"
    );
    source = source.replace(old, "static void logical_net_filter_reset(void);");
    let reset = "win_dark_deinit();\n\tif (LIST_EMPTY(ssid_filter))";
    ensure!(
        source.matches(reset).count() == 1,
        "Pinned network reset position changed"
    );
    source = source.replace(
        reset,
        "win_dark_deinit();\n\tlogical_net_filter_reset();\n\tif (LIST_EMPTY(ssid_filter))",
    );
    let start = source
        .find("static bool windivert_send_filter(")
        .context("Pinned driver send")?;
    let end = start
        + source[start..]
            .find("#else // *nix")
            .context("Pinned Windows send end")?;
    fs::write(directory.join("send_reference.inc"), &source[start..end])?;
    source.replace_range(start..end, "#include \"windivert_send_windows.inc\"\n\n");
    let start = source
        .find("bool rawsend_rep(")
        .context("Pinned repeat sends")?;
    let end = start
        + source[start..]
            .find("bool rawsend_rp(")
            .context("Pinned repeat send end")?;
    fs::write(
        directory.join("send_repeat_reference.inc"),
        &source[start..end],
    )?;
    source.replace_range(start..end, "#include \"rawsend_repeat_windows.inc\"\n\n");
    let executable = directory.join("windivert-send-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("windivert_send_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile driver send comparison")?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare driver send parameters",
    )?;
    ensure!(
        result.starts_with("PASS windivert_send ")
            && result
                .lines()
                .any(|line| line.starts_with("PASS windivert_handles "))
            && result
                .lines()
                .any(|line| line.starts_with("PASS network_gate ")),
        "Incomplete driver send or handle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    Ok(())
}
