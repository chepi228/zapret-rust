//! Compare capture/export/duplicate admission before replacing the native main block.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Capture preflight source parent")?
        .join("capture-preflight-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("\tif (params.intercept)\n\t{\n\t\tif (!*params.windivert_filter)")
        .context("Pinned capture preflight start")?;
    let end = start
        + source[start..]
            .find("\n#endif\n\n\tif (bDry)")
            .context("Pinned capture preflight end")?;
    fs::write(
        directory.join("capture_preflight_reference.inc"),
        &source[start..end],
    )?;
    let exe = directory.join("capture-preflight-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DPREFLIGHT_INTEGRATED_CHECK",
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
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("capture_preflight_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile capture preparation and mutex ownership comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check filter/export errors, private mutex ownership and C adapter",
    )?;
    ensure!(
        result.starts_with("PASS capture_preflight "),
        "Incomplete capture preflight comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end,concat!(
        "\tHANDLE hMutexArg=NULL;\n",
        "\tzapret_capture_prepare_result prepared=native_capture_prepare(IfIdx,SubIfIdx,wf_ipv4,wf_ipv6,wf_filter_lan,wf_filter_loopback,wf_tcp_empty,bDupCheck,bDry,wf_save_file,hash_wf,&hMutexArg);\n",
        "\tif(prepared.status==8)exit_clean(0);\n\tif(prepared.status)goto exiterr;\n"));
    let include = "#include \"startup_validation_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned capture preflight include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"capture_preflight_windows.inc\""),
    );
    fs::write(path, source)?;
    Ok(())
}
