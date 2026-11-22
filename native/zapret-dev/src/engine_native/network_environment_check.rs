//! Validate Windows network observations against fake COM and WLAN results.
use super::{network_diagnostics_check, tools::Tools};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    report_object: &Path,
    output: &Path,
) -> Result<()> {
    let path = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&path)?;
    let parent = nfq.parent().context("Windows environment source parent")?;
    let directory = parent.join("network-environment-check");
    fs::create_dir(&directory)?;
    let start = source
        .find("typedef DWORD (WINAPI *t_WlanOpenHandle)(")
        .context("Pinned WLAN functions")?;
    let end = source[start..]
        .find("bool nlm_list(")
        .context("Pinned environment initialization end")?
        + start;
    source.replace_range(
        start..end,
        "#include \"network_environment_windows.inc\"\n\n",
    );
    let start = source
        .find("static bool nlm_filter_match(")
        .context("Pinned NLM observer")?;
    let end = start
        + source[start..]
            .find("bool logical_net_filter_present(void)")
            .context("Pinned observer end")?;
    let reference = source[start..end].to_owned();
    fs::write(
        directory.join("network_environment_reference.inc"),
        reference,
    )?;
    source.replace_range(start..end, "");
    let present = "return (wlan_filter_ssid && !LIST_EMPTY(wlan_filter_ssid)) || (nlm_filter_net && !LIST_EMPTY(nlm_filter_net));";
    ensure!(
        source.matches(present).count() == 1,
        "Pinned logical network presence"
    );
    source = source.replace(
        present,
        "return zapret_network_bind_present(&network_binding);",
    );
    let guid = source
        .find("static bool str2guid(")
        .context("Pinned GUID parser")?;
    let end = guid
        + source[guid..]
            .find("\n}\n")
            .context("Pinned GUID parser end")?
        + "\n}\n".len();
    fs::write(directory.join("guid_reference.inc"), &source[guid..end])?;
    source.replace_range(guid..end, "");
    ensure!(
        source
            .matches("INetworkListManager* pNetworkListManager=NULL;")
            .count()
            == 1,
        "Pinned NLM global changed"
    );
    source = source.replace("INetworkListManager* pNetworkListManager=NULL;", "");

    let exe = directory.join("network-environment-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    let lua = parent
        .parent()
        .context("Pinned Lua headers")?
        .join("luajit2-2.1-20250826/src");
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        &lua,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("network_environment_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lole32",
            "-loleaut32",
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
        "Compile Windows network observation comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare Windows network observations",
    )?;
    ensure!(
        result.starts_with("PASS network_environment "),
        "Incomplete Windows network comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    network_diagnostics_check::run(
        tools,
        nfq,
        shim,
        [library, report_object],
        &lua,
        &mut source,
        &output.with_file_name("network-diagnostics-check.log"),
    )?;
    fs::write(path, source)?;
    Ok(())
}
