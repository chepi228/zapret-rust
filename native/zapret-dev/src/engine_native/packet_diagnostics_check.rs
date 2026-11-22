//! Compare complete packet and profile diagnostics before selecting their Rust owners.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, ops::Range, path::Path, process::Command};

fn function(source: &str, signature: &str) -> Result<Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("Pinned diagnostics: {signature}"))?;
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("Pinned diagnostics body end")?
        + 3;
    Ok(start..end)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    diagnostics: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Packet diagnostics parent")?
        .join("packet-diagnostics-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let packet = function(&source, "static void packet_debug(")?;
    let find = function(&source, "static struct desync_profile *dp_find(")?;
    ensure!(
        packet.end < find.start,
        "Packet and profile diagnostics source order"
    );

    let selector_path = shim.join("profile_selection_windows.inc");
    let mut selector = fs::read_to_string(&selector_path)?;
    let select = function(
        &selector,
        "static struct desync_profile *profile_find_windows(",
    )?;
    let reference = format!(
        "{}\n{}\n{}\n",
        &source[packet.clone()],
        &selector[select.clone()],
        &source[find.clone()]
    );
    fs::write(
        directory.join("packet_diagnostics_reference.inc"),
        reference,
    )?;

    let mut selected_find = source[find.clone()].to_owned();
    let search_start = selected_find
        .find("\n\tif (params.debug)\n")
        .context("Pinned profile search log start")?;
    let search_end = selected_find
        .find("\n\tconst struct zapret_profile_query query")
        .context("Pinned profile query")?;
    ensure!(
        search_start < search_end,
        "Profile query begins after logging"
    );
    selected_find.replace_range(search_start..search_end, "");
    let return_at = selected_find
        .find("\treturn profile_find_windows(head, &query);")
        .context("Pinned profile call")?;
    selected_find.insert_str(
        return_at,
        "\tzapret_profile_search_report(&query, ssid, fwmark, params.debug, DLOG);\n",
    );
    fs::write(
        directory.join("packet_diagnostics_find.inc"),
        &selected_find,
    )?;

    let result_start = select.start
        + selector[select.clone()]
            .find("    if (profile) {")
            .context("Pinned selected profile diagnostics")?;
    let result_end = select.start
        + selector[select.clone()]
            .find("    return profile;")
            .context("Pinned selected profile return")?;
    ensure!(
        result_start < result_end,
        "Profile result diagnostics before return"
    );
    selector.replace_range(
        result_start..result_end,
        "    zapret_profile_result_report(profile, query, DLOG);\n",
    );
    selector.insert_str(select.start, "#include \"profile_debug_windows.inc\"\n\n");
    fs::write(directory.join("packet_diagnostics_selector.inc"), &selector)?;

    let exe = directory.join("packet-diagnostics-check.exe");
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
        lua,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("packet_diagnostics_oracle.c"))
        .arg(diagnostics)
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
        "Compile complete packet and profile diagnostic comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare complete diagnostic output and deferred native reads",
    )?;
    ensure!(
        result.starts_with("PASS packet_diagnostics "),
        "Incomplete packet diagnostic comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(find, &selected_find);
    source.replace_range(packet, "#include \"packet_debug_windows.inc\"\n");
    fs::write(path, source)?;
    fs::write(selector_path, selector)?;
    Ok(())
}
