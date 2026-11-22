//! Verify and replace the ordered profile search in the pinned engine.
use super::{play_prolog, profile_rediscovery, tools::Tools};
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
    let first = source
        .find("// ipr,ipr6 - reverse ip")
        .context("Pinned profile search start")?;
    let last = source
        .find("static void ctrack_stop_retrans_counter(")
        .context("Pinned profile search end")?;
    ensure!(first < last, "Pinned profile search boundaries changed");
    let reference = &source[first..last];
    let actual = adapter(reference)?;

    let parent = nfq.parent().context("Pinned profile source parent")?;
    let directory = parent.join("profile-selection-check");
    fs::create_dir(&directory)?;
    profile_rediscovery::reference(&source, &directory)?;
    play_prolog::reference(&source, nfq, &directory)?;
    fs::write(directory.join("profile_selection_reference.inc"), reference)?;
    fs::write(directory.join("profile_selection_actual.inc"), &actual)?;
    // Keep the protocol names used by the diagnostics without linking the driver.
    let packet_helpers = fs::read_to_string(nfq.join("darkmagic.c"))?;
    let names_start = packet_helpers
        .find("const char *proto_name(")
        .context("Pinned protocol names")?;
    let (names, _) = packet_helpers[names_start..]
        .split_once("void str_proto_name(")
        .context("Pinned protocol names end")?;
    fs::write(directory.join("profile_protocol_names.inc"), names)?;

    let executable = directory.join("profile-selection-check.exe");
    let luajit = parent
        .parent()
        .context("Pinned Lua source parent")?
        .join("luajit2-2.1-20250826/src");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-Dzapret_localtime_r=fixture_localtime_r",
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
    command.arg("-include").arg(shim.join("win_platform.h"));
    command.arg(shim.join("profile_selection_oracle.c"));
    for name in ["pools.c", "filter.c", "hostlist.c", "ipset.c", "helpers.c"] {
        command.arg(nfq.join(name));
    }
    tools.run_command(
        command
            .arg(shim.join("win_files.c"))
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
            .arg(&executable),
        &directory,
        "Compile C and Rust profile selection conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust profile selection",
    )?;
    ensure!(
        result.starts_with("PASS profile_selection ")
            && result
                .lines()
                .any(|line| line.starts_with("PASS profile_rediscovery "))
            && result
                .lines()
                .any(|line| line.starts_with("PASS play_prolog ")),
        "Profile selection, discovery or setup comparison incomplete"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(first..last, &actual);
    play_prolog::apply(&mut source)?;
    profile_rediscovery::apply(&mut source)?;
    fs::write(path, source)?;
    Ok(())
}

fn adapter(reference: &str) -> Result<String> {
    let start = reference
        .find("static struct desync_profile *dp_find(")
        .context("Pinned dp_find signature")?;
    let (signature, body) = reference[start..]
        .split_once("\n{\n")
        .context("Pinned dp_find body")?;
    let start = body
        .find("\tif (params.debug)\n")
        .context("Pinned dp_find diagnostics")?;
    let (diagnostics, _) = body[start..]
        .split_once("\tif (bCheckDone) *bCheckDone = false;")
        .context("Pinned dp_find search loop")?;
    Ok(format!(
        "#include \"profile_selection_windows.inc\"\n\n{signature}\n{{\n{diagnostics}{}",
        concat!(
            "\tconst struct zapret_profile_query query = {\n",
            "\t\t.ipv4 = ip, .ipv6 = ip6, .reverse_ipv4 = ipr, .reverse_ipv6 = ipr6,\n",
            "\t\t.hostname = hostname, .l7 = l7proto, .port = port,\n",
            "\t\t.icmp_type = icmp_type, .icmp_code = icmp_code,\n",
            "\t\t.no_subdomains = bNoSubdom, .protocol = l3proto,\n",
            "\t\t.check_done = bCheckDone, .check_result = bCheckResult, .excluded = bExcluded\n",
            "\t};\n\treturn profile_find_windows(head, &query);\n}\n\n"
        )
    ))
}
