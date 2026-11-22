//! Verify profile filter option behavior before replacing its pinned C cases.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const CASES: [(&str, &str); 12] = [
    ("IDX_FILTER_L3", "\t\tcase IDX_FILTER_TCP:"),
    ("IDX_FILTER_TCP", "\t\tcase IDX_FILTER_UDP:"),
    ("IDX_FILTER_UDP", "\t\tcase IDX_FILTER_ICMP:"),
    ("IDX_FILTER_ICMP", "\t\tcase IDX_FILTER_IPP:"),
    ("IDX_FILTER_IPP", "\t\tcase IDX_FILTER_L7:"),
    ("IDX_FILTER_L7", "\n#ifdef HAS_FILTER_SSID"),
    ("IDX_PAYLOAD_DISABLE", "\t\tcase IDX_REASM_DISABLE:"),
    ("IDX_REASM_DISABLE", "\n#if defined(__linux__)"),
    ("IDX_PAYLOAD", "\t\tcase IDX_OUT_RANGE:"),
    ("IDX_OUT_RANGE", "\t\tcase IDX_IN_RANGE:"),
    ("IDX_IN_RANGE", "\t\tcase IDX_LUA_DESYNC:"),
    ("IDX_LUA_DESYNC", "\n#ifdef ZAPRET_WINDOWS"),
];
fn range(source: &str, id: &str, end: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(&format!("\t\tcase {id}:"))
        .context("Pinned profile filter option")?;
    let last = source[first..]
        .find(end)
        .context("Pinned profile filter boundary")?
        + first;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Profile filter source parent")?
        .join("cli-profile-filters-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (id, end) in CASES {
        reference.push_str(&source[range(&source, id, end)?]);
    }
    fs::write(
        directory.join("cli_profile_filters_reference.inc"),
        reference,
    )?;
    let exe = directory.join("cli-profile-filters-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-Wno-macro-redefined",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("cli_profile_filters_oracle.c"))
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
        "Compile profile filter option decisions and C adapter",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare profile filters, failure transactions and Lua context",
    )?;
    ensure!(
        result.starts_with("PASS cli_profile_filters "),
        "Incomplete profile filter option comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (id, end) in CASES {
        let section = range(&source, id, end)?;
        source.replace_range(section, "");
    }
    let include = "#include \"cli_list_options_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned profile filter include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"cli_profile_filters_windows.inc\""),
    );
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned profile filter dispatch"
    );
    source = source.replace(anchor, concat!(
        "\t\t{\n\t\t\tint filter = engine_profile_filter(option_index, optarg, dp, &payload_type, &range_in, &range_out);\n",
        "\t\t\tif (filter < 0) exit_clean(1);\n\t\t\tif (filter > 0) continue;\n\t\t}\n",
        "\t\tswitch (option_index)"));
    fs::write(path, source)?;
    Ok(())
}
