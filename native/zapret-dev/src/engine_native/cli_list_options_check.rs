//! Compare the pinned nine C cases and adapter before removing their option policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const CASES: [(&str, &str); 9] = [
    ("IDX_HOSTLIST", "IDX_HOSTLIST_DOMAINS"),
    ("IDX_HOSTLIST_DOMAINS", "IDX_HOSTLIST_EXCLUDE"),
    ("IDX_HOSTLIST_EXCLUDE", "IDX_HOSTLIST_EXCLUDE_DOMAINS"),
    ("IDX_HOSTLIST_EXCLUDE_DOMAINS", "IDX_HOSTLIST_AUTO"),
    ("IDX_HOSTLIST_AUTO", "IDX_NEW"),
    ("IDX_IPSET", "IDX_IPSET_IP"),
    ("IDX_IPSET_IP", "IDX_IPSET_EXCLUDE"),
    ("IDX_IPSET_EXCLUDE", "IDX_IPSET_EXCLUDE_IP"),
    ("IDX_IPSET_EXCLUDE_IP", "IDX_PAYLOAD"),
];
fn range(source: &str, id: &str, end: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(&format!("\t\tcase {id}:"))
        .context("Pinned list option")?;
    let last = source[first..]
        .find(&format!("\t\tcase {end}:"))
        .context("Pinned list option boundary")?
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
        .context("List option parent")?
        .join("cli-list-options-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (id, end) in CASES {
        reference.push_str(&source[range(&source, id, end)?]);
    }
    fs::write(directory.join("cli_list_options_reference.inc"), reference)?;
    let exe = directory.join("cli-list-options-check.exe");
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
        .arg(shim.join("cli_list_options_oracle.c"))
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
        "Compile list option policy and C adapter comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check list option order, reuse, skip and I/O failures",
    )?;
    ensure!(
        result.starts_with("PASS cli_list_options "),
        "Incomplete list option comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (id, end) in CASES {
        let section = range(&source, id, end)?;
        source.replace_range(section, "");
    }
    let include = "#include \"cli_startup_options_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned list option include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"cli_list_options_windows.inc\""),
    );
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned list option dispatch"
    );
    source = source.replace(anchor, concat!(
        "\t\t{\n\t\t\tint list = engine_list_option(option_index, optarg, dp, profile_flow.skip, &anon_hl, &anon_hl_exclude, &anon_ips, &anon_ips_exclude);\n",
        "\t\t\tif (list < 0) exit_clean(1);\n\t\t\tif (list > 0) continue;\n\t\t}\n",
        "\t\tswitch (option_index)"));
    fs::write(path, source)?;
    Ok(())
}
