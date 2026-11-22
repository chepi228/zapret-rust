//! Replace the final common option decisions after comparing their pinned C flow.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
const CASES: [(&str, &str); 2] = [
    ("IDX_NEW", "\n#ifdef HAS_FILTER_SSID"),
    ("IDX_DRY_RUN", "\n#ifdef __linux__"),
];
fn range(source: &str, start: &str, end: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(&format!("\t\tcase {start}:"))
        .context("Pinned CLI control start")?;
    let last = first
        + source[first..]
            .find(end)
            .context("Pinned CLI control end")?;
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
        .context("CLI control parent")?
        .join("cli-control-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (start, end) in CASES {
        reference.push_str(&source[range(&source, start, end)?]);
    }
    fs::write(directory.join("cli_control_reference.inc"), reference)?;
    let exe = directory.join("cli-control-check.exe");
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
        .arg(shim.join("cli_control_oracle.c"))
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
        "Compile remaining CLI control and C adapter comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare profile state resets, template failures and exit requests",
    )?;
    ensure!(
        result.starts_with("PASS cli_control "),
        "Incomplete CLI control comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (start, end) in CASES {
        let section = range(&source, start, end)?;
        source.replace_range(section, "");
    }
    let include = "#include \"profile_flow_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned CLI control include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"cli_control_windows.inc\""),
    );
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned CLI control dispatch"
    );
    source=source.replace(anchor,concat!(
        "\t\t{\n\t\t\tint control=engine_control_option(option_index,optarg,&profile_flow,&dpl,&dp,&anon_hl,&anon_hl_exclude,&anon_ips,&anon_ips_exclude,&payload_type,&range_in,&range_out,&bDry);\n",
        "\t\t\tif(control<0){uint32_t status=(uint32_t)(-control-1);if(status==6)DLOG_ERR(\"invalid CLI control storage\\n\");else native_profile_exit(status,option_index==IDX_NEW?dp->name:optarg);exit_clean(1);}\n",
        "\t\t\tif(control==2)exit_clean(0);\n\t\t\tif(control>0)continue;\n\t\t}\n",
        "\t\tswitch (option_index)"));
    fs::write(path, source)?;
    Ok(())
}
