//! Check startup option side effects, then replace the pinned C decisions.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
const CASES: [(&str, &str); 6] = [
    ("IDX_DEBUG", "\t\tcase IDX_DRY_RUN:"),
    ("IDX_CHDIR", "\t\tcase IDX_PIDFILE:"),
    ("IDX_PIDFILE", "\n#ifndef ZAPRET_WINDOWS"),
    ("IDX_WRITABLE", "\t\tcase IDX_BLOB:"),
    ("IDX_LUA_INIT", "\t\tcase IDX_HOSTLIST:"),
    ("IDX_HOSTLIST_AUTO_DEBUG", "\t\tcase IDX_NEW:"),
];
fn range(source: &str, id: &str, end: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(&format!("\t\tcase {id}:"))
        .context("Pinned startup option")?;
    let last = source[first..]
        .find(end)
        .context("Pinned startup option boundary")?
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
        .context("Startup options parent")?
        .join("cli-startup-options-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (id, end) in CASES {
        reference.push_str(&source[range(&source, id, end)?]);
    }
    fs::write(
        directory.join("cli_startup_options_reference.inc"),
        reference,
    )?;
    let exe = directory.join("cli-startup-options-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-Wno-macro-redefined",
        "-DSTARTUP_INTEGRATED_CHECK",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("cli_startup_options_oracle.c"))
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
        "Compile startup option decisions and C adapter comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check startup option side effects and atomic fields",
    )?;
    ensure!(
        result.starts_with("PASS cli_startup_options "),
        "Incomplete startup option comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (id, end) in CASES {
        let range = range(&source, id, end)?;
        source.replace_range(range, "");
    }
    let include = "#include \"cli_numeric_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned startup option include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"cli_startup_options_windows.inc\""),
    );
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned startup option dispatch"
    );
    source = source.replace(
        anchor,
        concat!(
            "\t\t{\n\t\t\tint startup = engine_startup_option(option_index, optarg);\n",
            "\t\t\tif (startup < 0) exit_clean(1);\n\t\t\tif (startup > 0) continue;\n\t\t}\n",
            "\t\tswitch (option_index)"
        ),
    );
    fs::write(path, source)?;
    Ok(())
}
