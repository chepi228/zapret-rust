//! Exercise the Windows option table against the pinned getopt implementation.
use super::{cli_numeric_patch, tools::Tools};
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
        .context("Engine CLI source parent")?
        .join("cli-check");
    fs::create_dir(&directory)?;
    let file = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&file)?;
    let start = source
        .find("enum opt_indices {")
        .context("Pinned CLI option indices")?;
    let table = source
        .find("static const struct option long_options[] = {")
        .context("Pinned CLI option table")?;
    let end = table
        + source[table..]
            .find("\n};")
            .context("Pinned CLI table end")?
        + "\n};".len();
    ensure!(start < table, "Pinned CLI table precedes its indices");
    fs::write(directory.join("option_reference.inc"), &source[start..end])?;
    cli_numeric_patch::reference(&source, &directory)?;
    let exe = directory.join("cli-check.exe");
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
    let luajit = nfq
        .parent()
        .and_then(Path::parent)
        .context("Pinned Lua headers")?
        .join("luajit2-2.1-20250826/src");
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
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("cli_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile engine argument comparison")?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Compare engine argument cursor",
    )?;
    ensure!(
        result.starts_with("PASS engine_cli ")
            && result
                .lines()
                .any(|line| line.starts_with("PASS engine_numbers ")),
        "Incomplete argument comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.insert_str(end, "\n#include \"cli_windows.inc\"\n");
    let old =
        "\twhile ((v = getopt_long_only(argc, argv, \"\", long_options, &option_index)) != -1)";
    ensure!(
        source.matches(old).count() == 1,
        "Pinned option loop changed"
    );
    source = source.replace(
        old,
        concat!(
            "\tsize_t argument_cursor = 1;\n",
            "\tconst bool stop_at_operand = getenv(\"POSIXLY_CORRECT\") != NULL;\n",
            "\tchar *optarg = NULL;\n",
            "\twhile ((v = native_cli_next(argc, argv, long_options, IDX_LAST, &argument_cursor, ",
            "stop_at_operand, &optarg, &option_index)) != -1)",
        ),
    );
    cli_numeric_patch::apply(&mut source)?;
    fs::write(file, source)?;
    Ok(())
}
