//! Check engine helper semantics independently before replacing their C bodies.
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
        .context("Helper source parent")?
        .join("helpers-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("helpers.c");
    let mut source = fs::read_to_string(&path)?;
    let aliases = fs::read_to_string(shim.join("helpers_windows.inc"))?;
    let names: Vec<_> = aliases
        .lines()
        .filter_map(|line| {
            line.strip_prefix("#define ")
                .and_then(|rest| rest.split_once(' ').map(|v| v.0))
        })
        .collect();
    ensure!(names.len() == 33, "Unexpected helper ABI count");
    let mut reference = String::new();
    for name in &names {
        reference.push_str(&format!("#undef {name}\n#define {name} reference_{name}\n"));
    }
    for (first, last) in [
        ("#define UNIQ_SORT", "bool load_file("),
        ("void expand_bits(", "// \"       [fd00::1]\""),
        ("bool seq_within(", "int fprint_localtime("),
        (
            "void fill_random_bytes(",
            "#if defined(__FreeBSD__) && __FreeBSD_version <= 1200000",
        ),
        (
            "#if defined(__GNUC__) && !defined(__llvm__)",
            "void set_console_io_buffering(",
        ),
    ] {
        let start = source.find(first).context("Pinned helper block start")?;
        let end = start
            + source[start..]
                .find(last)
                .context("Pinned helper block end")?;
        ensure!(start < end, "Pinned helper order changed");
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    for name in &names {
        reference.push_str(&format!("#undef {name}\n"));
    }
    fs::write(directory.join("helpers_reference.inc"), reference)?;
    let exe = directory.join("helpers-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("helpers_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lole32",
            "-loleaut32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(&command, &directory, "Compile engine helper comparison")?;
    let result = tools.run_command(&Command::new(exe), &directory, "Compare engine helpers")?;
    ensure!(
        result.starts_with("PASS engine_helpers "),
        "Incomplete helper comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    let header = nfq.join("helpers.h");
    let source = fs::read_to_string(&header)?;
    ensure!(
        source.starts_with("#pragma once\n"),
        "Pinned helper guard changed"
    );
    fs::write(
        header,
        source.replacen(
            "#pragma once\n",
            "#pragma once\n#include \"helpers_windows.inc\"\n",
            1,
        ),
    )?;
    Ok(())
}
