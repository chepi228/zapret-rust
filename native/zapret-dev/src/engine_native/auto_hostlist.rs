//! Differential checks for automatic hostlist detection and publication.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn section<'a>(source: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing {first}"))?;
    let len = source[start..]
        .find(last)
        .with_context(|| format!("Missing {last}"))?;
    ensure!(len > 0, "Empty pinned auto hostlist section");
    Ok(&source[start..start + len])
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let reference = section(
        &source,
        "static void ctrack_stop_retrans_counter(",
        "static bool send_delayed(",
    )?
    .to_owned();
    let incoming = section(
        &source,
        "\t\t// process reply packets for auto hostlist mode",
        "\n\t}\n\t// not reverse",
    )?
    .to_owned();
    let parent = nfq.parent().context("Auto hostlist source parent")?;
    let directory = parent.join("auto-hostlist-check");
    fs::create_dir(&directory)?;
    fs::write(directory.join("auto_hostlist_reference.inc"), &reference)?;
    fs::write(directory.join("auto_incoming_reference.inc"), &incoming)?;
    let helpers = fs::read_to_string(nfq.join("darkmagic.c"))?;
    fs::write(
        directory.join("auto_packet_reference.inc"),
        section(&helpers, "void reverse_ip(", "uint8_t ttl46(")?,
    )?;

    let helper_path = nfq.join("helpers.c");
    let mut helpers = fs::read_to_string(&helper_path)?;
    let old = section(&helpers, "bool append_to_list_file(", "void expand_bits(")?.to_owned();
    let writer = concat!(
        "bool append_to_list_file(const char *filename, const char *s)\n{\n",
        "\tFILE *F = fopen(filename, \"at\");\n\tif (!F) return false;\n",
        "\tbool ok = fprintf(F, \"%s\\n\", s) > 0;\n",
        "\tif (fflush(F)) ok = false;\n\tif (fclose(F)) ok = false;\n",
        "\treturn ok;\n}\n\n"
    );
    helpers = helpers.replacen(&old, writer, 1);
    fs::write(&helper_path, helpers)?;
    fs::write(directory.join("auto_writer_actual.inc"), writer)?;

    let luajit = parent
        .parent()
        .context("Auto hostlist Lua parent")?
        .join("luajit2-2.1-20250826/src");
    let executable = directory.join("auto-hostlist-check.exe");
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
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("auto_hostlist_oracle.c"));
    for name in ["pools.c", "filter.c", "helpers.c", "checksum.c"] {
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
        "Compile C and Rust auto hostlist conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust auto hostlists",
    )?;
    ensure!(
        result.starts_with("PASS auto_hostlist "),
        "Incomplete auto hostlist comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source = source.replacen(&incoming,
        "\t\tprocess_incoming_fail(ps.ctrack, ps.dp, dis, ps.l7payload, ps.l7proto, (struct sockaddr *)&ps.dst);", 1);
    source = source.replacen(&reference, "#include \"auto_hostlist_windows.inc\"\n\n", 1);
    ensure!(
        !source.contains("static bool auto_hostlist_retrans")
            && !source.contains("// process reply packets for auto hostlist mode"),
        "Pinned auto hostlist state machine was not replaced"
    );
    fs::write(path, source)?;
    Ok(())
}
