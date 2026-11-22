//! Compare the real C connection table and the Rust-backed C API in memory.
use super::{conntrack_patch, reassembly_patch, tools::Tools};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let parent = nfq.parent().context("Pinned conntrack source parent")?;
    let directory = parent.join("conntrack-check");
    fs::create_dir(&directory)?;
    let desync = nfq.join("desync.c");
    let packet_handlers = fs::read_to_string(&desync)?;
    let lifecycle = reassembly_patch::lifecycle(&packet_handlers)?;
    fs::write(
        directory.join("reassembly_session_reference.inc"),
        &packet_handlers[lifecycle],
    )?;
    let luajit = parent
        .parent()
        .context("Pinned Lua source parent")?
        .join("luajit2-2.1-20250826/src");
    let source = fs::read_to_string(nfq.join("conntrack.c"))?;
    let dump = source
        .find("static void taddr2str(")
        .context("Pinned conntrack dump boundary")?;
    let reassembly = source
        .find("void ReasmClear(")
        .context("Pinned conntrack reassembly boundary")?;
    ensure!(dump < reassembly, "Pinned conntrack boundaries changed");
    // The oracle compares storage and state, excluding the text-only dump.
    let source = format!("{}{}", &source[..dump], &source[reassembly..]);
    let helpers = fs::read_to_string(nfq.join("darkmagic.c"))?;
    let first = helpers
        .find("uint8_t *tcp_find_option(")
        .context("Pinned conntrack TCP helpers")?;
    let last = helpers
        .find("bool extract_dst(")
        .context("Pinned conntrack TCP helper boundary")?;
    ensure!(first < last, "Pinned TCP helper boundaries changed");
    fs::write(directory.join("tcp_helpers.inc"), &helpers[first..last])?;
    let reference = directory.join("reference.c");
    fs::write(
        &reference,
        format!(
            "#include \"conntrack_fixture.h\"\n#define clock_gettime fixture_clock_gettime\n\
             {source}\n#include \"conntrack_reference.c\"\n"
        ),
    )?;
    let command = || {
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
        // Keep LuaJIT before nfq: its lauxlib.h includes <lua.h>.
        for include in [
            directory.clone(),
            shim.to_owned(),
            shim.join("include"),
            nfq.join("windows"),
            luajit.clone(),
            nfq.to_owned(),
        ] {
            command.arg(format!("-I{}", include.display()));
        }
        command.arg("-include").arg(shim.join("win_platform.h"));
        command
    };
    let object = directory.join("reference.o");
    let mut compile = command();
    for name in [
        "ConntrackPoolInit",
        "ConntrackPoolDestroy",
        "ConntrackPoolFeed",
        "ConntrackPoolDoubleSearch",
        "ConntrackPoolDrop",
        "ConntrackExtractConn",
        "ConntrackPoolDump",
        "ConntrackPoolPurge",
        "ConntrackClearHostname",
        "ReasmInit",
        "ReasmResize",
        "ReasmClear",
        "ReasmFeed",
        "ReasmHasSpace",
    ] {
        compile.arg(format!("-D{name}=reference_{name}"));
    }
    // Compile before replacing the header, so the oracle uses the pinned
    // uthash record layout and unmodified C algorithms.
    tools.run_command(
        compile.args(["-c", "-o"]).arg(&object).arg(reference),
        &directory,
        "Compile pinned C conntrack reference",
    )?;
    conntrack_patch::apply(nfq)?;
    let actual = directory.join("actual.c");
    fs::write(
        &actual,
        "#include \"conntrack_fixture.h\"\n#define clock_gettime fixture_clock_gettime\n\
         #include \"conntrack_windows.c\"\n",
    )?;
    let executable = directory.join("conntrack-check.exe");
    tools.run_command(
        command()
            .arg(actual)
            .arg(shim.join("conntrack_oracle.c"))
            .arg(&object)
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-o",
            ])
            .arg(&executable),
        &directory,
        "Compile C and Rust conntrack conformance",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare C and Rust conntrack semantics",
    )?;
    ensure!(
        result.lines().count() == 2 && result.lines().all(|line| line.starts_with("PASS ")),
        "Conntrack or reassembly lifecycle comparison incomplete"
    );
    fs::write(output, &result)?;
    println!("{}", result.trim());
    reassembly_patch::apply(&desync)?;
    Ok(())
}
