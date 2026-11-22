//! Select lifecycle only after complete old/new entries and failure VM traces.
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
    let parent = nfq.parent().context("Conntrack lifecycle parent")?;
    let directory = parent.join("conntrack-lifecycle-check");
    fs::create_dir(&directory)?;
    let previous = parent.join("conntrack-check");
    for name in ["tcp_helpers.inc", "reassembly_session_reference.inc"] {
        fs::copy(previous.join(name), directory.join(name))?;
    }
    let path = shim.join("conntrack_windows.c");
    let original = fs::read_to_string(&path)?;
    ensure!(
        original.contains("static void ConntrackInitTrack(")
            && original.contains("ConntrackClearTrack(track)"),
        "Pinned complete conntrack facade changed"
    );
    fs::write(directory.join("conntrack_lifecycle_before.inc"), &original)?;
    let mut candidate = original;
    for name in [
        "ConntrackClearHostname",
        "ConntrackClearTrack",
        "ConntrackFreeElem",
        "ConntrackInitTrack",
        "ConntrackPoolDestroy",
        "ConntrackPoolInit",
        "ConntrackNew",
        "ConntrackFeedPacket",
        "ConntrackPoolDoubleSearch",
        "ConntrackPoolFeed",
        "ConntrackPoolDrop",
        "ConntrackPoolPurge",
    ] {
        let at = candidate
            .find(&format!("{name}("))
            .with_context(|| format!("Pinned conntrack lifecycle {name}"))?;
        let start = candidate[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = start
            + candidate[start..]
                .find("\n}\n")
                .context("Conntrack lifecycle body end")?
            + 3;
        candidate.replace_range(start..end, "");
    }
    candidate.push_str("\n#include \"conntrack_lifecycle_windows.inc\"\n");
    let actual = directory.join("actual.c");
    fs::write(
        &actual,
        format!(
            "#include \"conntrack_fixture.h\"\n#define clock_gettime fixture_clock_gettime\n{candidate}"
        ),
    )?;
    let core = fs::read_to_string(shim.join("conntrack_oracle.c"))?;
    ensure!(
        core.contains("int main(void)"),
        "Pinned conntrack oracle main"
    );
    fs::write(
        directory.join("conntrack_lifecycle_core.inc"),
        core.replace("int main(void)", "int conntrack_lifecycle_core_main(void)"),
    )?;
    let lua = parent
        .parent()
        .context("Lua source parent")?
        .join("luajit2-2.1-20250826/src");
    let command = || {
        let mut c = Command::new(tools.compiler);
        c.args([
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
        for p in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            &lua,
            nfq,
        ] {
            c.arg(format!("-I{}", p.display()));
        }
        c.arg("-include").arg(shim.join("win_platform.h"));
        c
    };
    let names = [
        "ConntrackPoolInit",
        "ConntrackPoolDestroy",
        "ConntrackPoolFeed",
        "ConntrackPoolDoubleSearch",
        "ConntrackPoolDrop",
        "ConntrackExtractConn",
        "ConntrackPoolPurge",
        "ConntrackClearHostname",
    ];
    let object = directory.join("before.o");
    let mut c = command();
    c.arg("-include")
        .arg(shim.join("conntrack_lifecycle_fixture.h"));
    for name in names {
        c.arg(format!("-D{name}=reference_{name}"));
    }
    tools.run_command(
        c.arg("-c")
            .arg(shim.join("conntrack_lifecycle_reference.c"))
            .arg("-o")
            .arg(&object),
        &directory,
        "Compile complete C conntrack facade reference",
    )?;
    let actual_object = directory.join("after.o");
    let mut c = command();
    c.arg("-include")
        .arg(shim.join("conntrack_lifecycle_fixture.h"));
    tools.run_command(
        c.arg("-c").arg(actual).arg("-o").arg(&actual_object),
        &directory,
        "Compile Rust lifecycle conntrack facade",
    )?;
    let exe = directory.join("conntrack-lifecycle-check.exe");
    let mut c = command();
    c.arg(shim.join("conntrack_lifecycle_oracle.c"))
        .arg(object)
        .arg(actual_object)
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
        .arg(&exe);
    tools.run_command(&c, &directory, "Link whole conntrack lifecycle comparison")?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare conntrack full entries, partial failures and VM operation traces",
    )?;
    ensure!(
        result.lines().count() == 3
            && result.lines().all(|s| s.starts_with("PASS "))
            && result.contains("PASS conntrack_lifecycle entries=8 "),
        "Incomplete conntrack lifecycle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, candidate)?;
    Ok(())
}
