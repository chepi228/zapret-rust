//! Select timer lifecycle only after whole-entry VM/mutation/longjmp comparison.
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
        .context("Timer lifecycle parent")?
        .join("timer-lifecycle-check");
    fs::create_dir(&directory)?;
    let path = shim.join("timer_windows.c");
    let original = fs::read_to_string(&path)?;
    ensure!(
        original.contains("if (*dirty)") && original.contains("static bool run_timer("),
        "Pinned complete timer lifecycle changed"
    );
    let mut candidate = original.clone();
    for name in ["TimerPoolDestroy", "TimerPoolNext", "TimerPoolRun"] {
        let at = candidate
            .find(&format!("{name}("))
            .with_context(|| format!("Pinned timer entry {name}"))?;
        let start = candidate[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = start
            + candidate[start..]
                .find("\n}\n")
                .context("Timer lifecycle body end")?
            + 3;
        candidate.replace_range(start..end, "");
    }
    let fire_format = "    DLOG(\"\\ntimer: '%s' period %llu oneshot %u fires=%u\\n\",";
    ensure!(
        candidate.matches(fire_format).count() == 1,
        "Pinned timer fire diagnostic changed"
    );
    candidate = candidate.replace(
        fire_format,
        "    DLOG(zapret_lua_timer_report(false,false).format,",
    );
    candidate.insert_str(0, "#include \"lua_timer_report_windows.h\"\n");
    candidate.push_str("\n#include \"timer_lifecycle_windows.inc\"\n");
    let before = directory.join("before.c");
    fs::write(
        &before,
        format!("#include \"timer_lifecycle_fixture.h\"\n{original}"),
    )?;
    let after = directory.join("after.c");
    fs::write(
        &after,
        format!("#include \"timer_lifecycle_fixture.h\"\n{candidate}"),
    )?;
    let command = || {
        let mut c = Command::new(tools.compiler);
        c.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
        ]);
        for p in [&directory, shim, &shim.join("include"), nfq] {
            c.arg(format!("-I{}", p.display()));
        }
        c.arg("-include").arg(shim.join("win_platform.h"));
        c
    };
    let object = directory.join("before.o");
    let mut c = command();
    for name in [
        "TimerPoolDestroy",
        "TimerPoolNext",
        "TimerPoolRun",
        "zapret_timer_unref",
    ] {
        c.arg(format!("-D{name}=reference_{name}"));
    }
    tools.run_command(
        c.arg("-c").arg(before).arg("-o").arg(&object),
        &directory,
        "Compile complete C timer dispatch reference",
    )?;
    let exe = directory.join("timer-lifecycle-check.exe");
    let mut c = command();
    c.arg(after)
        .arg(shim.join("timer_lifecycle_oracle.c"))
        .arg(object)
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
    tools.run_command(
        &c,
        &directory,
        "Compile complete timer lifecycle comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare timer dispatch callbacks, mutations, VM traces and C longjmp",
    )?;
    ensure!(
        result.starts_with("PASS timer_lifecycle entries=3 "),
        "Incomplete timer lifecycle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, candidate)?;
    Ok(())
}
