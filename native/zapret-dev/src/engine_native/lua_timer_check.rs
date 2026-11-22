//! Compare complete timer APIs before selecting their Rust entry policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua timer helper {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua timer helper end")?
        + 3;
    Ok(first..last)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua timer parent")?
        .join("lua-timer-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let reference = fs::read_to_string(shim.join("timer_lua.c"))?;
    ensure!(
        reference.contains("switch (lua_type(L, 2))")
            && reference.contains("static int luacall_timer_enum("),
        "Pinned timer API reference changed"
    );
    fs::write(directory.join("lua_timer_reference.inc"), reference)?;
    let path = nfq.join("lua.c");
    let source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "static void lua_check_argc_range(",
        "void lua_pushf_lint(",
        "void lua_pushf_bool(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_timer_common.inc"), common)?;
    let exe = directory.join("lua-timer-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        lua,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("lua_timer_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(lua.join("libluajit.a"))
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
            "-lshell32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile complete Lua timer comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare timer validation, registry ownership, mutation, nesting and VM allocation failures",
    )?;
    ensure!(
        result.starts_with("PASS lua_timer "),
        "Incomplete timer comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    // The old C file stays a comparison reference. The new include, unlike an
    // overwritten include-only C file, is captured in the active source audit.
    ensure!(
        source.matches("#include \"timer_lua.c\"").count() == 1
            && !source.contains("#include \"lua_timer_windows.inc\""),
        "Pinned timer API include changed"
    );
    fs::write(
        path,
        source.replace(
            "#include \"timer_lua.c\"",
            "#include \"lua_timer_windows.inc\"",
        ),
    )?;
    Ok(())
}
