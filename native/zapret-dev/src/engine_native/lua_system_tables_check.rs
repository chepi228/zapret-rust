//! Compare complete system/time Lua entries before changing their table policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned system/time function: {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("System/time function end")?
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
        .context("Lua system table parent")?
        .join("lua-system-tables-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "static int luacall_uname(",
        "static int luacall_clock_gettime(",
        "static int luacall_clock_getfloattime(",
        "static int luacall_stat(",
        "static void lua_xtime(",
        "static int luacall_localtime(",
        "static int luacall_gmtime(",
        "static void lua_timex(",
        "static int luacall_timelocal(",
        "static int luacall_timegm(",
    ];
    let macro_start = source
        .find("#define TIMEX_VAL(v)")
        .context("Pinned TIMEX macro")?;
    let macro_end = source[macro_start..]
        .find("static void lua_timex(")
        .context("TIMEX end")?
        + macro_start;
    let mut reference = source[macro_start..macro_end].to_owned();
    for name in names {
        reference.push_str(&source[function(&source, name)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_system_tables_reference.inc"), reference)?;
    let mut common = String::new();
    for name in [
        "static void lua_check_argc(",
        "void lua_pushf_str(",
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_number(",
    ] {
        common.push_str(&source[function(&source, name)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_system_tables_common.inc"), common)?;
    let exe = directory.join("lua-system-tables-check.exe");
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
        .arg(shim.join("lua_system_tables_oracle.c"))
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
        "Compile complete system/time Lua table comparison",
    )?;
    let result = tools.run_command(&Command::new(&exe), &directory, "Compare native snapshots, time lookup order, numeric widths, CRT formatting and protected VM errors")?;
    ensure!(
        result.starts_with("PASS lua_system_tables "),
        "Incomplete Lua system/time comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(macro_start..macro_end, "");
    for (index, name) in names.iter().enumerate().rev() {
        let range = function(&source, name)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_system_tables_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
