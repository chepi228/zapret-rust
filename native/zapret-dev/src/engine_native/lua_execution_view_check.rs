//! Exercise Lua argument views and execution plans before replacing the C policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua execution function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua execution function end")?
        + 3;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua execution parent")?
        .join("lua-execution-view-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "int lua_absindex(",
        "void lua_pushf_nil(",
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_bool(",
        "void lua_pushf_str(",
        "void lua_pushf_table(",
        "bool lua_push_blob(",
        "bool lua_pushf_blob(",
        "void lua_pushf_pos(",
        "void lua_pushf_range(",
        "static t_lua_desync_context *lua_desync_ctx(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_execution_common.inc"), common)?;
    let mut reference = String::new();
    for anchor in ["bool lua_pushf_args(", "static int luacall_execution_plan("] {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_execution_reference.inc"), reference)?;
    let mut results = String::new();
    for direct in [false, true] {
        let exe = directory.join(if direct {
            "lua-execution-view-rust-check.exe"
        } else {
            "lua-execution-view-check.exe"
        });
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
            .arg(shim.join("lua_execution_view_oracle.c"))
            .arg(shim.join("win_files.c"));
        if direct {
            command
                .args(["-DZAPRET_RUST_LUA_EXECUTION_VIEW=1", "-fexceptions"])
                .arg(object);
        }
        command
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
            "Compile Lua argument and execution plan comparison",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare lazy blobs, plan metadata, guards and real VM allocation faults",
        )?;
        ensure!(
            if direct {
                result.starts_with("PASS windows_lua_execution_view ")
            } else {
                result.starts_with("PASS lua_execution_view ")
            },
            "Incomplete Lua execution view comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    let range = function(&source, "bool lua_pushf_args(")?;
    source.replace_range(range, "");
    let range = function(&source, "static int luacall_execution_plan(")?;
    source.replace_range(range, "#include \"lua_execution_view_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
