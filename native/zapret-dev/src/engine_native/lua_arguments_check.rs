//! Compare escaped CLI rules and verify that an invalid rule leaves the list intact.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn through_function(source: &str, start: usize) -> Result<usize> {
    Ok(start
        + source[start..]
            .find("\n}\n")
            .context("Pinned Lua parser function end")?
        + 3)
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
        .context("Lua arguments source parent")?
        .join("lua-arguments-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let name = source
        .find("static char* item_name(")
        .context("Pinned option name parser")?;
    let name_end = through_function(&source, name)?;
    let start = source
        .find("bool lua_call_param_add(")
        .context("Pinned Lua parameter parser")?;
    let parse = source[start..]
        .find("struct func_list *parse_lua_call(")
        .context("Pinned Lua call parser")?
        + start;
    let end = through_function(&source, parse)?;
    fs::write(
        directory.join("lua_arguments_reference.inc"),
        format!("{}\n{}", &source[name..name_end], &source[start..end]),
    )?;
    let pools = fs::read_to_string(nfq.join("pools.c"))?;
    let first = pools
        .find("static void str2list_entry_destroy(")
        .context("Pinned argument list")?;
    let last = pools
        .find("bool funclist_copy(")
        .context("Pinned function list")?;
    fs::write(
        directory.join("lua_arguments_pools.inc"),
        &pools[first..through_function(&pools, last)?],
    )?;

    let executable = directory.join("lua-arguments-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
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
        .arg(shim.join("lua_arguments_oracle.c"))
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
        .arg(&executable);
    tools.run_command(&command, &directory, "Compile Lua argument comparison")?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare Lua argument parsing",
    )?;
    ensure!(
        result.starts_with("PASS lua_arguments "),
        "Incomplete Lua argument comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"lua_arguments_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
