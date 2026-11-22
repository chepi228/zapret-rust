//! Verify streaming file behavior and cleanup before replacing the pinned C loop.
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
        .context("Gzip file source parent")?
        .join("gzip-file-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("gzip.c");
    let source = fs::read_to_string(&path)?;
    ensure!(
        source.contains("int z_readfile(FILE *F,") && source.contains("bool is_gzip(FILE* F)"),
        "Pinned gzip file reader changed"
    );
    fs::write(directory.join("gzip_file_reference.inc"), &source)?;
    let exe = directory.join("gzip-file-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-Wno-macro-redefined",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("gzip_file_oracle.c"))
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
        "Compile gzip file parity and error ownership checks",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare gzip/zlib files, partial reads and failed allocations",
    )?;
    ensure!(
        result.contains("PASS gzip_file "),
        "Incomplete gzip file comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    // lua_init_scripts calls this status-returning loader directly from C.
    // Match luaL_loadfile's error protocol instead of throwing across main.
    let lua_path = nfq.join("lua.c");
    let mut lua = fs::read_to_string(&lua_path)?;
    for (old, new) in [
        (
            "\t\tluaL_error(L, \"could not open lua file '%s' or '%s.gz'\", filename, filename);",
            "\t{\n\t\tlua_pushfstring(L, \"could not open lua file '%s' or '%s.gz'\", filename, filename);\n\t\treturn LUA_ERRFILE;\n\t}",
        ),
        (
            "\t\t\tluaL_error(L, \"could not open lua file '%s'\", fname);",
            "\t\t{\n\t\t\tlua_pushfstring(L, \"could not open lua file '%s'\", fname);\n\t\t\treturn LUA_ERRFILE;\n\t\t}",
        ),
        (
            "\t\t\tluaL_error(L, \"could not unzip lua file '%s'\", fname);",
            "\t\t{\n\t\t\tlua_pushfstring(L, \"could not unzip lua file '%s'\", fname);\n\t\t\treturn LUA_ERRFILE;\n\t\t}",
        ),
    ] {
        ensure!(
            lua.matches(old).count() == 1,
            "Pinned Lua file error boundary changed"
        );
        lua = lua.replace(old, new);
    }
    fs::write(lua_path, lua)?;
    Ok(())
}
