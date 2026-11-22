//! Exercise address representations, invalid strings and output capacities.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

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
        .context("Lua IP source parent")?
        .join("lua-ip-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static int luacall_ntop(")
        .context("Pinned Lua address formatter")?;
    let end = source[start..]
        .find("static void lua_rawsend_extract_options(")
        .context("Pinned Lua address conversion end")?
        + start;
    fs::write(directory.join("lua_ip_reference.inc"), &source[start..end])?;
    let exe = directory.join("lua-ip-check.exe");
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
        .arg(shim.join("lua_ip_oracle.c"))
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
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile Lua address conversion comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Compare Lua address conversion",
    )?;
    ensure!(
        result.starts_with("PASS lua_ip "),
        "Incomplete Lua address conversion comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"lua_ip_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
