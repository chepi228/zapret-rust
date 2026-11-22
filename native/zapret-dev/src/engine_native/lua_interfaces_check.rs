//! Compare Windows adapter-to-Lua projection before replacing its iteration.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua interface function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua interface function end")?
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
        .context("Lua interface parent")?
        .join("lua-interfaces-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let range = function(&source, "static int lua_get_ifaddrs(")?;
    fs::write(
        directory.join("lua_interfaces_reference.inc"),
        &source[range.clone()],
    )?;
    let mut common = String::new();
    for anchor in [
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_str(",
        "void lua_pushf_lstr(",
        "void lua_pushf_table(",
        "void lua_pushi_table(",
        "void lua_push_ipaddr(",
        "void lua_pushf_ipaddr(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_interfaces_common.inc"), common)?;
    let exe = directory.join("lua-interfaces-check.exe");
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
        .arg(shim.join("lua_interfaces_oracle.c"))
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
        "Compile Windows interface Lua projection comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare interface fields, address masks, iteration, duplicate writes, failures and VM ownership")?;
    ensure!(
        result.starts_with("PASS lua_interfaces "),
        "Incomplete Lua interface comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(range, "#include \"lua_interfaces_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
