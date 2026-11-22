//! Compare real LuaJIT assembly, including lazy lookups and protected VM OOM.
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
        .context("Lua packet parent")?
        .join("lua-packet-assembly-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "static void lua_check_argc_range(",
        "int lua_absindex(",
        "const char *lua_reqlstring(",
        "const char *lua_reqstring(",
    ] {
        let first = source
            .find(anchor)
            .context("Pinned Lua scalar marshaller")?;
        let last = first
            + source[first..]
                .find("\n}\n")
                .context("Pinned Lua marshaller end")?
            + 3;
        common.push_str(&source[first..last]);
        common.push('\n');
    }
    fs::write(directory.join("lua_packet_common.inc"), common)?;
    let first = source
        .find("uint8_t lua_ip6_l4proto_from_dissect(")
        .context("Pinned packet protocol probe")?;
    let last = first
        + source[first..]
            .find("static int luacall_reconstruct_dissect(")
            .context("Pinned packet assembly end")?;
    fs::write(
        directory.join("lua_packet_reference.inc"),
        &source[first..last],
    )?;
    let exe = directory.join("lua-packet-assembly-check.exe");
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
        .arg(shim.join("lua_packet_assembly_oracle.c"))
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
        "Compile Lua packet assembly comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare packet bytes, lookup order, guards and real Lua allocation faults",
    )?;
    ensure!(
        result.starts_with("PASS lua_packet_assembly "),
        "Incomplete Lua packet assembly comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(
        first..last,
        "#include \"lua_packet_assembly_windows.inc\"\n\n",
    );
    let marker = "#include \"packet_lua_windows.c\"";
    ensure!(
        source.matches(marker).count() == 1,
        "Pinned packet marshalling include changed"
    );
    source = source.replace(
        marker,
        "#define ZAPRET_LUA_PACKET_ASSEMBLY_RUST\n#include \"packet_lua_windows.c\"",
    );
    fs::write(path, source)?;
    Ok(())
}
