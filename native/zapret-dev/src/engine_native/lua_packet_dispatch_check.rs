//! Compare complete outer Lua packet entries before moving their stage policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned outer Lua packet function: {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Outer Lua packet function end")?
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
        .context("Packet dispatch parent")?
        .join("lua-packet-dispatch-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    fs::copy(
        shim.join("packet_lua_windows.c"),
        directory.join("lua_packet_dispatch_headers.inc"),
    )?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "static int luacall_reconstruct_dissect(",
        "static int luacall_dissect(",
        "static int luacall_rawsend(",
        "static int luacall_rawsend_dissect(",
        "static int luacall_conntrack_feed(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(
        directory.join("lua_packet_dispatch_reference.inc"),
        reference,
    )?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc_range(",
        "int lua_absindex(",
        "const char *lua_reqlstring(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_packet_dispatch_common.inc"), common)?;
    let exe = directory.join("lua-packet-dispatch-check.exe");
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
        .arg(shim.join("lua_packet_dispatch_oracle.c"))
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
        "Compile complete outer Lua packet dispatch comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare validation order, mutable pools, packet bytes, send outcomes, nested dispatch and protected VM errors")?;
    ensure!(
        result.starts_with("PASS lua_packet_dispatch "),
        "Incomplete outer Lua packet comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (index, anchor) in names.iter().enumerate().rev() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_packet_dispatch_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
