//! Compare source-address socket ownership and the complete Lua wrapper.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned source IP function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Source IP function end")?
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
        .context("Route source parent")?
        .join("route-source-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let packet_path = nfq.join("darkmagic.c");
    let mut packet = fs::read_to_string(&packet_path)?;
    let mut reference = String::new();
    for anchor in ["bool get_source_ip4(", "bool get_source_ip6("] {
        reference.push_str(&packet[function(&packet, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("route_source_reference.inc"), reference)?;
    let lua_path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&lua_path)?;
    let range = function(&source, "static int luacall_get_source_ip(")?;
    fs::write(
        directory.join("lua_source_ip_reference.inc"),
        &source[range.clone()],
    )?;
    let mut common = String::new();
    for anchor in ["static void lua_check_argc(", "const char *lua_reqlstring("] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_source_ip_common.inc"), common)?;
    let exe = directory.join("route-source-check.exe");
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
        .arg(shim.join("route_source_oracle.c"))
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
        "Compile source IP ownership and Lua result comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare socket failures, exact address bytes, close-before-publish and Lua allocation cleanup")?;
    ensure!(
        result.starts_with("PASS route_source "),
        "Incomplete source address comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (version, anchor, ty) in [
        (6, "bool get_source_ip6(", "in6_addr"),
        (4, "bool get_source_ip4(", "in_addr"),
    ] {
        let range = function(&packet, anchor)?;
        packet.replace_range(range,&format!("{}bool get_source_ip{version}(const struct {ty} *target,struct {ty} *source)\n{{\n    return zapret_route_source({version},(const uint8_t *)target,(uint8_t *)source,NULL);\n}}\n",if version==4{"#include \"route_source_windows.h\"\n"}else{""}));
    }
    source.replace_range(range, "#include \"lua_source_ip_windows.inc\"\n");
    fs::write(lua_path, source)?;
    fs::write(packet_path, packet)?;
    Ok(())
}
