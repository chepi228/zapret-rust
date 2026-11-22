//! Compare checksum API outputs/errors in the pinned real LuaJIT before patching.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua checksum function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua checksum end")?
        + 3;
    Ok(first..last)
}
pub(super) fn capture(nfq: &Path) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Pinned checksum parent")?
        .join("lua-checksum-pinned");
    fs::create_dir(&directory)?;
    fs::copy(
        nfq.join("checksum.c"),
        directory.join("checksum_reference.inc"),
    )?;
    let source = fs::read_to_string(nfq.join("darkmagic.c"))?;
    let mut predicates = String::new();
    for name in [
        "proto_check_ipv4",
        "proto_check_ipv6",
        "proto_check_tcp",
        "proto_check_udp",
        "proto_check_icmp",
    ] {
        predicates.push_str(&source[function(&source, &format!("bool {name}("))?]);
        predicates.push('\n');
    }
    fs::write(directory.join("checksum_predicates.inc"), predicates)?;
    Ok(())
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
        .context("Lua checksum parent")?
        .join("lua-checksum-check");
    fs::create_dir(&directory)?;
    let pinned = nfq
        .parent()
        .context("Pinned Lua checksum parent")?
        .join("lua-checksum-pinned");
    for name in ["checksum_reference.inc", "checksum_predicates.inc"] {
        fs::copy(pinned.join(name), directory.join(name))?;
    }
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in ["static void lua_check_argc(", "const char *lua_reqlstring("] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_checksum_common.inc"), common)?;
    let names = [
        "static int luacall_csum_ip4_fix(",
        "static int luacall_csum_tcp_fix(",
        "static int luacall_csum_udp_fix(",
        "static int luacall_csum_icmp_fix(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_checksum_reference.inc"), reference)?;
    let exe = directory.join("lua-checksum-check.exe");
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
        .arg(shim.join("lua_checksum_oracle.c"))
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
        "Compile Lua checksum wire/error comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare checksums, malformed inputs, guarded buffers and VM allocation failures",
    )?;
    ensure!(
        result.starts_with("PASS lua_checksum "),
        "Incomplete Lua checksum comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (index, anchor) in names.into_iter().enumerate() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_checksum_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
