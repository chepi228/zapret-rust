//! Compare borrowed header fields and option iterators using real LuaJIT tables.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned Lua header function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua header function end")?
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
        .context("Lua dissection parent")?
        .join("lua-packet-dissection-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_push_raw(",
        "void lua_pushf_raw(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_dissection_common.inc"), common)?;
    let names = [
        "void lua_pushf_tcphdr_options(",
        "void lua_push_tcphdr(",
        "void lua_push_udphdr(",
        "void lua_push_icmphdr(",
        "void lua_push_iphdr(",
        "void lua_pushf_ip6exthdr(",
        "void lua_push_ip6hdr(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_dissection_reference.inc"), reference)?;
    let exe = directory.join("lua-packet-dissection-check.exe");
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
        .arg(shim.join("lua_packet_dissection_oracle.c"))
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
        "Compile Lua packet dissection comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare decoded Lua tables, guard pages and VM OOM cleanup",
    )?;
    ensure!(
        result.starts_with("PASS lua_packet_dissection "),
        "Incomplete Lua dissection comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (index, anchor) in names.into_iter().enumerate() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_packet_dissection_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
