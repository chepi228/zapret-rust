//! Compare complete LuaJIT header builders before moving their scalar schema.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn candidate(mut source: String) -> Result<String> {
    for (kind, first, last, local) in [
        (
            0,
            "    zapret_ipv4_fields fields;",
            "\n    lua_getfield(L, idx, \"options\");",
            "",
        ),
        (
            1,
            "    zapret_ipv6_fields fields = {0};",
            "\n    uint8_t *output = (uint8_t *)ip;",
            "    lua_Integer value;\n",
        ),
        (
            2,
            "    zapret_tcp_fields fields;",
            "\n    size_t available = *len - sizeof(*tcp);",
            "    lua_Integer value;\n",
        ),
        (
            3,
            "    zapret_udp_fields fields;",
            "\n    zapret_write_udp(",
            "",
        ),
        (
            4,
            "    zapret_icmp_fields fields;",
            "\n    zapret_write_icmp(",
            "",
        ),
    ] {
        ensure!(
            source.matches(first).count() == 1,
            "Pinned header scalar declaration: {first}"
        );
        let start = source.find(first).context("Header scalar region")?;
        let end = start + source[start..].find(last).context("Header scalar end")?;
        let declaration = first.replace(" = {0}", "");
        source.replace_range(start..end, &format!("{declaration}\n    if (!native_lua_header_fields(L, idx, {kind}, &fields, sizeof(fields))) return false;\n{local}"));
    }
    let first = source
        .find("bool lua_reconstruct_iphdr(")
        .context("Header adapter insertion")?;
    source.insert_str(first, "#include \"lua_header_fields_windows.inc\"\n\n");
    // These helpers have no remaining callers; the option/extension loop retains
    // the integer helper until its own migration and independent comparison.
    let first = source
        .find("static bool read_packet_u32(")
        .context("Exact scalar helper")?;
    let last = source
        .find("#include \"lua_header_fields_windows.inc\"")
        .context("Header schema adapter")?;
    source.replace_range(first..last, "");
    Ok(source)
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
        .context("Lua header parent")?
        .join("lua-header-fields-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = shim.join("packet_lua_windows.c");
    let source = fs::read_to_string(&path)?;
    fs::write(directory.join("lua_header_fields_reference.inc"), &source)?;
    let replacement = candidate(source)?;
    fs::write(
        directory.join("lua_header_fields_candidate.inc"),
        &replacement,
    )?;
    let source = fs::read_to_string(nfq.join("lua.c"))?;
    let first = source
        .find("int lua_absindex(")
        .context("Lua absolute index helper")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua absolute index end")?
        + 3;
    fs::write(
        directory.join("lua_header_fields_common.inc"),
        &source[first..last],
    )?;
    let exe = directory.join("lua-header-fields-check.exe");
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
        .arg(shim.join("lua_header_fields_oracle.c"))
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
        "Compile complete Lua header builder comparison",
    )?;
    let result = tools.run_command(&Command::new(&exe), &directory, "Compare header fields, lookup order, coercions, partial writes and protected VM allocation failures")?;
    ensure!(
        result.starts_with("PASS lua_header_fields "),
        "Incomplete Lua header field comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, replacement)?;
    Ok(())
}
