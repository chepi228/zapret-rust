//! Compare complete builders after scalar extraction, before replacing list policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, ops::Range, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned header list function: {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Header list function end")?
        + 3;
    Ok(first..last)
}
fn candidate(mut source: String) -> Result<String> {
    for (anchor, mode, output, extra) in [
        (
            "bool lua_reconstruct_ip6hdr(",
            1,
            "ip",
            "last_protocol, preserve_next",
        ),
        ("bool lua_reconstruct_tcphdr(", 0, "tcp", "0, false"),
    ] {
        let range = function(&source, anchor)?;
        let start = range.start
            + source[range.clone()]
                .find("    lua_Integer value;")
                .context("Header list local boundary")?;
        source.replace_range(start..range.end,&format!("    if (!native_lua_header_list(L, idx, {mode}, {output}, len, &fields, {extra})) return false;\n    LUA_STACK_GUARD_LEAVE(L, 0)\n    return true;\n}}\n"));
    }
    let integer = function(&source, "static bool read_packet_integer(")?;
    source.replace_range(integer, "");
    let include = "#include \"lua_header_fields_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned header field adapter include"
    );
    let at = source.find(include).context("Scalar adapter include")? + include.len();
    source.insert_str(at, "\n#include \"lua_header_list_windows.inc\"");
    for (kind, header, capacity) in [
        (0, "iphdr", "*ip"),
        (1, "ip6hdr", "*ip"),
        (2, "tcphdr", "*tcp"),
        (3, "udphdr", ""),
        (4, "icmphdr", ""),
    ] {
        let range = function(&source, &format!("bool lua_reconstruct_{header}("))?;
        let mut body = source[range.clone()].to_owned();
        let before = if capacity.is_empty() {
            String::new()
        } else {
            format!("*len < sizeof({capacity}) || ")
        };
        let after = if capacity.is_empty() {
            ""
        } else {
            "*len < api.minimum || "
        };
        let check = format!("    if ({before}lua_type(L, idx) != LUA_TTABLE) return false;");
        ensure!(
            body.matches(&check).count() == 1,
            "Pinned Lua {header} input guard"
        );
        body = body.replace(&check, &format!(
            "    const zapret_lua_header_write_api api=zapret_lua_header_write_entry({kind});\n    if ({after}lua_type(L, idx) != api.table_tag) return false;"
        ));
        if kind == 0 {
            ensure!(
                body.matches("lua_getfield(L, idx, \"options\")").count() == 1
                    && body.matches("lua_type(L, -1) == LUA_TSTRING").count() == 1,
                "Pinned IPv4 option extraction"
            );
            body = body
                .replace(
                    "lua_getfield(L, idx, \"options\")",
                    "lua_getfield(L, idx, api.options_field)",
                )
                .replace(
                    "lua_type(L, -1) == LUA_TSTRING",
                    "lua_type(L, -1) == api.options_tag",
                );
        }
        source.replace_range(range, &body);
    }
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
        .context("Header list parent")?
        .join("lua-header-list-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = shim.join("packet_lua_windows.c");
    let source = fs::read_to_string(&path)?;
    fs::write(
        directory.join("lua_header_list_source_reference.c"),
        &source,
    )?;
    let mut reference = String::new();
    for anchor in [
        "static bool read_packet_integer(",
        "bool lua_reconstruct_ip6hdr(",
        "bool lua_reconstruct_tcphdr(",
    ] {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_header_list_reference.inc"), reference)?;
    let replacement = candidate(source)?;
    let mut functions = String::new();
    for anchor in [
        "bool lua_reconstruct_ip6hdr(",
        "bool lua_reconstruct_tcphdr(",
    ] {
        functions.push_str(&replacement[function(&replacement, anchor)?]);
        functions.push('\n');
    }
    fs::write(directory.join("lua_header_list_candidate.inc"), functions)?;
    fs::write(
        directory.join("lua_header_list_source_candidate.c"),
        &replacement,
    )?;
    let source = fs::read_to_string(nfq.join("lua.c"))?;
    fs::write(
        directory.join("lua_header_list_common.inc"),
        &source[function(&source, "int lua_absindex(")?],
    )?;
    let exe = directory.join("lua-header-list-check.exe");
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
        .arg(shim.join("lua_header_list_oracle.c"))
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
        "Compile complete TCP option and IPv6 extension comparison",
    )?;
    let control = tools.run_command(
        Command::new(&exe).arg("--oom-control"),
        &directory,
        "Validate independent C VM allocation checkpoints against the C reference",
    )?;
    ensure!(
        control.starts_with("PASS lua_header_list_reference_control "),
        "Incomplete C VM allocation control"
    );
    fs::write(
        output.with_file_name("lua-header-list-control-check.log"),
        &control,
    )?;
    print!("{control}");
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare header list progression, partial output, lazy lookups, reentry and protected VM allocation failures")?;
    ensure!(
        result.starts_with("PASS lua_header_list "),
        "Incomplete Lua header list comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, replacement)?;
    Ok(())
}
