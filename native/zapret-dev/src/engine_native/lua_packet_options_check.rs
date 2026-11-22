//! Compare option policy and complete position entries against the pinned Lua APIs.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, ops::Range, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua packet API: {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua packet API function end")?
        + 3;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    positions: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua option parent")?
        .join("lua-packet-options-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "static void lua_reconstruct_extract_options(",
        "static void lua_rawsend_extract_options(",
        "static int luacall_resolve_pos(",
        "static int luacall_resolve_multi_pos(",
        "static int luacall_resolve_range(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(
        directory.join("lua_packet_options_reference.inc"),
        reference,
    )?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc_range(",
        "const char *lua_reqlstring(",
        "const char *lua_reqstring(",
        "void lua_pushi_int(",
    ] {
        let helper = &source[function(&source, anchor)?];
        common.push_str(helper.strip_prefix("static ").unwrap_or(helper));
        common.push('\n');
    }
    fs::write(directory.join("lua_packet_options_common.inc"), common)?;
    let exe = directory.join("lua-packet-options-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-fexceptions",
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
        .arg(shim.join("lua_packet_options_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(positions)
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
        "Compile complete packet option and marker Lua APIs",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare option outputs and Rust position results, errors, guarded spans, GC reentry and allocation failures")?;
    ensure!(
        result.starts_with("PASS lua_packet_options "),
        "Incomplete packet option comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (index, anchor) in names.iter().enumerate().rev() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            match index {
                0 => "#include \"lua_packet_options_windows.inc\"\n",
                2 => "#include \"windows_lua_packet_positions_abi.h\"\n",
                _ => "",
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
