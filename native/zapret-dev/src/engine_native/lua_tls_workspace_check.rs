//! Compare complete TLS Lua entry, including VM memory and exact diagnostics.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned TLS Lua function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("TLS Lua function end")?
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
        .context("TLS workspace parent")?
        .join("lua-tls-workspace-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let range = function(&source, "static int luacall_tls_mod(")?;
    fs::write(
        directory.join("lua_tls_workspace_reference.inc"),
        &source[range.clone()],
    )?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc_range(",
        "const char *lua_reqlstring(",
        "const char *lua_reqstring(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_tls_workspace_common.inc"), common)?;
    let exe = directory.join("lua-tls-workspace-check.exe");
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
        .arg(shim.join("lua_tls_workspace_oracle.c"))
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
        "Compile complete TLS Lua workspace comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare TLS errors, workspace growth, immutable input, PRNG state and protected VM failure cleanup")?;
    ensure!(
        result.starts_with("PASS lua_tls_workspace "),
        "Incomplete TLS workspace comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(range, "#include \"lua_tls_workspace_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
