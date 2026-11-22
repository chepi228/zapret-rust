//! Compare SHA-224/SHA-256 and HKDF through the actual LuaJIT boundary.
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
        .context("Lua hash source parent")?
        .join("lua-hash-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    let include = source
        .find("static SHAversion lua_hash_type(")
        .context("Pinned Lua hash helper")?;
    for name in ["lua_hash_type", "luacall_hash", "luacall_hkdf"] {
        let start = source
            .find(&format!(" {name}("))
            .context("Pinned Lua hash function")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned Lua hash function end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("lua_hash_reference.inc"), reference)?;
    let exe = directory.join("lua-hash-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
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
        .arg(shim.join("lua_hash_oracle.c"));
    for file in ["sha224-256.c", "usha.c", "hmac.c", "hkdf.c"] {
        command.arg(nfq.join("crypto").join(file));
    }
    command
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
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile Lua SHA-2 and HKDF comparison",
    )?;
    let result = tools.run_command(&Command::new(exe), &directory, "Compare Lua SHA-2 and HKDF")?;
    ensure!(
        result.starts_with("PASS lua_hash "),
        "Incomplete Lua SHA-2 comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.insert_str(include, "#include \"lua_hash_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
