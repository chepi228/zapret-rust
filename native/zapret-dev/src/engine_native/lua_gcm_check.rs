//! Compare the legacy Lua GCM contract for every key size and runtime IV sizes.
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
        .context("Lua GCM source parent")?
        .join("lua-gcm-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static int luacall_aes_gcm(")
        .context("Pinned Lua GCM function")?;
    let end = source[start..]
        .find("\n}\n")
        .context("Pinned Lua GCM function end")?
        + start
        + 3;
    let original = &source[start..end];
    let updated = original.replace("aes_gcm_crypt(bEncrypt, output, input, input_len, key, key_len, iv, iv_len, add, add_len, atag, sizeof(atag))",
        "!zapret_lua_aes_gcm(bEncrypt, key, key_len, iv, iv_len, input, input_len, add, add_len, output, atag)");
    ensure!(updated != original, "Pinned GCM computation changed");
    let declaration = "bool zapret_lua_aes_gcm(bool, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, uint8_t *);\n";
    fs::write(
        directory.join("lua_gcm_comparison.inc"),
        format!(
            "{declaration}#define luacall_aes_gcm reference_luacall_aes_gcm\n{original}\n#undef luacall_aes_gcm\n{updated}"
        ),
    )?;
    let exe = directory.join("lua-gcm-check.exe");
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
        .arg(shim.join("lua_gcm_oracle.c"));
    for file in ["aes.c", "gcm.c", "aes-gcm.c"] {
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
    tools.run_command(&command, &directory, "Compile Lua GCM comparison")?;
    let result = tools.run_command(&Command::new(exe), &directory, "Compare Lua GCM")?;
    ensure!(
        result.starts_with("PASS lua_gcm "),
        "Incomplete Lua GCM comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, &updated);
    source.insert_str(0, declaration);
    fs::write(path, source)?;
    let main = nfq.join("nfqws.c");
    let source = fs::read_to_string(&main)?;
    let initialization = "\taes_init_keygen_tables(); // required for aes\n";
    ensure!(
        source.matches(initialization).count() == 1,
        "Pinned AES initialization changed"
    );
    fs::write(main, source.replace(initialization, ""))?;
    Ok(())
}
