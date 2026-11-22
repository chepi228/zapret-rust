//! Compare the Lua AES entry points using the pinned implementation and LuaJIT.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, name: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(&format!("static int {name}("))
        .with_context(|| format!("Pinned Lua AES function: {name}"))?;
    let end = source[start..]
        .find("\n}\n")
        .context("Pinned Lua AES function end")?
        + start
        + 3;
    Ok(start..end)
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
        .context("Lua AES source parent")?
        .join("lua-aes-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut comparison = String::new();
    for name in ["luacall_aes_ctr", "luacall_aes"] {
        let range = function(&source, name)?;
        let original = &source[range.clone()];
        comparison.push_str(&format!(
            "#define {name} reference_{name}\n{original}\n#undef {name}\n"
        ));
        let updated = if name == "luacall_aes" {
            ensure!(
                original.contains("aes_context ctx;"),
                "Pinned AES context changed"
            );
            original.replace("\taes_context ctx;\n", "").replace(
                "aes_setkey(&ctx, bEncrypt, key, key_len) || aes_cipher(&ctx, input, output)",
                "!zapret_lua_aes_block(bEncrypt, key, key_len, input, output)",
            )
        } else {
            original.replace(
                "aes_ctr_crypt(key, key_len, iv, input, input_len, output)",
                "!zapret_lua_aes_ctr(key, key_len, iv, input, input_len, output)",
            )
        };
        ensure!(updated != original, "Pinned AES call did not change");
        comparison.push_str(&updated);
        comparison.push('\n');
        source.replace_range(range, &updated);
    }
    let declarations = concat!(
        "bool zapret_lua_aes_block(bool, const uint8_t *, size_t, const uint8_t *, uint8_t *);\n",
        "bool zapret_lua_aes_ctr(const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t, uint8_t *);\n",
    );
    fs::write(
        directory.join("lua_aes_comparison.inc"),
        format!("{declarations}{comparison}"),
    )?;
    source.insert_str(0, declarations);
    let executable = directory.join("lua-aes-check.exe");
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
        .arg(shim.join("lua_aes_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(nfq.join("crypto/aes.c"))
        .arg(nfq.join("crypto/aes-ctr.c"))
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
        .arg(&executable);
    tools.run_command(&command, &directory, "Compile Lua AES comparison")?;
    let result = tools.run_command(&Command::new(executable), &directory, "Compare Lua AES")?;
    ensure!(
        result.starts_with("PASS lua_aes "),
        "Incomplete Lua AES comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    Ok(())
}
