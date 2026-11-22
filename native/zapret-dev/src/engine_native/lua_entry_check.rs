//! Compare complete crypto entries and codec lifecycle before replacing policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua entry {anchor}"))?;
    let last = first + source[first..].find("\n}\n").context("Lua entry end")? + 3;
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
        .context("Lua entry parent")?
        .join("lua-entry-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let crypto = [
        "static int luacall_aes(",
        "static int luacall_aes_gcm(",
        "static int luacall_aes_ctr(",
    ];
    let codec = [
        "static int lua_cfunc_zstream_gc(",
        "static struct userdata_zs *lua_uzs(",
        "static int luacall_gunzip_init(",
        "static int luacall_gunzip_end(",
        "static int luacall_gzip_init(",
        "static int luacall_gzip_end(",
    ];
    for (name, anchors) in [
        ("lua_crypto_entry_reference.inc", crypto.as_slice()),
        ("lua_codec_entry_reference.inc", codec.as_slice()),
    ] {
        let mut text = String::new();
        for anchor in anchors {
            text.push_str(&source[function(&source, anchor)?]);
            text.push('\n');
        }
        fs::write(directory.join(name), text)?;
    }
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "static void lua_check_argc_range(",
        "const char *lua_reqlstring(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_entry_common.inc"), common)?;
    let first = source
        .find("struct userdata_zs\n{")
        .context("Pinned codec userdata")?;
    let last = first + source[first..].find("\n};").context("Codec userdata end")? + 4;
    let mut common = source[first..last].to_owned();
    common.push('\n');
    for anchor in ["static void *z_alloc(", "static void z_free("] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_codec_entry_common.inc"), common)?;
    let mut results = String::new();
    for name in ["lua_crypto_entry", "lua_codec_entry"] {
        let exe = directory.join(format!("{name}-check.exe"));
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
            .arg(shim.join(format!("{name}_oracle.c")))
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
            &format!("Compile complete {name} comparison"),
        )?;
        let result=tools.run_command(&Command::new(&exe),&directory,&format!("Compare {name} argument/error order, results, native lifecycle and allocation failures"))?;
        ensure!(
            result.starts_with(&format!("PASS {name} ")),
            "Incomplete {name} comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    for (anchors, include) in [
        (crypto.as_slice(), "lua_crypto_windows.inc"),
        (codec.as_slice(), "lua_codec_windows.inc"),
    ] {
        for (index, anchor) in anchors.iter().enumerate().rev() {
            let range = function(&source, anchor)?;
            source.replace_range(
                range,
                &if index == 0 {
                    format!("#include \"{include}\"\n")
                } else {
                    String::new()
                },
            );
        }
    }
    fs::write(path, source)?;
    Ok(())
}
