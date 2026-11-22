//! Compare streaming Lua codec calls and VM allocation-error ownership.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned Lua zstream function")?;
    let end = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua zstream end")?
        + 3;
    Ok(first..end)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    vm_object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua zstream parent")?
        .join("lua-zstream-check");
    fs::create_dir(&directory)?;
    let definitions = fs::read_to_string(lua.join("lj_def.h"))?;
    ensure!(definitions.lines().any(|line|line.starts_with("#define LJ_MAX_MEM32") && line.contains("0x7fffff00")) && definitions.lines().any(|line|line.starts_with("#define LJ_MAX_STR") && line.contains("LJ_MAX_MEM32")),"Pinned LuaJIT string bound changed");
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("struct userdata_zs\n{")
        .context("Pinned codec userdata")?;
    let end = source[first..]
        .find("static int luacall_stat(")
        .context("Pinned codec block end")?
        + first;
    let mut common = source[first..end].to_owned();
    let mut reference = String::new();
    for anchor in [
        "static int luacall_gunzip_inflate(",
        "static int luacall_gzip_deflate(",
    ] {
        let range = function(&common, anchor)?;
        reference.push_str(&common[range.clone()]);
        common.replace_range(range, "");
    }
    let static_validator = "static struct userdata_zs *lua_uzs(";
    ensure!(
        common.matches(static_validator).count() == 1,
        "Pinned stream validator changed"
    );
    common = common.replacen(static_validator, "struct userdata_zs *lua_uzs(", 1);
    fs::write(directory.join("lua_zstream_common.inc"), common)?;
    fs::write(directory.join("lua_zstream_reference.inc"), reference)?;
    let observed = directory.join("zstream-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=zapret_lua_zstream_process=zapret_zstream_fixture_process",
                "--redefine-sym=zapret_lua_zstream_release=zapret_zstream_fixture_release",
            ])
            .arg(vm_object)
            .arg(&observed),
        &directory,
        "Observe streaming codec output ownership",
    )?;
    let exe = directory.join("lua-zstream-check.exe");
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
        .arg(shim.join("lua_zstream_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(&observed)
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
        "Compile Lua stream parity and memory-error comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare streaming modes, buffer growth and VM OOM cleanup",
    )?;
    ensure!(
        result.starts_with("PASS lua_zstream "),
        "Incomplete streaming comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let range = function(&source, "static int luacall_gzip_deflate(")?;
    source.replace_range(range, "");
    let range = function(&source, "static int luacall_gunzip_inflate(")?;
    source.replace_range(range, "#include \"lua_zstream_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
