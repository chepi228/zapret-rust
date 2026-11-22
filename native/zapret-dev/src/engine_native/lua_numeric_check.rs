//! Compare the Lua numeric API in the same protected VM as the pinned C code.
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
        .context("Lua numeric source parent")?
        .join("lua-numeric-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static int luacall_bitlshift(")
        .context("Pinned Lua numeric API")?;
    let end = source
        .find("static int luacall_brandom(")
        .context("Pinned Lua random API")?;
    ensure!(start < end, "Pinned numeric API order changed");
    let reference = &source[start..end];
    let names: Vec<_> = reference
        .lines()
        .filter_map(|line| {
            line.strip_prefix("static int ")
                .and_then(|rest| rest.split_once('(').map(|v| v.0))
        })
        .collect();
    let mut comparison = String::new();
    for name in &names {
        comparison.push_str(&format!("#define {name} reference_{name}\n"));
    }
    comparison.push_str(reference);
    for name in &names {
        comparison.push_str(&format!("#undef {name}\n"));
    }
    comparison.push_str("#include \"lua_numeric_windows.inc\"\nstatic const struct numeric_function functions[] = {\n");
    let mut count = 0;
    for name in &names {
        if let Some(public) = name.strip_prefix("luacall_") {
            comparison.push_str(&format!("{{\"{public}\", reference_{name}, {name}}},\n"));
            count += 1;
        }
    }
    comparison.push_str("};\n");
    ensure!(count == 32, "Pinned numeric function count changed");
    fs::write(directory.join("lua_numeric_comparison.inc"), comparison)?;
    let exe = directory.join("lua-numeric-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-Dzapret_localtime_r=fixture_localtime_r",
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
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
        .arg(shim.join("lua_numeric_oracle.c"))
        .arg(nfq.join("helpers.c"))
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
    tools.run_command(&command, &directory, "Compile Lua numeric comparison")?;
    let result = tools.run_command(&Command::new(exe), &directory, "Compare Lua numeric API")?;
    ensure!(
        result.starts_with("PASS lua_numeric "),
        "Incomplete Lua numeric comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, "#include \"lua_numeric_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
