//! Compare Lua connection tables before replacing the pinned C calculations.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua connection function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua connection function end")?
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
        .context("Lua connection parent")?
        .join("lua-conntrack-view-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_number(",
        "void lua_pushf_bool(",
        "void lua_pushf_str(",
        "void lua_pushf_reg(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_conntrack_common.inc"), common)?;
    let mut reference = String::new();
    let names = ["void lua_pushf_ctrack_pos(", "void lua_push_ctrack("];
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    // Keep the normal named-field wrapper on both sides of the oracle.
    let wrapper = source[function(&source, "void lua_pushf_ctrack(")?].to_owned();
    reference.push_str(&wrapper);
    fs::write(directory.join("lua_conntrack_reference.inc"), reference)?;
    fs::write(directory.join("lua_conntrack_wrapper.inc"), wrapper)?;
    let exe = directory.join("lua-conntrack-view-check.exe");
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
        .arg(shim.join("lua_conntrack_view_oracle.c"))
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
        "Compile Lua connection view comparison",
    )?;
    let result = tools.run_command(&Command::new(&exe), &directory,
        "Compare connection tables, alias identity, timestamps, guards and real VM allocation faults")?;
    ensure!(
        result.starts_with("PASS lua_conntrack_view "),
        "Incomplete Lua connection comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (index, anchor) in names.into_iter().enumerate() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_conntrack_view_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
