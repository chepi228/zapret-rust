//! Compare complete binary-buffer entries before replacing their VM policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua buffer entry {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua buffer entry end")?
        + 3;
    Ok(first..last)
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
        .context("Lua buffer parent")?
        .join("lua-buffer-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let anchors = [
        "static int luacall_brandom(",
        "static int luacall_brandom_az(",
        "static int luacall_brandom_az09(",
        "static int luacall_bcryptorandom(",
        "static int luacall_parse_hex(",
        "static int luac_bop(",
        "static int luacall_bxor(",
        "static int luacall_bor(",
        "static int luacall_band(",
    ];
    let mut reference = String::new();
    for anchor in anchors {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_buffer_reference.inc"), reference)?;
    let mut common = String::new();
    for anchor in ["static void lua_check_argc(", "const char *lua_reqlstring("] {
        let body = &source[function(&source, anchor)?];
        common.push_str(body.strip_prefix("static ").unwrap_or(body));
        common.push('\n');
    }
    fs::write(directory.join("lua_buffer_common.inc"), common)?;
    // Redirect only the tested object's imports. LuaJIT retains its real
    // allocator, stack entries and error handler.
    let observed = directory.join("buffer-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_newuserdata=zapret_buffer_fixture_userdata",
                "--redefine-sym=lua_pushlstring=zapret_buffer_fixture_string",
                "--redefine-sym=lua_settop=zapret_buffer_fixture_settop",
                "--redefine-sym=lua_remove=zapret_buffer_fixture_remove",
                "--redefine-sym=zapret_lua_buffer_step=zapret_buffer_fixture_step",
            ])
            .arg(vm_object)
            .arg(&observed),
        &directory,
        "Observe Lua buffer VM boundaries",
    )?;
    let exe = directory.join("lua-buffer-check.exe");
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
        .arg(shim.join("lua_buffer_oracle.c"))
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
        "Compile complete Lua buffer comparison",
    )?;
    let result = tools.run_command(&Command::new(&exe), &directory, "Compare buffer entry errors, seeded random state, VM order, allocation failures and nested calls")?;
    ensure!(
        result.starts_with("PASS lua_buffer "),
        "Incomplete Lua buffer comparison"
    );
    print!("{result}");
    fs::write(output, result)?;
    for (index, anchor) in anchors.iter().enumerate().rev() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            &if index == 0 {
                String::from("#include \"lua_buffer_windows.inc\"\n")
            } else {
                String::new()
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
