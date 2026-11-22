//! Compare Lua initialization against pinned C before replacing its traversal.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned Lua startup function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua startup end")?
        + 3;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [scripts, sandbox, startup]: [&Path; 3],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua startup parent")?
        .join("lua-startup-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "static bool lua_desync_functions_exist(",
        "bool lua_test_init_script_files(",
        "static bool lua_init_scripts(",
        "static void lua_sec_harden(",
        "static void lua_init_blobs(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_startup_reference.inc"), reference)?;
    fs::write(
        directory.join("lua_startup_order_reference.inc"),
        &source[function(&source, "bool lua_init(")?],
    )?;
    let observed = directory.join("windows-lua-startup-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_basic_init=boot_basic",
                "--redefine-sym=lua_sec_harden=boot_harden",
                "--redefine-sym=lua_init_blobs=boot_blobs",
                "--redefine-sym=lua_init_const=boot_constants",
                "--redefine-sym=lua_init_functions=boot_functions",
                "--redefine-sym=lua_init_mt=boot_mt",
                "--redefine-sym=zapret_lua_publish=boot_publish",
                "--redefine-sym=lua_init_scripts=boot_scripts",
                "--redefine-sym=lua_desync_functions_exist=boot_exists",
                "--redefine-sym=lua_shutdown=boot_shutdown",
            ])
            .arg(startup)
            .arg(&observed),
        &directory,
        "Observe phase execution in the Rust Lua startup entry",
    )?;
    let mut results = String::new();
    for (rust, name) in [(false, "lua_startup"), (true, "windows_lua_startup")] {
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
        if rust {
            command.args([
                "-fexceptions",
                "-DZAPRET_RUST_LUA_SCRIPTS=1",
                "-DZAPRET_RUST_LUA_STARTUP=1",
                "-D_FILE_OFFSET_BITS=64",
            ]);
        }
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
            .arg(shim.join("lua_startup_oracle.c"))
            .arg(shim.join("win_files.c"));
        if rust {
            command.args([scripts, sandbox, &observed]);
        }
        command
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
        tools.run_command(&command, &directory, &format!("Compile {name} comparison"))?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            &format!("Compare {name} traversal, startup phases and protected errors"),
        )?;
        ensure!(
            result.starts_with(&format!("PASS {name} "))
                && (!rust || result.contains("direct_sandbox=1 direct_order=1")),
            "Incomplete {name} comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    // Insert after the file loader is defined; all helper functions precede init.
    for anchor in names {
        let range = function(&source, anchor)?;
        source.replace_range(range, "");
    }
    let at = source
        .find("static void lua_init_const(")
        .context("Lua constants anchor")?;
    source.insert_str(at, "#include \"lua_startup_windows.inc\"\n\n");
    let range = function(&source, "bool lua_init(")?;
    source.replace_range(range, "#include \"lua_startup_order_windows.inc\"\n");
    fs::write(path, source)?;
    Ok(())
}
