//! Compare file/native owners and complete VM entry policies before patching.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua runtime function {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua runtime function end")?
        + 3;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [file_object, luajit_guard, vm_object]: [&Path; 3],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua runtime parent")?
        .join("lua-runtime-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let files = [
        "static bool lua_file_open_test(",
        "static int luaL_doZfile(",
    ];
    let vm = [
        "void lua_cleanup(",
        "void lua_shutdown(",
        "static bool lua_basic_init(",
        "void lua_do_gc(",
    ];
    for (name, anchors) in [
        ("lua_file_reference.inc", files.as_slice()),
        ("lua_vm_reference.inc", vm.as_slice()),
    ] {
        let mut reference = if name.contains("vm") {
            "static uint64_t gc_time=0;\n".to_owned()
        } else {
            String::new()
        };
        for anchor in anchors {
            reference.push_str(&source[function(&source, anchor)?]);
            reference.push('\n');
        }
        fs::write(directory.join(name), reference)?;
    }
    let mut common = String::new();
    for anchor in ["static void lua_perror(", "static int lua_panic("] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_vm_common.inc"), common)?;
    let comparisons = [
        ("lua_file", "lua_file", &[][..], &[][..], ""),
        ("lua_vm", "lua_vm", &[][..], &[][..], ""),
        (
            "lua_file",
            "lua_file",
            &[file_object, luajit_guard][..],
            &["-DZAPRET_LUA_FILE_DIRECT", "-fms-extensions"][..],
            "escaped_unwind_release=1",
        ),
        (
            "lua_vm",
            "windows_lua_vm",
            &[vm_object][..],
            &[
                "-DZAPRET_RUST_LUA_VM=1",
                "-Wl,--wrap=luaL_newstate,--wrap=lua_close,--wrap=luaL_openlibs,--wrap=lua_gc,--wrap=zapret_lua_vm_detach",
            ][..],
            "protected_cleanup_errors=6 parameter_cleanup_pairs=5",
        ),
    ];
    let mut results = String::new();
    for (source_name, result_name, objects, options, marker) in comparisons {
        let mode = if objects.is_empty() { "c" } else { "rust" };
        let exe = directory.join(format!("{source_name}-{mode}-check.exe"));
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
        if !objects.is_empty() {
            command.args(["-fexceptions", "-D_FILE_OFFSET_BITS=64"]);
        }
        command.args(options);
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
            .arg(shim.join(format!("{source_name}_oracle.c")))
            .arg(shim.join("win_files.c"))
            .args(objects)
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
            &format!("Compile {source_name} {mode} runtime comparison"),
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            &format!("Compare {source_name} {mode} order, failures, nested calls and ownership"),
        )?;
        ensure!(
            result.starts_with(&format!("PASS {result_name} ")) && result.contains(marker),
            "Incomplete {source_name} {mode} comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    for (index, anchor) in files.iter().enumerate().rev() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_file_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    for anchor in vm {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if anchor == "static bool lua_basic_init(" {
                "#include \"lua_vm_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    ensure!(
        source.matches("static uint64_t gc_time=0;").count() == 1,
        "Pinned GC storage changed"
    );
    source = source.replace("static uint64_t gc_time=0;", "");
    fs::write(path, source)?;
    Ok(())
}
