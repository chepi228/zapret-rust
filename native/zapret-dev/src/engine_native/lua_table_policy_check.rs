//! Compare table publication policies before replacing the active C adapters.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua table function {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua table function end")?
        + 3;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [tables, projection]: [&Path; 2],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua table parent")?
        .join("lua-table-policy-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let old_metadata = fs::read_to_string(shim.join("lua_packet_dissection_windows.inc"))?;
    ensure!(
        old_metadata.contains("static const char *fields"),
        "Packet metadata reference must precede its replacement"
    );
    fs::write(
        directory.join("lua_packet_projection_reference.inc"),
        old_metadata,
    )?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let anchors = [
        "bool lua_push_blob(",
        "bool lua_pushf_blob(",
        "void lua_pushf_pos(",
        "void lua_pushf_range(",
    ];
    let mut reference = String::new();
    for anchor in anchors {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_table_policy_reference.inc"), reference)?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "static void lua_check_argc_range(",
        "const char *lua_reqlstring(",
        "int lua_absindex(",
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_push_raw(",
        "void lua_pushf_raw(",
        "void lua_pushf_str(",
        "void lua_pushf_bool(",
        "void lua_pushf_table(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_table_common.inc"), common)?;
    let observed = directory.join("windows-lua-tables-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_pushstring=policy_vm_string",
                "--redefine-sym=lua_getfield=policy_vm_getfield",
                "--redefine-sym=lua_tolstring=policy_vm_tolstring",
                "--redefine-sym=lua_type=policy_vm_type",
                "--redefine-sym=lua_settop=policy_vm_settop",
                "--redefine-sym=lua_rawset=policy_vm_rawset",
            ])
            .arg(tables)
            .arg(&observed),
        &directory,
        "Observe Lua operations in the Rust table entries",
    )?;
    let view = directory.join("windows-lua-projection-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_createtable=metadata_vm_table",
                "--redefine-sym=lua_pushstring=metadata_vm_string",
                "--redefine-sym=lua_pushinteger=metadata_vm_integer",
                "--redefine-sym=lua_pushnil=metadata_vm_nil",
                "--redefine-sym=lua_rawset=metadata_vm_rawset",
            ])
            .arg(projection)
            .arg(&view),
        &directory,
        "Observe Lua operations in the Rust metadata publisher",
    )?;
    let mut results = String::new();
    for (fixture, name) in [
        ("lua_packet_projection", "lua_packet_projection"),
        ("lua_table_policy", "lua_table_policy"),
        ("lua_packet_projection", "windows_lua_packet_projection"),
    ] {
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
        if name == "lua_table_policy" {
            command.arg("-fexceptions").arg(&observed);
        }
        if name == "windows_lua_packet_projection" {
            command
                .args([
                    "-DZAPRET_RUST_LUA_PACKET_PROJECTION=1",
                    "-fexceptions",
                    "-D_FILE_OFFSET_BITS=64",
                    "-D_POSIX_C_SOURCE=200809L",
                ])
                .arg(&view);
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
            .arg(shim.join(format!("{fixture}_oracle.c")))
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
        let result=tools.run_command(&Command::new(&exe),&directory,&format!("Compare {name} VM order, mutable inputs, nested calls, guard pages and allocation failures"))?;
        ensure!(
            result.starts_with(&format!("PASS {name} ")),
            "Incomplete {name} comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    // The old metadata template remains a build-time comparison reference.
    // Only the proven candidate is compiled into the engine and snapshotted.
    fs::copy(
        shim.join("lua_packet_projection_windows.inc"),
        shim.join("lua_packet_dissection_windows.inc"),
    )?;
    for (index, anchor) in anchors.iter().enumerate().rev() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            &if index == 0 {
                String::from("#include \"lua_table_policy_windows.inc\"\n")
            } else {
                String::new()
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
