//! Compare Lua header entries and packet projections against the pinned C source.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua header function {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua header function end")?
        + 3;
    Ok(first..last)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [views, addresses, decode, guards]: [&Path; 4],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua header entry parent")?
        .join("lua-header-entry-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    fs::copy(
        shim.join("packet_lua_windows.c"),
        directory.join("lua_header_entry_headers.inc"),
    )?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let anchors = [
        "void lua_push_ipaddr(",
        "void lua_pushf_ipaddr(",
        "void lua_pushi_ipaddr(",
        "void lua_pushf_tcphdr(",
        "void lua_pushf_udphdr(",
        "void lua_pushf_icmphdr(",
        "void lua_pushf_iphdr(",
        "void lua_pushf_ip6hdr(",
        "static int luacall_dissect_tcphdr(",
        "static int luacall_dissect_udphdr(",
        "static int luacall_dissect_icmphdr(",
        "static int luacall_dissect_iphdr(",
        "static int luacall_dissect_ip6hdr(",
        "static int luacall_reconstruct_tcphdr(",
        "static int luacall_reconstruct_udphdr(",
        "static int luacall_reconstruct_icmphdr(",
        "static int luacall_reconstruct_iphdr(",
        "static int luacall_reconstruct_ip6hdr(",
        "void lua_push_dissect(",
        "void lua_pushf_dissect(",
    ];
    let mut reference = String::new();
    for anchor in anchors {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_header_entry_reference.inc"), reference)?;
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
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_header_entry_common.inc"), common)?;
    let observed_views = directory.join("windows-lua-header-views-observed.o");
    let observed_decode = directory.join("windows-lua-header-decode-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_createtable=boundary_table",
                "--redefine-sym=lua_pushlstring=boundary_bytes",
                "--redefine-sym=lua_pushnil=boundary_nil",
                "--redefine-sym=lua_rawset=boundary_rawset",
                "--redefine-sym=native_lua_push_packet_header=observe_header",
            ])
            .arg(views)
            .arg(&observed_views),
        &directory,
        "Observe the Rust header views with the pinned LuaJIT",
    )?;
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .arg("--redefine-sym=native_lua_push_packet_header=observe_header")
            .arg(decode)
            .arg(&observed_decode),
        &directory,
        "Observe the Rust header entries with the pinned LuaJIT",
    )?;
    let mut results = String::new();
    for (fixture, name, objects, options) in [
        (
            "lua_header_entry",
            "lua_header_entry",
            &[observed_decode.as_path(), guards][..],
            &[][..],
        ),
        (
            "lua_header_entry",
            "windows_lua_header_views",
            &[observed_views.as_path(), guards][..],
            &["-DZAPRET_RUST_LUA_HEADER_VIEWS=1"][..],
        ),
        (
            "windows_lua_ipaddr",
            "windows_lua_ipaddr",
            &[addresses][..],
            &[
                "-Wl,--wrap=lua_pushstring,--wrap=lua_pushinteger,--wrap=lua_pushlstring,--wrap=lua_pushnil,--wrap=lua_rawset,--wrap=zapret_lua_packet_address",
            ][..],
        ),
    ] {
        let exe = directory.join(format!("{name}-check.exe"));
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-fexceptions",
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
            .arg(shim.join(format!("{fixture}_oracle.c")))
            .arg(shim.join("win_files.c"))
            .args(objects)
            .args(options)
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
            "Compile complete Lua header entry comparison",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare strict header reads, reconstruction, packet views, addresses and VM faults",
        )?;
        ensure!(
            result.starts_with(&format!("PASS {name} ")),
            "Incomplete Lua header entry comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    for (index, anchor) in [
        "void lua_push_ipaddr(",
        "void lua_pushf_ipaddr(",
        "void lua_pushi_ipaddr(",
    ]
    .iter()
    .enumerate()
    .rev()
    {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            &if index == 0 {
                String::from("#include \"lua_packet_address_windows.inc\"\n")
            } else {
                String::new()
            },
        );
    }
    for (index, anchor) in [
        "void lua_pushf_tcphdr(",
        "void lua_pushf_udphdr(",
        "void lua_pushf_icmphdr(",
        "void lua_pushf_iphdr(",
        "void lua_pushf_ip6hdr(",
        "static int luacall_dissect_tcphdr(",
        "static int luacall_dissect_udphdr(",
        "static int luacall_dissect_icmphdr(",
        "static int luacall_dissect_iphdr(",
        "static int luacall_dissect_ip6hdr(",
        "static int luacall_reconstruct_tcphdr(",
        "static int luacall_reconstruct_udphdr(",
        "static int luacall_reconstruct_icmphdr(",
        "static int luacall_reconstruct_iphdr(",
        "static int luacall_reconstruct_ip6hdr(",
        "void lua_push_dissect(",
        "void lua_pushf_dissect(",
    ]
    .iter()
    .enumerate()
    .rev()
    {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            &if index == 0 {
                String::from("#include \"lua_header_entry_windows.inc\"\n")
            } else {
                String::new()
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
