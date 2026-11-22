//! Prove connection publication order and identity before replacing its C policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned Lua connection function {anchor}"))?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Lua connection function end")?
        + 3;
    Ok(first..last)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua connection parent")?
        .join("lua-connection-publication-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let old = fs::read_to_string(shim.join("lua_conntrack_view_windows.inc"))?;
    ensure!(
        old.contains("static const char *counters"),
        "Connection publication reference must precede its replacement"
    );
    let first = old
        .find("static void native_lua_push_track_position(")
        .context("Connection publication reference body")?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let wrapper = function(&source, "void lua_pushf_ctrack(")?;
    fs::write(
        directory.join("lua_conntrack_reference.inc"),
        format!("{}\n{}", &old[first..], &source[wrapper.clone()]),
    )?;
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
    fs::write(directory.join("lua_conntrack_wrapper.inc"), "")?;
    fs::copy(
        shim.join("lua_connection_publication_windows.inc"),
        directory.join("lua_conntrack_view_windows.inc"),
    )?;
    let mut fixture = fs::read_to_string(shim.join("lua_conntrack_view_oracle.c"))?;
    // Reuse the original boundary, identity, guard-page and OOM fixtures; add
    // complete VM tracing and direct position-view publication to that fixture.
    for (before, after) in [
        ("int main(void)", "int connection_baseline_main(void)"),
        (
            "#define lua_pushf_ctrack_pos reference_position",
            "#define native_lua_push_track_position reference_publish_position\n#define lua_pushf_ctrack_pos reference_position",
        ),
        (
            "#undef lua_pushf_ctrack_pos",
            "#undef lua_pushf_ctrack_pos\n#undef native_lua_push_track_position",
        ),
        (
            "static int invoke(lua_State *L,bool rust)\n{",
            "static int invoke(lua_State *L,bool rust)\n{\n    publication_start(rust);",
        ),
        (
            "    if(mode==0)(rust?lua_pushf_ctrack_pos:reference_position)",
            "    if(mode==3){observed_position=&manual_position;(rust?native_lua_push_track_position:reference_publish_position)(L,manual_source);}\n    else if(mode==0)(rust?lua_pushf_ctrack_pos:reference_position)",
        ),
        (
            "    CHECK(lua_gettop(L)==1);\n    return 1;",
            "    CHECK(lua_gettop(L)==1);\n    publication_end();\n    return 1;",
        ),
        (
            "    lua_getglobal(L,\"SAME\");",
            "    CHECK(!memcmp(&traces[0],&traces[1],sizeof(traces[0])));\n    lua_getglobal(L,\"SAME\");",
        ),
        (
            "int status=lua_pcall(L,0,1,0);a.armed=false;",
            "int status=lua_pcall(L,0,1,0);publication_end();a.armed=false;",
        ),
    ] {
        ensure!(
            fixture.matches(before).count() == 1,
            "Pinned connection fixture: {before}"
        );
        fixture = fixture.replacen(before, after, 1);
    }
    fs::write(directory.join("lua_connection_fixture.inc"), fixture)?;
    let observed = directory.join("windows-lua-connection-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=lua_pushlstring=publication_bytes",
                "--redefine-sym=lua_createtable=publication_table",
                "--redefine-sym=lua_rawset=publication_rawset",
                "--redefine-sym=lua_getfield=publication_getfield",
                "--redefine-sym=zapret_lua_track_position=publication_query_position",
                "--redefine-sym=zapret_lua_track_view=publication_query_track",
            ])
            .arg(object)
            .arg(&observed),
        &directory,
        "Observe VM publication and native view reads in the actual Rust object",
    )?;
    let mut results = String::new();
    for direct in [false, true] {
        let (exe_name, marker) = if direct {
            (
                "lua-connection-publication-rust-check.exe",
                "PASS windows_lua_connection_view ",
            )
        } else {
            (
                "lua-connection-publication-check.exe",
                "PASS lua_connection_publication ",
            )
        };
        let exe = directory.join(exe_name);
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
            .arg(shim.join("lua_connection_publication_oracle.c"))
            .arg(shim.join("win_files.c"));
        if direct {
            command
                .args([
                    "-DZAPRET_RUST_LUA_CONNECTION_VIEW=1",
                    "-fexceptions",
                    "-D_FILE_OFFSET_BITS=64",
                    "-D_POSIX_C_SOURCE=200809L",
                ])
                .arg(&observed);
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
        tools.run_command(
            &command,
            &directory,
            "Compile complete connection publication comparison",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare connection VM order, identities, mutable inputs, nesting, guard pages and allocation failures",
        )?;
        ensure!(
            result.lines().any(|line| line.starts_with(marker)),
            "Incomplete connection publication comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    // Keep the repository's old template as the build-time comparison reference.
    // Only the candidate proven above is compiled and captured in the snapshot.
    fs::copy(
        shim.join("lua_connection_publication_windows.inc"),
        shim.join("lua_conntrack_view_windows.inc"),
    )?;
    source.replace_range(wrapper, "");
    fs::write(path, source)?;
    Ok(())
}
