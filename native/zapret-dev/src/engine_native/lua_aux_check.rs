//! Select the Lua glue after its full old and new functions compare.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn field_helpers(source: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find("void lua_pushf_nil(")
        .context("Pinned field helper start")?;
    let final_entry = source[first..]
        .find("void lua_pushf_global(")
        .context("Pinned final field helper")?
        + first;
    let end = source[final_entry..]
        .find("\n}\n")
        .context("Pinned field helper end")?
        + final_entry
        + 3;
    Ok(first..end)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [guards, timer, fields, lifetime, timer_host]: [&Path; 5],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua helper parent")?
        .join("lua-aux-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("lua.c");
    let mut candidate = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (name, replacement) in [
        (
            "static void lua_check_argc(",
            "#include \"lua_aux_arity_windows.inc\"\n",
        ),
        ("static void lua_check_argc_range(", ""),
        (
            "static void lua_desync_ctx_destroy(",
            "#include \"lua_aux_context_windows.inc\"\n",
        ),
        (
            "static void lua_perror(",
            "#include \"lua_aux_error_windows.inc\"\n",
        ),
        ("static int lua_panic(", ""),
        ("void lua_dlog_error(", ""),
    ] {
        let start = candidate
            .find(name)
            .with_context(|| format!("Pinned Lua helper {name}"))?;
        let end = start + candidate[start..].find("\n}\n").context("Lua helper end")? + 3;
        reference.push_str(&candidate[start..end]);
        reference.push('\n');
        candidate.replace_range(start..end, replacement);
    }
    fs::write(directory.join("lua_aux_reference.inc"), reference)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let helpers = &candidate[field_helpers(&candidate)?];
    let names: Vec<_> = helpers
        .lines()
        .filter_map(|line| line.strip_prefix("void ")?.split_once('('))
        .map(|(name, _)| name)
        .collect();
    ensure!(
        names.len() == 22 && names.iter().all(|name| name.starts_with("lua_push")),
        "Unexpected pinned Lua publication entries"
    );
    let mut helper_reference = helpers.to_owned();
    for name in names {
        let call = format!("{name}(");
        helper_reference = helper_reference.replace(&call, &format!("reference_{call}"));
    }
    fs::write(directory.join("lua_fields_reference.inc"), helper_reference)?;
    let exe = directory.join("lua-aux-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [&directory, shim, lua] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("lua_aux_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile Lua helper comparison")?;
    let mut text = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare arity errors, registry unref and deferred error-reporting VM reads",
    )?;
    ensure!(
        text.starts_with("PASS lua_aux "),
        "Incomplete Lua helper comparison"
    );
    for (name, prefix, object) in [
        ("lua_guards", "PASS windows_lua_guards ", guards),
        ("timer_vm", "PASS timer_vm ", timer),
        ("lua_fields", "PASS lua_fields ", fields),
        ("lua_lifetime", "PASS windows_lua_lifetime ", lifetime),
        ("timer_host_vm", "PASS timer_vm ", timer_host),
    ] {
        let fixture = directory.join(format!("{name}.exe"));
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu11",
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
        if name == "lua_fields" {
            command.arg("-Wl,--wrap=lj_prng_seed_secure");
        }
        if name == "lua_lifetime" {
            command.arg(
                "-Wl,--wrap=lua_isstring,--wrap=lua_tolstring,--wrap=lua_settop,--wrap=luaL_unref",
            );
        }
        let source_name = if name == "timer_host_vm" {
            command
                .args([
                    "-DZAPRET_TIMER_HOST_DIRECT=1",
                    "-Wl,--wrap=lua_rawgeti,--wrap=lua_tolstring,--wrap=lua_settop,--wrap=lua_pcall,--wrap=luaL_unref",
                ])
                .arg(timer);
            "timer_vm"
        } else {
            name
        };
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join(format!("windows_{source_name}_oracle.c")))
            .arg(object)
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
            .arg(&fixture);
        tools.run_command(&command, &directory, &format!("Compile {name} VM fixture"))?;
        let result = tools.run_command(
            &Command::new(&fixture),
            &directory,
            &format!("Check {name} with protected LuaJIT errors"),
        )?;
        ensure!(
            result.starts_with(prefix)
                && (name != "timer_host_vm" || result.contains("rust_host=1")),
            "Incomplete {name} VM comparison"
        );
        text.push_str(&result);
    }
    fs::write(output, &text)?;
    print!("{text}");
    fs::write(path, candidate)?;
    Ok(())
}
