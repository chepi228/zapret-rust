//! Compare context control with pinned C before replacing its Lua bindings.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const REGISTRY_ENTRIES: [&str; 2] = [
    "static t_lua_desync_context *lua_desync_ctx(",
    "static void lua_desync_ctx_create(",
];

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(anchor).context("Pinned Lua context function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua context function end")?
        + 3;
    Ok(first..last)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    [registry, cutoff]: [&Path; 2],
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Lua context parent")?
        .join("lua-context-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let mut common = String::new();
    for anchor in [
        "static void lua_check_argc(",
        "static void lua_check_argc_range(",
        "void lua_pushi_bool(",
        "void lua_pushf_table(",
        "void lua_pushi_table(",
        "static void lua_desync_ctx_destroy(",
    ] {
        common.push_str(&source[function(&source, anchor)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_context_common.inc"), common)?;
    let names = [
        REGISTRY_ENTRIES[0],
        REGISTRY_ENTRIES[1],
        "static int luacall_instance_cutoff(",
        "bool lua_instance_cutoff_check(",
        "static int luacall_lua_cutoff(",
        "static int luacall_execution_plan_cancel(",
        "static int luacall_raw_packet(",
    ];
    let mut reference = String::new();
    for anchor in names {
        reference.push_str(&source[function(&source, anchor)?]);
        reference.push('\n');
    }
    fs::write(directory.join("lua_context_reference.inc"), reference)?;
    let adapter = fs::read_to_string(shim.join("lua_context_windows.inc"))?;
    let mut context_reference = String::new();
    for name in REGISTRY_ENTRIES {
        context_reference.push_str(&adapter[function(&adapter, name)?]);
        context_reference.push('\n');
    }
    fs::write(
        directory.join("lua_context_entry_reference.inc"),
        context_reference,
    )?;
    let mut results = String::new();
    for (fixture, name, object, options) in [
        ("lua_context", "lua_context", None, &[][..]),
        (
            "windows_lua_context",
            "windows_lua_context",
            Some(registry),
            &[
                "-Wl,--wrap=lua_newuserdata,--wrap=zapret_lua_context_init,--wrap=lua_getfield,--wrap=lua_setmetatable,--wrap=luaL_ref,--wrap=luaL_checkudata,--wrap=lua_objlen",
            ][..],
        ),
        (
            "lua_context",
            "windows_lua_cutoff",
            Some(cutoff),
            &["-DZAPRET_DIRECT_LUA_CUTOFF=1"][..],
        ),
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
        if object.is_some() {
            command.args([
                "-fexceptions",
                "-D_FILE_OFFSET_BITS=64",
                "-D_POSIX_C_SOURCE=200809L",
            ]);
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
            .arg(shim.join(format!("{fixture}_oracle.c")));
        if let Some(object) = object {
            command.arg(object);
        }
        command
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
        tools.run_command(&command, &directory, &format!("Compile {name} comparison"))?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            &format!("Compare {name} with real VM errors and reentry"),
        )?;
        ensure!(
            result.starts_with(&format!("PASS {name} ")),
            "Incomplete {name} comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    for (index, anchor) in names.into_iter().enumerate() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_context_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    let header = nfq.join("lua.h");
    let source = fs::read_to_string(&header)?;
    fs::write(
        header,
        format!("{source}\n#include \"lua_context_windows.h\"\n"),
    )?;
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let original = "\t\tctx->dp = dp;\n\t\tctx->ctrack = ctrack;\n\t\tctx->dis = dis;\n\t\tctx->cancel = false;\n\t\tctx->incoming = bIncoming;";
    ensure!(
        source.matches(original).count() == 1,
        "Pinned context preparation changed"
    );
    source = source.replace(
        original,
        "\t\tif (!zapret_lua_context_prepare(ctx,dp,ctrack,dis,bIncoming)) goto err;",
    );
    for (original, replacement) in [
        ("ctx->valid = true;", "zapret_lua_context_active(ctx,true);"),
        (
            "ctx->valid = false;",
            "zapret_lua_context_active(ctx,false);",
        ),
        (
            "if (ctx->cancel) break;",
            "if (zapret_lua_context_cancelled(ctx)) break;",
        ),
    ] {
        ensure!(
            source.matches(original).count() == 1,
            "Pinned Lua context transition changed: {original}"
        );
        source = source.replace(original, replacement);
    }
    fs::write(path, source)?;
    Ok(())
}
