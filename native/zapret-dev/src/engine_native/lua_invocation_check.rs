//! Compare the complete packet-to-Lua dispatch before replacing invocation policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(anchor)
        .context("Pinned Lua invocation function")?;
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("Lua invocation function end")?
        + 3;
    Ok(start..end)
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
        .context("Invocation source parent")?
        .join("lua-invocation-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let result = function(&source, "static bool desync_get_result(")?;
    let handler = function(&source, "static uint8_t desync(\n")?;
    fs::write(
        directory.join("lua_invocation_reference.inc"),
        format!("{}\n{}", &source[result.clone()], &source[handler.clone()]),
    )?;
    let mut candidate = source[handler.clone()].to_owned();
    let first = candidate
        .find("\t\t\tzapret_rule_cursor cursor = lua_rule_cursor(")
        .context("Lua invocation loop")?;
    let last = first
        + candidate[first..]
            .find("\n\t\t}\n\n\t\tif ((verdict & VERDICT_MASK)")
            .context("Lua invocation loop end")?;
    candidate.replace_range(first..last,"\t\t\tif (!native_lua_invocation(dp,pos,bIncoming,l7payload,ctrack,ctx,ref_arg,instance,sizeof(instance),&verdict)) goto err;");
    for (before, after) in [
        (
            "uint8_t verdict = VERDICT_PASS, verdict_func;",
            "uint8_t verdict = VERDICT_PASS;",
        ),
        ("\tstruct func_list *func;\n", ""),
        (
            "int ref_arg = LUA_NOREF, status;",
            "int ref_arg = LUA_NOREF;",
        ),
        ("\tconst struct packet_range *range;\n", ""),
        ("\tsize_t l;\n", ""),
        ("\t\t\tsockaddr_in46 sa;\n", ""),
    ] {
        ensure!(
            candidate.matches(before).count() == 1,
            "Pinned unused invocation local: {before}"
        );
        candidate = candidate.replace(before, after);
    }
    fs::write(directory.join("lua_invocation_candidate.inc"), &candidate)?;
    let lua_source = fs::read_to_string(nfq.join("lua.c"))?;
    let mut common = String::new();
    for anchor in [
        "int lua_absindex(",
        "void lua_pushf_int(",
        "void lua_pushf_bool(",
        "void lua_pushf_str(",
        "void lua_pushf_table(",
        "void lua_pushi_table(",
        "bool lua_push_blob(",
        "bool lua_pushf_blob(",
        "void lua_dlog_error(",
    ] {
        common.push_str(&lua_source[function(&lua_source, anchor)?]);
        common.push('\n');
    }
    let context = fs::read_to_string(shim.join("lua_context_windows.inc"))?;
    common.push_str(&context[function(&context, "bool lua_instance_cutoff_check(")?]);
    common.push('\n');
    let arguments = fs::read_to_string(shim.join("lua_execution_view_windows.inc"))?;
    let end = arguments
        .find("typedef struct {const struct func_list *next;")
        .context("Lua argument view end")?;
    common.push_str(&arguments[..end]);
    fs::write(directory.join("lua_invocation_common.inc"), common)?;
    let exe = directory.join("lua-invocation-check.exe");
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
        .arg(shim.join("lua_invocation_oracle.c"))
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
        "Compile Lua handler invocation comparison",
    )?;
    let text=tools.run_command(&Command::new(&exe),&directory,"Compare handler order, cutoff, result coercion, cancellation, error fallback and VM allocation cleanup")?;
    ensure!(
        text.starts_with("PASS lua_invocation "),
        "Incomplete Lua invocation comparison"
    );
    fs::write(output, &text)?;
    print!("{text}");
    source.replace_range(handler, candidate.as_str());
    source.replace_range(result, "#include \"lua_invocation_result_windows.inc\"\n");
    let at = source
        .find("static uint8_t desync(\n")
        .context("Patched desync position")?;
    source.insert_str(at, "#include \"lua_invocation_windows.inc\"\n\n");
    fs::write(path, source)?;
    Ok(())
}
