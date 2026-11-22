//! Compare the complete registration catalog with pinned C through real LuaJIT.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua registry function")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Pinned Lua registry function end")?
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
        .context("Lua registry parent")?
        .join("lua-registry-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "static void lua_mt_init_desync_ctx(",
        "static void lua_mt_init_zstream(",
        "static void lua_init_const(",
        "static void lua_init_functions(",
        "static void lua_init_mt(",
    ];
    let reference = names
        .iter()
        .map(|anchor| function(&source, anchor).map(|range| source[range].to_owned()))
        .collect::<Result<Vec<_>>>()?
        .join("\n");
    fs::write(directory.join("lua_registry_reference.inc"), &reference)?;
    let context = fs::read_to_string(shim.join("lua_context_windows.inc"))?;
    fs::write(
        directory.join("lua_registry_context.inc"),
        &context[function(&context, "static void lua_desync_ctx_create(")?],
    )?;
    let first = reference
        .find("} lfunc[] = {")
        .context("Pinned callback table")?;
    let body = &reference[first
        ..first
            + reference[first..]
                .find("\n\t};")
                .context("Callback table end")?];
    let mut callbacks = Vec::new();
    for line in body.lines().map(str::trim) {
        let Some(entry) = line.strip_prefix("{\"") else {
            continue;
        };
        let (name, address) = entry.split_once("\",").context("Callback table entry")?;
        let address = address.trim_end_matches([',', '}']).trim();
        ensure!(
            !name.is_empty()
                && address.starts_with("luacall_")
                && address
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
            "Pinned callback identifier"
        );
        callbacks.push((name.to_owned(), address.to_owned()));
    }
    ensure!(callbacks.len() == 101, "Pinned callback catalog changed");
    let rust_callbacks = include_str!("windows_lua_registry_bindings.inc.rs")
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_suffix(','));
    ensure!(
        rust_callbacks.eq(callbacks.iter().map(|(_, address)| address.as_str())),
        "Rust registry callback order differs from the pinned C catalog"
    );
    let mut bindings =
        String::from("static const lua_CFunction native_lua_registry_callbacks[]={\n");
    let mut stubs = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, (_, address)) in callbacks.iter().enumerate() {
        bindings.push_str(&format!("    {address},\n"));
        if seen.insert(address) {
            stubs.push_str(&format!(
                "static int {address}(lua_State *L){{lua_pushinteger(L,{index});return 1;}}\n"
            ));
        }
    }
    bindings.push_str("};\n");
    // These are C addresses only; public names, slots and ordering live in Rust.
    fs::write(shim.join("lua_registry_callbacks.inc"), bindings)?;
    fs::write(directory.join("lua_registry_stubs.inc"), stubs)?;
    let mut global_names = String::from("static const char *catalog_names[]={\n");
    for line in reference.lines().map(str::trim) {
        if let Some(entry) = line.strip_prefix("{\"") {
            if let Some((name, _)) = entry.split_once("\",") {
                global_names.push_str(&format!("    \"{name}\",\n"));
            }
        }
    }
    global_names.push_str("};\n");
    fs::write(directory.join("lua_registry_names.inc"), global_names)?;
    let exe = directory.join("lua-registry-check.exe");
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
        .arg(shim.join("lua_registry_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(vm_object)
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
        "Compile Lua registration catalog comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare constants, callback identities, metatables, publication order and VM failure cleanup")?;
    ensure!(
        result.starts_with("PASS lua_registry "),
        "Incomplete Lua registry comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let range = function(&source, names[0])?;
    source.replace_range(range,"#include \"lua_registry_windows.h\"\nstatic void lua_mt_init_desync_ctx(lua_State *L)\n{\n    native_lua_registry_metatable(L,1,NULL);\n}\n");
    let range = function(&source, names[1])?;
    source.replace_range(range,"static void lua_mt_init_zstream(lua_State *L)\n{\n    LUA_STACK_GUARD_ENTER(L)\n    native_lua_registry_metatable(L,0,lua_cfunc_zstream_gc);\n    LUA_STACK_GUARD_LEAVE(L,0)\n}\n");
    for (index, anchor) in names[2..].iter().enumerate() {
        let range = function(&source, anchor)?;
        source.replace_range(
            range,
            if index == 0 {
                "#include \"lua_registry_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
