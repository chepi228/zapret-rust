//! Compare complete numeric entries before selecting the Rust VM policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const NAMES: [&str; 32] = [
    "bitlshift",
    "bitrshift",
    "bitand",
    "bitor",
    "bitxor",
    "bitnot8",
    "bitnot16",
    "bitnot24",
    "bitnot32",
    "bitnot48",
    "bitget",
    "bitset",
    "swap16",
    "swap24",
    "swap32",
    "swap48",
    "u8add",
    "u16add",
    "u24add",
    "u32add",
    "u48add",
    "divint",
    "u8",
    "u16",
    "u24",
    "u32",
    "u48",
    "bu8",
    "bu16",
    "bu24",
    "bu32",
    "bu48",
];

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
        .context("Numeric entry parent")?
        .join("lua-numeric-entry-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let reference = fs::read_to_string(shim.join("lua_numeric_windows.inc"))?;
    ensure!(
        reference.contains("int count = lua_gettop(L);")
            && reference.contains("static int native_lua_read("),
        "Pinned numeric entry reference changed"
    );
    fs::write(directory.join("lua_numeric_reference.inc"), reference)?;
    let mut comparison = String::new();
    for name in ["native_lua_number", "native_lua_read", "native_lua_write"] {
        comparison.push_str(&format!("#define {name} reference_{name}\n"));
    }
    for name in NAMES {
        comparison.push_str(&format!("#define luacall_{name} reference_{name}\n"));
    }
    comparison.push_str("#include \"lua_numeric_reference.inc\"\n");
    for name in NAMES {
        comparison.push_str(&format!("#undef luacall_{name}\n"));
    }
    for name in ["native_lua_number", "native_lua_read", "native_lua_write"] {
        comparison.push_str(&format!("#undef {name}\n"));
    }
    comparison.push_str("#include \"lua_numeric_entry_windows.inc\"\nstatic const struct numeric_function functions[] = {\n");
    for name in NAMES {
        comparison.push_str(&format!(
            "{{\"{name}\",reference_{name},luacall_{name}}},\n"
        ));
    }
    comparison.push_str("};\n");
    fs::write(
        directory.join("lua_numeric_entry_comparison.inc"),
        comparison,
    )?;
    let exe = directory.join("lua-numeric-entry-check.exe");
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
        .arg(shim.join("lua_numeric_entry_oracle.c"))
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
        "Compile complete numeric entry comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare numeric entries, VM order, nesting, borrowed inputs and VM allocation failures",
    )?;
    ensure!(
        result.starts_with("PASS lua_numeric_entry "),
        "Incomplete numeric entry comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let path = nfq.join("lua.c");
    let source = fs::read_to_string(&path)?;
    ensure!(
        source
            .matches("#include \"lua_numeric_windows.inc\"")
            .count()
            == 1
            && !source.contains("#include \"lua_numeric_entry_windows.inc\""),
        "Pinned numeric entry include changed"
    );
    fs::write(
        path,
        source.replace(
            "#include \"lua_numeric_windows.inc\"",
            "#include \"lua_numeric_entry_windows.inc\"",
        ),
    )?;
    Ok(())
}
