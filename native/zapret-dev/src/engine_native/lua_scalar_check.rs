//! Compare all remaining scalar/system entry policies before selecting them.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .with_context(|| format!("Pinned scalar function {anchor}"))?;
    let line = source[first..]
        .lines()
        .next()
        .context("Scalar declaration line")?;
    let end = if line.contains('{') && line.trim_end().ends_with('}') {
        first + line.len()
    } else {
        first
            + source[first..]
                .find("\n}\n")
                .context("Scalar function end")?
            + 3
    };
    Ok(first..end)
}
const MAIN: [&str; 6] = [
    "DLOG",
    "DLOG_ERR",
    "DLOG_CONDUP",
    "getpid",
    "gettid",
    "get_ifaddrs",
];
const SYSTEM: [&str; 8] = [
    "uname",
    "clock_gettime",
    "clock_getfloattime",
    "stat",
    "localtime",
    "gmtime",
    "timelocal",
    "timegm",
];

pub(super) fn prepare(nfq: &Path, shim: &Path, directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let source = fs::read_to_string(nfq.join("lua.c"))?;
    let mut common = String::new();
    for name in [
        "static void lua_check_argc(",
        "const char *lua_reqlstring(",
        "const char *lua_reqstring(",
        "void lua_pushf_str(",
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_number(",
    ] {
        common.push_str(&source[function(&source, name)?]);
        common.push('\n');
    }
    fs::write(directory.join("lua_system_tables_common.inc"), common)?;
    let mut reference = String::new();
    for name in MAIN {
        reference.push_str(&source[function(&source, &format!("static int luacall_{name}("))?]);
        reference.push('\n');
    }
    let system = fs::read_to_string(shim.join("lua_system_tables_windows.inc"))?;
    for helper in ["static int native_lua_clock(", "static void lua_xtime("] {
        reference.push_str(&system[function(&system, helper)?]);
        reference.push('\n');
    }
    for name in SYSTEM {
        reference.push_str(&system[function(&system, &format!("static int luacall_{name}("))?]);
        reference.push('\n');
    }
    let source_ip = fs::read_to_string(shim.join("lua_source_ip_windows.inc"))?;
    reference.push_str(&source_ip[function(&source_ip, "static int luacall_get_source_ip(")?]);
    fs::write(directory.join("lua_scalar_reference.inc"), reference)?;
    let mut comparison = String::from(
        "#define ZAPRET_LUA_SCALAR_OUTER_RUST 1\n#include \"lua_system_tables_windows.inc\"\n#undef ZAPRET_LUA_SCALAR_OUTER_RUST\n",
    );
    for name in MAIN.into_iter().chain(SYSTEM).chain(["get_source_ip"]) {
        comparison.push_str(&format!(
            "#define luacall_{name} reference_luacall_{name}\n"
        ));
    }
    comparison.push_str("#include \"lua_scalar_reference.inc\"\n");
    for name in MAIN.into_iter().chain(SYSTEM).chain(["get_source_ip"]) {
        comparison.push_str(&format!("#undef luacall_{name}\n"));
    }
    comparison.push_str("#include \"lua_scalar_windows.inc\"\n");
    fs::write(directory.join("lua_scalar_comparison.inc"), comparison)?;
    Ok(())
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
        .context("Lua scalar parent")?
        .join("lua-scalar-check");
    prepare(nfq, shim, &directory)?;
    let exe = directory.join("lua-scalar-check.exe");
    let mut c = Command::new(tools.compiler);
    c.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    for p in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        lua,
        nfq,
    ] {
        c.arg(format!("-I{}", p.display()));
    }
    c.arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("lua_scalar_oracle.c"))
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
        &c,
        &directory,
        "Compile complete Lua scalar/system comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare all scalar APIs, native/VM order, errno, reentry and VM failures",
    )?;
    ensure!(
        result.starts_with("PASS lua_scalar apis=15 "),
        "Incomplete scalar comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    for name in MAIN {
        let range = function(&source, &format!("static int luacall_{name}("))?;
        source.replace_range(
            range,
            if name == "DLOG" {
                "#include \"lua_scalar_windows.inc\"\n"
            } else {
                ""
            },
        );
    }
    ensure!(
        source
            .matches("#include \"lua_source_ip_windows.inc\"")
            .count()
            == 1,
        "Pinned source IP include"
    );
    source = source.replace("#include \"lua_source_ip_windows.inc\"", "");
    fs::write(path, source)?;
    Ok(())
}
