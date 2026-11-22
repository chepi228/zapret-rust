//! Gate complete hash/HKDF and IP entry policy against the preceding adapters.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

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
        .context("Hash/IP entry parent")?
        .join("lua-hash-ip-entry-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    for (name, anchor) in [
        ("hash", "static unsigned native_lua_hash_bits("),
        ("ip", "static int luacall_pton("),
    ] {
        let reference = fs::read_to_string(shim.join(format!("lua_{name}_windows.inc")))?;
        ensure!(
            reference.contains(anchor),
            "Pinned {name} entry reference changed"
        );
        fs::write(
            directory.join(format!("lua_{name}_entry_reference.inc")),
            reference,
        )?;
    }
    let exe = directory.join("lua-hash-ip-entry-check.exe");
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
        .arg(shim.join("lua_hash_ip_entry_oracle.c"))
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
        "Compile complete hash/HKDF/IP entry comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare hash/HKDF/IP VM order, failures, borrowed inputs, nesting and allocations",
    )?;
    ensure!(
        result.starts_with("PASS lua_hash_ip_entry "),
        "Incomplete hash/IP entry comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let path = nfq.join("lua.c");
    let mut source = fs::read_to_string(&path)?;
    ensure!(
        !source.contains("#include \"lua_hash_ip_entry_windows.inc\""),
        "Duplicate hash/IP entry selection"
    );
    for name in ["hash", "ip"] {
        let old = format!("#include \"lua_{name}_windows.inc\"");
        ensure!(
            source.matches(&old).count() == 1,
            "Pinned {name} entry include changed"
        );
        source = source.replace(
            &old,
            if name == "hash" {
                "#include \"lua_hash_ip_entry_windows.inc\""
            } else {
                ""
            },
        );
    }
    fs::write(path, source)?;
    Ok(())
}
