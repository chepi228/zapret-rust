//! Verify private console callbacks and Lua lifetime synchronization.
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
        .context("Console source parent")?
        .join("console-check");
    fs::create_dir(&directory)?;
    let exe = directory.join("console-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [shim, lua] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("console_oracle.c"))
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
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile private console and Lua lifetime fixture",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check engine console and Lua lifetime",
    )?;
    ensure!(
        result.starts_with("PASS engine_console ") && result.contains("PASS lua_lifetime "),
        "Incomplete console or Lua lifetime fixture"
    );
    fs::write(output, &result)?;
    print!("{result}");

    let main = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&main)?;
    let start = source
        .find("static void onint(")
        .context("Pinned interrupt handler")?;
    let end = source[start..]
        .find("static uint8_t processPacketData(")
        .context("Pinned console handlers end")?
        + start;
    source.replace_range(start..end, "#include \"console_windows.inc\"\n\n");
    fs::write(main, source)?;

    let lua_source = nfq.join("lua.c");
    let mut source = fs::read_to_string(&lua_source)?;
    source.insert_str(0, "#include \"lua_lifetime_windows.h\"\n");
    let start = source
        .find("static void lua_interrupt_hook(")
        .context("Pinned Lua interrupt hook")?;
    let end = source[start..]
        .find("bool lua_init(void)")
        .context("Pinned Lua interrupt end")?
        + start;
    source.replace_range(start..end, "#include \"lua_lifetime_windows.inc\"\n\n");
    let close = "\t\tlua_cleanup(params.L);";
    ensure!(
        source.matches(close).count() == 1,
        "Pinned Lua cleanup changed"
    );
    source = source.replace(
        close,
        "\t\tzapret_lua_vm_detach(params.L);\n\t\tlua_cleanup(params.L);",
    );
    let publish = "\tlua_init_mt();\n\tif (!lua_init_scripts())";
    ensure!(
        source.matches(publish).count() == 1,
        "Pinned Lua initialization changed"
    );
    source = source.replace(publish, "\tlua_init_mt();\n\tzapret_lua_vm_publish(params.L,native_lua_install_interrupt);\n\tif (!lua_init_scripts())");
    fs::write(lua_source, source)?;
    Ok(())
}
