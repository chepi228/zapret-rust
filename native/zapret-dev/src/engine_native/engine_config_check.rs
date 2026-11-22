//! Compare full global defaults and fault every filter-buffer allocation.
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
        .context("Engine configuration parent")?
        .join("engine-config-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("params.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for name in [
        "cleanup_windivert_portfilters",
        "alloc_windivert_portfilters",
        "init_params",
    ] {
        let start = source
            .find(&format!(" {name}("))
            .context("Pinned engine configuration function")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned configuration function end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    fs::write(directory.join("engine_config_reference.inc"), reference)?;
    let exe = directory.join("engine-config-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
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
        .arg(shim.join("engine_config_oracle.c"))
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
        "Compile engine global defaults comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check engine configuration and filter failures",
    )?;
    ensure!(
        result.starts_with("PASS engine_config "),
        "Incomplete engine configuration comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.push_str("\n#include \"desync.h\"\n#include \"engine_config_windows.inc\"\n");
    fs::write(path, source)?;
    let main = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&main)?;
    let initialization = "\tinit_params(&params);";
    ensure!(
        source.matches(initialization).count() == 1,
        "Pinned global initialization changed"
    );
    source = source.replace(initialization, "");
    let version = "\tMAKE_VER(params.verstr, sizeof(params.verstr));";
    ensure!(
        source.matches(version).count() == 1,
        "Pinned version initialization changed"
    );
    source = source.replace(version, &format!("{initialization}\n{version}"));
    fs::write(main, source)?;
    Ok(())
}
