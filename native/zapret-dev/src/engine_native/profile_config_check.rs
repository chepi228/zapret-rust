//! Compare profile construction and template imports, including failed copies.
use super::{profile_flow_patch, tools::Tools};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Profile configuration source parent")?
        .join("profile-config-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("params.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("void dp_init_dynamic(")
        .context("Pinned profile lifecycle")?;
    let last = source
        .find("bool dp_list_have_autohostlist(")
        .context("Pinned profile lookup")?;
    let end = last
        + source[last..]
            .find("\n}\n")
            .context("Pinned profile lifecycle end")?
        + "\n}\n".len();
    fs::write(
        directory.join("profile_config_reference.inc"),
        &source[start..end],
    )?;
    source.replace_range(start..end, "#include \"profile_config_windows.inc\"\n\n");
    let cli = nfq.join("nfqws.c");
    let mut options = fs::read_to_string(&cli)?;
    let start = options
        .find("static bool filter_defaults(")
        .context("Pinned profile filter defaults")?;
    let end = start
        + options[start..]
            .find("\n}\n")
            .context("Pinned profile filter defaults end")?
        + "\n}\n".len();
    fs::write(
        directory.join("profile_defaults_reference.inc"),
        &options[start..end],
    )?;
    options.replace_range(start..end, "#include \"profile_defaults_windows.inc\"\n");

    let executable = directory.join("profile-config-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-Dzapret_localtime_r=fixture_localtime_r",
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    let lua = nfq
        .parent()
        .and_then(Path::parent)
        .context("Pinned Lua source")?
        .join("luajit2-2.1-20250826/src");
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        &lua,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("profile_config_oracle.c"));
    for name in ["pools.c", "filter.c", "helpers.c"] {
        command.arg(nfq.join(name));
    }
    command
        .arg(shim.join("win_files.c"))
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
        .arg(&executable);
    tools.run_command(
        &command,
        &directory,
        "Compile profile configuration comparison",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare profile imports and lifecycle",
    )?;
    ensure!(
        result.starts_with("PASS profile_config "),
        "Incomplete profile configuration comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    profile_flow_patch::apply(&mut options)?;
    fs::write(cli, options)?;
    Ok(())
}
