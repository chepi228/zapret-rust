//! Verify the final main transition and cleanup after the C-owned Lua shutdown.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn section(source: &str, start: &str, end: &str) -> Result<std::ops::Range<usize>> {
    let first = source.find(start).context("Pinned lifecycle start")?;
    let last = first + source[first..].find(end).context("Pinned lifecycle end")?;
    Ok(first..last)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Engine lifecycle parent")?
        .join("engine-lifecycle-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let prepare = section(
        &source,
        "\n\tif (bDry)\n\t{",
        "\n#ifdef __linux__\n\tresult = nfq_main();",
    )?;
    fs::write(
        directory.join("engine_prepare_reference.inc"),
        &source[prepare.clone()],
    )?;
    let mutex = section(&source, "\tif (hMutexArg)\n\t{", "\n#endif")?;
    fs::write(
        directory.join("engine_mutex_reference.inc"),
        &source[mutex.clone()],
    )?;
    let config_path = nfq.join("params.c");
    let mut config = fs::read_to_string(&config_path)?;
    let first = config
        .find("void cleanup_params(")
        .context("Pinned cleanup function")?;
    let last = first
        + config[first..]
            .find("\n}\n")
            .context("Pinned cleanup function end")?
        + 3;
    fs::write(
        directory.join("engine_cleanup_reference.inc"),
        &config[first..last],
    )?;
    let observed = directory.join("windows-main-lifecycle-observed.o");
    tools.run_command(
        Command::new(tools.llvm.join("llvm-objcopy.exe"))
            .args([
                "--redefine-sym=ConntrackPoolInit=model_init",
                "--redefine-sym=DLOG=model_debug",
                "--redefine-sym=DLOG_CONDUP=model_console",
                "--redefine-sym=DLOG_ERR=model_debug",
                "--redefine-sym=ReleaseMutex=model_release_mutex",
                "--redefine-sym=CloseHandle=model_close_handle",
            ])
            .arg(object)
            .arg(&observed),
        &directory,
        "Observe Rust lifecycle entry callouts",
    )?;
    let exe = directory.join("engine-lifecycle-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
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
        .arg(shim.join("engine_lifecycle_oracle.c"))
        .arg(&observed)
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile native main/cleanup and C VM boundary comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Check final preparation, cleanup order, idempotence and mutex release",
    )?;
    ensure!(
        result.starts_with("PASS engine_lifecycle ") && result.contains("rust_entry=1"),
        "Incomplete lifecycle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(mutex, "\tnative_lifecycle_release_mutex(&hMutexArg);\n");
    source.replace_range(
        prepare,
        concat!(
            "\n\tuint32_t lifecycle=native_lifecycle_prepare(bDry);\n",
            "\tif(lifecycle==8)exit_clean(0);\n\tif(lifecycle)goto exiterr;\n"
        ),
    );
    let include = "#include \"capture_preflight_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned lifecycle include"
    );
    source = source.replace(
        include,
        &format!("{include}\n#include \"engine_lifecycle_windows.inc\""),
    );
    fs::write(path, source)?;
    config.replace_range(first..last, "#include \"engine_cleanup_windows.inc\"\n");
    fs::write(config_path, config)?;
    Ok(())
}
