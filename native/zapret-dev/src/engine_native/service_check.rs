//! Run service callbacks on a private dispatcher with no SCM registration.
use super::tools::Tools;
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
        .context("Service source parent")?
        .join("service-check");
    fs::create_dir(&directory)?;
    let exe = directory.join("service-check.exe");
    let mut command = Command::new(tools.compiler);
    command
        .args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
        ])
        .arg(shim.join("service_oracle.c"))
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
        "Compile private service lifecycle fixture",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check engine service lifecycle",
    )?;
    ensure!(
        result.starts_with("PASS engine_service "),
        "Incomplete service lifecycle fixture"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let header = nfq.join("nfqws.h");
    let mut source = fs::read_to_string(&header)?;
    let declaration = "extern volatile sig_atomic_t bQuit;";
    ensure!(
        source.matches(declaration).count() == 1,
        "Pinned quit flag declaration changed"
    );
    source = source.replace(declaration, concat!(
        "#include <stdatomic.h>\n",
        "_Static_assert(ATOMIC_INT_LOCK_FREE == 2, \"engine shutdown requires lock-free flags\");\n",
        "_Static_assert(sizeof(_Atomic(sig_atomic_t)) == 4 && _Alignof(_Atomic(sig_atomic_t)) == 4, \"Rust shutdown flag ABI\");\n",
        "extern _Atomic(sig_atomic_t) bQuit;",
    ));
    fs::write(header, source)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    for flag in ["bQuit", "bReload"] {
        let old = format!("volatile sig_atomic_t {flag} = false;");
        ensure!(
            source.matches(&old).count() == 1,
            "Pinned signal flag changed: {flag}"
        );
        source = source.replace(&old, &format!("_Atomic(sig_atomic_t) {flag} = false;"));
    }
    fs::write(path, source)?;
    Ok(())
}
