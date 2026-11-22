//! Validate real startup paths and ownership after argument cleanup.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};
fn dry(bin: &Path, path: &Path, option: &str) -> Result<String> {
    let prefix = if option == "--debug" { "@" } else { "" };
    engine_case(
        bin,
        &[
            "--dry-run".into(),
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            format!("{option}={prefix}{}", path.display()).into(),
        ],
        0,
        &[],
    )
}
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let debug = temporary.join("cli-debug-данные-é-中.log");
    std::fs::write(&debug, b"old debug sentinel")?;
    let text = dry(bin, &debug, "--debug")?;
    ensure!(
        text.contains("command line parameters verified") && std::fs::metadata(&debug)?.is_file(),
        "Debug path did not finish"
    );
    let content = std::fs::read(&debug)?;
    ensure!(
        !content
            .windows(b"old debug sentinel".len())
            .any(|part| part == b"old debug sentinel"),
        "Debug file retained the preceding content"
    );
    zapret_core::atomic_write(&logs.join("cli-debug-path.log"), text.as_bytes())?;
    let auto = temporary.join("cli-auto-данные-é-中.log");
    const SENTINEL: &[u8] = b"old auto sentinel\n";
    std::fs::write(&auto, SENTINEL)?;
    let text = dry(bin, &auto, "--hostlist-auto-debug")?;
    ensure!(
        std::fs::read(&auto)? == SENTINEL,
        "Auto log touch replaced the preceding content"
    );
    zapret_core::atomic_write(&logs.join("cli-auto-path.log"), text.as_bytes())?;
    let working = temporary.join("cli-working-данные-é-中");
    std::fs::create_dir(&working)?;
    std::fs::write(working.join("начало-é-中.lua"), b"CLI_STARTUP_MARKER=641\n")?;
    let finish = "assert(CLI_STARTUP_MARKER==641); print('ok owned relative Lua init'); io.stdout:flush(); os.exit(0)";
    let text = engine_case(
        bin,
        &[
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            format!("--chdir={}", working.display()).into(),
            "--lua-init=@начало-é-中.lua".into(),
            format!("--lua-init={finish}").into(),
        ],
        0,
        &[],
    )?;
    ensure!(
        text.contains("ok owned relative Lua init"),
        "Relative script did not survive argument cleanup"
    );
    zapret_core::atomic_write(&logs.join("cli-relative-lua.log"), text.as_bytes())?;
    std::fs::write(
        bin.join("cli-exedir-marker.lua"),
        b"CLI_EXEDIR_MARKER=642\n",
    )?;
    let text=engine_case(bin,&["--intercept=0".into(),"--wf-dup-check=0".into(),format!("--chdir={}",working.display()).into(),"--chdir".into(),"--lua-init=@cli-exedir-marker.lua".into(),"--lua-init=assert(CLI_EXEDIR_MARKER==642); print('ok EXEDIR startup restore'); io.stdout:flush(); os.exit(0)".into()],0,&[])?;
    ensure!(
        text.contains("ok EXEDIR startup restore"),
        "Optional chdir did not use EXEDIR"
    );
    zapret_core::atomic_write(&logs.join("cli-exedir.log"), text.as_bytes())?;
    let config = temporary.join("cli-owned-данные-é-中.conf");
    std::fs::write(
        &config,
        r#"--intercept=0 --wf-dup-check=0 --lua-init='print("ok retained config Lua init"); io.stdout:flush(); os.exit(0)'"#,
    )?;
    let text = engine_case(
        bin,
        &[OsString::from(format!("@{}", config.display()))],
        0,
        &[],
    )?;
    ensure!(
        text.contains("ok retained config Lua init"),
        "Literal Lua init retained a freed config argument"
    );
    zapret_core::atomic_write(&logs.join("cli-config-lua.log"), text.as_bytes())?;
    println!("ok real engine: startup log paths, working directory and owned Lua init");
    Ok(5)
}
