//! Confirm PID output through the real no-capture startup and Lua API.
use super::engine_case;
use anyhow::{Result, ensure};
use std::path::Path;
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let pid = temporary.join("startup-данные-é-中.pid");
    let script = "local f=assert(io.open(os.getenv('ZAPRET_PID_FIXTURE'),'rb')); local data=f:read('*a'); f:close(); assert(data==tostring(getpid())); print('ok native PID file matches running process'); io.stdout:flush(); os.exit(0)";
    let text = engine_case(
        bin,
        &[
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            format!("--pidfile={}", pid.display()).into(),
            format!("--lua-init={script}").into(),
        ],
        0,
        &[("ZAPRET_PID_FIXTURE".into(), pid.clone().into_os_string())],
    )?;
    ensure!(
        text.contains("ok native PID file matches running process"),
        "Missing real PID startup assertion"
    );
    zapret_core::atomic_write(&logs.join("startup-pid-unicode.log"), text.as_bytes())?;
    let bytes = std::fs::read(&pid)?;
    ensure!(
        !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit),
        "Invalid PID bytes"
    );
    let directory = temporary.join("startup-pid-directory");
    std::fs::create_dir(&directory)?;
    let text = engine_case(
        bin,
        &[
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            format!("--pidfile={}", directory.display()).into(),
        ],
        4,
        &[],
    )?;
    ensure!(
        text.contains("could not write pidfile") && directory.is_dir(),
        "Missing PID write failure or changed directory"
    );
    zapret_core::atomic_write(&logs.join("startup-pid-failure.log"), text.as_bytes())?;
    println!("ok real engine: native PID file and write failure");
    Ok(2)
}
