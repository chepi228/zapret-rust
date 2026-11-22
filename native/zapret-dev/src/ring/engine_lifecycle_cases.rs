//! Normal return and Lua-init failure must both close the VM before owned cleanup.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};
pub(super) fn check(bin: &Path, logs: &Path) -> Result<usize> {
    let common: Vec<OsString> = vec![
        "--intercept=0".into(),
        "--wf-dup-check=0".into(),
        "--debug".into(),
        "--ctrack-timeouts=11:12:13:14".into(),
        "--ipcache-lifetime=321".into(),
    ];
    let mut dry = common.clone();
    dry.push("--dry-run".into());
    let text = engine_case(bin, &dry, 0, &[])?;
    ensure!(
        text.contains("command line parameters verified")
            && !text.contains("initializing conntrack with timeouts"),
        "Dry-run initialized connection state"
    );
    zapret_core::atomic_write(&logs.join("lifecycle-dry-prepare.log"), text.as_bytes())?;
    const SCRIPT: &str = "LIFECYCLE_KEEP=newproxy(true); getmetatable(LIFECYCLE_KEEP).__gc=function() print('ok lifecycle finalizer'); io.stdout:flush() end; print('ok lifecycle ready'); io.stdout:flush()";
    for disabled in [false, true] {
        let mut args = common.clone();
        if disabled {
            args.push("--ctrack-disable".into());
        }
        args.push(format!("--lua-init={SCRIPT}").into());
        let text = engine_case(bin, &args, 0, &[])?;
        ensure!(
            text.contains("ok lifecycle ready")
                && text.contains("ok lifecycle finalizer")
                && text.contains("LUA SHUTDOWN")
                && text.contains("ipcache lifetime 321s"),
            "Normal return lost VM shutdown or finalizer"
        );
        if disabled {
            ensure!(
                text.contains("conntrack disabled !")
                    && !text.contains("initializing conntrack with timeouts"),
                "Disabled conntrack was initialized"
            );
        } else {
            ensure!(
                text.contains("initializing conntrack with timeouts tcp=11:12:13 udp=14"),
                "Connection timeouts changed at final preparation"
            );
        }
        zapret_core::atomic_write(
            &logs.join(format!("lifecycle-normal-{}.log", u8::from(disabled))),
            text.as_bytes(),
        )?;
    }
    let mut args = common;
    args.push("--lua-init=error('owned lifecycle startup failure')".into());
    let text = engine_case(bin, &args, 87, &[])?;
    ensure!(
        text.contains("owned lifecycle startup failure") && text.contains("LUA SHUTDOWN"),
        "Failed Lua initialization did not close its VM"
    );
    zapret_core::atomic_write(
        &logs.join("lifecycle-lua-init-failure.log"),
        text.as_bytes(),
    )?;
    println!(
        "ok real engine: dry/disabled preparation, normal VM finalizers and failed Lua initialization"
    );
    Ok(4)
}
