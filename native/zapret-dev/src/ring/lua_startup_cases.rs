//! Exercise startup policy in the real engine without enabling packet capture.
use super::engine_case;
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, fs, path::Path};

fn printed(text: &str, marker: &str) -> bool {
    text.lines().any(|line| line.trim() == marker)
}

pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let root = temporary.join("lua-startup-данные");
    fs::create_dir(&root)?;
    let ordered = root.join("порядок.lua");
    fs::write(
        &ordered,
        "assert(startup_order=='first'); startup_order='file'; print('ok startup file'); io.stdout:flush()\n",
    )?;
    let failed = root.join("ошибка.lua");
    fs::write(&failed, "error('startup file failure')\n")?;
    const KEEP: &str = "STARTUP_KEEP=newproxy(true); getmetatable(STARTUP_KEEP).__gc=function() print('ok startup closed'); io.stdout:flush() end";
    let first = format!(
        "assert(os.execute==nil and io.popen==nil and package.loadlib==nil and debug==nil and package.loaded.debug==nil); assert(startup_payload==string.char(0,65,255,66)); assert(type(NFQWS2_VER)=='string' and type(VERDICT_PASS)=='number' and type(rawsend)=='function'); startup_order='first'; {KEEP}; print('ok startup first'); io.stdout:flush()"
    );
    let cases: [(&str, Vec<OsString>, u32, &str); 6] = [
        (
            "ordered",
            vec![
                "--blob=startup_payload:0x0041ff42".into(),
                format!("--lua-init={first}").into(),
                format!("--lua-init=@{}", ordered.display()).into(),
                "--lua-init=assert(startup_order=='file'); function startup_first() return VERDICT_PASS end; function startup_second() return VERDICT_PASS end; print('ok startup last'); io.stdout:flush()".into(),
                "--lua-desync=startup_first".into(),
                "--new=second".into(),
                "--lua-desync=startup_second".into(),
            ],
            0,
            "LUA INIT DONE",
        ),
        (
            "inline-error",
            vec![
                format!("--lua-init={KEEP}").into(),
                "--lua-init=error('startup inline failure')".into(),
                "--lua-init=print('unexpected startup continuation'); io.stdout:flush()".into(),
            ],
            87,
            "startup inline failure",
        ),
        (
            "file-error",
            vec![
                format!("--lua-init={KEEP}").into(),
                format!("--lua-init=@{}", failed.display()).into(),
                "--lua-init=print('unexpected startup continuation'); io.stdout:flush()".into(),
            ],
            87,
            "startup file failure",
        ),
        (
            "missing-function",
            vec![
                format!("--lua-init={KEEP}; print('ok startup scripts complete'); io.stdout:flush()").into(),
                "--lua-desync=startup_missing".into(),
            ],
            87,
            "desync function 'startup_missing' does not exist",
        ),
        (
            "nonfunction",
            vec![
                format!("--lua-init={KEEP}; startup_not_function={{}}; print('ok startup scripts complete'); io.stdout:flush()").into(),
                "--lua-desync=startup_not_function".into(),
            ],
            87,
            "desync function 'startup_not_function' does not exist",
        ),
        (
            "missing-file",
            vec![
                "--lua-init=print('unexpected startup continuation'); io.stdout:flush()".into(),
                format!("--lua-init=@{}", root.join("отсутствует.lua").display()).into(),
            ],
            1,
            "not accessible",
        ),
    ];
    let count = cases.len();
    for (name, extra, code, expected) in cases {
        let mut args: Vec<OsString> = vec![
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            "--debug".into(),
        ];
        args.extend(extra);
        let text = engine_case(bin, &args, code, &[])
            .with_context(|| format!("Lua startup fixture {name}"))?;
        zapret_core::atomic_write(
            &logs.join(format!("lua-startup-{name}.log")),
            text.as_bytes(),
        )?;
        ensure!(
            text.contains(expected),
            "Lua startup {name} lost its result"
        );
        ensure!(
            !printed(&text, "unexpected startup continuation"),
            "Lua startup {name} executed a script after failure"
        );
        if name == "missing-file" {
            ensure!(
                !text.contains("\nLUA INIT\n"),
                "Missing startup file was checked after starting the VM"
            );
        } else {
            ensure!(
                text.contains("LUA SHUTDOWN") && printed(&text, "ok startup closed"),
                "Lua startup {name} lost VM cleanup or its finalizer"
            );
            if code != 0 {
                ensure!(
                    !text.contains("LUA INIT DONE"),
                    "Lua startup {name} incorrectly reported success"
                );
            }
        }
        if name == "ordered" {
            let markers: Vec<_> = text
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("ok startup "))
                .collect();
            ensure!(
                markers
                    == [
                        "ok startup first",
                        "ok startup file",
                        "ok startup last",
                        "ok startup closed"
                    ],
                "Lua startup changed script/cleanup order: {markers:?}"
            );
        } else if matches!(name, "missing-function" | "nonfunction") {
            ensure!(
                printed(&text, "ok startup scripts complete"),
                "Lua strategy lookup ran before startup scripts completed"
            );
        }
    }
    println!(
        "ok real engine: Lua startup order, sandbox, binary blobs, Unicode files, strategy lookup and failure cleanup"
    );
    Ok(count)
}
