//! Real no-driver engine initialization from compressed private Lua scripts.
use super::engine_case;
use anyhow::{Context, Result, ensure};
use flate2::{Compression, write::GzEncoder};
use std::{ffi::OsString, fs, io::Write, path::Path};
fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}
pub(super) fn check(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let root = temporary.join("gzip-files-данные");
    fs::create_dir(&root)?;
    let script = b"print('ok compressed file ready'); io.stdout:flush()\n";
    let small = gzip(script)?;
    let mut large = Vec::with_capacity(2 * 1024 * 1024 + script.len() + 8);
    large.extend_from_slice(b"--[[");
    large.resize(2 * 1024 * 1024, b'x');
    large.extend_from_slice(b"]]\n");
    large.extend_from_slice(script);
    let mut corrupt = small.clone();
    let length = corrupt.len();
    corrupt[length - 8] ^= 0xff;
    let mut members = small.clone();
    members.extend_from_slice(&gzip(b"error('second gzip member must stay unread')")?);
    let mut trailing = small.clone();
    trailing.extend_from_slice(b"ignored non-gzip trailer");
    let mut bom = b"\xef\xbb\xbf#!/usr/bin/lua\n".to_vec();
    bom.extend_from_slice(script);
    let fixtures = [
        ("small", small.clone(), false, 0, "ok compressed file ready"),
        ("large", gzip(&large)?, false, 0, "ok compressed file ready"),
        (
            "fallback",
            small.clone(),
            true,
            0,
            "ok compressed file ready",
        ),
        ("empty", gzip(b"")?, false, 0, "LUA INIT DONE"),
        (
            "truncated",
            small[..small.len() - 1].to_vec(),
            false,
            87,
            "could not unzip lua file",
        ),
        ("corrupt", corrupt, false, 87, "could not unzip lua file"),
        ("members", members, false, 0, "ok compressed file ready"),
        (
            "plain-extension",
            script.to_vec(),
            false,
            0,
            "ok compressed file ready",
        ),
        (
            "plain-fallback",
            script.to_vec(),
            true,
            0,
            "ok compressed file ready",
        ),
        ("empty-plain", Vec::new(), false, 0, "LUA INIT DONE"),
        ("bom-shebang", bom, false, 0, "ok compressed file ready"),
        (
            "syntax",
            gzip(b"local invalid = !")?,
            false,
            87,
            "syntax.lua.gz",
        ),
        (
            "runtime",
            gzip(b"error('compressed runtime failure')")?,
            false,
            87,
            "compressed runtime failure",
        ),
        (
            "precedence",
            gzip(b"error('fallback must not override an existing file')")?,
            true,
            0,
            "ok compressed file ready",
        ),
        ("trailing", trailing, false, 0, "ok compressed file ready"),
    ];
    let count = fixtures.len();
    for (name, bytes, fallback, code, expected) in fixtures {
        let file = root.join(format!("{name}.lua.gz"));
        fs::write(&file, bytes)?;
        let input = if fallback {
            root.join(format!("{name}.lua"))
        } else {
            file
        };
        if name == "precedence" {
            fs::write(&input, script)?;
        }
        let args: Vec<OsString> = vec![
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            "--debug".into(),
            format!("--lua-init=@{}", input.display()).into(),
        ];
        let text = engine_case(bin, &args, code, &[])
            .with_context(|| format!("Compressed Lua fixture {name}"))?;
        ensure!(
            text.contains(expected),
            "Compressed Lua {name} did not reach its expected result"
        );
        ensure!(
            text.contains("LUA SHUTDOWN"),
            "Compressed Lua {name} did not close its VM"
        );
        zapret_core::atomic_write(&logs.join(format!("gzip-{name}.log")), text.as_bytes())?;
    }
    println!(
        "ok real engine: compressed Lua, Unicode paths, fallback, empty, corruption and first-member behavior"
    );
    Ok(count)
}
