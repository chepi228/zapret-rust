//! Reproducible orchestration for the pinned Cygwin engine + Rust policy module.
use crate::{Build, checked, engine_native::rust_engine_object};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap, env, ffi::OsString, fs, path::Path, process::Command, time::Duration,
};
use zapret_core::{atomic_write, sha256, sha256_file};
use zapret_platform::{RunOptions, run_owned};
pub(super) const COMMIT: &str = "221d7dff24bfec0cd5ac0a5070b8acef2008af3d";
pub(super) const BASE_HASH: &str =
    "c9925bb194eea8c19feb05ea6b24a848e8b50af8c64643b9e394ffe653327d87";
pub(super) const LUA_HASH: &str =
    "5a49743ad6ce4b7f19aac71b55a08052c1feb62750f051982082c12bf62f39c0";
const CYGWIN_BRIDGE_TARGET: &str = "x86_64-pc-windows-gnu";
pub(super) fn q(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
pub(super) fn cyg(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .context("Cygwin build path must be Unicode")?
        .replace('\\', "/");
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":/",
        "Cygwin build requires a drive-qualified path"
    );
    Ok(format!(
        "/cygdrive/{}/{}",
        (bytes[0] as char).to_ascii_lowercase(),
        &text[3..]
    ))
}
pub(super) fn patch(path: &Path, anchor: &str, replacement: &str) -> Result<()> {
    let text = String::from_utf8(fs::read(path)?)?;
    ensure!(
        text.matches(anchor).count() == 1,
        "Pinned engine patch anchor changed: {}",
        path.display()
    );
    fs::write(path, text.replacen(anchor, replacement, 1))?;
    Ok(())
}

fn patch_cygwin_sources(nfq: &Path) -> Result<()> {
    for name in ["nfqws.c", "lua.c", "protocol.c"] {
        patch(
            &nfq.join(name),
            "#include \"params.h\"",
            "#include \"params.h\"\n#include \"cygwin_engine_abi.h\"",
        )?;
    }
    let main = nfq.join("nfqws.c");
    patch(
        &main,
        "params.windivert_filter = malloc(WINDIVERT_MAX);",
        "params.windivert_filter = zapret_cygwin_alloc_filter(WINDIVERT_MAX);",
    )?;
    let anchor = "\tif (!win_dark_init(";
    patch(
        &main,
        anchor,
        &format!(
            "\tconst int selftest_status = zapret_cygwin_selftest(params.intercept);\n\tif (selftest_status >= 0) return selftest_status;\n\n{anchor}"
        ),
    )?;
    patch(
        &nfq.join("lua.c"),
        "luaL_openlibs(params.L); /* Load Lua libraries */",
        "if (!zapret_cygwin_openlibs(&params.L)) return false;",
    )?;

    // The public header already declares these readers. Keep the upstream
    // callers and supply the same exports from the shared Rust parser.
    let protocol = nfq.join("protocol.c");
    let mut source = fs::read_to_string(&protocol)?;
    let first = "\nconst char *TLSVersionStr(";
    let last = "\nssize_t TLSPos(";
    ensure!(
        source.matches(first).count() == 1 && source.matches(last).count() == 1,
        "Pinned Cygwin TLS reader block changed"
    );
    let start = source.find(first).context("Cygwin TLS reader start")?;
    let end = source.find(last).context("Cygwin TLS reader end")?;
    ensure!(start < end, "Pinned Cygwin TLS reader order changed");
    source.replace_range(start..end, "");
    fs::write(&protocol, source)?;
    for delta in ["slen_delta", "4"] {
        patch(
            &protocol,
            &format!("if ((*fake_tls_size + {delta}) > fake_tls_buf_size)"),
            &format!(
                "if (!zapret_cygwin_tls_resize_fits(*fake_tls_size, fake_tls_buf_size, TLSRecordDataLen(fake_tls), {delta}))"
            ),
        )?;
    }
    Ok(())
}

pub(crate) fn run(build: &Build<'_>, queue: bool) -> Result<()> {
    let _lock = build.lock_release()?;
    checked(
        build
            .cargo("build", Some("zapret-ring-ffi"))
            .args(["--locked", "--release", "--target-dir"])
            .arg(&build.target),
    )?;
    let root = build.root;
    let work = root.join("dist/upstream/rust-ring-build");
    for (name, hash) in [
        ("zapret2-221d7dff.tar.gz", BASE_HASH),
        ("luajit2-2.1-20250826.tar.gz", LUA_HASH),
    ] {
        let path = work.join(name);
        ensure!(
            path.is_file(),
            "Missing pinned source archive {}. See native/zapret-ring-ffi/README.md for the verified source URLs",
            path.display()
        );
        ensure!(
            sha256_file(&path)?.eq_ignore_ascii_case(hash),
            "Source archive hash mismatch: {name}"
        );
    }
    let bash = root.join("dist/rust-tools/cygwin/bin/bash.exe");
    ensure!(
        bash.is_file(),
        "Private Cygwin compiler is missing; see native/zapret-ring-ffi/README.md"
    );
    let staged = tempfile::Builder::new()
        .prefix("cygwin-")
        .tempdir_in(&work)?;
    let sources = staged.path();
    let extract = format!(
        "set -eu\nexport PATH=/usr/bin:/bin\ncd {}\ntar -xzf {} -C {}\ntar -xzf {} -C {}\n",
        q(&cyg(root)?),
        q(&cyg(&work.join("zapret2-221d7dff.tar.gz"))?),
        q(&cyg(sources)?),
        q(&cyg(&work.join("luajit2-2.1-20250826.tar.gz"))?),
        q(&cyg(sources)?)
    );
    shell(
        root,
        &bash,
        &work.join("extract-native.sh"),
        &extract,
        "ring-extract.log",
    )?;
    let nfq = sources.join(format!("zapret2-{COMMIT}/nfq2"));
    let luajit = sources.join("luajit2-2.1-20250826");
    let bridge = root.join("native/zapret-ring-ffi/bridge/cygwin");
    let header = nfq.join("cygwin_engine_abi.h");
    fs::copy(bridge.join("engine_abi.h"), &header)?;
    patch_cygwin_sources(&nfq)?;
    let dll = fs::read(build.target.join("release/zapret_ring_ffi.dll"))?;
    let support_target = build.target.join("cygwin-ring-support");
    checked(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(root)
            .args([
                "build",
                "--locked",
                "--release",
                "--target",
                CYGWIN_BRIDGE_TARGET,
                "--manifest-path",
            ])
            .arg(bridge.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&support_target)
            .env("ZAPRET_RING_DLL_SHA256", sha256(&dll).to_ascii_uppercase()),
    )?;
    let support = support_target
        .join(CYGWIN_BRIDGE_TARGET)
        .join("release/libzapret_cygwin_ring_support.a");
    let ring_vm = sources.join("windows_ring_vm.o");
    let startup = sources.join("cygwin_startup.o");
    for (source, object) in [
        ("windows_ring_vm.rs", &ring_vm),
        ("cygwin_startup.rs", &startup),
    ] {
        checked(
            rust_engine_object(root, source, object, "panic=unwind").args([
                "--target",
                CYGWIN_BRIDGE_TARGET,
                "-C",
                "force-unwind-tables=yes",
            ]),
        )?;
    }
    let mut bridge_inputs = Vec::new();
    for (name, path) in [
        ("nfqws.c", &nfq.join("nfqws.c")),
        ("lua.c", &nfq.join("lua.c")),
        ("protocol.c", &nfq.join("protocol.c")),
        ("cygwin_engine_abi.h", &header),
        ("cygwin_startup.o", &startup),
        ("windows_ring_vm.o", &ring_vm),
        ("libzapret_cygwin_ring_support.a", &support),
    ] {
        let bytes = fs::read(path)?;
        bridge_inputs.extend_from_slice(name.as_bytes());
        bridge_inputs.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        bridge_inputs.extend_from_slice(&bytes);
    }
    let map = build.target.join("ring-engine-link.map");
    let libraries = format!(
        "{} {} {} {}",
        q(&cyg(&startup)?),
        q(&cyg(&ring_vm)?),
        q(&cyg(&luajit.join("src/libluajit.a"))?),
        q(&cyg(&support)?),
    );
    // Cygwin compiler children must not inherit a cwd with a second cygwin1.dll.
    let script = format!(
        "set -eu\nexport PATH=/usr/bin:/bin\ncd {}\nmake -j4 BUILDMODE=static XCFLAGS='-DLUAJIT_DISABLE_FFI'\ncd {}\nmake cygwin64 -j4 LUA_JIT=1 LUA_CFLAGS={} LUA_LIB={} CFLAGS={} LIBS_CYGWIN={} LDFLAGS={}\n",
        q(&cyg(&luajit)?),
        q(&cyg(&nfq)?),
        q(&format!("-I{}", cyg(&luajit.join("src"))?)),
        q(&libraries),
        q(&format!(
            "-std=gnu99 -O2 -flto=auto -ffunction-sections -fdata-sections -DZAPRET_GH_VER=v1.0.6-rust-ring.1 -DZAPRET_GH_HASH={COMMIT}"
        )),
        q("-lz -Lwindows/windivert -Iwindows -lole32 -loleaut32 -liphlpapi -lntdll -lbcrypt"),
        q(&q(&format!("-Wl,-Map,{}", cyg(&map)?))),
    );
    shell(
        root,
        &bash,
        &work.join("compile-native.sh"),
        &script,
        "ring-native-build.log",
    )?;
    let candidate = build.target.join("ring-candidate");
    for (source, name) in [
        (nfq.join("winws2.exe"), "bin/winws2.exe"),
        (
            root.join("dist/rust-tools/cygwin/bin/cygwin1.dll"),
            "bin/cygwin1.dll",
        ),
    ] {
        atomic_write(&candidate.join(name), &fs::read(source)?)?;
    }
    atomic_write(&candidate.join("bin/zapret-ring.dll"), &dll)?;
    for name in ["autoring.lua", "ring-store.lua", "host-cache.lua"] {
        atomic_write(
            &candidate.join("lua").join(name),
            &fs::read(root.join("native/zapret-ring/lua").join(name))?,
        )?;
    }
    finish(
        build,
        &candidate,
        &bridge_inputs,
        1,
        queue,
        "ring-engine-check.json",
    )
}

pub(super) fn finish(
    build: &Build<'_>,
    candidate: &Path,
    bridge_inputs: &[u8],
    schema: u32,
    queue: bool,
    report: &str,
) -> Result<()> {
    let root = build.root;
    let hashes = zapret_core::RING_FILES
        .into_iter()
        .filter(|name| !zapret_core::omits_engine_file(schema, name))
        .map(|name| {
            Ok((
                name.to_owned(),
                sha256_file(&candidate.join(name))?.to_ascii_lowercase(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let own = zapret_core::RingManifest {
        schema,
        abi: 1,
        backend: "Rust".into(),
        base_commit: COMMIT.into(),
        base_source_sha256: BASE_HASH.into(),
        luajit_source_sha256: LUA_HASH.into(),
        rust_lua_source_sha256: (schema == zapret_core::RUST_LUA_SCHEMA)
            .then(|| zapret_core::RUST_LUA_SOURCE_SHA256.into()),
        bridge_source_sha256: sha256(bridge_inputs),
        hashes,
    };
    atomic_write(
        &candidate.join("tools/rust-ring.json"),
        &serde_json::to_vec_pretty(&own)?,
    )?;
    let base = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
    let mut text = format!(
        "# zapret2 {} base; locally built Rust ring derivative. See rust-ring.json.\nschema={schema}\ntag={}\ncommit={}\narchive-sha256={}\n",
        base.tag, base.tag, base.commit, base.archive_sha256
    );
    let mut checksums = format!(
        "zapret2 {} base, original archive SHA-256 {}.\nLocal Rust ring derivative; source provenance: tools/rust-ring.json, native/zapret-ring-ffi/README.md.\nSHA-256 of the bundled files:\n",
        base.tag, base.archive_sha256
    );
    for name in zapret_core::CORE_FILES {
        if zapret_core::omits_engine_file(schema, name) {
            continue;
        }
        let hash = own
            .hashes
            .get(name)
            .or_else(|| base.hashes.get(name))
            .with_context(|| format!("Missing base engine pin: {name}"))?;
        text.push_str(&format!("{name}={hash}\n"));
        checksums.push_str(&format!("{hash}  {}\n", name.rsplit('/').next().unwrap()));
    }
    checksums.push_str(&format!(
        "{}  zapret-ring.dll\n",
        own.hashes["bin/zapret-ring.dll"]
    ));
    atomic_write(&candidate.join("tools/upstream.txt"), text.as_bytes())?;
    atomic_write(&candidate.join("CHECKSUMS.txt"), checksums.as_bytes())?;
    crate::ring::engine(root, candidate, &build.target.join(report), None)?;
    if queue {
        let _control = zapret_platform::ControlGuard::acquire(root, "ring-prepare")?;
        zapret_core::prepare_ring_update(root, candidate)?;
        println!(
            "Queued the verified Rust ring backend. It activates on the next explicit start/restart; the running bypass is unchanged."
        );
    }
    println!("Rust ring candidate: {}", candidate.display());
    Ok(())
}
pub(super) fn shell(root: &Path, bash: &Path, path: &Path, source: &str, log: &str) -> Result<()> {
    atomic_write(path, source.as_bytes())?;
    let result = run_owned(
        bash,
        &[OsString::from(cyg(path)?)],
        &RunOptions {
            cwd: Some(root.into()),
            timeout: Duration::from_secs(600),
            max_output_bytes: 8 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    let mut bytes = result.stdout;
    bytes.extend_from_slice(&result.stderr);
    let log = root.join("dist/native").join(log);
    atomic_write(&log, &bytes)?;
    ensure!(
        result.exit_code == 0 && !result.timed_out && !result.output_truncated,
        "Native build failed ({}); see {}",
        result.exit_code,
        log.display()
    );
    Ok(())
}
