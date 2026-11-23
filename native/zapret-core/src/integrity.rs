use crate::{io::hex, read_bounded, sha256, sha256_file};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const CYGWIN_DLL: &str = "bin/cygwin1.dll";
// Both engine manifests share the same schema numbers.
pub const NATIVE_ONLY_SCHEMA: u32 = 2;
pub const BUILTIN_RULES_SCHEMA: u32 = 3;
pub const RUST_LUA_SCHEMA: u32 = 4;
pub const RUST_LUA_SOURCE_SHA256: &str =
    "0162144beb06b927dce484b6447ca7ec6a62f331bbd257b6c16eab9186497c82";
pub const BUNDLED_LUA_FILES: [&str; 7] = [
    "lua/zapret-lib.lua",
    "lua/zapret-antidpi.lua",
    "lua/zapret-auto.lua",
    "lua/host-cache.lua",
    "lua/fooling.lua",
    "lua/ring-store.lua",
    "lua/autoring.lua",
];

pub fn omits_engine_file(schema: u32, name: &str) -> bool {
    let license = name.strip_prefix("licenses/").unwrap_or(name);
    (schema >= NATIVE_ONLY_SCHEMA && (name == CYGWIN_DLL || license == "LICENSE-cygwin.txt"))
        || (schema >= BUILTIN_RULES_SCHEMA && BUNDLED_LUA_FILES.contains(&name))
        || (schema == RUST_LUA_SCHEMA && license == "LICENSE-LuaJIT.txt")
        || (schema != RUST_LUA_SCHEMA && license == "LICENSE-Luna.txt")
}

pub const CORE_FILES: [&str; 8] = [
    "bin/winws2.exe",
    CYGWIN_DLL,
    "bin/WinDivert.dll",
    "bin/WinDivert64.sys",
    "lua/zapret-lib.lua",
    "lua/zapret-antidpi.lua",
    "lua/zapret-auto.lua",
    "windivert/quic_initial_ietf.txt",
];
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreManifest {
    pub schema: u32,
    pub tag: String,
    pub commit: String,
    pub archive_sha256: String,
    pub hashes: BTreeMap<String, String>,
    pub content_hash: String,
}
pub fn read_core_manifest(path: &Path) -> Result<CoreManifest> {
    let bytes = read_bounded(path, 8192)?;
    parse_core_manifest(&bytes)
}
pub fn uses_builtin_rules(root: &Path) -> bool {
    read_core_manifest(&root.join("tools/upstream.txt"))
        .is_ok_and(|manifest| manifest.schema >= BUILTIN_RULES_SCHEMA)
}
pub fn parse_core_manifest(bytes: &[u8]) -> Result<CoreManifest> {
    ensure!(
        (1..=8192).contains(&bytes.len()),
        "Invalid core manifest size"
    );
    let text = std::str::from_utf8(bytes)?.trim_start_matches('\u{feff}');
    let mut values = BTreeMap::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.trim_start_matches(' ').starts_with('#') {
            continue;
        }
        ensure!(
            raw.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "Core manifest records must be printable ASCII"
        );
        let line = raw.trim_matches(' ');
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid core manifest record"))?;
        ensure!(
            ["schema", "tag", "commit", "archive-sha256"].contains(&key)
                || CORE_FILES.contains(&key),
            "Unknown core manifest key"
        );
        ensure!(
            values.insert(key.to_owned(), value.to_owned()).is_none(),
            "Duplicate core manifest key"
        );
    }
    let schema = match values.get("schema").map(String::as_str) {
        Some("1") => 1,
        Some("2") => NATIVE_ONLY_SCHEMA,
        Some("3") => BUILTIN_RULES_SCHEMA,
        Some("4") => RUST_LUA_SCHEMA,
        _ => anyhow::bail!("Unsupported core manifest schema"),
    };
    let files = CORE_FILES
        .into_iter()
        .filter(|name| !omits_engine_file(schema, name));
    ensure!(
        values.len() == 4 + files.clone().count()
            && ["schema", "tag", "commit", "archive-sha256"]
                .into_iter()
                .chain(files.clone())
                .all(|name| values.contains_key(name)),
        "Incomplete core manifest or inconsistent file catalog"
    );
    let tag = &values["tag"];
    let version = tag.strip_prefix('v').unwrap_or("");
    let parts: Vec<_> = version.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts.iter().all(|v| !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit())
                && (v.len() == 1 || !v.starts_with('0'))
                && v.parse::<u32>().is_ok()),
        "Invalid upstream tag"
    );
    ensure!(
        hex(&values["commit"], 40) && hex(&values["archive-sha256"], 64),
        "Invalid upstream provenance"
    );
    let mut hashes = BTreeMap::new();
    for file in files {
        ensure!(hex(&values[file], 64), "Invalid pinned hash");
        hashes.insert(file.to_owned(), values[file].to_ascii_lowercase());
    }
    Ok(CoreManifest {
        schema,
        tag: tag.clone(),
        commit: values["commit"].to_ascii_lowercase(),
        archive_sha256: values["archive-sha256"].to_ascii_lowercase(),
        hashes,
        content_hash: sha256(bytes),
    })
}
pub fn core_manifest_current(manifest: &CoreManifest, path: &Path) -> bool {
    read_bounded(path, 8192).is_ok_and(|bytes| sha256(&bytes) == manifest.content_hash)
}
fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if m.file_attributes() & 0x400 != 0 {
                return false;
            }
        }
        m.file_type().is_file() && !m.file_type().is_symlink()
    })
}
pub fn verify_integrity(root: &Path, manifest: &CoreManifest) -> Result<Vec<String>> {
    ensure!(
        core_manifest_current(manifest, &root.join("tools/upstream.txt")),
        "Core manifest changed after capture"
    );
    let mut bad = Vec::new();
    for (file, expected) in &manifest.hashes {
        let path = root.join(file);
        if !regular_file(&path) {
            bad.push(format!("{file} - нет обычного файла"));
            continue;
        }
        match sha256_file(&path) {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => {}
            _ => bad.push(format!("{file} - изменён")),
        }
    }
    match crate::verify_ring(root) {
        Ok(Some(ring)) if ring.schema != manifest.schema => {
            bad.push("Rust ring: core and ring manifest schemas differ".into());
        }
        Ok(None) if manifest.schema >= NATIVE_ONLY_SCHEMA => {
            bad.push("Rust ring: native engine requires a ring manifest".into());
        }
        Err(error) => bad.push(format!("Rust ring: {error:#}")),
        _ => {}
    }
    Ok(bad)
}

/// A conservative check for POSIX runtime names, including delayed imports.
/// Engine builds also check the PE import table and run without the POSIX DLL.
pub fn mentions_posix_runtime(image: &[u8]) -> bool {
    ["cygwin1.dll", "msys-2.0.dll", "msys-1.0.dll"]
        .into_iter()
        .any(|name| {
            image
                .windows(name.len())
                .any(|bytes| bytes.eq_ignore_ascii_case(name.as_bytes()))
        })
}
pub fn verify_package(root: &Path) -> Result<Vec<String>> {
    let manifest = read_core_manifest(&root.join("tools/upstream.txt"))?;
    verify_integrity(root, &manifest)
}
// Telegram's Rust core is linked into the controller and covered by the native
// package's per-file digest catalog. No external executable needs downloading.
pub const TELEGRAM_RELATIVE_PATH: &str = "bin/zapret-rust.exe";
pub fn verify_telegram(root: &Path) -> Result<PathBuf> {
    let path = root.join(TELEGRAM_RELATIVE_PATH);
    ensure!(regular_file(&path), "Native Telegram controller is missing");
    use std::io::Read;
    let mut signature = [0; 2];
    fs::File::open(&path)?.read_exact(&mut signature)?;
    ensure!(
        signature == *b"MZ",
        "Native Telegram controller is not a Windows image"
    );
    Ok(path)
}

#[cfg(test)]
mod telegram_tests {
    use super::*;

    #[test]
    fn telegram_core_is_inside_the_native_controller_without_an_external_asset() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        let controller = directory.path().join("bin/zapret-rust.exe");
        fs::write(&controller, b"MZnative controller fixture").unwrap();
        assert_eq!(verify_telegram(directory.path()).unwrap(), controller);
        fs::write(&controller, b"invalid image").unwrap();
        assert!(verify_telegram(directory.path()).is_err());
    }
}
