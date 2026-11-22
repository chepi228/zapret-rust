//! Fixed-file native ring update. Preparation and release overlays never stop a
//! process. The platform applies it only during an explicitly requested start,
//! after its ownership, game and stopped-process checks.
use crate::{
    BUILTIN_RULES_SCHEMA, CYGWIN_DLL, NATIVE_ONLY_SCHEMA, RUST_LUA_SCHEMA, RUST_LUA_SOURCE_SHA256,
    atomic_write, mentions_posix_runtime, omits_engine_file, read_bounded, sha256, sha256_file,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const RING_FILES: [&str; 6] = [
    "bin/winws2.exe",
    CYGWIN_DLL,
    "bin/zapret-ring.dll",
    "lua/ring-store.lua",
    "lua/autoring.lua",
    "lua/host-cache.lua",
];
pub const RING_UPDATE_FILES: [&str; 9] = [
    "bin/zapret-ring.dll",
    CYGWIN_DLL,
    "bin/winws2.exe",
    "lua/ring-store.lua",
    "lua/autoring.lua",
    "lua/host-cache.lua",
    "CHECKSUMS.txt",
    "tools/rust-ring.json",
    "tools/upstream.txt",
];
pub const RING_QUEUE: &str = "tools/rust-ring-next";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingManifest {
    pub schema: u32,
    pub abi: u32,
    pub backend: String,
    pub base_commit: String,
    pub base_source_sha256: String,
    pub luajit_source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_lua_source_sha256: Option<String>,
    pub bridge_source_sha256: String,
    pub hashes: BTreeMap<String, String>,
}
fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn checked(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Absolute ring path required");
    for ancestor in path.ancestors() {
        if ancestor.try_exists()? {
            let m = fs::symlink_metadata(ancestor)?;
            ensure!(!m.file_type().is_symlink(), "Ring update rejects links");
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                ensure!(
                    m.file_attributes() & 0x400 == 0,
                    "Ring update rejects reparse points"
                );
            }
        }
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    checked(path)?;
    ensure!(
        fs::metadata(path)?.is_file(),
        "Ring input must be a regular file"
    );
    read_bounded(path, 32 * 1024 * 1024)
}
pub fn verify_ring(root: &Path) -> Result<Option<RingManifest>> {
    let path = root.join("tools/rust-ring.json");
    if !path.try_exists()? {
        ensure!(
            !root.join("bin/zapret-ring.dll").try_exists()?,
            "Rust ring module has no integrity manifest"
        );
        return Ok(None);
    }
    let manifest: RingManifest = serde_json::from_slice(&read(&path)?)?;
    ensure!(
        matches!(
            manifest.schema,
            1 | NATIVE_ONLY_SCHEMA | BUILTIN_RULES_SCHEMA | RUST_LUA_SCHEMA
        ) && manifest.abi == 1
            && manifest.backend == "Rust"
            && manifest.base_commit == "221d7dff24bfec0cd5ac0a5070b8acef2008af3d",
        "Unsupported Rust ring manifest"
    );
    ensure!(
        [
            &manifest.base_source_sha256,
            &manifest.luajit_source_sha256,
            &manifest.bridge_source_sha256
        ]
        .into_iter()
        .all(|v| digest(v)),
        "Invalid Rust ring provenance"
    );
    ensure!(
        if manifest.schema == RUST_LUA_SCHEMA {
            manifest
                .rust_lua_source_sha256
                .as_ref()
                .is_some_and(|pin| pin.eq_ignore_ascii_case(RUST_LUA_SOURCE_SHA256))
        } else {
            manifest.rust_lua_source_sha256.is_none()
        },
        "Invalid Rust Lua interpreter provenance"
    );
    let native_only = manifest.schema >= NATIVE_ONLY_SCHEMA;
    let files = RING_FILES
        .into_iter()
        .filter(|name| !omits_engine_file(manifest.schema, name));
    ensure!(
        manifest.hashes.len() == files.clone().count(),
        "Incomplete Rust ring hash catalog"
    );
    for name in files {
        let expected = manifest
            .hashes
            .get(name)
            .context("Missing Rust ring input")?;
        let bytes = read(&root.join(name))?;
        ensure!(
            digest(expected) && sha256(&bytes).eq_ignore_ascii_case(expected),
            "Rust ring integrity mismatch: {name}"
        );
        if native_only && matches!(name, "bin/winws2.exe" | "bin/zapret-ring.dll") {
            ensure!(
                bytes.starts_with(b"MZ") && !mentions_posix_runtime(&bytes),
                "Native-only ring image is invalid or references a POSIX runtime: {name}"
            );
        }
    }
    Ok(Some(manifest))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum State {
    Prepared,
    Applying,
    Applied,
    Rejected,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    before: Option<String>,
    after: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    state: State,
    files: BTreeMap<String, Entry>,
}
type Bytes = BTreeMap<String, Vec<u8>>;
pub struct RingUpdate {
    root: PathBuf,
    stage: PathBuf,
    journal: Journal,
    before: BTreeMap<String, Option<Vec<u8>>>,
    after: Bytes,
}
impl RingUpdate {
    /// Read and validate the complete immutable candidate and rollback data.
    pub fn load(root: &Path) -> Result<Option<Self>> {
        let stage = root.join(RING_QUEUE);
        let path = stage.join("journal.json");
        checked(&path)?;
        if !path.try_exists()? {
            return Ok(None);
        }
        let journal: Journal = serde_json::from_slice(&read_bounded(&path, 16384)?)?;
        ensure!(
            journal.schema == 1 && journal.files.len() == RING_UPDATE_FILES.len(),
            "Invalid ring update journal"
        );
        if matches!(journal.state, State::Applied | State::Rejected) {
            return Ok(None);
        }
        let mut before = BTreeMap::new();
        let mut after = BTreeMap::new();
        let mut total = 0;
        for name in RING_UPDATE_FILES {
            let entry = journal
                .files
                .get(name)
                .context("Unexpected ring update file set")?;
            ensure!(
                digest(&entry.after) && entry.before.as_deref().is_none_or(digest),
                "Invalid ring update digest"
            );
            let bytes = read(&stage.join("after").join(name))?;
            ensure!(
                sha256(&bytes).eq_ignore_ascii_case(&entry.after),
                "Changed ring candidate: {name}"
            );
            total += bytes.len();
            after.insert(name.into(), bytes);
            let previous = if let Some(hash) = &entry.before {
                let bytes = read(&stage.join("before").join(name))?;
                ensure!(
                    sha256(&bytes).eq_ignore_ascii_case(hash),
                    "Changed ring rollback input: {name}"
                );
                total += bytes.len();
                Some(bytes)
            } else {
                None
            };
            before.insert(name.into(), previous);
        }
        ensure!(
            total <= 96 * 1024 * 1024,
            "Ring update exceeds memory budget"
        );
        let update = Self {
            root: root.into(),
            stage,
            journal,
            before,
            after,
        };
        update.current(update.journal.state == State::Applying)?;
        Ok(Some(update))
    }
    fn state(&mut self, state: State) -> Result<()> {
        self.journal.state = state;
        atomic_write(
            &self.stage.join("journal.json"),
            &serde_json::to_vec_pretty(&self.journal)?,
        )
    }
    fn current(&self, allow_after: bool) -> Result<()> {
        for (name, entry) in &self.journal.files {
            let path = self.root.join(name);
            checked(&path)?;
            let hash = if path.try_exists()? {
                Some(sha256(&read(&path)?))
            } else {
                None
            };
            ensure!(
                hash.as_ref().map(|s| s.to_ascii_lowercase())
                    == entry.before.as_ref().map(|s| s.to_ascii_lowercase())
                    || (allow_after
                        && hash
                            .as_ref()
                            .is_some_and(|s| s.eq_ignore_ascii_case(&entry.after))),
                "Ring update refuses an external edit: {name}"
            );
        }
        Ok(())
    }
    /// Caller must hold the control lock and confirm that this engine is stopped.
    pub fn apply(&mut self) -> Result<()> {
        if self.journal.state == State::Applying {
            self.rollback(false)?;
        }
        self.current(false)?;
        self.state(State::Applying)?;
        let result = (|| {
            for name in RING_UPDATE_FILES {
                checked(&self.root.join(name))?;
                atomic_write(&self.root.join(name), &self.after[name])?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.rollback(true)
                .context("Restore previous ring bundle")?;
            return Err(error);
        }
        Ok(())
    }
    pub fn rollback(&mut self, reject: bool) -> Result<()> {
        self.current(true)?;
        for name in RING_UPDATE_FILES.into_iter().rev() {
            let path = self.root.join(name);
            match &self.before[name] {
                Some(bytes) => {
                    if !path.try_exists()? || sha256(&read(&path)?) != sha256(bytes) {
                        atomic_write(&path, bytes)?;
                    }
                }
                None => {
                    if path.try_exists()? {
                        fs::remove_file(path)?;
                    }
                }
            }
        }
        self.state(if reject {
            State::Rejected
        } else {
            State::Prepared
        })
    }
    pub fn commit(&mut self) -> Result<()> {
        self.current(true)?;
        for (name, bytes) in &self.after {
            ensure!(
                sha256_file(&self.root.join(name))? == sha256(bytes),
                "Ring update was not fully installed"
            );
        }
        self.state(State::Applied)
    }
}
/// Prepare on disk without changing the active product files or process.
pub fn prepare_ring_update(root: &Path, candidate: &Path) -> Result<()> {
    verify_ring(candidate)?.context("Candidate has no Rust ring backend")?;
    checked(&root.join(RING_QUEUE))?;
    if let Some(old) = RingUpdate::load(root)? {
        ensure!(
            old.journal.state == State::Prepared,
            "Finish the interrupted ring update first"
        );
    }
    let stage = root.join(RING_QUEUE);
    let mut journal = Journal {
        schema: 1,
        state: State::Prepared,
        files: BTreeMap::new(),
    };
    // Keep the publication marker absent until every before/after file is durable.
    let marker = stage.join("journal.json");
    if marker.try_exists()? {
        fs::remove_file(&marker)?;
    }
    for name in RING_UPDATE_FILES {
        let bytes = read(&candidate.join(name))?;
        atomic_write(&stage.join("after").join(name), &bytes)?;
        let path = root.join(name);
        checked(&path)?;
        let before = if path.try_exists()? {
            let old = read(&path)?;
            atomic_write(&stage.join("before").join(name), &old)?;
            Some(sha256(&old))
        } else {
            None
        };
        journal.files.insert(
            name.into(),
            Entry {
                before,
                after: sha256(&bytes),
            },
        );
    }
    atomic_write(&marker, &serde_json::to_vec_pretty(&journal)?)
}
/// Export a complete queued candidate into release bytes without activating it.
pub fn ring_release_overlay(root: &Path) -> Result<Bytes> {
    match RingUpdate::load(root)? {
        None => Ok(BTreeMap::new()),
        Some(update) => {
            ensure!(
                update.journal.state == State::Prepared,
                "Finish interrupted ring update before packaging"
            );
            Ok(update.after)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn locked_late_file_rolls_back_earlier_writes_without_rewriting_unchanged_files() {
        use std::os::windows::fs::OpenOptionsExt;
        let (_tmp, root, _stage) = fixture();
        let pin = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(root.join("bin/winws2.exe"))
            .unwrap();
        let mut update = RingUpdate::load(&root).unwrap().unwrap();
        assert!(update.apply().is_err());
        assert!(!root.join("bin/zapret-ring.dll").exists());
        assert_eq!(
            fs::read(root.join("bin/cygwin1.dll")).unwrap(),
            b"old bin/cygwin1.dll"
        );
        assert!(RingUpdate::load(&root).unwrap().is_none());
        drop(pin);
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let stage = root.join(RING_QUEUE);
        let mut journal = Journal {
            schema: 1,
            state: State::Prepared,
            files: BTreeMap::new(),
        };
        for name in RING_UPDATE_FILES {
            let previous =
                (name != "bin/zapret-ring.dll").then(|| format!("old {name}").into_bytes());
            let next = format!("new {name}").into_bytes();
            if let Some(bytes) = &previous {
                atomic_write(&root.join(name), bytes).unwrap();
                atomic_write(&stage.join("before").join(name), bytes).unwrap();
            }
            atomic_write(&stage.join("after").join(name), &next).unwrap();
            journal.files.insert(
                name.into(),
                Entry {
                    before: previous.as_deref().map(sha256),
                    after: sha256(&next),
                },
            );
        }
        atomic_write(
            &stage.join("journal.json"),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        (temp, root, stage)
    }
    #[test]
    fn interrupted_bundle_recovers_all_files_and_preserves_external_edits() {
        let (_tmp, root, stage) = fixture();
        let mut update = RingUpdate::load(&root).unwrap().unwrap();
        update.state(State::Applying).unwrap();
        atomic_write(
            &root.join(RING_UPDATE_FILES[0]),
            &update.after[RING_UPDATE_FILES[0]],
        )
        .unwrap();
        let mut recovered = RingUpdate::load(&root).unwrap().unwrap();
        recovered.apply().unwrap();
        recovered.rollback(true).unwrap();
        assert!(!root.join("bin/zapret-ring.dll").exists());
        assert_eq!(
            fs::read(root.join("lua/autoring.lua")).unwrap(),
            b"old lua/autoring.lua"
        );
        assert!(RingUpdate::load(&root).unwrap().is_none());
        assert!(stage.join("before/bin/winws2.exe").exists());
        let (_tmp, root, stage) = fixture();
        fs::write(stage.join("before/bin/winws2.exe"), b"corrupted").unwrap();
        assert!(RingUpdate::load(&root).is_err());
        assert_eq!(
            fs::read(root.join("bin/winws2.exe")).unwrap(),
            b"old bin/winws2.exe"
        );
        let (_tmp, root, _stage) = fixture();
        fs::write(root.join("lua/autoring.lua"), b"user edit").unwrap();
        assert!(RingUpdate::load(&root).is_err());
        assert!(!root.join("bin/zapret-ring.dll").exists());
    }
    #[test]
    fn release_overlay_is_read_only_and_commit_requires_every_new_file() {
        let (_tmp, root, _stage) = fixture();
        let overlay = ring_release_overlay(&root).unwrap();
        assert_eq!(overlay.len(), 9);
        assert!(!root.join("bin/zapret-ring.dll").exists());
        let mut update = RingUpdate::load(&root).unwrap().unwrap();
        assert!(update.commit().is_err());
        update.apply().unwrap();
        update.commit().unwrap();
        assert!(RingUpdate::load(&root).unwrap().is_none());
        assert_eq!(
            fs::read(root.join("lua/autoring.lua")).unwrap(),
            b"new lua/autoring.lua"
        );
    }
}
