use crate::process::{Handle, wide};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::Storage::FileSystem::*;

/// All existing ancestors are checked. Junctions and symbolic links are rejected.
pub(crate) fn no_reparse(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Absolute path required");
    for p in path.ancestors() {
        if p.exists() {
            let m = std::fs::symlink_metadata(p)?;
            ensure!(
                m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "Reparse point is not allowed: {}",
                p.display()
            );
        }
    }
    Ok(())
}
pub(crate) fn relative(root: &Path, value: &str) -> Result<PathBuf> {
    ensure!(!value.is_empty(), "Empty relative path");
    let normalized = value.replace('\\', "/");
    for part in normalized.split('/') {
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && !part.ends_with(['.', ' '])
                && !part.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c)),
            "Invalid relative path segment"
        );
        let stem = part.split('.').next().unwrap().to_uppercase();
        ensure!(
            ![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9"
            ]
            .contains(&stem.as_str()),
            "Reserved path segment"
        );
    }
    let p = Path::new(&normalized);
    ensure!(
        p.components().all(|c| matches!(c, Component::Normal(_))),
        "Relative package path required"
    );
    let out = root.join(p);
    no_reparse(&out)?;
    Ok(out)
}
pub(crate) fn read_limited(path: &Path, budget: u64) -> Result<Vec<u8>> {
    read_limited_with_share(path, budget, FILE_SHARE_READ)
}
/// Read mutable state while its owner retains an open write handle. This handle
/// stays read-only; the owner's share mode still denies other writers/deletion.
pub(crate) fn read_shared_limited(path: &Path, budget: u64) -> Result<Vec<u8>> {
    read_limited_with_share(path, budget, FILE_SHARE_READ | FILE_SHARE_WRITE)
}
fn read_limited_with_share(path: &Path, budget: u64, share: u32) -> Result<Vec<u8>> {
    let mut f = open_limited(path, budget, share)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(budget.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= budget,
        "File grew beyond its size budget"
    );
    Ok(bytes)
}
fn open_limited(path: &Path, budget: u64, share: u32) -> Result<File> {
    no_reparse(path)?;
    let f = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(path)
        .with_context(|| format!("Read {}", path.display()))?;
    ensure!(
        f.metadata()?.len() <= budget,
        "File exceeds size budget: {}",
        path.display()
    );
    Ok(f)
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:X}", Sha256::digest(bytes))
}
pub(crate) fn file_hash(path: &Path) -> Result<String> {
    hash_handle(&mut open_limited(path, HASH_LIMIT, FILE_SHARE_READ)?).map(|(digest, _)| digest)
}
const HASH_LIMIT: u64 = 64 * 1024 * 1024;
fn hash_handle(file: &mut File) -> Result<(String, u64)> {
    let result = zapret_core::sha256_reader(file.take(HASH_LIMIT + 1))?;
    ensure!(result.1 <= HASH_LIMIT, "File grew beyond its size budget");
    Ok(result)
}
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    no_reparse(path)?;
    let parent = path.parent().context("Output path has no parent")?;
    std::fs::create_dir_all(parent)?;
    no_reparse(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    // ReplaceFile needs delete access; close the temporary writer before publishing it.
    let tmp = tmp.into_temp_path();
    let from = wide(&tmp)?;
    let to = wide(path)?;
    let ok = unsafe {
        if path.exists() {
            ReplaceFileW(to.as_ptr(), from.as_ptr(), null(), 0, null(), null())
        } else {
            MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH)
        }
    };
    ensure!(
        ok != 0,
        "Atomic replacement {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}
/// Read leases deny writes/deletes; directory leases deny rename of leased package ancestors.
pub(crate) struct Pins {
    pub files: Vec<File>,
    pub dirs: Vec<Handle>,
}
impl Pins {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
        }
    }
    pub fn directory(&mut self, path: &Path) -> Result<()> {
        no_reparse(path)?;
        let p = wide(path)?;
        let h = Handle::new(unsafe {
            CreateFileW(
                p.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        no_reparse(path)?;
        self.dirs.push(h);
        Ok(())
    }
    pub fn file(&mut self, path: &Path) -> Result<Vec<u8>> {
        let mut f = open_limited(path, HASH_LIMIT, FILE_SHARE_READ)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(HASH_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= HASH_LIMIT,
            "File grew beyond its size budget"
        );
        self.files.push(f);
        Ok(bytes)
    }
    pub fn file_hash(&mut self, path: &Path) -> Result<(String, u64)> {
        let mut file = open_limited(path, HASH_LIMIT, FILE_SHARE_READ)?;
        let result = hash_handle(&mut file)?;
        self.files.push(file);
        Ok(result)
    }
}

#[cfg(test)]
#[test]
fn streaming_digest_keeps_the_file_pinned_and_honors_the_existing_size_limit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.bin");
    for bytes in [Vec::new(), (0..131_073).map(|i| (i % 251) as u8).collect()] {
        std::fs::write(&path, &bytes).unwrap();
        let mut pins = Pins::new();
        assert_eq!(
            pins.file_hash(&path).unwrap(),
            (hash(&bytes), bytes.len() as u64)
        );
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, temp.path().join("renamed.bin")).is_err());
    }
    File::create(&path)
        .unwrap()
        .set_len(HASH_LIMIT + 1)
        .unwrap();
    assert!(Pins::new().file_hash(&path).is_err());
}
