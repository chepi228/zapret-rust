//! Package ACLs and Mark-of-the-Web removal use bounded inventories before mutation.
use crate::storage::no_reparse;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError},
    Storage::FileSystem::DeleteFileW,
};

const DIRECTORIES: &[&str] = &["bin", "lua", "tools", "strategies", "fake", "windivert"];
fn inventory(path: &Path, depth: usize, output: &mut Vec<PathBuf>) -> Result<()> {
    no_reparse(path)?;
    ensure!(
        depth <= 32 && output.len() < 16384,
        "Package inventory exceeds depth or entry budget"
    );
    output.push(path.into());
    if path.is_dir() {
        let mut children = std::fs::read_dir(path)?
            .map(|entry| Ok(entry?.path()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            children.len() <= 16384 - output.len(),
            "Package directory exceeds entry budget"
        );
        children.sort();
        for child in children {
            inventory(&child, depth + 1, output)?;
        }
    }
    Ok(())
}
fn code_paths(root: &Path) -> Result<Vec<PathBuf>> {
    no_reparse(root)?;
    ensure!(root.is_dir(), "Package root is unavailable");
    let mut paths = Vec::new();
    for name in DIRECTORIES {
        let path = root.join(name);
        if path.exists() {
            ensure!(path.is_dir(), "Expected package code directory: {name}");
            inventory(&path, 0, &mut paths)?;
        }
    }
    let launcher = root.join("zapret-rust.bat");
    if launcher.exists() {
        no_reparse(&launcher)?;
        ensure!(launcher.is_file(), "Package launcher is not a file");
        paths.push(launcher);
    }
    Ok(paths)
}
fn unblock(path: &Path) -> Result<bool> {
    no_reparse(path)?;
    ensure!(
        path.is_file(),
        "Only regular package files can have download markers removed"
    );
    let mut name = path.as_os_str().encode_wide().collect::<Vec<_>>();
    name.extend(":Zone.Identifier".encode_utf16());
    name.push(0);
    if unsafe { DeleteFileW(name.as_ptr()) } != 0 {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    ensure!(
        error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND,
        "Remove package download marker: Windows error {error}"
    );
    Ok(false)
}
pub(crate) fn dispatch(root: &Path, action: &str) -> Result<Value> {
    no_reparse(root)?;
    if root.join("dev").exists() || root.join(".git").exists() {
        return Ok(json!({"known":true,"skipped":true,"reason":"DeveloperCheckout","changed":0}));
    }
    let _guard = crate::ControlGuard::acquire(root, action)?;
    // No protected file or ACL changes before the complete inventory passes validation.
    let paths = if action == "unblock-package" {
        let mut paths = Vec::new();
        inventory(root, 0, &mut paths)?;
        paths
    } else {
        code_paths(root)?
    };
    let mut changed = 0;
    let mut errors = Vec::new();
    for path in paths {
        let result = match action {
            "protect-package" => crate::protect_readable_path(&path).map(|_| true),
            "unprotect-package" => crate::control::unprotect(&path).map(|_| true),
            "unblock-package" if path.is_file() => unblock(&path),
            "unblock-package" => Ok(false),
            _ => anyhow::bail!("Unsupported package maintenance action"),
        };
        match result {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(error) => errors.push(json!({"path":path,"error":format!("{error:#}")})),
        }
    }
    Ok(
        json!({"known":errors.is_empty(),"skipped":false,"action":action,"changed":changed,"errors":errors}),
    )
}
pub(crate) fn require_protected(root: &Path) -> Result<()> {
    let state = dispatch(root, "protect-package")?;
    ensure!(
        state["known"] == true,
        "Package code permissions could not be protected: {state}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn developer_checkout_protection_is_a_noop_and_inventory_excludes_user_data() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("dev")).unwrap();
        let result = dispatch(root.path(), "protect-package").unwrap();
        assert_eq!(result["skipped"], true);
        std::fs::remove_dir(root.path().join("dev")).unwrap();
        for name in ["bin", "lua", "runtime", "lists"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }
        std::fs::write(root.path().join("bin/zapret-rust.exe"), b"fixture").unwrap();
        std::fs::write(root.path().join("zapret-rust.bat"), b"fixture").unwrap();
        let paths = code_paths(root.path()).unwrap();
        assert!(paths.contains(&root.path().join("bin/zapret-rust.exe")));
        assert!(paths.contains(&root.path().join("zapret-rust.bat")));
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with(root.path().join("runtime"))
                    || path.starts_with(root.path().join("lists")))
        );
    }
    #[test]
    fn removing_fixture_download_stream_keeps_the_base_file_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file.exe");
        std::fs::write(&path, b"fixture file").unwrap();
        let mut stream = path.as_os_str().to_os_string();
        stream.push(":Zone.Identifier");
        std::fs::write(&stream, b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
        assert!(unblock(&path).unwrap());
        assert!(!unblock(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"fixture file");
        assert!(!Path::new(&stream).exists());
    }
    #[test]
    fn invalid_code_directory_aborts_before_any_permission_change() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("bin"), b"not a directory").unwrap();
        assert!(dispatch(root.path(), "protect-package").is_err());
        assert_eq!(
            std::fs::read(root.path().join("bin")).unwrap(),
            b"not a directory"
        );
    }
}
