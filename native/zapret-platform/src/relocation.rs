//! Recover registrations after moving a package with its protected runtime proof.
use crate::{
    process::same_path,
    storage::{atomic_write, no_reparse, read_limited},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct RootRecord {
    schema: u32,
    root: PathBuf,
}

fn directory(root: &Path) -> PathBuf {
    root.join("runtime/installation")
}

fn read_previous(root: &Path) -> Result<Option<PathBuf>> {
    for path in [
        directory(root).join("root.json"),
        root.join("runtime/launch-state/confirmed-native.json"),
    ] {
        if !path.try_exists()? {
            continue;
        }
        no_reparse(&path)?;
        ensure!(
            crate::trusted_path(path.parent().unwrap())? && crate::trusted_path(&path)?,
            "Данные прежней установки не защищены; перенос отменён"
        );
        let record: RootRecord = serde_json::from_slice(&read_limited(&path, 16384)?)?;
        ensure!(
            record.schema == 1 && record.root.is_absolute(),
            "Некорректный путь прежней установки"
        );
        return Ok((!same_path(root, &record.root)).then_some(record.root));
    }
    Ok(None)
}

fn write_protected(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let dir = directory(root);
    no_reparse(&dir)?;
    std::fs::create_dir_all(&dir)?;
    crate::protect_path(&dir)?;
    let path = dir.join(name);
    if path.try_exists()? {
        ensure!(
            crate::trusted_path(&path)?,
            "Файл переноса установки не защищён"
        );
    }
    atomic_write(&path, bytes)?;
    crate::protect_path(&path)
}

pub(crate) fn backup_task(root: &Path, kind: &str, xml: &str) -> Result<()> {
    ensure!(
        ["autotune", "notify", "telegram", "watch"].contains(&kind),
        "Unknown relocated task"
    );
    write_protected(root, &format!("previous-{kind}.xml"), xml.as_bytes())
}

pub(crate) fn rewrite_paths(value: &str, previous: &Path, root: &Path) -> String {
    let previous = previous.to_string_lossy();
    let replacement = root.to_string_lossy();
    let prefixes = std::collections::BTreeSet::from([
        previous.to_string(),
        previous.replace('\\', "/"),
        previous.replace('/', "\\"),
    ]);
    let mut result = value.to_owned();
    for prefix in prefixes {
        let mut offset = 0;
        while let Some(found) = result[offset..]
            .to_ascii_lowercase()
            .find(&prefix.to_ascii_lowercase())
        {
            let start = offset + found;
            let end = start + prefix.len();
            let boundary = end == result.len()
                || result[end..].starts_with(['/', '\\', '"', '\'', '<', ' ', '\r', '\n']);
            if boundary {
                result.replace_range(start..end, &replacement);
                offset = start + replacement.len();
            } else {
                offset = end;
            }
        }
    }
    result
}

fn validate_previous(previous: &Path) -> Result<()> {
    no_reparse(previous)?;
    ensure!(
        !previous.try_exists()?,
        "Прежняя папка zapret-rust ещё существует. Автоматический перенос другой установки отменён"
    );
    Ok(())
}

/// The caller holds ControlGuard and has already checked game/update guards.
pub(crate) fn recover(root: &Path) -> Result<()> {
    crate::package::require_protected(root)?;
    if let Some(previous) = read_previous(root)? {
        validate_previous(&previous)?;
        let manifest = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
        ensure!(
            zapret_core::verify_integrity(root, &manifest)?.is_empty(),
            "Файлы перенесённого движка повреждены"
        );
        crate::service::relocate(root, &previous)?;
        for kind in ["telegram", "watch", "notify", "autotune"] {
            crate::tasks::relocate(root, &previous, kind)?;
        }
    }
    // Commit only after all repairs succeeded, so a partial repair can resume.
    write_protected(
        root,
        "root.json",
        &serde_json::to_vec(&RootRecord {
            schema: 1,
            root: root.into(),
        })?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copying_a_package_cannot_take_over_another_existing_installation() {
        let base = tempfile::tempdir().unwrap();
        let previous = base.path().join("original");
        std::fs::create_dir(&previous).unwrap();
        assert!(validate_previous(&previous).is_err());
        std::fs::remove_dir(&previous).unwrap();
        assert!(validate_previous(&previous).is_ok());
    }

    #[test]
    fn relocation_rewrites_only_complete_package_path_prefixes() {
        let old = Path::new("C:/old");
        let new = Path::new("C:/moved package");
        assert_eq!(
            rewrite_paths("--lua-init=@c:/old/lua/lib.lua", old, new),
            "--lua-init=@C:/moved package/lua/lib.lua"
        );
        assert_eq!(
            rewrite_paths("C:\\old\\bin\\winws2.exe", old, new),
            "C:/moved package\\bin\\winws2.exe"
        );
        assert_eq!(
            rewrite_paths("--file=C:/old-copy/a", old, new),
            "--file=C:/old-copy/a"
        );
        assert_eq!(
            rewrite_paths("<x>C:/old</x>", old, new),
            "<x>C:/moved package</x>"
        );
    }

    #[test]
    fn launch_confirmation_proof_can_be_read_without_treating_other_fields_as_new_authority() {
        let proof: RootRecord =
            serde_json::from_value(serde_json::json!({"schema":1,"root":"C:/previous",
            "version":"2.2","config_hash":"old hash","settings":{"alt":"57"}}))
            .unwrap();
        assert_eq!(proof.schema, 1);
        assert!(same_path(&proof.root, Path::new("C:/previous")));
        assert!(serde_json::from_value::<RootRecord>(serde_json::json!({"schema":1})).is_err());
    }
}
