use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

pub struct Snapshot {
    source: PathBuf,
    storage: tempfile::TempDir,
    hashes: BTreeMap<String, String>,
    pins: Vec<(PathBuf, File)>,
    complete: bool,
}

pub fn relative_path(text: &str) -> Result<PathBuf> {
    ensure!(
        !text.is_empty() && !text.contains([':', '\\', '\0']),
        "Некорректный относительный путь"
    );
    let path = Path::new(text);
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("Путь выходит за пределы пакета")
        };
        let name = name.to_string_lossy();
        ensure!(!name.ends_with(['.', ' ']), "Неканоническое имя файла");
        let base = name.split('.').next().unwrap_or("").to_ascii_lowercase();
        ensure!(
            !matches!(base.as_str(), "con" | "prn" | "aux" | "nul")
                && !(base.len() == 4
                    && (base.starts_with("com") || base.starts_with("lpt"))
                    && base.as_bytes()[3].is_ascii_digit()),
            "Зарезервированное имя Windows"
        );
    }
    ensure!(path.components().count() <= 16, "Слишком глубокий путь");
    Ok(path.to_owned())
}

pub fn check_plain(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Недоступен {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Ссылка в пути {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "Reparse point {}",
            path.display()
        );
    }
    Ok(())
}

fn input_file(path: &Path, pin: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    if pin {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let _ = pin;
    options
        .open(path)
        .with_context(|| format!("Не удалось закрепить {}", path.display()))
}

fn pin_directory(path: &Path) -> Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        Ok(OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x02000000)
            .open(path)?)
    }
    #[cfg(not(windows))]
    Ok(File::open(path)?)
}

pub fn hash_parts(parts: &[String]) -> String {
    format!("{:X}", Sha256::digest(parts.join("\n").as_bytes()))
}

pub fn package_inputs(root: &Path) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for directory in [
        "bin",
        "fake",
        "lists",
        "lua",
        "strategies",
        "tools",
        "windivert",
    ] {
        let path = root.join(directory);
        if !path.exists() {
            continue;
        }
        collect_files(root, &path, &mut result)?;
    }
    for name in [
        "CHECKSUMS.txt",
        "runtime/settings.ini",
        "runtime/test-rank.txt",
        "runtime/test-cover.txt",
        "runtime/test-scores.txt",
        "runtime/tested-strategies.txt",
        "runtime/test-selection-cache.json",
    ] {
        if root.join(name).is_file() {
            result.push(name.into());
        }
    }
    result.sort();
    Ok(result)
}

fn collect_files(root: &Path, directory: &Path, names: &mut Vec<String>) -> Result<()> {
    check_plain(directory)?;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        check_plain(&path)?;
        if path.is_dir() {
            collect_files(root, &path, names)?;
        } else {
            let name = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            if !zapret_core::is_native_build_artifact(&name) {
                names.push(name);
            }
        }
    }
    ensure!(names.len() <= 4096, "Слишком много файлов в пакете");
    Ok(())
}

impl Snapshot {
    pub fn package(root: &Path) -> Result<Self> {
        let mut snapshot = Self::capture(root, &package_inputs(root)?, true)?;
        snapshot.complete = true;
        Ok(snapshot)
    }

    pub fn capture(root: &Path, paths: &[String], pin: bool) -> Result<Self> {
        check_plain(root)?;
        let storage = tempfile::Builder::new()
            .prefix("zapret-rust-native-run-")
            .tempdir()?;
        let mut snapshot = Self {
            source: root.to_owned(),
            storage,
            hashes: BTreeMap::new(),
            pins: Vec::new(),
            complete: false,
        };
        if pin {
            snapshot.pins.push((root.to_owned(), pin_directory(root)?));
        }
        let mut total = 0;
        for name in paths {
            let relative = relative_path(name)?;
            let source = root.join(&relative);
            let mut parent = root.to_owned();
            for part in relative.parent().into_iter().flat_map(Path::components) {
                parent.push(part);
                check_plain(&parent)?;
                if pin && !snapshot.pins.iter().any(|(path, _)| path == &parent) {
                    snapshot
                        .pins
                        .push((parent.clone(), pin_directory(&parent)?));
                }
            }
            check_plain(&source)?;
            let mut input = input_file(&source, pin)?;
            let length = input.metadata()?.len();
            total += length;
            ensure!(total <= 536870912, "Пакет превышает бюджет снимка 512 МиБ");
            let destination = snapshot.storage.path().join(&relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)?;
            let mut reader = BufReader::with_capacity(128 * 1024, (&mut input).take(length + 1));
            let copied = std::io::copy(&mut reader, &mut output)?;
            ensure!(copied == length, "Размер входа изменился во время снимка");
            output.flush()?;
            snapshot
                .hashes
                .insert(name.clone(), zapret_core::sha256_file(&destination)?);
            if pin {
                snapshot.pins.push((source, input));
            }
        }
        fs::create_dir_all(snapshot.root().join("runtime"))?;
        snapshot.assert_current()?;
        Ok(snapshot)
    }

    pub fn root(&self) -> &Path {
        self.storage.path()
    }

    pub fn fingerprint(&self) -> String {
        hash_parts(
            &self
                .hashes
                .iter()
                .map(|(name, hash)| format!("{name}={hash}"))
                .collect::<Vec<_>>(),
        )
    }

    pub fn assert_current(&self) -> Result<()> {
        if self.complete {
            ensure!(
                package_inputs(&self.source)?.iter().eq(self.hashes.keys()),
                "Состав входных файлов изменился"
            );
        }
        for (name, expected) in &self.hashes {
            let path = self.source.join(relative_path(name)?);
            check_plain(&path)?;
            ensure!(
                zapret_core::sha256_file(&path)? == *expected,
                "Изменился вход {name}"
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn pinned_source_hash(&self, path: &Path) -> Option<&str> {
        let relative = path.strip_prefix(&self.source).ok()?.to_str()?;
        // The existing handle denies write and delete sharing through validation.
        if !self.pins.iter().any(|(source, _)| source == path) {
            return None;
        }
        self.hashes
            .get(&relative.replace('\\', "/"))
            .map(String::as_str)
    }

    pub fn release_state_pins(&mut self) {
        self.pins
            .retain(|(path, _)| !path.starts_with(self.source.join("runtime")));
    }
}

#[cfg(test)]
pub(crate) fn write_builtin_manifest_fixture(root: &Path) {
    use std::fmt::Write as _;

    let schema = zapret_core::RUST_LUA_SCHEMA;
    let digest = "a".repeat(64);
    let mut manifest = format!(
        "schema={schema}\ntag=v1.0.6\ncommit={}\narchive-sha256={digest}\n",
        "a".repeat(40)
    );
    for name in zapret_core::CORE_FILES {
        if !zapret_core::omits_engine_file(schema, name) {
            writeln!(manifest, "{name}={digest}").unwrap();
        }
    }
    fs::create_dir_all(root.join("tools")).unwrap();
    fs::write(root.join("tools/upstream.txt"), manifest).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn strategy_context_accepts_a_builtin_package_snapshot_without_a_lua_directory() {
        let source = tempfile::tempdir().unwrap();
        let root = source.path();
        write_builtin_manifest_fixture(root);
        fs::create_dir(root.join("lua")).unwrap();
        for name in [
            "bin/zapret-rust.exe",
            "fake/sample.bin",
            "lists/sample.txt",
            "strategies/alt12.txt",
            "windivert/quic_initial_ietf.txt",
            "tools/targets.txt",
            "tools/dpi-suite.json",
            "CHECKSUMS.txt",
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, name).unwrap();
        }
        let snapshot = Snapshot::package(root).unwrap();
        assert!(!snapshot.root().join("lua").exists());
        let context = zapret_core::test_result_context_with_identity(
            snapshot.root(),
            &zapret_core::Settings::default(),
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .unwrap();
        assert!(context.valid());
    }

    #[test]
    fn old_native_build_images_are_not_copied_or_leased_as_test_inputs() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("bin")).unwrap();
        fs::write(source.path().join("bin/winws2.exe"), b"engine fixture").unwrap();
        let leftover = source
            .path()
            .join("bin/.native-build-0123456789abcdef0123456789abcdef.tmp.old");
        fs::write(&leftover, b"previous controller").unwrap();
        assert_eq!(package_inputs(source.path()).unwrap(), ["bin/winws2.exe"]);
        let snapshot = Snapshot::package(source.path()).unwrap();
        assert!(
            !snapshot
                .root()
                .join("bin/.native-build-0123456789abcdef0123456789abcdef.tmp.old")
                .exists()
        );
        fs::write(&leftover, b"released previous controller").unwrap();
        snapshot.assert_current().unwrap();
        assert_eq!(
            fs::read(snapshot.root().join("bin/winws2.exe")).unwrap(),
            b"engine fixture"
        );
    }

    #[test]
    fn frozen_inputs_are_copied_and_mutation_is_detected() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("strategies")).unwrap();
        fs::write(source.path().join("strategies/alt12.txt"), "original").unwrap();
        let snapshot =
            Snapshot::capture(source.path(), &["strategies/alt12.txt".into()], false).unwrap();
        assert_eq!(
            fs::read_to_string(snapshot.root().join("strategies/alt12.txt")).unwrap(),
            "original"
        );
        fs::write(source.path().join("strategies/alt12.txt"), "changed").unwrap();
        assert!(snapshot.assert_current().is_err());
        assert_eq!(
            fs::read_to_string(snapshot.root().join("strategies/alt12.txt")).unwrap(),
            "original"
        );
    }

    #[cfg(windows)]
    #[test]
    fn released_state_still_checks_same_size_changes_and_loses_pinned_hash() {
        let source = tempfile::tempdir().unwrap();
        let root = source.path();
        fs::create_dir(root.join("runtime")).unwrap();
        let settings = root.join("runtime/settings.ini");
        fs::write(&settings, b"alt=12").unwrap();
        let mut snapshot = Snapshot::package(root).unwrap();

        assert_eq!(
            snapshot.pinned_source_hash(&settings),
            Some(zapret_core::sha256(b"alt=12").as_str())
        );
        assert!(fs::write(&settings, b"alt=42").is_err());
        snapshot.release_state_pins();
        assert!(snapshot.pinned_source_hash(&settings).is_none());
        fs::write(&settings, b"alt=42").unwrap();
        assert!(snapshot.assert_current().is_err());
    }

    #[test]
    fn relative_paths_cannot_escape_the_package() {
        let source = tempfile::tempdir().unwrap();
        for input in [
            "../outside",
            "/absolute",
            "C:/Windows/win.ini",
            "bin/../outside",
        ] {
            assert!(
                Snapshot::capture(source.path(), &[input.into()], false).is_err(),
                "{input}"
            );
        }
    }
}
