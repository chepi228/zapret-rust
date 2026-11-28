//! Bounded package handling and crash-recoverable schema-1 file transactions.
use crate::App;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zapret_core::{
    CYGWIN_DLL, CoreManifest, NATIVE_ONLY_SCHEMA, RingManifest, atomic_write,
    mentions_posix_runtime, parse_core_manifest, read_bounded, read_text, sha256, sha256_file,
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const MAX_ARCHIVE: u64 = 128 * 1024 * 1024;
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;
const MAX_FILE: u64 = 96 * 1024 * 1024;
const MAX_ENTRIES: usize = 500;
const CATALOG: &str = "package-manifest.json";
const PACKAGE_FILES: &str = include_str!("../../../dev/native-package-files.txt");
mod download;

pub fn recover(root: &Path) -> Result<Value> {
    let trust = SystemTrust;
    let mut pending = Vec::new();
    for path in journal_paths(root)? {
        let journal = read_journal(root, &path, &trust)?;
        if ["Prepared", "Applying"].contains(&journal.state.as_str()) {
            pending.push((path, journal));
        }
    }
    ensure!(
        pending.len() <= 1,
        "Несколько незавершённых обновлений; автоматическое восстановление остановлено"
    );
    if pending.is_empty() {
        return Ok(json!({"recovered":false}));
    }
    let _guard = zapret_platform::ControlGuard::acquire(root, "update-recovery")?;
    let status = zapret_platform::command(root, "status", &json!({}))?;
    let running = confirmed_running(&status)?;
    recover_pending(root, &pending, running, &trust)
}
fn recover_pending(
    root: &Path,
    pending: &[(PathBuf, Journal)],
    running: bool,
    trust: &impl StateTrust,
) -> Result<Value> {
    let mut restored = Vec::new();
    let mut restart_required = false;
    for (path, _) in pending {
        let journal = read_journal(root, path, trust)?;
        ensure!(
            journal.state != "Applying" || !running,
            "Обход работает; восстановление файлов отложено до его остановки"
        );
        if restore_journal(root, path, trust)? {
            // An Applying recovery can replace the currently mapped executable.
            // A new process must load the restored package before more control work.
            restart_required |= journal.state == "Applying";
            restored.push(journal.id);
        }
        if running {
            trusted_write(
                &checked_path(root, "runtime/update-restart.txt")?,
                b"",
                trust,
            )?;
        }
    }
    let mut outcome = json!({"recovered":!restored.is_empty(),"transactions":restored,"restart_required":restart_required,"restart_intent":read_text(&root.join("runtime/update-restart.txt"),64).unwrap_or_default().trim()=="start"});
    if restart_required {
        outcome["text"] = json!(
            "Прежние файлы восстановлены. Откройте zapret-rust заново, чтобы загрузить восстановленную программу."
        );
    }
    Ok(outcome)
}
pub fn update(
    app: &App,
    install: bool,
    from: Option<&Path>,
    expected_sha256: Option<&str>,
) -> Result<Value> {
    let work = tempfile::tempdir()?;
    let ((archive_bytes, digest), expected_tag) = if let Some(path) = from {
        let archive = std::path::absolute(path)?;
        no_reparse(&archive)?;
        (
            download::verified_archive(read_bounded(&archive, MAX_ARCHIVE)?, expected_sha256)?,
            None,
        )
    } else {
        let (route, (tag, release)) = download::latest()?;
        let Some(release) = release else {
            ensure!(
                !install,
                "В последнем релизе ещё нет проверяемого native архива"
            );
            return Ok(
                json!({"available":false,"latest_tag":tag,"text":"В последнем релизе ещё нет native архива."}),
            );
        };
        let available = version_newer(&release.tag, &format!("v{}", crate::VERSION));
        if !install {
            return Ok(json!({"available":available,"release":release,"current":crate::VERSION}));
        }
        ensure!(
            available,
            "Уже установлена эта или более новая версия zapret-rust"
        );
        (download::archive(&release, route)?, Some(release.tag))
    };
    // Keep a complete inspected copy. No executable from TEMP is ever run.
    let inspected = work.path().join("inspected.zip");
    atomic_write(&inspected, &archive_bytes)?;
    let preview = work.path().join("preview");
    let names = extract_archive(&inspected, &preview)?;
    let (manifest, core) = validate_package(&preview, &names, expected_tag.as_deref())?;
    let (preview_plan, preview_remove) =
        update_plan(&preview, &app.root, core.schema >= NATIVE_ONLY_SCHEMA)?;
    if !install {
        return Ok(
            json!({"installable":true,"version":manifest.version,"sha256":digest,"replace":preview_plan,"remove":preview_remove}),
        );
    }
    if !app.confirm(&format!(
        "Установить zapret-rust {}? Файлов для замены: {}, для удаления: {}. SHA256 {}",
        manifest.version,
        preview_plan.len(),
        preview_remove.len(),
        digest
    ))? {
        return Ok(json!({"cancelled":true}));
    }
    let _guard = zapret_platform::ControlGuard::acquire(&app.root, "update-install")?;
    let recovery = recover(&app.root)?;
    if recovery["restart_required"] == true {
        return Ok(recovery);
    }
    app.game_check("Обновление временно остановит обход")?;
    let trust = SystemTrust;
    let directory = new_transaction_directory(&app.root, &trust)?;
    trusted_write(&directory.join("archive.zip"), &archive_bytes, &trust)?;
    ensure!(
        file_hash(&directory.join("archive.zip"))? == digest,
        "Archive identity changed while staging"
    );
    let source = directory.join("source");
    trusted_directory(&source, &trust)?;
    let names = extract_archive(&directory.join("archive.zip"), &source)?;
    protect_tree(&source, &trust)?;
    let (installed_manifest, core) = validate_package(&source, &names, expected_tag.as_deref())?;
    ensure!(
        installed_manifest.version == manifest.version,
        "Staged package version changed"
    );
    let (plan, remove) = update_plan(&source, &app.root, core.schema >= NATIVE_ONLY_SCHEMA)?;
    protect_tree(&source, &trust)?;
    let status = app.platform("status", json!({}))?;
    let was_running = confirmed_running(&status)?;
    // Keep a launchable native recovery entry before a mapped main image can
    // be renamed. The public launcher uses this copy if an interrupted update
    // temporarily leaves bin/zapret-rust.exe absent.
    stage_recovery_image(&app.root, &std::env::current_exe()?, &trust)?;
    let mut journal = prepare_transaction(
        &source,
        &app.root,
        &directory,
        &plan,
        &remove,
        was_running,
        &trust,
    )?;
    let result = (|| -> Result<()> {
        if was_running {
            app.platform(
                "stop",
                json!({"unload":true,"game_approved":true,"allow_pending_update":true}),
            )?;
            ensure!(
                !confirmed_running(&app.platform("status", json!({}))?)?,
                "Обход не остановлен; файлы не заменены"
            );
        }
        apply_prepared(&app.root, &source, &directory, &mut journal, &trust)
    })();
    if let Err(error) = result {
        let live = match app
            .platform("status", json!({}))
            .and_then(|status| confirmed_running(&status))
        {
            Ok(live) => live,
            Err(unknown) => {
                return Err(error.context(format!(
                    "Состояние обхода неизвестно; откат отложен: {unknown:#}. Копии: {}",
                    directory.display()
                )));
            }
        };
        if journal.state == "Applying" && live {
            return Err(error.context(format!(
                "Откат отложен: обход работает. Резервные копии: {}",
                directory.display()
            )));
        }
        let restored = restore_journal(&app.root, &directory.join("journal.json"), &trust);
        if let Err(rollback) = restored {
            return Err(error.context(format!(
                "Автоматический откат остановлен: {rollback:#}. Копии: {}",
                directory.display()
            )));
        }
        if was_running && !live {
            let restart = app.platform("start", json!({"game_approved":true}));
            if let Err(restart) = restart {
                return Err(error.context(format!(
                    "Файлы восстановлены; запуск прежнего обхода: {restart:#}"
                )));
            }
        }
        if live {
            trusted_write(&app.root.join("runtime/update-restart.txt"), b"", &trust)?;
        }
        return Err(error.context("Файлы обновления возвращены к прежнему состоянию"));
    }
    Ok(
        json!({"installed":true,"version":manifest.version,"sha256":digest,"replaced":plan.len(),"retired":remove,"restart_required":true,"was_running":was_running,"journal":directory.join("journal.json"),"text":format!("Обновлено до zapret-rust {}. Перезапустите меню, чтобы использовать новую программу.",manifest.version)}),
    )
}
pub fn package(root: &Path, output: &Path, compatibility: bool) -> Result<Value> {
    let bad = zapret_core::verify_package(root)?;
    ensure!(bad.is_empty(), "Повреждено ядро: {}", bad.join(", "));
    zapret_core::verify_telegram(root)?;
    let ring_overlay = zapret_core::ring_release_overlay(root)?;
    let core = if let Some(bytes) = ring_overlay.get("tools/upstream.txt") {
        parse_core_manifest(bytes)?
    } else {
        zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?
    };
    ensure!(
        !compatibility || core.schema == 1,
        "The compatibility ZIP needs a schema-1 build candidate with its pinned Cygwin DLL"
    );
    let mut inputs = BTreeMap::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    for name in PACKAGE_FILES
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
    {
        normalized_relative(name)?;
        ensure!(
            allowed_package_path(name) && seen.insert(name.to_ascii_lowercase()),
            "Invalid native package manifest entry: {name}"
        );
        if zapret_core::omits_engine_file(core.schema, name) {
            continue;
        }
        if ["bin/zapret-ring.dll", "tools/rust-ring.json"].contains(&name)
            && !root.join(name).is_file()
            && !ring_overlay.contains_key(name)
        {
            continue;
        }
        let bytes = if let Some(bytes) = ring_overlay.get(name) {
            bytes.clone()
        } else {
            match name {
                "lists/list-general-user.txt" => {
                    include_bytes!("../../../dev/package-defaults/lists/list-general-user.txt")
                        .to_vec()
                }
                "lists/list-exclude-user.txt" => {
                    include_bytes!("../../../dev/package-defaults/lists/list-exclude-user.txt")
                        .to_vec()
                }
                "lists/ipset-user.txt" => {
                    include_bytes!("../../../dev/package-defaults/lists/ipset-user.txt").to_vec()
                }
                "lists/ipset-exclude-user.txt" => {
                    include_bytes!("../../../dev/package-defaults/lists/ipset-exclude-user.txt")
                        .to_vec()
                }
                "bin/zapret-rust-recovery.exe" => {
                    let main = checked_path(root, "bin/zapret-rust.exe")?;
                    let executable = if main.is_file() {
                        main
                    } else {
                        std::env::current_exe()?
                    };
                    read_bounded(&executable, MAX_FILE)?
                }
                "bin/zapret-rust.exe" if !root.join(name).is_file() => {
                    read_bounded(&std::env::current_exe()?, MAX_FILE)?
                }
                _ => read_bounded(&checked_path(root, name)?, MAX_FILE)?,
            }
        };
        total = total
            .checked_add(bytes.len() as u64)
            .context("Package size overflow")?;
        ensure!(total <= MAX_UNPACKED, "Native package size limit exceeded");
        inputs.insert(name.to_owned(), bytes);
    }
    let native_only = core.schema >= NATIVE_ONLY_SCHEMA
        || (!compatibility
            && inputs.contains_key("tools/rust-ring.json")
            && !mentions_posix_runtime(&inputs["bin/winws2.exe"]));
    if native_only && core.schema == 1 {
        omit_cygwin(&mut inputs, &core)?;
    }
    let bytes = build_archive(&inputs)?;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "Native ZIP exceeds size budget"
    );
    let inspection = tempfile::tempdir()?;
    let staged = inspection.path().join("native.zip");
    atomic_write(&staged, &bytes)?;
    let source = inspection.path().join("package");
    let names = extract_archive(&staged, &source)?;
    let (manifest, core) = validate_package(&source, &names, None)?;
    let output = std::path::absolute(output)?;
    let output = if output
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
    {
        output
    } else if compatibility {
        output.join(format!(
            "zapret-rust-native-v{}-transition.zip",
            crate::VERSION
        ))
    } else {
        output.join(format!("zapret-rust-native-v{}.zip", crate::VERSION))
    };
    no_reparse(&output)?;
    atomic_write(&output, &bytes)?;
    let digest = sha256(&bytes);
    Ok(
        json!({"output":output,"sha256":digest,"files":names.len()+1,"version":manifest.version,"bytes":bytes.len(),"includes_cygwin":core.schema==1,"text":format!("Готово: {} (SHA256 {})",output.display(),digest)}),
    )
}

fn omit_cygwin(inputs: &mut BTreeMap<String, Vec<u8>>, core: &CoreManifest) -> Result<()> {
    let mut ring: RingManifest = serde_json::from_slice(&inputs["tools/rust-ring.json"])?;
    ensure!(ring.schema == 1, "Expected a compatible ring manifest");
    ring.schema = NATIVE_ONLY_SCHEMA;
    ring.hashes
        .remove(CYGWIN_DLL)
        .context("Missing Cygwin ring pin")?;
    inputs.insert(
        "tools/rust-ring.json".into(),
        serde_json::to_vec_pretty(&ring)?,
    );
    let mut manifest = String::new();
    for line in std::str::from_utf8(&inputs["tools/upstream.txt"])?.lines() {
        match line.trim_matches(' ').split_once('=') {
            Some((CYGWIN_DLL, _)) => continue,
            Some(("schema", "1")) => manifest.push_str("schema=2"),
            _ => manifest.push_str(line),
        }
        manifest.push('\n');
    }
    inputs.insert("tools/upstream.txt".into(), manifest.into_bytes());
    let sums = std::str::from_utf8(&inputs["CHECKSUMS.txt"])?;
    let removed = format!("{}  cygwin1.dll", core.hashes[CYGWIN_DLL]);
    let sums = sums
        .lines()
        .filter(|line| !line.eq_ignore_ascii_case(&removed))
        .collect::<Vec<_>>()
        .join("\n");
    inputs.insert("CHECKSUMS.txt".into(), format!("{sums}\n").into_bytes());
    inputs
        .remove(CYGWIN_DLL)
        .context("Missing pinned Cygwin file")?;
    inputs.remove("licenses/LICENSE-cygwin.txt");
    Ok(())
}
fn no_reparse(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Reparse update path: {}",
                    ancestor.display()
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "Reparse update path: {}",
                        ancestor.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn normalized_relative(relative: &str) -> Result<String> {
    ensure!(
        !relative.is_empty() && relative.len() <= 2048,
        "Invalid update path length"
    );
    let relative = relative.replace('\\', "/");
    for segment in relative.split('/') {
        let lower = segment.to_ascii_lowercase();
        let stem = lower.split('.').next().unwrap_or("");
        let reserved = ["con", "prn", "aux", "nul"].contains(&stem)
            || ["com", "lpt"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&suffix)
                })
            });
        ensure!(
            !segment.is_empty()
                && !segment.starts_with('.')
                && !segment.ends_with(['.', ' '])
                && !reserved
                && !segment
                    .chars()
                    .any(|c| c.is_control() || "<>:\"|?*".contains(c)),
            "Invalid Windows update path: {relative}"
        );
    }
    Ok(relative)
}
fn checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = normalized_relative(relative)?;
    let root = std::path::absolute(root)?;
    let target = relative
        .split('/')
        .fold(root.clone(), |path, part| path.join(part));
    ensure!(
        target.starts_with(&root) && target != root,
        "Update path escapes package"
    );
    no_reparse(&target)?;
    Ok(target)
}
fn walk_files(root: &Path) -> Result<Vec<String>> {
    no_reparse(root)?;
    let mut result = Vec::new();
    let mut queue = vec![root.to_owned()];
    while let Some(dir) = queue.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            no_reparse(&path)?;
            if entry.file_type()?.is_dir() {
                queue.push(path);
            } else {
                ensure!(entry.file_type()?.is_file(), "Unexpected update file type");
                let relative = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                normalized_relative(&relative)?;
                result.push(relative);
            }
            ensure!(result.len() <= MAX_ENTRIES, "Too many package files");
        }
    }
    result.sort();
    Ok(result)
}
/// Extract regular files ourselves: ZIP attributes can never create links or devices.
/// Validate the complete catalog before the first staged write; CRC is checked while consuming every file.
fn extract_archive(archive: &Path, destination: &Path) -> Result<Vec<String>> {
    no_reparse(archive)?;
    ensure!(
        archive.metadata()?.is_file() && archive.metadata()?.len() <= MAX_ARCHIVE,
        "Oversized archive"
    );
    let mut zip = ZipArchive::new(File::open(archive)?)?;
    ensure!(
        !zip.is_empty() && zip.len() <= MAX_ENTRIES + 32,
        "Invalid ZIP entry count"
    );
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        ensure!(
            !entry.encrypted() && !entry.is_symlink(),
            "Encrypted or linked ZIP entry"
        );
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            ensure!(
                kind == 0 || kind == 0o100000 || kind == 0o040000,
                "Special ZIP file type"
            );
        }
        let raw = std::str::from_utf8(entry.name_raw()).context("ZIP name is not UTF-8")?;
        ensure!(
            !raw.contains('\\') && !raw.contains('\0'),
            "Noncanonical ZIP path"
        );
        let name = raw
            .strip_prefix("zapret-rust/")
            .context("ZIP must contain one zapret-rust/ package")?;
        if name.is_empty() {
            ensure!(entry.is_dir(), "Invalid ZIP root entry");
            continue;
        }
        let name = name.trim_end_matches('/');
        if name == "runtime/.keep" {
            ensure!(
                !entry.is_dir() && entry.size() == 0 && seen.insert(name.to_ascii_lowercase()),
                "Invalid or duplicate runtime placeholder"
            );
            continue;
        }
        let name = normalized_relative(name)?;
        checked_path(destination, &name)?;
        ensure!(
            seen.insert(name.to_lowercase()),
            "Case-alias or duplicate ZIP path"
        );
        if entry.is_dir() {
            ensure!(entry.size() == 0, "Directory ZIP entry has data");
            continue;
        }
        ensure!(entry.size() <= MAX_FILE, "ZIP file exceeds size budget");
        total = total
            .checked_add(entry.size())
            .context("ZIP size overflow")?;
        ensure!(total <= MAX_UNPACKED, "ZIP exceeds total size budget");
        ensure!(
            entry.size() < 1024 * 1024 || entry.size() <= entry.compressed_size().max(1) * 1000,
            "ZIP compression ratio exceeds budget"
        );
        files.push((index, name, entry.size()));
        ensure!(files.len() <= MAX_ENTRIES, "Too many ZIP files");
    }
    fs::create_dir_all(destination)?;
    let mut names = Vec::new();
    for (index, name, expected) in files {
        let mut entry = zip.by_index(index)?;
        let mut bytes = Vec::new();
        entry.by_ref().take(expected + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == expected,
            "Incomplete ZIP entry: {name}"
        );
        // Read through EOF even at the exact declared size to force the CRC verifier.
        let mut tail = [0u8; 1];
        ensure!(
            entry.read(&mut tail)? == 0,
            "ZIP entry exceeds declared length"
        );
        atomic_write(&checked_path(destination, &name)?, &bytes)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}
fn preserved_list(relative: &str) -> bool {
    let Some(name) = relative.strip_prefix("lists/") else {
        return false;
    };
    name.ends_with("-user.txt")
        || [
            "autohostlist.txt",
            "ipset-all.txt",
            "ipset-exclude.txt",
            "list-general.txt",
            "list-google.txt",
            "list-exclude.txt",
            "hosts-flowseal.txt",
        ]
        .contains(&name)
}

fn license_name(name: &str) -> bool {
    !name.contains('/')
        && (matches!(name, "LICENSE" | "THIRD-PARTY-NOTICES.md")
            || (name.starts_with("LICENSE-") && name.ends_with(".txt")))
}

fn installed_license_hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = checked_path(root, CATALOG)?;
    // Older or incomplete installations may have no readable catalog. Only
    // catalog-owned, byte-identical originals can be retired automatically.
    let catalog = read_bounded(&path, 1024 * 1024)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<PackageManifest>(&bytes).ok());
    let mut hashes = BTreeMap::new();
    if let Some(catalog) = catalog.filter(|catalog| catalog.schema == 1) {
        for path in PACKAGE_FILES.lines() {
            let Some(leaf) = path.strip_prefix("licenses/") else {
                continue;
            };
            for name in [path, leaf] {
                if let Some(hash) = catalog.files.get(name) {
                    hashes.insert(name.to_owned(), hash.clone());
                }
            }
        }
    }
    Ok(hashes)
}

fn update_plan(
    source: &Path,
    root: &Path,
    native_only: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut plan = Vec::new();
    for relative in walk_files(source)? {
        if relative.starts_with("runtime/") {
            continue;
        }
        let target = checked_path(root, &relative)?;
        if target.exists() && preserved_list(&relative) {
            continue;
        }
        if !target.exists() || sha256_file(&source.join(&relative))? != sha256_file(&target)? {
            plan.push(relative);
        }
    }
    let mut remove = Vec::new();
    if source.join("zapret-rust.exe").is_file() && !source.join("zapret-rust.bat").exists() {
        let old = checked_path(root, "zapret-rust.bat")?;
        if old.is_file() && file_hash(&old)? == STOCK_BATCH_SHA256 {
            remove.push("zapret-rust.bat".into());
        }
    }
    for (name, hash) in installed_license_hashes(root)? {
        let original = checked_path(root, &name)?;
        if !source.join(&name).exists()
            && original.is_file()
            && file_hash(&original)?.eq_ignore_ascii_case(&hash)
        {
            remove.push(name);
        }
    }
    if native_only {
        let old = checked_path(root, CYGWIN_DLL)?;
        let installed = checked_path(root, "tools/upstream.txt")?;
        // Retire only the DLL owned by the previous package. A stray or edited
        // file can remain on disk without being given a pin in the new package.
        if old.is_file()
            && zapret_core::read_core_manifest(&installed).is_ok_and(|manifest| {
                manifest.hashes.get(CYGWIN_DLL).is_some_and(|expected| {
                    file_hash(&old).is_ok_and(|hash| hash.eq_ignore_ascii_case(expected))
                })
            })
        {
            remove.push(CYGWIN_DLL.into());
        }
    }
    let retired = source.join("strategies/retired.txt");
    if retired.exists() {
        for name in zapret_core::list_lines(&retired)? {
            let lower = name.to_ascii_lowercase();
            let Some(id) = lower
                .strip_prefix("alt")
                .and_then(|n| n.strip_suffix(".txt"))
            else {
                continue;
            };
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let relative = format!("strategies/{lower}");
            if !checked_path(source, &relative)?.exists()
                && checked_path(root, &relative)?.is_file()
            {
                remove.push(relative);
            }
        }
    }
    remove.sort();
    remove.dedup();
    let settings = root.join("runtime/settings.ini");
    if settings.exists() {
        let text = read_text(&settings, 16 * 1024 * 1024)?;
        let effective = zapret_core::read_settings(root)?.get("alt").to_owned();
        if remove.contains(&format!("strategies/alt{effective}.txt")) {
            let fallback = [zapret_core::DEFAULT_STRATEGY_ID, "12"]
                .into_iter()
                .find(|id| source.join(format!("strategies/alt{id}.txt")).is_file())
                .context("Обновление не содержит запасную стратегию")?;
            let text: String = text
                .split_inclusive('\n')
                .map(|line| {
                    if let Some((start, end, _)) = alt_value(line) {
                        format!("{}{fallback}{}", &line[..start], &line[end..])
                    } else {
                        line.to_owned()
                    }
                })
                .collect();
            atomic_write(&source.join("runtime/settings.ini"), text.as_bytes())?;
            plan.push("runtime/settings.ini".into());
        }
    }
    Ok((plan, remove))
}
fn alt_value(line: &str) -> Option<(usize, usize, &str)> {
    let eq = line.find('=')?;
    if !line[..eq]
        .trim_matches([' ', '\t'])
        .eq_ignore_ascii_case("alt")
    {
        return None;
    }
    let after = &line[eq + 1..];
    let digits = after.trim_matches([' ', '\t', '\r', '\n']);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let start = eq + 1 + after.len() - after.trim_start_matches([' ', '\t']).len();
    Some((start, start + digits.len(), digits))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    relative: String,
    existed: bool,
    old_hash: String,
    new_hash: String,
    remove: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Journal {
    schema: u32,
    id: String,
    root: PathBuf,
    state: String,
    was_running: bool,
    entries: Vec<Entry>,
}
trait StateTrust {
    fn protect(&self, path: &Path) -> Result<()>;
    fn trusted(&self, path: &Path) -> Result<bool>;
    fn protect_published(&self, path: &Path) -> Result<()> {
        self.protect(path)
    }
}
struct SystemTrust;
impl StateTrust for SystemTrust {
    fn protect(&self, path: &Path) -> Result<()> {
        zapret_platform::protect_path(path)
    }
    fn trusted(&self, path: &Path) -> Result<bool> {
        zapret_platform::trusted_path(path)
    }
    fn protect_published(&self, path: &Path) -> Result<()> {
        zapret_platform::protect_readable_path(path)
    }
}
fn trusted_directory(path: &Path, trust: &impl StateTrust) -> Result<()> {
    no_reparse(path)?;
    fs::create_dir_all(path)?;
    trust.protect(path)?;
    ensure!(trust.trusted(path)?, "Update storage is not trusted");
    Ok(())
}
fn trusted_write(path: &Path, bytes: &[u8], trust: &impl StateTrust) -> Result<()> {
    write_with_access(path, bytes, trust, false)
}
fn write_with_access(
    path: &Path,
    bytes: &[u8],
    trust: &impl StateTrust,
    published: bool,
) -> Result<()> {
    let parent = path.parent().context("Update target has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".update-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if published {
        trust.protect_published(temporary.path())?;
    } else {
        trust.protect(temporary.path())?;
    }
    let staged = temporary.into_temp_path();
    zapret_core::atomic_replace_file(&staged, path)?;
    ensure!(
        trust.trusted(path)?,
        "Published update file lost trusted ACL"
    );
    Ok(())
}
fn file_hash(path: &Path) -> Result<String> {
    no_reparse(path)?;
    ensure!(
        path.is_file(),
        "Update entry is not a regular file: {}",
        path.display()
    );
    sha256_file(path)
}
fn stage_recovery_image(root: &Path, current: &Path, trust: &impl StateTrust) -> Result<()> {
    let target = checked_path(root, "bin/zapret-rust-recovery.exe")?;
    if same_path(&target, current) {
        ensure!(
            file_hash(&target)? == file_hash(current)?,
            "Recovery image changed"
        );
        return Ok(());
    }
    let bytes = read_bounded(current, MAX_FILE)?;
    write_with_access(&target, &bytes, trust, true)?;
    ensure!(
        file_hash(&target)? == sha256(&bytes),
        "Native recovery image was not preserved"
    );
    Ok(())
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn id_valid(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn same_path(a: &Path, b: &Path) -> bool {
    let key = |p: &Path| {
        p.to_string_lossy()
            .trim_start_matches(r"\\?\")
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_lowercase()
    };
    key(a) == key(b)
}
fn write_journal(path: &Path, journal: &Journal, trust: &impl StateTrust) -> Result<()> {
    let bytes = serde_json::to_vec(journal)?;
    ensure!(bytes.len() <= 1024 * 1024, "Oversized update journal");
    trusted_write(path, &bytes, trust)
}
fn journal_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let store = checked_path(root, "runtime/update")?;
    if !store.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for child in fs::read_dir(store)? {
        let child = child?;
        no_reparse(&child.path())?;
        if child.file_type()?.is_dir() && id_valid(&child.file_name().to_string_lossy()) {
            let journal = child.path().join("journal.json");
            if journal.exists() {
                result.push(journal);
            }
        }
    }
    result.sort();
    Ok(result)
}
fn read_journal(root: &Path, path: &Path, trust: &impl StateTrust) -> Result<Journal> {
    let directory = path.parent().context("Unexpected journal path")?;
    let id = directory
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid journal ID")?;
    ensure!(
        id_valid(id)
            && same_path(
                path,
                &checked_path(root, &format!("runtime/update/{id}/journal.json"))?
            ),
        "Unexpected update journal location"
    );
    for file in [
        directory.parent().context("No update store")?,
        directory,
        path,
    ] {
        ensure!(
            trust.trusted(file)?,
            "Untrusted update journal: {}",
            file.display()
        );
        no_reparse(file)?;
    }
    let journal: Journal = serde_json::from_slice(&read_bounded(path, 1024 * 1024)?)?;
    ensure!(
        journal.schema == 1
            && journal.id == id
            && same_path(&journal.root, &std::path::absolute(root)?)
            && ["Prepared", "Applying", "Committed", "RolledBack"]
                .contains(&journal.state.as_str())
            && journal.entries.len() <= MAX_ENTRIES,
        "Unsupported update journal"
    );
    let mut seen = HashSet::new();
    for entry in &journal.entries {
        let relative = normalized_relative(&entry.relative)?;
        ensure!(
            seen.insert(relative.to_lowercase()),
            "Duplicate update journal path"
        );
        ensure!(
            !relative.to_lowercase().starts_with("runtime/")
                || relative.eq_ignore_ascii_case("runtime/settings.ini"),
            "Unexpected runtime update entry"
        );
        ensure!(
            (!entry.existed || hash_valid(&entry.old_hash))
                && (entry.remove || hash_valid(&entry.new_hash)),
            "Invalid update entry hashes"
        );
        checked_path(root, &relative)?;
        checked_path(&directory.join("backup"), &relative)?;
    }
    Ok(journal)
}
fn prepare_transaction(
    source: &Path,
    root: &Path,
    directory: &Path,
    plan: &[String],
    remove: &[String],
    was_running: bool,
    trust: &impl StateTrust,
) -> Result<Journal> {
    let id = directory
        .file_name()
        .and_then(|s| s.to_str())
        .context("Missing transaction ID")?;
    ensure!(
        id_valid(id)
            && same_path(
                directory,
                &checked_path(root, &format!("runtime/update/{id}"))?
            ),
        "Invalid transaction directory"
    );
    ensure!(
        !directory.join("journal.json").exists() && !directory.join("backup").exists(),
        "Transaction directory has already been used"
    );
    ensure!(
        plan.len() + remove.len() <= MAX_ENTRIES,
        "Too many transaction entries"
    );
    trusted_directory(directory.parent().context("Missing store")?, trust)?;
    trusted_directory(directory, trust)?;
    let backup = directory.join("backup");
    trusted_directory(&backup, trust)?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let previous_licenses = installed_license_hashes(root)?;
    for (is_remove, paths) in [(false, plan), (true, remove)] {
        for relative in paths {
            let relative = normalized_relative(relative)?;
            ensure!(
                seen.insert(relative.to_lowercase()),
                "Duplicate update entry"
            );
            ensure!(
                !relative.to_lowercase().starts_with("runtime/")
                    || relative.eq_ignore_ascii_case("runtime/settings.ini"),
                "Unexpected runtime update file"
            );
            let target = checked_path(root, &relative)?;
            let existed = target.exists();
            let new_hash = if is_remove {
                String::new()
            } else {
                file_hash(&checked_path(source, &relative)?)?
            };
            let old_hash = if existed {
                let old_hash = file_hash(&target)?;
                let bytes = read_bounded(&target, MAX_FILE)?;
                ensure!(sha256(&bytes) == old_hash, "Original changed during backup");
                let saved = checked_path(&backup, &relative)?;
                fs::create_dir_all(saved.parent().context("No backup parent")?)?;
                for parent in saved
                    .parent()
                    .context("No backup parent")?
                    .ancestors()
                    .take_while(|p| p.starts_with(&backup))
                {
                    trust.protect(parent)?;
                }
                trusted_write(&saved, &bytes, trust)?;
                ensure!(file_hash(&saved)? == old_hash, "Backup hash mismatch");
                old_hash
            } else {
                String::new()
            };
            if is_remove && license_name(relative.strip_prefix("licenses/").unwrap_or(&relative)) {
                ensure!(
                    previous_licenses
                        .get(&relative)
                        .is_some_and(|hash| hash.eq_ignore_ascii_case(&old_hash)),
                    "License or its catalog entry changed before update: {relative}"
                );
            }
            if is_remove && relative == CYGWIN_DLL {
                let installed =
                    zapret_core::read_core_manifest(&checked_path(root, "tools/upstream.txt")?)?;
                ensure!(
                    installed
                        .hashes
                        .get(CYGWIN_DLL)
                        .is_some_and(|hash| hash.eq_ignore_ascii_case(&old_hash)),
                    "Cygwin DLL or its pin changed before update preparation"
                );
            }
            entries.push(Entry {
                relative,
                existed,
                old_hash,
                new_hash,
                remove: is_remove,
            });
        }
    }
    let journal = Journal {
        schema: 1,
        id: id.into(),
        root: std::path::absolute(root)?,
        state: "Prepared".into(),
        was_running,
        entries,
    };
    write_journal(&directory.join("journal.json"), &journal, trust)?;
    Ok(journal)
}
fn detach_loaded_image(target: &Path, directory: &Path, trust: &impl StateTrust) -> Result<()> {
    if !target.exists() {
        return Ok(());
    }
    let name = match target.file_name().and_then(|part| part.to_str()) {
        Some("zapret-rust-worker.exe") if target.ends_with("bin/zapret-rust-worker.exe") => {
            "zapret-rust-worker"
        }
        Some("zapret-rust.exe") if target.ends_with("bin/zapret-rust.exe") => "zapret-rust",
        _ if same_path(target, &std::env::current_exe()?) => "zapret-rust-recovery",
        _ => return Ok(()),
    };
    // A scheduled worker can keep its image mapped even after the engine stops.
    // The durable Applying journal retains a verified backup during the rename.
    let id =
        sha256(format!("{:?}|{}", std::time::SystemTime::now(), std::process::id()).as_bytes())
            [..24]
            .to_ascii_lowercase();
    let detached = checked_path(directory, &format!("running-{name}-{id}.exe"))?;
    ensure!(!detached.exists(), "Detached executable path collision");
    fs::rename(target, &detached)?;
    trust.protect(&detached)?;
    Ok(())
}
fn copy_verified(
    source: &Path,
    target: &Path,
    expected: &str,
    directory: &Path,
    trust: &impl StateTrust,
    published: bool,
) -> Result<()> {
    let bytes = read_bounded(source, MAX_FILE)?;
    ensure!(
        sha256(&bytes) == expected,
        "Update source changed: {}",
        source.display()
    );
    detach_loaded_image(target, directory, trust)?;
    write_with_access(target, &bytes, trust, published)
}
fn restore_journal(root: &Path, path: &Path, trust: &impl StateTrust) -> Result<bool> {
    let mut journal = read_journal(root, path, trust)?;
    if !["Prepared", "Applying"].contains(&journal.state.as_str()) {
        return Ok(false);
    }
    let directory = path.parent().context("No transaction directory")?;
    let backup = directory.join("backup");
    if journal.state == "Applying" {
        // Complete preflight precedes the first target write, including every
        // backup and every current path. A user's later edit is never overwritten.
        for entry in &journal.entries {
            if entry.existed {
                let saved = checked_path(&backup, &entry.relative)?;
                for part in saved.ancestors().take_while(|p| p.starts_with(&backup)) {
                    ensure!(trust.trusted(part)?, "Untrusted backup");
                }
                ensure!(
                    file_hash(&saved)? == entry.old_hash,
                    "Damaged update backup; recovery stopped"
                );
            }
            let target = checked_path(root, &entry.relative)?;
            if target.exists() {
                let hash = file_hash(&target)?;
                ensure!(
                    hash == entry.old_hash || hash == entry.new_hash,
                    "File edited after update interruption: {}",
                    entry.relative
                );
            }
        }
        for entry in journal.entries.iter().rev() {
            let target = checked_path(root, &entry.relative)?;
            if entry.existed {
                copy_verified(
                    &checked_path(&backup, &entry.relative)?,
                    &target,
                    &entry.old_hash,
                    directory,
                    trust,
                    !entry.relative.starts_with("runtime/"),
                )?;
            } else if target.exists() {
                detach_loaded_image(&target, directory, trust)?;
                if target.exists() {
                    fs::remove_file(&target)?;
                }
            }
        }
    }
    trusted_write(
        &checked_path(root, "runtime/update-restart.txt")?,
        if journal.was_running { b"start" } else { b"" },
        trust,
    )?;
    journal.state = "RolledBack".into();
    write_journal(path, &journal, trust)?;
    Ok(true)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PackageManifest {
    schema: u32,
    version: String,
    #[serde(deserialize_with = "unique_hashes")]
    files: BTreeMap<String, String>,
}
fn unique_hashes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique package hash map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate package hash key"));
                }
                if result.len() > MAX_ENTRIES {
                    return Err(serde::de::Error::custom("oversized package hash catalog"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique)
}
// Shipped public BAT in 1.0–1.2. A locally edited launcher belongs to the user.
const STOCK_BATCH_SHA256: &str = "91728FEC8260A243BBBF876B3238B26BCD7F820A01D3DA65DD895D7219E4FB51";

fn allowed_package_path(name: &str) -> bool {
    if name.to_ascii_lowercase().ends_with(".ps1") || name.to_ascii_lowercase().ends_with(".cs") {
        return false;
    }
    if let Some(image) = name.strip_prefix("bin/") {
        return [
            "zapret-rust.exe",
            "zapret-rust-worker.exe",
            "zapret-rust-recovery.exe",
            "winws2.exe",
            "WinDivert.dll",
            "WinDivert64.sys",
            "cygwin1.dll",
            "zapret-ring.dll",
        ]
        .contains(&image);
    }
    if let Some(leaf) = name.strip_prefix("licenses/") {
        return license_name(leaf);
    }
    if let Some((directory, _)) = name.split_once('/') {
        return [
            "bin",
            "fake",
            "lists",
            "lua",
            "strategies",
            "tools",
            "windivert",
        ]
        .contains(&directory);
    }
    [
        "CHANGELOG.md",
        "CHECKSUMS.txt",
        "README.md",
        "README.en.md",
        "zapret-rust.exe",
        "zapret-rust.bat",
        CATALOG,
    ]
    .contains(&name)
        || license_name(name)
}
fn verify_catalog(source: &Path, actual: &[String], manifest: &PackageManifest) -> Result<()> {
    ensure!(
        manifest.schema == 1
            && !manifest.version.is_empty()
            && manifest
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && manifest.version.as_bytes()[0].is_ascii_digit(),
        "Unsupported native package catalog"
    );
    let actual: BTreeSet<_> = actual
        .iter()
        .filter(|name| name.as_str() != CATALOG)
        .cloned()
        .collect();
    let expected: BTreeSet<_> = manifest.files.keys().cloned().collect();
    ensure!(
        actual == expected,
        "Native package catalog does not cover every file"
    );
    let mut seen = HashSet::new();
    for (name, expected) in &manifest.files {
        normalized_relative(name)?;
        ensure!(
            name != CATALOG
                && allowed_package_path(name)
                && seen.insert(name.to_lowercase())
                && hash_valid(expected),
            "Invalid native catalog file"
        );
        ensure!(
            file_hash(&checked_path(source, name)?)?.eq_ignore_ascii_case(expected),
            "Native package hash mismatch: {name}"
        );
    }
    Ok(())
}
fn validate_package(
    source: &Path,
    names: &[String],
    expected_tag: Option<&str>,
) -> Result<(PackageManifest, CoreManifest)> {
    let manifest: PackageManifest =
        serde_json::from_slice(&read_bounded(&checked_path(source, CATALOG)?, 1024 * 1024)?)?;
    verify_catalog(source, names, &manifest)?;
    if let Some(tag) = expected_tag {
        ensure!(
            format!("v{}", manifest.version) == tag,
            "Native archive version differs from release tag"
        );
    }
    for name in [
        "bin/zapret-rust.exe",
        "bin/zapret-rust-worker.exe",
        "bin/zapret-rust-recovery.exe",
        "tools/upstream.txt",
        "tools/targets.txt",
        "tools/dpi-suite.json",
    ] {
        ensure!(
            manifest.files.contains_key(name),
            "Native package missing required file: {name}"
        );
    }
    let grouped = manifest
        .files
        .keys()
        .any(|name| name.starts_with("licenses/"));
    ensure!(
        !grouped || !manifest.files.keys().any(|name| license_name(name)),
        "Mixed license layouts in the native package"
    );
    for leaf in [
        "LICENSE",
        "LICENSE-zapret2.txt",
        "LICENSE-flowseal.txt",
        "LICENSE-tg-ws-proxy.txt",
        "LICENSE-rust.txt",
        "THIRD-PARTY-NOTICES.md",
    ] {
        let name = if grouped {
            format!("licenses/{leaf}")
        } else {
            leaf.to_owned()
        };
        ensure!(
            manifest.files.contains_key(&name),
            "Native package missing required file: {name}"
        );
    }
    ensure!(
        manifest.files["bin/zapret-rust.exe"] == manifest.files["bin/zapret-rust-recovery.exe"],
        "Native recovery image differs from the packaged application"
    );
    let bad = zapret_core::verify_package(source)?;
    ensure!(
        bad.is_empty(),
        "Native archive failed upstream integrity: {}",
        bad.join(", ")
    );
    zapret_core::verify_telegram(source)?;
    if manifest.files.contains_key("zapret-rust.exe") {
        let image = read_bounded(&source.join("zapret-rust.exe"), MAX_FILE)?;
        let pe = image
            .get(60..64)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .map(|n| n as usize);
        ensure!(
            image.starts_with(b"MZ")
                && pe.is_some_and(|n| image.get(n..n.saturating_add(6)) == Some(b"PE\0\0\x64\x86")),
            "Invalid x64 Windows launcher"
        );
    } else {
        // Recovery also accepts packages produced before the EXE launcher.
        let launcher = read_text(&source.join("zapret-rust.bat"), 65536)?.to_ascii_lowercase();
        ensure!(
            launcher.contains("bin\\zapret-rust.exe") || launcher.contains("bin/zapret-rust.exe"),
            "Archive launcher does not use the native application"
        );
    }
    let upstream = zapret_core::read_core_manifest(&source.join("tools/upstream.txt"))?;
    ensure!(
        manifest
            .files
            .keys()
            .all(|name| !zapret_core::omits_engine_file(upstream.schema, name)),
        "Native ZIP contains files outside the engine schema"
    );
    let checksums = read_text(&source.join("CHECKSUMS.txt"), 32768)?.to_ascii_lowercase();
    ensure!(
        checksums.contains(&upstream.tag) && checksums.contains(&upstream.archive_sha256),
        "CHECKSUMS provenance differs from upstream manifest"
    );
    for (path, hash) in &upstream.hashes {
        let name = path.rsplit('/').next().unwrap_or("");
        ensure!(
            checksums.contains(&format!("{hash}  {name}").to_ascii_lowercase()),
            "CHECKSUMS is missing a pinned upstream file"
        );
    }
    Ok((manifest, upstream))
}
fn build_archive(inputs: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut hashes = BTreeMap::new();
    for (name, bytes) in inputs {
        normalized_relative(name)?;
        ensure!(
            name != CATALOG && allowed_package_path(name),
            "Invalid native package input: {name}"
        );
        hashes.insert(name.clone(), sha256(bytes));
    }
    let catalog = serde_json::to_vec_pretty(&PackageManifest {
        schema: 1,
        version: crate::VERSION.into(),
        files: hashes,
    })?;
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let timestamp = zip::DateTime::from_date_and_time(2000, 1, 1, 0, 0, 0)
        .map_err(|_| anyhow::anyhow!("Invalid fixed ZIP timestamp"))?;
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .last_modified_time(timestamp)
        .unix_permissions(0o644);
    for (name, bytes) in inputs {
        writer.start_file(format!("zapret-rust/{name}"), options)?;
        writer.write_all(bytes)?;
    }
    writer.start_file(format!("zapret-rust/{CATALOG}"), options)?;
    writer.write_all(&catalog)?;
    writer.start_file("zapret-rust/runtime/.keep", options)?;
    Ok(writer.finish()?.into_inner())
}
fn apply_prepared(
    root: &Path,
    source: &Path,
    directory: &Path,
    journal: &mut Journal,
    trust: &impl StateTrust,
) -> Result<()> {
    ensure!(journal.state == "Prepared", "Transaction is not prepared");
    // Validate every source and original before entering Applying, so a changed
    // late input cannot cause even the first destination replacement.
    for entry in &journal.entries {
        let target = checked_path(root, &entry.relative)?;
        if entry.existed {
            let backup = directory.join("backup");
            let saved = checked_path(&backup, &entry.relative)?;
            for part in saved.ancestors().take_while(|p| p.starts_with(&backup)) {
                ensure!(trust.trusted(part)?, "Untrusted backup before update");
            }
            ensure!(
                file_hash(&saved)? == entry.old_hash,
                "Damaged backup before first replacement: {}",
                entry.relative
            );
            ensure!(
                file_hash(&target)? == entry.old_hash,
                "Original changed after backup: {}",
                entry.relative
            );
        } else {
            ensure!(
                !target.exists(),
                "New target appeared after preparation: {}",
                entry.relative
            );
        }
        if !entry.remove {
            ensure!(
                file_hash(&checked_path(source, &entry.relative)?)? == entry.new_hash,
                "Staged source changed: {}",
                entry.relative
            );
        }
    }
    journal.state = "Applying".into();
    write_journal(&directory.join("journal.json"), journal, trust)?;
    for entry in &journal.entries {
        let target = checked_path(root, &entry.relative)?;
        if entry.existed {
            ensure!(
                file_hash(&target)? == entry.old_hash,
                "Original changed during update: {}",
                entry.relative
            );
        } else {
            ensure!(
                !target.exists(),
                "New target appeared during update: {}",
                entry.relative
            );
        }
        if entry.remove {
            if target.exists() {
                fs::remove_file(target)?;
            }
        } else {
            copy_verified(
                &checked_path(source, &entry.relative)?,
                &target,
                &entry.new_hash,
                directory,
                trust,
                !entry.relative.starts_with("runtime/"),
            )?;
        }
    }
    trusted_write(
        &checked_path(root, "runtime/update-restart.txt")?,
        if journal.was_running { b"start" } else { b"" },
        trust,
    )?;
    journal.state = "Committed".into();
    write_journal(&directory.join("journal.json"), journal, trust)
}
fn protect_tree(root: &Path, trust: &impl StateTrust) -> Result<()> {
    trust.protect(root)?;
    for relative in walk_files(root)? {
        let path = checked_path(root, &relative)?;
        for ancestor in path.ancestors().take_while(|p| p.starts_with(root)) {
            trust.protect(ancestor)?;
        }
    }
    Ok(())
}
fn new_transaction_directory(root: &Path, trust: &impl StateTrust) -> Result<PathBuf> {
    let store = checked_path(root, "runtime/update")?;
    trusted_directory(&store, trust)?;
    for counter in 0..16 {
        let entropy = tempfile::NamedTempFile::new_in(&store)?;
        let id = sha256(
            format!(
                "{:?}|{:?}|{counter}",
                entropy.path(),
                std::time::SystemTime::now()
            )
            .as_bytes(),
        )[..32]
            .to_ascii_lowercase();
        let directory = checked_path(&store, &id)?;
        match fs::create_dir(&directory) {
            Ok(()) => {
                trust.protect(&directory)?;
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("Cannot allocate a unique update transaction")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Release {
    tag: String,
    name: String,
    url: String,
    sha256: String,
    bytes: u64,
}
fn parse_release(metadata: &Value) -> Result<Option<Release>> {
    let tag = metadata["tag_name"]
        .as_str()
        .context("GitHub release has no tag")?;
    ensure!(
        tag.starts_with('v')
            && tag.len() <= 64
            && tag[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && !tag.ends_with('.'),
        "Invalid GitHub release tag"
    );
    let expected_name = format!("zapret-rust-native-{tag}.zip");
    let assets = metadata["assets"]
        .as_array()
        .context("GitHub release has no assets")?;
    let matching: Vec<_> = assets
        .iter()
        .filter(|a| a["name"].as_str() == Some(&expected_name))
        .collect();
    ensure!(matching.len() <= 1, "Duplicate native release asset");
    let Some(asset) = matching.first() else {
        return Ok(None);
    };
    let url = asset["browser_download_url"]
        .as_str()
        .context("Native asset has no URL")?;
    ensure!(
        url == format!(
            "https://github.com/chepi228/zapret-rust/releases/download/{tag}/{expected_name}"
        ),
        "Native asset URL is outside the authoritative release"
    );
    let digest = asset["digest"]
        .as_str()
        .context("Native asset has no authoritative digest")?;
    let digest = digest
        .strip_prefix("sha256:")
        .context("Native asset digest is not SHA256")?;
    ensure!(
        hash_valid(digest),
        "Native asset SHA256 is missing or invalid"
    );
    let bytes = asset["size"].as_u64().context("Native asset has no size")?;
    ensure!(
        bytes > 0 && bytes <= MAX_ARCHIVE,
        "Native release archive exceeds size budget"
    );
    Ok(Some(Release {
        tag: tag.into(),
        name: expected_name,
        url: url.into(),
        sha256: digest.to_ascii_uppercase(),
        bytes,
    }))
}
fn version_newer(tag: &str, current: &str) -> bool {
    let numeric = |text: &str| -> Option<Vec<u64>> {
        text.strip_prefix('v')?
            .split('.')
            .map(str::parse::<u64>)
            .collect::<std::result::Result<_, _>>()
            .ok()
    };
    match (numeric(tag), numeric(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}
fn confirmed_running(status: &Value) -> Result<bool> {
    ensure!(
        status["known"].as_bool() == Some(true)
            && status["ownership_known"].as_bool() == Some(true),
        "Состояние обхода или владелец процесса не подтверждены; замена файлов отложена"
    );
    status["running"].as_bool().context("Unknown bypass state")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};
    use zip::{ZipWriter, write::SimpleFileOptions};
    fn zip_file(path: &Path, entries: &[(&str, &[u8])]) {
        let mut writer = ZipWriter::new(fs::File::create(path).unwrap());
        for (name, data) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
    }
    #[test]
    fn archives_use_the_product_root_and_reject_previous_or_external_images() {
        let inputs = BTreeMap::from([
            ("zapret-rust.bat".into(), b"launcher".to_vec()),
            ("bin/zapret-rust.exe".into(), b"controller".to_vec()),
            ("bin/zapret-rust-worker.exe".into(), b"host".to_vec()),
            (
                "bin/zapret-rust-recovery.exe".into(),
                b"controller".to_vec(),
            ),
        ]);
        let bytes = build_archive(&inputs).unwrap();
        let archive = ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert!(
            archive
                .file_names()
                .all(|name| name.starts_with("zapret-rust/"))
        );
        for name in [
            "zapret.bat",
            "bin/zapret.exe",
            "bin/zapret-worker.exe",
            "bin/zapret-recovery.exe",
            "bin/tgws/TgWsProxy_windows.exe",
        ] {
            let mut with_previous_image = inputs.clone();
            with_previous_image.insert(name.into(), b"previous external image".to_vec());
            assert!(build_archive(&with_previous_image).is_err(), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn apply_and_rollback_can_replace_a_live_background_worker() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("package");
        let source = temp.path().join("release");
        let directory = root.join("runtime/update").join("a".repeat(32));
        let relative = "bin/zapret-rust-worker.exe";
        let worker = root.join(relative);
        fs::create_dir_all(worker.parent().unwrap()).unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        let command =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
        fs::copy(command, &worker).unwrap();
        fs::write(source.join(relative), b"new worker").unwrap();
        let old_hash = file_hash(&worker).unwrap();
        let mut journal = prepare_transaction(
            &source,
            &root,
            &directory,
            &[relative.to_owned()],
            &[],
            false,
            &FixtureTrust,
        )
        .unwrap();
        let mut child = Command::new(&worker)
            .args(["/d", "/q"])
            .creation_flags(0x08000000)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let result = (|| -> Result<()> {
            apply_prepared(&root, &source, &directory, &mut journal, &FixtureTrust)?;
            ensure!(
                fs::read(&worker)? == b"new worker" && child.try_wait()?.is_none(),
                "Live worker replacement failed"
            );
            let path = directory.join("journal.json");
            journal.state = "Applying".into();
            write_journal(&path, &journal, &FixtureTrust)?;
            ensure!(
                restore_journal(&root, &path, &FixtureTrust)? && file_hash(&worker)? == old_hash
            );
            Ok(())
        })();
        drop(child.stdin.take());
        child.wait().unwrap();
        result.unwrap();
    }
    #[test]
    fn rejects_noncanonical_windows_update_paths_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        for bad in [
            "../escape",
            "C:/escape",
            "a\\..\\escape",
            "a/file.",
            "a/file ",
            "a/nul.txt",
            "a/a:b",
            "a//b",
            ".hidden/file",
            "runtime/../escape",
        ] {
            assert!(checked_path(temp.path(), bad).is_err(), "{bad}");
        }
        assert_eq!(
            checked_path(temp.path(), "strategies/alt12.txt").unwrap(),
            temp.path().join("strategies").join("alt12.txt")
        );
    }
    #[test]
    fn rejects_zip_symlinks_high_expansion_and_duplicate_manifest_hash_keys() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bad.zip");
        let mut writer = ZipWriter::new(File::create(&path).unwrap());
        writer
            .add_symlink(
                "zapret-rust/bin/redirect",
                "../../escape",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.finish().unwrap();
        assert!(extract_archive(&path, &temp.path().join("symlink")).is_err());
        let mut writer = ZipWriter::new(File::create(&path).unwrap());
        writer
            .start_file(
                "zapret-rust/lists/ipset-all.txt",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![b'a'; 4 * 1024 * 1024]).unwrap();
        writer.finish().unwrap();
        assert!(extract_archive(&path, &temp.path().join("bomb")).is_err());
        let duplicate = format!(
            r#"{{"schema":1,"version":"2.2","files":{{"LICENSE":"{}","LICENSE":"{}"}}}}"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(serde_json::from_str::<PackageManifest>(&duplicate).is_err());
    }
    #[test]
    fn rejects_zip_traversal_case_aliases_and_corrupted_late_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fixture.zip");
        zip_file(
            &path,
            &[
                ("zapret-rust/good.txt", b"valid"),
                ("zapret-rust/../escape.txt", b"bad"),
            ],
        );
        assert!(extract_archive(&path, &temp.path().join("traversal")).is_err());
        assert!(!temp.path().join("escape.txt").exists());
        zip_file(
            &path,
            &[
                ("zapret-rust/README.md", b"valid"),
                ("zapret-rust/readme.md", b"alias"),
            ],
        );
        assert!(extract_archive(&path, &temp.path().join("alias")).is_err());
        zip_file(
            &path,
            &[
                ("zapret-rust/README.md", b"valid"),
                ("zapret-rust/LICENSE", b"CRC-DAMAGE-PAYLOAD-TEST"),
            ],
        );
        let mut bytes = fs::read(&path).unwrap();
        let position = bytes
            .windows(23)
            .position(|b| b == b"CRC-DAMAGE-PAYLOAD-TEST")
            .unwrap();
        bytes[position] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(extract_archive(&path, &temp.path().join("crc")).is_err());
    }
    #[test]
    fn preserves_user_and_flowseal_lists_and_retires_only_explicit_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        for root in [&source, &target] {
            for dir in ["strategies", "lists", "runtime"] {
                fs::create_dir_all(root.join(dir)).unwrap();
            }
        }
        for file in [
            "lists/list-general.txt",
            "lists/list-general-user.txt",
            "lists/autohostlist.txt",
            "strategies/alt99.txt",
        ] {
            fs::write(target.join(file), b"keep user data").unwrap();
        }
        for file in [
            "lists/list-general.txt",
            "lists/list-general-user.txt",
            "lists/autohostlist.txt",
        ] {
            fs::write(source.join(file), b"new bundled data").unwrap();
        }
        fs::write(
            source.join("strategies/retired.txt"),
            b"alt54.txt\n../bad\n",
        )
        .unwrap();
        fs::write(target.join("strategies/alt54.txt"), b"retired").unwrap();
        fs::write(source.join("strategies/alt12.txt"), b"older fallback").unwrap();
        fs::write(source.join("strategies/alt31.txt"), b"fallback").unwrap();
        fs::write(
            target.join("runtime/settings.ini"),
            b"alt=54\r\nauto=off\r\nfuture=keep\r\n",
        )
        .unwrap();
        let (plan, remove) = update_plan(&source, &target, false).unwrap();
        assert!(plan.contains(&"strategies/alt31.txt".into()));
        assert!(!plan.iter().any(|p| p.starts_with("lists/")));
        assert_eq!(remove, vec!["strategies/alt54.txt"]);
        assert!(plan.contains(&"runtime/settings.ini".into()));
        assert_eq!(
            fs::read_to_string(source.join("runtime/settings.ini")).unwrap(),
            "alt=31\r\nauto=off\r\nfuture=keep\r\n"
        );
        assert_eq!(
            fs::read(target.join("strategies/alt99.txt")).unwrap(),
            b"keep user data"
        );
    }
    #[test]
    fn retired_primary_uses_the_same_case_insensitive_last_record_as_runtime_settings() {
        for (text, repair) in [
            ("ALT=54\r\nFutureSetting=keep\r\n", true),
            ("alt=12\r\nAlt=54\r\nFutureSetting=keep\r\n", true),
            ("ALT=54\r\nalt=12\r\nFutureSetting=keep\r\n", false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let root = temp.path().join("target");
            for path in [
                source.join("strategies"),
                root.join("strategies"),
                root.join("runtime"),
            ] {
                fs::create_dir_all(path).unwrap();
            }
            fs::write(source.join("strategies/retired.txt"), "alt54.txt\n").unwrap();
            fs::write(source.join("strategies/alt12.txt"), "fallback").unwrap();
            fs::write(root.join("strategies/alt54.txt"), "retired").unwrap();
            fs::write(root.join("runtime/settings.ini"), text).unwrap();
            let (plan, remove) = update_plan(&source, &root, false).unwrap();
            assert_eq!(remove, vec!["strategies/alt54.txt"]);
            assert_eq!(
                plan.contains(&"runtime/settings.ini".into()),
                repair,
                "{text}"
            );
            assert_eq!(
                fs::read_to_string(root.join("runtime/settings.ini")).unwrap(),
                text
            );
            if repair {
                let repaired = fs::read_to_string(source.join("runtime/settings.ini")).unwrap();
                assert!(repaired.contains("FutureSetting=keep"));
                assert_eq!(
                    zapret_core::read_settings(&source).unwrap().get("alt"),
                    "12"
                );
                assert!(repaired.contains(if text.starts_with("ALT") {
                    "ALT=12"
                } else {
                    "Alt=12"
                }));
            }
        }
    }
    struct FixtureTrust;
    impl StateTrust for FixtureTrust {
        fn protect(&self, path: &Path) -> Result<()> {
            ensure!(
                path.starts_with(std::env::temp_dir()),
                "Fixture refuses non-TEMP state"
            );
            Ok(())
        }
        fn trusted(&self, path: &Path) -> Result<bool> {
            Ok(path.starts_with(std::env::temp_dir()) && path.exists())
        }
    }
    #[test]
    fn recovery_image_is_published_readable_before_the_main_image_can_disappear() {
        use std::cell::RefCell;
        struct RecordingTrust(RefCell<Vec<&'static str>>);
        impl StateTrust for RecordingTrust {
            fn protect(&self, _: &Path) -> Result<()> {
                self.0.borrow_mut().push("private");
                Ok(())
            }
            fn protect_published(&self, _: &Path) -> Result<()> {
                self.0.borrow_mut().push("published");
                Ok(())
            }
            fn trusted(&self, path: &Path) -> Result<bool> {
                Ok(path.exists())
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir(root.join("bin")).unwrap();
        let current = root.join("bin/zapret-rust.exe");
        fs::write(&current, b"verified running image").unwrap();
        let trust = RecordingTrust(RefCell::new(Vec::new()));
        stage_recovery_image(root, &current, &trust).unwrap();
        assert_eq!(*trust.0.borrow(), vec!["published"]);
        fs::rename(&current, root.join("mapped-old-image.exe")).unwrap();
        assert_eq!(
            fs::read(root.join("bin/zapret-rust-recovery.exe")).unwrap(),
            b"verified running image"
        );
        trusted_write(&root.join("runtime/journal.json"), b"private state", &trust).unwrap();
        assert_eq!(*trust.0.borrow(), vec!["published", "private"]);
    }
    #[test]
    fn interrupted_transaction_preflights_every_backup_and_external_edit_before_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("a.txt"), b"new a").unwrap();
        fs::write(source.join("b.txt"), b"new b").unwrap();
        fs::write(target.join("a.txt"), b"old a").unwrap();
        let directory = target.join("runtime/update").join("a".repeat(32));
        let trust = FixtureTrust;
        let mut journal = prepare_transaction(
            &source,
            &target,
            &directory,
            &["b.txt".into(), "a.txt".into()],
            &[],
            true,
            &trust,
        )
        .unwrap();
        assert_eq!(journal.state, "Prepared");
        assert_eq!(fs::read(target.join("a.txt")).unwrap(), b"old a");
        journal.state = "Applying".into();
        let path = directory.join("journal.json");
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        fs::write(target.join("a.txt"), b"new a").unwrap();
        fs::write(target.join("b.txt"), b"new b").unwrap();
        let backup = directory.join("backup/a.txt");
        fs::write(&backup, b"corrupt").unwrap();
        assert!(restore_journal(&target, &path, &trust).is_err());
        assert_eq!(fs::read(target.join("b.txt")).unwrap(), b"new b");
        fs::write(&backup, b"old a").unwrap();
        fs::write(target.join("a.txt"), b"external user edit").unwrap();
        assert!(restore_journal(&target, &path, &trust).is_err());
        assert_eq!(fs::read(target.join("b.txt")).unwrap(), b"new b");
        fs::write(target.join("a.txt"), b"new a").unwrap();
        assert!(restore_journal(&target, &path, &trust).unwrap());
        assert_eq!(fs::read(target.join("a.txt")).unwrap(), b"old a");
        assert!(!target.join("b.txt").exists());
        assert_eq!(
            fs::read(target.join("runtime/update-restart.txt")).unwrap(),
            b"start"
        );
        assert!(!restore_journal(&target, &path, &trust).unwrap());
    }
    #[test]
    fn native_upgrade_retires_only_pinned_cygwin_and_recovers_it_after_interruption() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir(&source).unwrap();
        let dll = target.join(CYGWIN_DLL);
        let manifest_path = target.join("tools/upstream.txt");
        let mut manifest = format!(
            "schema=1\ntag=v1.0.6\ncommit={}\narchive-sha256={}\n",
            "a".repeat(40),
            "b".repeat(64)
        );
        let dll_bytes = b"previous pinned Cygwin image";
        for name in zapret_core::CORE_FILES {
            manifest.push_str(&format!("{name}={}\n", sha256(dll_bytes)));
        }
        atomic_write(&manifest_path, manifest.as_bytes()).unwrap();
        atomic_write(&dll, b"unmanaged file").unwrap();
        assert!(update_plan(&source, &target, true).unwrap().1.is_empty());
        atomic_write(&dll, dll_bytes).unwrap();
        assert!(update_plan(&source, &target, false).unwrap().1.is_empty());
        let (plan, remove) = update_plan(&source, &target, true).unwrap();
        assert_eq!(remove, [CYGWIN_DLL]);
        let directory = target.join("runtime/update").join("c".repeat(32));
        let trust = FixtureTrust;
        let mut journal =
            prepare_transaction(&source, &target, &directory, &plan, &remove, false, &trust)
                .unwrap();
        assert_eq!(fs::read(&dll).unwrap(), dll_bytes);
        apply_prepared(&target, &source, &directory, &mut journal, &trust).unwrap();
        assert!(!dll.exists());
        assert_eq!(
            fs::read(directory.join("backup").join(CYGWIN_DLL)).unwrap(),
            dll_bytes
        );
        // Simulate a crash after removal and before the final commit record.
        let record = directory.join("journal.json");
        journal.state = "Applying".into();
        write_journal(&record, &journal, &trust).unwrap();
        assert!(restore_journal(&target, &record, &trust).unwrap());
        assert_eq!(fs::read(&dll).unwrap(), dll_bytes);
    }
    #[test]
    fn license_move_retires_only_catalogued_originals_and_rolls_back() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("installed");
        let source = temp.path().join("incoming");
        let mut files = BTreeMap::new();
        for leaf in ["LICENSE", "LICENSE-rust.txt", "THIRD-PARTY-NOTICES.md"] {
            atomic_write(&root.join(leaf), b"previous").unwrap();
            files.insert(leaf.to_owned(), sha256(b"previous"));
            atomic_write(&source.join("licenses").join(leaf), b"current").unwrap();
        }
        atomic_write(&root.join("LICENSE-rust.txt"), b"user edit").unwrap();
        atomic_write(&root.join("LICENSE-custom.txt"), b"user document").unwrap();
        let catalog = PackageManifest {
            schema: 1,
            version: "1.1".into(),
            files,
        };
        atomic_write(&root.join(CATALOG), &serde_json::to_vec(&catalog).unwrap()).unwrap();
        let (plan, remove) = update_plan(&source, &root, false).unwrap();
        assert_eq!(remove, ["LICENSE", "THIRD-PARTY-NOTICES.md"]);
        let trust = FixtureTrust;
        let directory = root.join("runtime/update").join("a".repeat(32));
        let mut journal =
            prepare_transaction(&source, &root, &directory, &plan, &remove, false, &trust).unwrap();
        apply_prepared(&root, &source, &directory, &mut journal, &trust).unwrap();
        assert!(!root.join("LICENSE").exists());
        assert_eq!(fs::read(root.join("licenses/LICENSE")).unwrap(), b"current");
        assert_eq!(
            fs::read(root.join("LICENSE-rust.txt")).unwrap(),
            b"user edit"
        );
        assert_eq!(
            fs::read(root.join("LICENSE-custom.txt")).unwrap(),
            b"user document"
        );
        let record = directory.join("journal.json");
        journal.state = "Applying".into();
        write_journal(&record, &journal, &trust).unwrap();
        assert!(restore_journal(&root, &record, &trust).unwrap());
        assert_eq!(fs::read(root.join("LICENSE")).unwrap(), b"previous");
        assert!(!root.join("licenses/LICENSE").exists());
        assert!(allowed_package_path("LICENSE") && allowed_package_path("licenses/LICENSE"));
        assert!(!allowed_package_path("licenses/bin/LICENSE"));
        assert!(!allowed_package_path("licenses/helper.exe"));
    }

    #[test]
    fn prepared_recovery_preserves_edits_and_durable_start_intent() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("a.txt"), b"new").unwrap();
        fs::write(target.join("a.txt"), b"old").unwrap();
        let directory = target.join("runtime/update").join("b".repeat(32));
        prepare_transaction(
            &source,
            &target,
            &directory,
            &["a.txt".into()],
            &[],
            true,
            &FixtureTrust,
        )
        .unwrap();
        fs::write(target.join("a.txt"), b"edit after preparation").unwrap();
        assert!(restore_journal(&target, &directory.join("journal.json"), &FixtureTrust).unwrap());
        assert_eq!(
            fs::read(target.join("a.txt")).unwrap(),
            b"edit after preparation"
        );
        assert_eq!(
            fs::read(target.join("runtime/update-restart.txt")).unwrap(),
            b"start"
        );
    }
    #[test]
    fn native_catalog_covers_exactly_every_file_and_detects_late_input_changes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("LICENSE"), b"license").unwrap();
        let manifest = PackageManifest {
            schema: 1,
            version: "2.2".into(),
            files: BTreeMap::from([("LICENSE".into(), sha256(b"license"))]),
        };
        verify_catalog(temp.path(), &["LICENSE".into(), CATALOG.into()], &manifest).unwrap();
        fs::write(temp.path().join("LICENSE"), b"late input change").unwrap();
        assert!(
            verify_catalog(temp.path(), &["LICENSE".into(), CATALOG.into()], &manifest).is_err()
        );
        fs::write(temp.path().join("LICENSE"), b"license").unwrap();
        assert!(
            verify_catalog(
                temp.path(),
                &["LICENSE".into(), CATALOG.into(), "extra.txt".into()],
                &manifest
            )
            .is_err()
        );
    }

    #[test]
    fn applying_recovery_requires_a_fresh_process_before_any_more_control_work() {
        for applying in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("source");
            let root = temp.path().join("target");
            fs::create_dir_all(source.join("bin")).unwrap();
            fs::create_dir_all(root.join("bin")).unwrap();
            fs::write(source.join("bin/zapret-rust.exe"), b"new image").unwrap();
            fs::write(root.join("bin/zapret-rust.exe"), b"old image").unwrap();
            let directory = root.join("runtime/update").join("d".repeat(32));
            let mut journal = prepare_transaction(
                &source,
                &root,
                &directory,
                &["bin/zapret-rust.exe".into()],
                &[],
                false,
                &FixtureTrust,
            )
            .unwrap();
            let path = directory.join("journal.json");
            if applying {
                journal.state = "Applying".into();
                write_journal(&path, &journal, &FixtureTrust).unwrap();
                fs::write(root.join("bin/zapret-rust.exe"), b"new image").unwrap();
            }
            let outcome = recover_pending(&root, &[(path, journal)], false, &FixtureTrust).unwrap();
            assert_eq!(outcome["recovered"], true);
            assert_eq!(outcome["restart_required"], applying);
            assert_eq!(
                fs::read(root.join("bin/zapret-rust.exe")).unwrap(),
                b"old image"
            );
            if applying {
                assert!(
                    outcome["text"]
                        .as_str()
                        .unwrap()
                        .contains("Откройте zapret-rust заново")
                );
            }
        }
    }
    #[test]
    fn native_archive_is_reproducible_and_contains_catalog_without_runtime_data() {
        let inputs = BTreeMap::from([
            ("LICENSE".into(), b"license".to_vec()),
            (
                "bin/zapret-rust.exe".into(),
                b"native executable fixture".to_vec(),
            ),
        ]);
        let bytes = build_archive(&inputs).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(bytes, build_archive(&inputs).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("native.zip");
        fs::write(&path, bytes).unwrap();
        let source = temp.path().join("source");
        let names = extract_archive(&path, &source).unwrap();
        assert_eq!(names, vec!["LICENSE", "bin/zapret-rust.exe", CATALOG]);
        let manifest: PackageManifest =
            serde_json::from_slice(&fs::read(source.join(CATALOG)).unwrap()).unwrap();
        verify_catalog(&source, &names, &manifest).unwrap();
    }
    #[test]
    fn native_commit_checks_all_sources_first_and_retains_backup_for_crash_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let root = temp.path().join("root");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(source.join("a.txt"), b"new a").unwrap();
        fs::write(source.join("b.txt"), b"new b").unwrap();
        fs::write(root.join("a.txt"), b"old a").unwrap();
        let dir = root.join("runtime/update").join("c".repeat(32));
        let mut journal = prepare_transaction(
            &source,
            &root,
            &dir,
            &["a.txt".into(), "b.txt".into()],
            &[],
            false,
            &FixtureTrust,
        )
        .unwrap();
        fs::write(source.join("b.txt"), b"tampered before apply").unwrap();
        assert!(apply_prepared(&root, &source, &dir, &mut journal, &FixtureTrust).is_err());
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"old a");
        fs::write(source.join("b.txt"), b"new b").unwrap();
        fs::write(
            dir.join("backup/a.txt"),
            b"damaged before first replacement",
        )
        .unwrap();
        assert!(apply_prepared(&root, &source, &dir, &mut journal, &FixtureTrust).is_err());
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"old a");
        assert_eq!(journal.state, "Prepared");
        fs::write(dir.join("backup/a.txt"), b"old a").unwrap();
        apply_prepared(&root, &source, &dir, &mut journal, &FixtureTrust).unwrap();
        assert_eq!(journal.state, "Committed");
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"new a");
        assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"new b");
        assert_eq!(fs::read(dir.join("backup/a.txt")).unwrap(), b"old a");
        assert_eq!(
            fs::read(root.join("runtime/update-restart.txt")).unwrap(),
            b""
        );
        assert!(!restore_journal(&root, &dir.join("journal.json"), &FixtureTrust).unwrap());
    }
    #[test]
    fn github_release_requires_native_asset_and_authoritative_sha256() {
        let release = json!({"tag_name":"v2.3","assets":[{"name":"zapret-rust-native-v2.3.zip","browser_download_url":"https://github.com/chepi228/zapret-rust/releases/download/v2.3/zapret-rust-native-v2.3.zip","digest":format!("sha256:{}","a".repeat(64)),"size":12345}]});
        assert_eq!(parse_release(&release).unwrap().unwrap().tag, "v2.3");
        let mut bad = release.clone();
        bad["assets"][0]["browser_download_url"] = json!("https://example.org/archive.zip");
        assert!(parse_release(&bad).is_err());
        let mut bad = release.clone();
        bad["assets"][0]["digest"] = json!("");
        assert!(parse_release(&bad).is_err());
        let mut old = release;
        old["assets"][0]["name"] = json!("zapret-v2.3.zip");
        assert!(parse_release(&old).unwrap().is_none());
    }
    #[test]
    fn unknown_process_ownership_never_becomes_a_safe_stopped_update_state() {
        for status in [
            json!({"running":false}),
            json!({"known":false,"ownership_known":false,"running":false}),
            json!({"known":true,"ownership_known":false,"running":false}),
            json!({"known":false,"ownership_known":true,"running":false}),
        ] {
            assert!(confirmed_running(&status).is_err(), "{status}");
        }
        assert!(
            !confirmed_running(&json!({"known":true,"ownership_known":true,"running":false}))
                .unwrap()
        );
        assert!(
            confirmed_running(&json!({"known":true,"ownership_known":true,"running":true}))
                .unwrap()
        );
    }
}
