use super::{download_entry, list_content, list_path, pc_check, update_lists, worker_lease};
use crate::{App, runtime_file};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path};
use zapret_core::{atomic_write, read_bounded, read_text};
use zapret_platform::ControlGuard;

const BUNDLED_IPSET: &[u8] = include_bytes!("../../../../lists/ipset-all.txt");
const SNAPSHOTS: &[(&str, &[u8])] = &[
    ("ipset-all.txt", BUNDLED_IPSET),
    (
        "ipset-exclude.txt",
        include_bytes!("../../../../lists/ipset-exclude.txt"),
    ),
    (
        "list-general.txt",
        include_bytes!("../../../../lists/list-general.txt"),
    ),
    (
        "list-google.txt",
        include_bytes!("../../../../lists/list-google.txt"),
    ),
    (
        "list-exclude.txt",
        include_bytes!("../../../../lists/list-exclude.txt"),
    ),
    (
        "hosts-flowseal.txt",
        include_bytes!("../../../../lists/hosts-flowseal.txt"),
    ),
];
const RETRY_SECONDS: i64 = 600;

#[derive(Default, Serialize, Deserialize)]
struct Progress {
    lists_updated: bool,
    compatibility_checked: bool,
    #[serde(default)]
    retry_after: i64,
}

// Old packages contained just a documentation address. A freshly extracted
// placeholder has today's mtime. Never use age to decide if it can serve games.
fn needs_seed(root: &Path, name: &str) -> Result<bool> {
    let path = list_path(root, name)?;
    if !path.try_exists()? {
        return Ok(true);
    }
    let mut unrecognized = false;
    for line in read_text(&path, 32 * 1024 * 1024)?.lines() {
        match list_content(line) {
            "" => (),
            "203.0.113.113" | "203.0.113.113/32" if name == "ipset-all.txt" => (),
            content if download_entry(name, content).is_ok() => return Ok(false),
            _ => unrecognized = true,
        }
    }
    anyhow::ensure!(
        !unrecognized,
        "В списке {name} не удалось распознать ни одной записи"
    );
    Ok(true)
}

pub(super) fn local_lists_ready(root: &Path) -> bool {
    SNAPSHOTS
        .iter()
        .all(|(name, _)| matches!(needs_seed(root, name), Ok(false)))
}

fn seed_missing(root: &Path) -> Result<()> {
    let _guard = ControlGuard::acquire(root, "first-run-lists")?;
    let mut errors = Vec::new();
    for &(name, snapshot) in SNAPSHOTS {
        if let Err(error) = needs_seed(root, name).and_then(|needed| {
            if needed {
                let path = list_path(root, name)?;
                fs::create_dir_all(path.parent().context("Папка списков")?)?;
                atomic_write(&path, snapshot)?;
            }
            Ok(())
        }) {
            errors.push(format!("{name} — {error:#}"));
        }
    }
    anyhow::ensure!(errors.is_empty(), "{}", errors.join(". "));
    Ok(())
}

fn last_update(root: &Path) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let path = runtime_file(root, "list-update-last.json").ok()?;
    let report: Value = serde_json::from_slice(&read_bounded(&path, 16 * 1024).ok()?).ok()?;
    if report["updated"] != true {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(report["updated_at"].as_str()?).ok()
}

pub(crate) fn lists_status(root: &Path) -> String {
    last_update(root).map_or_else(
        || "локальные копии".into(),
        |date| {
            format!(
                "обновлены {}",
                date.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M")
            )
        },
    )
}

pub(crate) fn run(app: &App, notify: impl FnMut(&str)) -> Result<Value> {
    run_with(
        &app.root,
        chrono::Utc::now().timestamp(),
        notify,
        || update_lists(app, 12000, || Ok(())).map(|_| ()),
        || pc_check(app),
    )
}

fn run_with(
    root: &Path,
    now: i64,
    mut notify: impl FnMut(&str),
    update: impl FnOnce() -> Result<()>,
    check: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let path = runtime_file(root, "first-run-v1.json")?;
    let Some(_lease) = worker_lease(root, "first-run-native.lock")? else {
        return Ok(
            json!({"busy":true,"complete":false,"text":"Первую настройку выполняет другое окно zapret-rust."}),
        );
    };
    let mut state: Progress = if path.try_exists()? {
        serde_json::from_slice(&read_bounded(&path, 4096)?).unwrap_or_default()
    } else {
        Progress::default()
    };
    let usable = local_lists_ready(root);
    let missing_report = !runtime_file(root, "pc-check-last.json")?.is_file();
    if (state.lists_updated && !usable) || (state.compatibility_checked && missing_report) {
        state.lists_updated &= usable;
        state.compatibility_checked &= !missing_report;
        atomic_write(&path, &serde_json::to_vec(&state)?)?;
    }
    // A manual refresh from Settings also completes a pending first-run download.
    if !state.lists_updated
        && usable
        && state.retry_after > 0
        && last_update(root)
            .is_some_and(|time| time.timestamp() >= state.retry_after.saturating_sub(RETRY_SECONDS))
    {
        state.lists_updated = true;
        state.retry_after = 0;
        atomic_write(&path, &serde_json::to_vec(&state)?)?;
    }
    if state.lists_updated && state.compatibility_checked {
        return Ok(
            json!({"complete":true,"already_complete":true,"lists_updated":true,"lists_usable":true,"compatibility_checked":true,"text":"Первая настройка уже выполнена."}),
        );
    }
    let mut lines = Vec::new();
    let delay = state.retry_after.saturating_sub(now);
    if !state.lists_updated && usable && (1..=RETRY_SECONDS).contains(&delay) {
        lines.push("Используются локальные списки. Обновить их сейчас можно в меню 7 → 8.".into());
    } else if !state.lists_updated {
        notify("Первый запуск. Обновляю списки адресов…");
        if !usable {
            if let Err(error) = seed_missing(root) {
                lines.push(format!(
                    "Не удалось подготовить локальные списки ({error:#})."
                ));
            }
        }
        match update() {
            Ok(()) => {
                state.lists_updated = true;
                state.retry_after = 0;
                atomic_write(&path, &serde_json::to_vec(&state)?)?;
                lines.push("Списки адресов обновлены.".to_owned());
            }
            Err(error) => {
                if local_lists_ready(root) {
                    state.retry_after = now.saturating_add(RETRY_SECONDS);
                    lines.push(format!("Используются локальные списки. Автоповтор доступен через 10 минут при открытии меню, ручной — в 7 → 8 ({error:#})."));
                } else {
                    state.retry_after = 0;
                    lines.push(format!("Часть общих списков недоступна. При следующем открытии программа повторит загрузку ({error:#})."));
                }
                atomic_write(&path, &serde_json::to_vec(&state)?)?;
            }
        }
    }
    if !state.compatibility_checked {
        notify("Проверяю совместимость и сетевые конфликты…");
        match check().and_then(|report| {
            let others = report["conflicts"]["foreign_bypass"]
                .as_array()
                .context("не удалось проверить процессы обхода")?;
            let intact = report["integrity"]["ok"]
                .as_bool()
                .context("не удалось проверить целостность файлов")?;
            if !intact {
                lines.push("Проверка целостности обнаружила повреждённые файлы.".into());
            }
            if !others.is_empty() || report["conflicts"]["foreign_service"] == true {
                lines.push(
                    "Другой обход или его служба обнаружены. Подробности доступны в пункте 6."
                        .into(),
                );
            }
            if report["conflicts"]["tun_adapters"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                lines.push("Обнаружен активный VPN-туннель.".into());
            }
            Ok(())
        }) {
            Ok(()) => {
                lines.push("Отчёт о совместимости сохранён в runtime\\pc-check-last.json.".into());
                state.compatibility_checked = true;
                atomic_write(&path, &serde_json::to_vec(&state)?)?;
            }
            Err(error) => lines.push(format!(
                "Проверка совместимости будет повторена при следующем запуске ({error:#})."
            )),
        }
    }
    Ok(
        json!({"complete":state.lists_updated && state.compatibility_checked,
        "lists_usable":local_lists_ready(root),"lists_updated":state.lists_updated,"retry_after":state.retry_after,
        "compatibility_checked":state.compatibility_checked,"text":lines.join("\n")}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    // These fixtures exercise the actual Windows system-wide control mutex.
    static CONTROL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn scheduled_selection_uses_available_lists_during_an_upstream_outage() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("lists"))?;
        fs::create_dir(root.join("runtime"))?;
        let run =
            || super::super::refresh_for_autotune(root, || anyhow::bail!("upstream unavailable"));
        assert!(run().is_err());
        for &(name, bytes) in SNAPSHOTS {
            fs::write(root.join("lists").join(name), bytes)?;
        }
        run()?;
        assert!(read_text(&root.join("runtime/autotune.log"), 4096)?.contains("локальные списки"));
        Ok(())
    }

    #[test]
    fn fresh_placeholder_offline_keeps_working_seed_and_retries_only_the_download() -> Result<()> {
        let _serial = CONTROL.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("lists"))?;
        fs::write(
            root.join("lists/ipset-all.txt"),
            b"# fresh ZIP\r\n203.0.113.113/32\r\n",
        )?;
        fs::write(root.join("lists/ipset-user.txt"), b"custom")?;
        let checks = Cell::new(0);
        let check = || {
            checks.set(checks.get() + 1);
            let report = json!({"conflicts":{"foreign_bypass":[{}]},"integrity":{"ok":true}});
            atomic_write(
                &root.join("runtime/pc-check-last.json"),
                &serde_json::to_vec(&report)?,
            )?;
            Ok(report)
        };
        let first = run_with(root, 1000, |_| {}, || anyhow::bail!("offline"), check)?;
        assert_eq!(first["complete"], false);
        assert_eq!(first["lists_usable"], true);
        assert!(first["text"].as_str().unwrap().contains("Другой обход"));
        assert_eq!(fs::read(root.join("lists/ipset-all.txt"))?, BUNDLED_IPSET);
        assert!(local_lists_ready(root));
        let cached = run_with(
            root,
            1030,
            |_| panic!("cooldown"),
            || panic!("download"),
            check,
        )?;
        assert_eq!(cached["complete"], false);
        assert_eq!(cached["lists_usable"], true);
        let second = run_with(root, 1600, |_| {}, || Ok(()), check)?;
        assert_eq!(second["complete"], true);
        let third = run_with(
            root,
            1601,
            |_| panic!("repeated first run"),
            || panic!("download"),
            check,
        )?;
        assert_eq!(third["already_complete"], true);
        assert_eq!(checks.get(), 1);
        assert_eq!(fs::read(root.join("lists/ipset-user.txt"))?, b"custom");
        Ok(())
    }

    #[test]
    fn incomplete_local_inventory_retries_the_check_without_replacing_existing_ips() -> Result<()> {
        let _serial = CONTROL.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("lists"))?;
        let custom = b"; existing\n8.8.8.8/32\n";
        fs::write(root.join("lists/ipset-all.txt"), custom)?;
        let first = run_with(
            root,
            1000,
            |_| {},
            || Ok(()),
            || Ok(json!({"conflicts":{"status":"Unavailable"},"integrity":{"ok":true}})),
        )?;
        assert_eq!(first["complete"], false);
        let next = run_with(
            root,
            1001,
            |_| {},
            || panic!("download repeated"),
            || {
                let report = json!({"conflicts":{"foreign_bypass":[]},"integrity":{"ok":false}});
                atomic_write(
                    &root.join("runtime/pc-check-last.json"),
                    &serde_json::to_vec(&report)?,
                )?;
                Ok(report)
            },
        )?;
        assert_eq!(next["complete"], true);
        assert!(next["text"].as_str().unwrap().contains("целостност"));
        assert_eq!(fs::read(root.join("lists/ipset-all.txt"))?, custom);
        Ok(())
    }

    #[test]
    fn legacy_unicode_lists_keep_custom_networks_and_recognize_the_old_placeholder() -> Result<()> {
        let _serial = CONTROL.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("lists"))?;
        let path = root.join("lists/ipset-all.txt");
        for bom in [&[0xff, 0xfe][..], &[0xfe, 0xff][..]] {
            for (address, placeholder) in [("203.0.113.113/32", true), ("2001:4860::/32", false)] {
                let bytes = super::super::text_with_original_encoding(
                    &format!("# адреса\r\n{address}\r\n"),
                    bom,
                );
                fs::write(&path, &bytes)?;
                assert_eq!(needs_seed(root, "ipset-all.txt")?, placeholder);
                seed_missing(root)?;
                if !placeholder {
                    assert_eq!(fs::read(&path)?, bytes);
                }
                assert!(local_lists_ready(root));
            }
        }
        Ok(())
    }

    #[test]
    fn missing_shared_file_is_repaired_even_after_completion_and_offline_cooldown() -> Result<()> {
        let _serial = CONTROL.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        seed_missing(root)?;
        for (&(name, _), &(expected, _)) in SNAPSHOTS.iter().zip(&super::super::LISTS) {
            assert_eq!(name, expected);
        }
        assert_eq!(SNAPSHOTS.len(), super::super::LISTS.len());
        let report = runtime_file(root, "pc-check-last.json")?;
        atomic_write(&report, b"{}")?;
        atomic_write(
            &runtime_file(root, "first-run-v1.json")?,
            br#"{"lists_updated":true,"compatibility_checked":true}"#,
        )?;
        let path = root.join("lists/list-google.txt");
        let original = fs::read(&path)?;
        fs::remove_file(&path)?;
        let value = run_with(
            root,
            2000,
            |_| {},
            || anyhow::bail!("offline"),
            || panic!("check repeated"),
        )?;
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(value["lists_usable"], true);
        assert_eq!(value["lists_updated"], false);
        let receipt = runtime_file(root, "list-update-last.json")?;
        atomic_write(
            &receipt,
            br#"{"updated":true,"updated_at":"1970-01-01T00:33:30Z"}"#,
        )?;
        let manual = run_with(
            root,
            2011,
            |_| panic!("manual refresh ignored"),
            || panic!(),
            || panic!(),
        )?;
        assert_eq!(manual["already_complete"], true);
        Ok(())
    }

    #[test]
    fn unreadable_shared_list_still_allows_pc_check_and_other_offline_repairs() -> Result<()> {
        let _serial = CONTROL.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("lists"))?;
        let bytes = b"\xff\xfe\x42";
        fs::write(root.join("lists/ipset-all.txt"), bytes)?;
        let checked = Cell::new(false);
        let value = run_with(
            root,
            1000,
            |_| {},
            || anyhow::bail!("offline"),
            || {
                checked.set(true);
                Ok(json!({"conflicts":{"foreign_bypass":[]},"integrity":{"ok":true}}))
            },
        )?;
        assert!(checked.get());
        assert_eq!(value["lists_usable"], false);
        assert_eq!(fs::read(root.join("lists/ipset-all.txt"))?, bytes);
        assert!(root.join("lists/list-general.txt").is_file());
        Ok(())
    }
}
