pub(crate) use crate::scheduler::Action;
use crate::{process::same_path, scheduler, storage::no_reparse};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use windows_sys::{Win32::Foundation::ERROR_FILE_NOT_FOUND, core::HRESULT};
pub(crate) const LEGACY_AUTOTUNE: &str = "NBA2K27-zapret2 autotune";

fn kind(args: &Value) -> Result<&str> {
    let k = args["kind"].as_str().context("Task kind is required")?;
    ensure!(
        ["autotune", "notify", "telegram", "watch"].contains(&k),
        "Unsupported task kind"
    );
    Ok(k)
}
fn name(kind: &str) -> &str {
    // Registration IDs stay stable across the product rename; XML uses zapret-rust branding.
    match kind {
        "autotune" => "zapret autotune",
        "notify" => "zapret notify",
        "telegram" => "zapret telegram",
        _ => "zapret network watch",
    }
}
fn telegram_name(root: &Path) -> String {
    let hash = crate::storage::hash(crate::process::path_key(root).as_bytes());
    format!("{} {}", name("telegram"), &hash[..24])
}
pub(crate) fn executable(root: &Path, args: &Value) -> Result<PathBuf> {
    let p = if let Some(s) = args["executable"].as_str() {
        PathBuf::from(s)
    } else {
        let bin = root.join("bin/zapret-rust.exe");
        if bin.is_file() {
            bin
        } else {
            std::env::current_exe()?
        }
    };
    ensure!(
        p.is_absolute(),
        "Native task executable must have an absolute path"
    );
    no_reparse(&p)?;
    ensure!(
        p.is_file(),
        "Native task executable is missing: {}",
        p.display()
    );
    Ok(p)
}
fn arguments(root: &Path, kind: &str) -> Vec<String> {
    let mut args = vec!["--root".into(), root.to_string_lossy().into_owned()];
    args.extend(
        match kind {
            "autotune" => vec!["autotune"],
            "notify" => vec!["notify", "--watch"],
            "telegram" => vec!["telegram", "supervise"],
            _ => vec!["watch"],
        }
        .into_iter()
        .map(String::from),
    );
    args
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn task_action(root: &Path, kind: &str, args: &Value) -> Result<(PathBuf, Vec<String>)> {
    let executable = if args["executable"].as_str().is_some() {
        executable(root, args)?
    } else if ["notify", "telegram"].contains(&kind) {
        root.join("bin/zapret-rust-worker.exe")
    } else {
        // SYSTEM maintenance can restore a detached engine. Keep it outside
        // the GUI host's kill-on-close job so that engine survives the task.
        root.join("bin/zapret-rust.exe")
    };
    Ok((executable, arguments(root, kind)))
}
fn native_owned(root: &Path, kind: &str, command: &str, actual: &[String]) -> Result<bool> {
    let expected = arguments(root, kind);
    // Accept exact registrations of the previous native filenames for migration only.
    // New registrations always use task_action's zapret-rust images in this same root.
    let controller = |path: &Path| {
        ["bin/zapret-rust.exe", "bin/zapret.exe"]
            .iter()
            .any(|name| same_path(path, &root.join(name)))
    };
    let worker = |path: &Path| {
        ["bin/zapret-rust-worker.exe", "bin/zapret-worker.exe"]
            .iter()
            .any(|name| same_path(path, &root.join(name)))
    };
    if actual == expected
        && (controller(Path::new(command))
            || ["notify", "telegram"].contains(&kind) && worker(Path::new(command)))
    {
        return Ok(true);
    }
    if !["notify", "telegram"].contains(&kind) || actual.len() < 2 || actual[0] != "--headless" {
        return Ok(false);
    }
    // Inspect previous native registrations without launching conhost again.
    Ok(same_path(
        Path::new(command),
        &crate::system::system_directory()?.join("conhost.exe"),
    ) && controller(Path::new(&actual[1]))
        && actual[2..] == expected)
}
pub(crate) fn specification(root: &Path, args: &Value) -> Result<String> {
    let k = kind(args)?;
    let (exe, parameters) = task_action(root, k, args)?;
    ensure!(
        exe.is_absolute() && exe.is_file(),
        "Native background worker is missing: {}",
        exe.display()
    );
    no_reparse(&exe)?;
    let sid = crate::control::current_sid()?;
    let principal = if ["autotune", "watch"].contains(&k) {
        // The XML schema infers the service-account logon from the SYSTEM SID;
        // ServiceAccount is only valid in the registration API enum.
        r#"<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>"#.into()
    } else {
        format!(
            "<UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>"
        )
    };
    let triggers = if k == "autotune" {
        "<CalendarTrigger><StartBoundary>2026-01-01T04:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>".into()
    } else if k == "watch" {
        "<BootTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></BootTrigger><LogonTrigger><Enabled>true</Enabled></LogonTrigger>".into()
    } else {
        format!(
            "<LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger><TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>"
        )
    };
    let idle = if k == "autotune" {
        "<IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT6H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><RunOnlyIfIdle>true</RunOnlyIfIdle>"
    } else {
        "<RunOnlyIfIdle>false</RunOnlyIfIdle>"
    };
    let limit = if k == "autotune" { "PT30M" } else { "PT0S" };
    let args = zapret_core::windows_command_line(&parameters);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>zapret-rust: {k}</Description></RegistrationInfo><Triggers>{triggers}</Triggers><Principals><Principal id="Author">{principal}</Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>{idle}<ExecutionTimeLimit>{limit}</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure><Enabled>true</Enabled><Hidden>true</Hidden></Settings><Actions Context="Author"><Exec><Command>{}</Command><Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions></Task>"#,
        escape(&exe.to_string_lossy()),
        escape(&args),
        escape(&root.to_string_lossy())
    ))
}
fn legacy_owned(root: &Path, kind: &str, command: &str, args: &[String]) -> Result<bool> {
    let system = crate::system::system_directory()?;
    let ps = system.join("WindowsPowerShell/v1.0/powershell.exe");
    let mut args = args.to_vec();
    let executable = if same_path(Path::new(command), &system.join("conhost.exe")) {
        if args.len() < 2 || args[0] != "--headless" {
            return Ok(false);
        }
        let executable = PathBuf::from(args.remove(1));
        args.remove(0);
        executable
    } else {
        PathBuf::from(command)
    };
    if !same_path(&executable, &ps) {
        return Ok(false);
    }
    let script = root.join("tools").join(match kind {
        "autotune" => "autotune.ps1",
        "notify" => "notify.ps1",
        "telegram" => "tgbridge.ps1",
        _ => "netwatch.ps1",
    });
    let mut expected = vec![
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ];
    if kind == "watch" {
        expected.retain(|p| *p != "-NonInteractive");
    }
    if kind == "autotune" {
        expected.extend(["-WindowStyle", "Hidden"]);
    }
    expected.push("-File");
    if args.len() != expected.len() + 1 {
        return Ok(false);
    }
    Ok(args
        .iter()
        .take(expected.len())
        .zip(expected)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
        && same_path(Path::new(args.last().unwrap()), &script))
}
pub(crate) fn status(root: &Path, args: &Value) -> Result<Value> {
    let k = kind(args)?;
    if k == "telegram" {
        telegram_status(root, |task| status_named(root, args, task))
    } else {
        status_named(root, args, name(k))
    }
}
fn telegram_status(root: &Path, mut lookup: impl FnMut(&str) -> Result<Value>) -> Result<Value> {
    let scoped = lookup(&telegram_name(root))?;
    if task_absent(&scoped) {
        let shared = lookup(name("telegram"))?;
        if task_owned(&shared) {
            return Ok(shared);
        }
    }
    Ok(scoped)
}
pub(crate) fn legacy_status(root: &Path, args: &Value) -> Result<Value> {
    let mut arguments = args.clone();
    arguments["kind"] = json!("autotune");
    status_named(root, &arguments, LEGACY_AUTOTUNE)
}
fn status_named(root: &Path, args: &Value, task_name: &str) -> Result<Value> {
    let k = kind(args)?;
    let xml = match scheduler::query(task_name)? {
        scheduler::TaskQuery::Registered(xml) => xml,
        scheduler::TaskQuery::LookupError(error) => {
            return Ok(failed_lookup(
                k,
                task_name,
                error,
                registry_task_status(task_name)?,
            ));
        }
    };
    registered_status(root, args, k, task_name, &xml)
}

fn registered_status(
    root: &Path,
    args: &Value,
    k: &str,
    task_name: &str,
    xml: &str,
) -> Result<Value> {
    let doc = roxmltree::Document::parse(xml)?;
    let execs = doc
        .descendants()
        .filter(|n| n.has_tag_name("Exec"))
        .collect::<Vec<_>>();
    let (expected, expected_arguments) = task_action(root, k, args)?;
    let action_count = doc
        .descendants()
        .filter(|n| n.has_tag_name("Actions"))
        .flat_map(|n| n.children().filter(|n| n.is_element()))
        .count();
    let mut owned = execs.len() == 1 && action_count == 1;
    let mut legacy = false;
    let mut command = String::new();
    let mut parameters = String::new();
    let mut working = String::new();
    if let Some(exec) = execs.first() {
        for n in exec.children().filter(|n| n.is_element()) {
            match n.tag_name().name() {
                "Command" => command = n.text().unwrap_or("").into(),
                "Arguments" => parameters = n.text().unwrap_or("").into(),
                "WorkingDirectory" => working = n.text().unwrap_or("").into(),
                _ => {}
            }
        }
        let mut actual = crate::service::argv(&format!("\"{command}\" {parameters}"))?;
        if !actual.is_empty() {
            actual.remove(0);
        }
        let current = same_path(Path::new(&command), &expected) && actual == expected_arguments;
        let native = native_owned(root, k, &command, &actual)?;
        let script = legacy_owned(root, k, &command, &actual)?;
        owned &= same_path(Path::new(&working), root) && (current || native || script);
        legacy = owned && !current && (native || script);
    }
    let enabled = match doc
        .root_element()
        .children()
        .find(|node| node.has_tag_name("Settings"))
        .and_then(|settings| {
            settings
                .children()
                .find(|node| node.has_tag_name("Enabled"))
        })
        .and_then(|node| node.text())
        .map(str::trim)
    {
        Some("false" | "0") => false,
        Some("true" | "1") | None => true,
        Some(_) => anyhow::bail!("Invalid task Enabled value"),
    };
    Ok(
        json!({"kind":k,"name":task_name,"known":true,"exists":true,"owned":owned,"enabled":enabled,"legacy":legacy,"command":command,"arguments":parameters,"working_directory":working,"xml":xml}),
    )
}

fn failed_lookup(kind: &str, name: &str, error: HRESULT, registry_error: u32) -> Value {
    // Restricted task registrations may not be visible to a caller. An access
    // or service failure must never authorize replacing an existing task.
    let exists = match registry_error {
        ERROR_FILE_NOT_FOUND if error == scheduler::TASK_NOT_FOUND => Some(false),
        0 => Some(true),
        _ => None,
    };
    json!({"kind":kind,"name":name,"exists":exists,"known":exists == Some(false),"owned":false,
        "query_hresult":format!("0x{:08X}",error as u32),"registry_error":registry_error})
}

fn registry_task_status(name: &str) -> Result<u32> {
    use windows_sys::Win32::System::Registry::*;
    let name = crate::process::wide(format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{name}"
    ))?;
    let mut handle = std::ptr::null_mut();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut handle,
        )
    };
    if !handle.is_null() {
        unsafe {
            RegCloseKey(handle);
        }
    }
    Ok(result)
}

pub(crate) fn legacy_present() -> Result<bool> {
    let result = registry_task_status(LEGACY_AUTOTUNE)?;
    ensure!(
        result == 0 || result == ERROR_FILE_NOT_FOUND,
        "Legacy task presence is unknown: {result}"
    );
    Ok(result == 0)
}
pub(crate) fn remove_legacy(root: &Path, args: &Value, before: &Value) -> Result<()> {
    ensure!(
        before["known"] == true && before["exists"] == true && before["owned"] == true,
        "Прежняя задача принадлежит другой папке; перенос отменён"
    );
    scheduler::action(LEGACY_AUTOTUNE, task_xml(before)?, Action::Delete)?;
    ensure!(
        task_absent(&legacy_status(root, args)?),
        "Legacy task removal is unconfirmed"
    );
    Ok(())
}
pub(crate) fn install(root: &Path, args: &Value) -> Result<Value> {
    let old = status(root, args)?;
    let xml = specification(root, args)?;
    register_xml(root, args, &xml, &old)
}

fn task_absent(state: &Value) -> bool {
    state["known"] == true && state["exists"] == false
}
fn task_owned(state: &Value) -> bool {
    state["known"] == true && state["exists"] == true && state["owned"] == true
}
fn observed_name<'a>(root: &Path, kind: &str, state: &'a Value) -> Result<&'a str> {
    let observed = state["name"]
        .as_str()
        .context("Нет имени проверенной задачи")?;
    ensure!(
        observed == name(kind) || (kind == "telegram" && observed == telegram_name(root)),
        "Имя задачи не соответствует папке установки"
    );
    Ok(observed)
}

fn task_xml(state: &Value) -> Result<&str> {
    state["xml"].as_str().context("Нет XML определения задачи")
}

fn register_xml(root: &Path, args: &Value, xml: &str, before: &Value) -> Result<Value> {
    let k = kind(args)?;
    ensure!(
        task_absent(before) || task_owned(before),
        "Владелец задачи изменился; регистрация отменена"
    );
    let previous_xml = (!task_absent(before))
        .then(|| task_xml(before))
        .transpose()?;
    register_checked(
        root,
        args,
        observed_name(root, k, before)?,
        xml,
        previous_xml,
    )
}

fn register_checked(
    root: &Path,
    args: &Value,
    task_name: &str,
    xml: &str,
    previous_xml: Option<&str>,
) -> Result<Value> {
    crate::package::require_protected(root)?;
    let registered = scheduler::register(task_name, xml, previous_xml)?;
    let result = (|| {
        registered.verify()?;
        let result = status_named(root, args, task_name)?;
        ensure!(
            result["known"] == true
                && result["owned"] == true
                && result["xml"].as_str() == Some(registered.xml.as_str()),
            "Принадлежность зарегистрированной задачи не подтверждена"
        );
        Ok(result)
    })();
    if let Err(error) = result {
        let restore = match previous_xml {
            Some(previous) => scheduler::register(task_name, previous, Some(&registered.xml))
                .and_then(|restored| restored.verify()),
            None => scheduler::action(task_name, &registered.xml, Action::Delete),
        };
        if let Err(restore) = restore {
            return Err(error.context(format!("Не удалось вернуть прежнюю задачу: {restore:#}")));
        }
        return Err(error);
    }
    result
}

fn relocated_task_xml(
    root: &Path,
    previous: &Path,
    k: &str,
    state: &Value,
) -> Result<Option<String>> {
    ensure!(
        state["known"] == true,
        "Не удалось проверить владельца задачи при переносе папки"
    );
    if state["exists"] == false || state["owned"] == true {
        return Ok(None);
    }
    let command = state["command"].as_str().unwrap_or("");
    let parameters = state["arguments"].as_str().unwrap_or("");
    let working = state["working_directory"].as_str().unwrap_or("");
    let mut actual = crate::service::argv(&format!("\"{command}\" {parameters}"))?;
    if !actual.is_empty() {
        actual.remove(0);
    }
    if !same_path(Path::new(working), previous) || !native_owned(previous, k, command, &actual)? {
        return Ok(None);
    }
    let xml = state["xml"]
        .as_str()
        .context("Нет XML переносимой задачи")?;
    let doc = roxmltree::Document::parse(xml)?;
    if doc
        .descendants()
        .filter(|node| node.has_tag_name("Exec"))
        .count()
        != 1
        || doc
            .descendants()
            .filter(|node| node.has_tag_name("Actions"))
            .flat_map(|node| node.children().filter(|node| node.is_element()))
            .count()
            != 1
    {
        return Ok(None);
    }
    let (command, parameters) = task_action(root, k, &json!({"kind":k}))?;
    let parameters = zapret_core::windows_command_line(&parameters);
    let mut edits = Vec::new();
    for field in doc
        .descendants()
        .filter(|node| node.has_tag_name("Exec"))
        .flat_map(|node| node.children().filter(|node| node.is_element()))
        .filter(|node| {
            ["Command", "Arguments", "WorkingDirectory"].contains(&node.tag_name().name())
        })
    {
        for text in field.children().filter(|node| node.is_text()) {
            edits.push((
                text.range(),
                escape(&match field.tag_name().name() {
                    "Command" => command.to_string_lossy().into_owned(),
                    "Arguments" => parameters.clone(),
                    _ => root.to_string_lossy().into_owned(),
                }),
            ));
        }
    }
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut rewritten = xml.to_owned();
    for (range, replacement) in edits {
        rewritten.replace_range(range, &replacement);
    }
    Ok(Some(rewritten))
}

pub(crate) fn relocate(root: &Path, previous: &Path, k: &str) -> Result<()> {
    let args = json!({"kind":k});
    kind(&args)?;
    if k == "telegram" {
        let old_name = telegram_name(previous);
        let before = status_named(root, &args, &old_name)?;
        if let Some(xml) = relocated_task_xml(root, previous, k, &before)? {
            return relocate_scoped_telegram(root, &args, &old_name, &before, &xml);
        }
    }
    let before = status_named(root, &args, name(k))?;
    let Some(xml) = relocated_task_xml(root, previous, k, &before)? else {
        return Ok(());
    };
    let old_xml = task_xml(&before)?;
    crate::relocation::backup_task(root, k, old_xml)?;
    crate::package::require_protected(root)?;
    scheduler::action(name(k), old_xml, Action::Stop)?;
    let after = register_checked(root, &args, name(k), &xml, Some(old_xml))?;
    ensure!(
        after["owned"] == true && after["enabled"] == before["enabled"],
        "Перенос задачи или её сохранённый режим не подтверждён"
    );
    Ok(())
}
fn relocate_scoped_telegram(
    root: &Path,
    args: &Value,
    old_name: &str,
    before: &Value,
    xml: &str,
) -> Result<()> {
    let new_name = telegram_name(root);
    let destination = status_named(root, args, &new_name)?;
    ensure!(
        task_absent(&destination)
            || (task_owned(&destination) && destination["enabled"] == before["enabled"]),
        "Новая задача Telegram уже существует с другим владельцем или режимом"
    );
    let old_xml = task_xml(before)?;
    crate::relocation::backup_task(root, "telegram", old_xml)?;
    crate::package::require_protected(root)?;
    scheduler::action(old_name, old_xml, Action::Stop)?;
    if task_absent(&destination) {
        let after = register_checked(root, args, &new_name, xml, None)?;
        ensure!(
            after["enabled"] == before["enabled"],
            "Режим задачи Telegram изменился"
        );
    }
    // Keep the old registration until the replacement is verified. A retry
    // after a failed deletion can reuse that already owned replacement.
    scheduler::action(old_name, old_xml, Action::Delete)?;
    ensure!(
        task_absent(&status_named(root, args, old_name)?),
        "Удаление прежней задачи Telegram не подтверждено"
    );
    Ok(())
}
pub(crate) fn action(root: &Path, args: &Value, action: Action) -> Result<Value> {
    let state = status(root, args)?;
    action_checked(root, args, &state, action)
}

pub(crate) fn action_checked(
    root: &Path,
    args: &Value,
    state: &Value,
    action: Action,
) -> Result<Value> {
    let k = kind(args)?;
    if task_absent(state) {
        return Ok(state.clone());
    }
    ensure!(
        task_owned(state),
        "Задача принадлежит другой папке; действие отменено"
    );
    let task_name = observed_name(root, k, state)?;
    scheduler::action(task_name, task_xml(state)?, action)?;
    if matches!(action, Action::Delete) {
        let after = status_named(root, args, task_name)?;
        ensure!(task_absent(&after), "Удаление задачи не подтверждено");
        return Ok(after);
    }
    Ok(state.clone())
}

fn transaction(
    change: impl FnOnce() -> Result<Value>,
    persist: impl FnOnce(&Value) -> Result<()>,
    restore: impl FnOnce(&Value) -> Result<()>,
) -> Result<Value> {
    let value = change()?;
    if let Err(error) = persist(&value) {
        if let Err(restore) = restore(&value) {
            return Err(error.context(format!(
                "Не удалось восстановить прежнюю задачу и её настройку: {restore:#}"
            )));
        }
        return Err(error);
    }
    Ok(value)
}

pub(crate) fn configure(root: &Path, args: &Value) -> Result<Value> {
    let enabled = args["enabled"]
        .as_bool()
        .context("Нужно указать режим задачи")?;
    let _guard = crate::ControlGuard::acquire(root, "task-configure")?;
    crate::launch::allowed(root, args)?;
    let k = kind(args)?;
    let before = status(root, args)?;
    ensure!(
        before["known"] == true && (before["exists"] == false || before["owned"] == true),
        "Владелец задачи не подтверждён; переключение отменено"
    );
    let settings_path = root.join("runtime/settings.ini");
    no_reparse(&settings_path)?;
    let original = zapret_core::read_settings(root)?;
    let mut desired = original.clone();
    if k == "notify" {
        desired.set("notify", if enabled { "on" } else { "off" })?;
    }
    let mut outcome = transaction(
        || {
            if enabled {
                register_xml(root, args, &specification(root, args)?, &before)
            } else {
                action_checked(root, args, &before, Action::Delete)
            }
        },
        |value| {
            ensure!(
                value["known"] == true
                    && if enabled {
                        value["exists"] == true
                            && value["owned"] == true
                            && value["enabled"] == true
                    } else {
                        value["exists"] == false
                    },
                "Новое состояние задачи не подтверждено"
            );
            if k == "notify" {
                no_reparse(&settings_path)?;
                ensure!(
                    zapret_core::read_settings(root)? == original,
                    "Настройки изменились во время переключения задачи"
                );
                zapret_core::save_settings(root, &desired)?;
            }
            Ok(())
        },
        |applied| {
            if let Some(xml) = before["xml"].as_str() {
                if applied["xml"].as_str() != Some(xml) {
                    let restored = register_xml(root, args, xml, applied)?;
                    ensure!(
                        restored["enabled"] == before["enabled"],
                        "Прежний режим задачи не восстановлен"
                    );
                }
            } else if !task_absent(applied) {
                action_checked(root, args, applied, Action::Delete)?;
            }
            if k == "notify" {
                no_reparse(&settings_path)?;
                let current = zapret_core::read_settings(root)?;
                if current == desired {
                    zapret_core::save_settings(root, &original)?;
                } else {
                    ensure!(
                        current == original,
                        "Настройка уведомлений изменена другим окном; возврат отменён"
                    );
                }
            }
            Ok(())
        },
    )?;
    outcome["enabled"] = json!(enabled);
    outcome["kind"] = json!(k);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_keeps_a_verified_shared_task_and_isolates_other_installations() {
        let one = Path::new(r"C:\example\zapret");
        let two = Path::new(r"C:\example\zapret-beta");
        assert_ne!(telegram_name(one), telegram_name(two));
        assert_eq!(
            telegram_name(one),
            telegram_name(Path::new("c:/Example/Zapret"))
        );

        let shared = name("telegram");
        let scoped = telegram_name(two);
        for (known, exists, owned, expected) in [
            (true, json!(true), true, shared),
            (true, json!(true), false, scoped.as_str()),
            (false, Value::Null, false, scoped.as_str()),
            (true, json!(false), false, scoped.as_str()),
        ] {
            let result = telegram_status(two, |task| {
                if task == shared {
                    Ok(json!({"name":task,"known":known,"exists":exists,"owned":owned}))
                } else {
                    assert_eq!(task, scoped);
                    Ok(json!({"name":task,"known":true,"exists":false,"owned":false}))
                }
            })
            .unwrap();
            assert_eq!(result["name"], expected);
        }

        for owned in [true, false] {
            let result = telegram_status(two, |task| {
                assert_eq!(task, scoped);
                Ok(json!({"name":task,"known":true,"exists":true,"owned":owned}))
            })
            .unwrap();
            assert_eq!(result["owned"], owned);
        }
    }

    #[test]
    fn failed_lookup_distinguishes_missing_and_restricted_tasks() {
        use windows_sys::Win32::Foundation::{E_ACCESSDENIED, ERROR_ACCESS_DENIED};
        let missing = scheduler::TASK_NOT_FOUND;
        for (error, registry, exists, known) in [
            (missing, ERROR_FILE_NOT_FOUND, json!(false), true),
            (missing, 0, json!(true), false),
            (missing, ERROR_ACCESS_DENIED, Value::Null, false),
            (E_ACCESSDENIED, ERROR_FILE_NOT_FOUND, Value::Null, false),
        ] {
            let state = failed_lookup("notify", "zapret notify", error, registry);
            assert_eq!(state["exists"], exists);
            assert_eq!(state["known"], known);
            assert_eq!(state["owned"], false);
        }
    }

    #[test]
    fn scheduler_status_keeps_enabled_state_and_validates_the_only_action() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("пакет & backup");
        let executable = root.join("bin/zapret-rust.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(executable, b"controller fixture").unwrap();
        std::fs::write(root.join("bin/zapret-rust-worker.exe"), b"GUI host fixture").unwrap();
        let args = json!({"kind":"notify"});
        let xml = specification(&root, &args).unwrap();
        let disabled = xml.replace(
            "<Enabled>true</Enabled><Hidden>",
            "<Enabled>0</Enabled><Hidden>",
        );
        let state = registered_status(&root, &args, "notify", "zapret notify", &disabled).unwrap();
        assert_eq!(state["owned"], true);
        assert_eq!(state["enabled"], false);
        assert_eq!(state["xml"], disabled);

        let foreign = xml.replace("</Actions>", "<ComHandler/></Actions>");
        let state = registered_status(&root, &args, "notify", "zapret notify", &foreign).unwrap();
        assert_eq!(state["owned"], false);
        assert_eq!(state["enabled"], true);
    }
    #[test]
    fn product_rename_keeps_only_exact_previous_native_registrations_owned() {
        let root = Path::new("C:/zapret-rust");
        for kind in ["autotune", "notify", "telegram", "watch"] {
            let args = arguments(root, kind);
            assert!(native_owned(root, kind, "C:/zapret-rust/bin/zapret.exe", &args).unwrap());
            assert!(!native_owned(root, kind, "C:/foreign/bin/zapret.exe", &args).unwrap());
            assert_eq!(
                native_owned(root, kind, "C:/zapret-rust/bin/zapret-worker.exe", &args).unwrap(),
                ["notify", "telegram"].contains(&kind)
            );
            let mut extra = args;
            extra.push("--unexpected".into());
            assert!(!native_owned(root, kind, "C:/zapret-rust/bin/zapret.exe", &extra).unwrap());
        }
    }
    #[test]
    fn previous_native_conhost_tasks_remain_owned_until_reconfigured() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("bin")).unwrap();
        std::fs::write(
            root.path().join("bin/zapret-rust-worker.exe"),
            b"GUI fixture",
        )
        .unwrap();
        for kind in ["notify", "telegram"] {
            let args = json!({"kind":kind});
            let current = specification(root.path(), &args).unwrap();
            let mut previous = vec![
                "--headless".into(),
                root.path()
                    .join("bin/zapret-rust.exe")
                    .to_string_lossy()
                    .into_owned(),
            ];
            previous.extend(arguments(root.path(), kind));
            let xml = current
                .replace(
                    &escape(
                        &root
                            .path()
                            .join("bin/zapret-rust-worker.exe")
                            .to_string_lossy(),
                    ),
                    &escape(
                        &crate::system::system_directory()
                            .unwrap()
                            .join("conhost.exe")
                            .to_string_lossy(),
                    ),
                )
                .replace(
                    &escape(&zapret_core::windows_command_line(&arguments(
                        root.path(),
                        kind,
                    ))),
                    &escape(&zapret_core::windows_command_line(&previous)),
                );
            assert_eq!(
                registered_status(root.path(), &args, kind, name(kind), &xml).unwrap()["owned"],
                true
            );
            let previous_controller = current
                .replace("bin/zapret-rust-worker.exe", "bin/zapret.exe")
                .replace("bin\\zapret-rust-worker.exe", "bin\\zapret.exe");
            let old = registered_status(root.path(), &args, kind, name(kind), &previous_controller)
                .unwrap();
            assert_eq!(old["owned"], true);
            assert_eq!(old["legacy"], true);
            let extra = xml.replace("</Arguments>", " --unexpected</Arguments>");
            assert_eq!(
                registered_status(root.path(), &args, kind, name(kind), &extra).unwrap()["owned"],
                false
            );
        }
    }

    #[test]
    fn relocation_preserves_task_settings_and_rejects_other_actions_or_roots() {
        let previous = Path::new("C:/old & package");
        let root = Path::new("C:/new & package");
        for k in ["telegram", "watch", "notify", "autotune"] {
            let controller = previous.join("bin/zapret-rust.exe");
            let mut args = arguments(previous, k);
            let command = if ["telegram", "notify"].contains(&k) {
                let mut hidden = vec![
                    "--headless".into(),
                    controller.to_string_lossy().into_owned(),
                ];
                hidden.append(&mut args);
                args = hidden;
                crate::system::system_exe("conhost.exe").unwrap()
            } else {
                controller
            };
            let parameters = zapret_core::windows_command_line(&args);
            let xml = format!(
                "<Task><Settings><Enabled>false</Enabled></Settings><Actions><Exec><Command>{}</Command><Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions></Task>",
                escape(&command.to_string_lossy()),
                escape(&parameters),
                escape(&previous.to_string_lossy())
            );
            let mut state = json!({"known":true,"exists":true,"owned":false,"enabled":false,
                "command":command,"arguments":parameters,"working_directory":previous,"xml":xml});
            let moved = relocated_task_xml(root, previous, k, &state)
                .unwrap()
                .unwrap();
            assert!(moved.contains("C:/new &amp; package"));
            assert!(!moved.contains("C:/old &amp; package"));
            assert!(moved.contains("<Enabled>false</Enabled>"));
            state["arguments"] = json!("--unknown-command");
            assert!(
                relocated_task_xml(root, previous, k, &state)
                    .unwrap()
                    .is_none()
            );
            state["arguments"] = json!(parameters);
            state["xml"] = json!(xml.replace("</Actions>", "<ComHandler/></Actions>"));
            assert!(
                relocated_task_xml(root, previous, k, &state)
                    .unwrap()
                    .is_none()
            );
            state["known"] = json!(false);
            assert!(relocated_task_xml(root, previous, k, &state).is_err());
        }
    }
    #[test]
    fn failed_registration_never_persists_the_notification_flag() {
        let persisted = std::cell::Cell::new(false);
        let restored = std::cell::Cell::new(false);
        let result = transaction(
            || anyhow::bail!("registration failed"),
            |_| {
                persisted.set(true);
                Ok(())
            },
            |_| {
                restored.set(true);
                Ok(())
            },
        );
        assert!(result.is_err() && !persisted.get() && !restored.get());
    }
    #[test]
    fn failure_saving_preference_rolls_the_task_back() {
        let definition = std::cell::Cell::new("original");
        let result = transaction(
            || {
                definition.set("new");
                Ok(json!({"known":true}))
            },
            |_| anyhow::bail!("save denied"),
            |applied| {
                assert_eq!(applied["known"], true);
                definition.set("original");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(definition.get(), "original");
    }
}
