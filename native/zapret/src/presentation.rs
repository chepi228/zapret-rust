//! Human descriptions are derived from typed action context, never inferred
//! from a bare `removed`, `enabled` or `ok` flag belonging to another command.
use crate::cli::Action;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub(crate) operation: String,
    kind: Option<String>,
}

impl Context {
    pub fn platform(name: &str) -> Self {
        Self {
            operation: name.into(),
            kind: None,
        }
    }
}

pub fn for_action(action: &Action) -> Context {
    let operation = match action {
        Action::Menu | Action::MenuPreview { .. } => "menu",
        Action::Status => "status",
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
        Action::Strategies => "strategies",
        Action::Settings { .. } => "settings",
        Action::Compose { .. } => "compose",
        Action::Integrity => "integrity",
        Action::Probe { .. } => "probe",
        Action::Test(arguments) => {
            if arguments.last {
                "test-last"
            } else {
                "test"
            }
        }
        Action::Lab(_) => "lab",
        Action::ComparisonReport { .. } => "comparison-report",
        Action::Autotune { .. } => "autotune",
        Action::ConnectionCheck(_) => "connection",
        Action::Webcheck(_) => "web",
        Action::Voicecheck(_) => "voice",
        Action::Latency(_) => "latency",
        Action::ProviderCheck(_) => "provider-check",
        Action::ProviderInfo(_) => "provider",
        Action::Track { .. } => "track-report",
        Action::Scan { .. } => "scan",
        Action::Exclude { .. } => "exclude",
        Action::Report { .. } => "report",
        Action::Lists { .. } => "lists",
        Action::Update { recover, .. } => {
            if *recover {
                "update-recover"
            } else {
                "update"
            }
        }
        Action::Package { .. } => "package",
        Action::Service { action } => return Context::platform(&format!("service-{action}")),
        Action::Task { action, kind } => {
            return Context {
                operation: format!("task-{action}"),
                kind: Some(kind.clone()),
            };
        }
        Action::Telegram { action, .. } => return Context::platform(&format!("telegram-{action}")),
        Action::TelegramCore { .. } => "telegram-core",
        Action::Hosts { action, .. } => return Context::platform(&format!("hosts-{action}")),
        Action::System { action, .. } | Action::PlatformWorker { action, .. } => {
            return Context::platform(action);
        }
        Action::DirectRules { .. } => "direct-rules",
        Action::Diag { run, .. } => {
            if *run {
                "diag-run"
            } else {
                "diag-plan"
            }
        }
        Action::Notify { .. } => "notify-worker",
        Action::Watch => "watch",
        Action::Uninstall => "uninstall",
    };
    Context::platform(operation)
}

pub fn text(context: &Context, value: &Value) -> String {
    let operation = context.operation.as_str();
    match operation {
        "service-autostart" => {
            if value["known"] != true {
                return "Режим автозапуска не подтверждён.".into();
            }
            let Some(enabled) = value["enabled"].as_bool() else {
                return fallback(value);
            };
            let mut message = format!(
                "Автозапуск {}. {}",
                if enabled {
                    "включён"
                } else {
                    "отключён"
                },
                match value["running"].as_bool() {
                    Some(true) => "Обход продолжает работать.",
                    Some(false) => "Обход остановлен.",
                    None => "Состояние обхода не подтверждено.",
                }
            );
            if value["watch_task_error"].is_string() {
                message.push_str("\nФоновую задачу контроля настроить не удалось.");
            }
            return message;
        }
        "service-status"
            if value["known"] == true && value["installed"] == true && value["owned"] != true =>
        {
            return "Служба принадлежит другой папке или её владелец не подтверждён.".into();
        }
        "service-status" | "status" => return service_status(value),
        "service-install" => {
            return crate::control_feedback(
                value,
                if value["known"] != false
                    && value["ownership_known"] != false
                    && value["running"] == true
                    && value["processes"]
                        .as_array()
                        .is_some_and(|processes| processes.len() == 1)
                {
                    "Служба установлена. Обход запущен."
                } else {
                    "Запуск установленной службы не подтверждён."
                },
            );
        }
        "service-remove" if value["removed"] == true && value["known"] != false => {
            return "Служба удалена. Обход остановлен; автозапуск отключён.".into();
        }
        "task-status" | "task-install" | "task-remove" | "task-configure" => {
            let kind = context
                .kind
                .as_deref()
                .or_else(|| value["kind"].as_str())
                .unwrap_or("");
            let label = match kind {
                "notify" => "Уведомления Windows",
                "autotune" => "Автонастройка по расписанию",
                "watch" => "Фоновый контроль сети",
                "telegram" => "Автозапуск моста Telegram",
                _ => "Фоновая задача",
            };
            let (on, off) = match kind {
                "notify" => ("включены", "отключены"),
                "watch" | "telegram" => ("включён", "отключён"),
                _ => ("включена", "отключена"),
            };
            if value["known"] != true || (value["exists"] == true && value["owned"] != true) {
                return format!("{label}: состояние или владелец задачи не подтверждены.");
            }
            if value["exists"] == false || value["enabled"] == false {
                return format!("{label} {off}.");
            }
            if value["exists"] == true && value["enabled"] == true {
                return format!("{label} {on}.");
            }
            return format!("{label}: состояние не подтверждено.");
        }
        name if name.starts_with("telegram-") => return telegram(value, name),
        "hosts-set" => {
            if value["updated"] != true {
                return "Изменение hosts не подтверждено.".into();
            }
            let mut message = "Файл hosts обновлён.".to_owned();
            if value["flush_dns"].is_object()
                && (value["flush_dns"]["exit_code"] != 0
                    || value["flush_dns"]["timed_out"] != false)
            {
                message.push_str(" Но кэш DNS обновить не удалось.");
            }
            return message;
        }
        "prefer-ipv4" => {
            if value["known"] == false {
                return "Режим IPv4 не подтверждён.".into();
            }
            return match value["enabled"].as_bool() {
                Some(true) => "Предпочтение IPv4 включено.",
                Some(false) => "Предпочтение IPv4 отключено.",
                None => "Режим IPv4 не подтверждён.",
            }
            .into();
        }
        "discord-cache" => {
            let Some(rows) = value.as_array().filter(|rows| !rows.is_empty()) else {
                return "Кэш Discord не найден.".into();
            };
            return rows
                .iter()
                .map(|row| {
                    let name = row["name"].as_str().unwrap_or("Discord");
                    let count = row["cleared"].as_array().map_or(0, Vec::len);
                    if count == 0 {
                        format!("{name}: папок кэша не найдено.")
                    } else {
                        format!("Кэш {name} очищен. Удалено папок: {count}.")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        "diag-plan" => {
            return "Диагностика не запускалась. Запустите её из меню для записи лога.".into();
        }
        "diag-run" => {
            let status = if value["timed_out"] == true {
                "Диагностика завершена по времени.".into()
            } else if let Some(code) = value["exit_code"].as_u64() {
                if code == 0 {
                    "Диагностический процесс завершён.".into()
                } else {
                    format!("Диагностический процесс завершился с ошибкой {code}.")
                }
            } else {
                "Завершение диагностики не подтверждено.".into()
            };
            return append_path(status, value, "log");
        }
        "update" if value["known"] == false => {
            return "Наличие обновления не удалось проверить.".into();
        }
        "update" if value["text"].is_null() => {
            return match value["available"].as_bool() {
                Some(true) => format!(
                    "Доступно обновление zapret-rust {}.",
                    value["release"]["tag"].as_str().unwrap_or("")
                ),
                Some(false) => "Установлена актуальная версия zapret-rust.".into(),
                None => "Наличие обновления не удалось проверить.".into(),
            };
        }
        "autotune" if value["deferred"] == true => {
            return "Автонастройка отложена: запущена игра или обнаружен другой обход.".into();
        }
        "autotune" if value["due"] == false => {
            return "Автонастройка пока не требуется: предыдущая проверка ещё актуальна.".into();
        }
        "integrity" => {
            return if !value["ok"].is_boolean() {
                "Проверка целостности недоступна.".into()
            } else if value["ok"] == true {
                "Целостность файлов проверена.".into()
            } else {
                "Проверка целостности обнаружила изменённые файлы.".into()
            };
        }
        "uninstall" => {
            if value["running"] != false || value["service"]["removed"] != true {
                return "Удаление zapret-rust не подтверждено полностью.".into();
            }
            let mut message = "Служба и задачи zapret-rust удалены. Обход остановлен.".to_owned();
            if value["package_permissions"]["known"] == false {
                message.push_str("\nПрава доступа к папке вернуть не удалось.");
            }
            if value["flush_dns"].is_object() && value["flush_dns"]["exit_code"] != 0 {
                message.push_str("\nКэш DNS обновить не удалось.");
            }
            return message;
        }
        "legacy-migrate" => {
            return "Регистрация zapret-rust перенесена. Проверьте состояние обхода в главном меню."
                .into();
        }
        "lists" if value["text"].is_null() => {
            return "Состояние списков прочитано. Обновление списков доступно в настройках.".into();
        }
        "settings" if value["saved"] != true => {
            if let (Some(key), Some(setting)) = (value["key"].as_str(), value["value"].as_str()) {
                return format!("{key}: {setting}");
            }
            if let Some(settings) = value.as_object() {
                return settings
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| format!("{key}: {value}"))
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }
        "strategies" => {
            if let Some(rows) = value.as_array() {
                return rows
                    .iter()
                    .filter_map(|row| row["name"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }
        "compose" => {
            if let Some(args) = value["arguments"].as_array() {
                return args
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }
        "update-recover" if value["recovered"] == false => {
            return "Прерванных обновлений не найдено.".into();
        }
        _ => {}
    }
    if let Some(text) = value["text"].as_str() {
        return text.to_owned();
    }
    fallback(value)
}

fn append_path(mut text: String, value: &Value, field: &str) -> String {
    if let Some(path) = value[field].as_str() {
        text.push_str(&format!("\nФайл: {path}"));
    }
    text
}

fn service_status(value: &Value) -> String {
    if value["known"] != true || value["ownership_known"] == false {
        return "Состояние обхода не подтверждено.".into();
    }
    if value["running"] == true {
        return "Обход работает.".into();
    }
    if value["running"] == false {
        return "Обход остановлен.".into();
    }
    if value["installed"] == false {
        return "Служба обхода не установлена.".into();
    }
    match value["state"].as_u64() {
        Some(4) => "Служба обхода работает.",
        Some(1) => "Служба обхода остановлена.",
        _ => "Служба меняет состояние; повторите проверку.",
    }
    .into()
}

fn telegram(value: &Value, operation: &str) -> String {
    if value["ownership_error"].is_string() {
        return "Состояние и владелец моста Telegram не подтверждено.".into();
    }
    let active_port = value["active_port"]
        .as_u64()
        .or_else(|| value["port"].as_u64());
    let configured = value["configured_port"]
        .as_u64()
        .or_else(|| value["port"].as_u64());
    let mut text = if operation == "telegram-config" && value["saved"] == true {
        let mut message = format!(
            "Сохранён порт Telegram: {}.",
            configured.map_or_else(|| "не подтверждён".into(), |port| port.to_string())
        );
        if value["requires_restart"] == true {
            message.push_str(&format!(
                " Сейчас используется порт {}; нужен перезапуск моста.",
                active_port.map_or_else(|| "не подтверждён".into(), |port| port.to_string())
            ));
        }
        message
    } else if value["running"] == true && value["current"] == true {
        format!(
            "Мост Telegram запущен. Порт: {}.",
            active_port.map_or_else(|| "не подтверждён".into(), |port| port.to_string())
        )
    } else if value["running"] == false && value["current"] == false {
        "Мост Telegram остановлен.".into()
    } else {
        "Состояние моста Telegram не подтверждено.".into()
    };
    if value["running"] == true && value["current"] == true {
        if let Some(link) = value["active_link"]
            .as_str()
            .filter(|link| !link.is_empty())
        {
            text.push_str(&format!("\nСсылка для Telegram: {link}"));
        }
        if value["link_opened"] == true {
            text.push_str(
                "\nСсылка передана Telegram. Подтвердите подключение прокси в приложении.",
            );
        } else if value["link_open_error"].is_string() {
            text.push_str("\nАвтоматически открыть Telegram не удалось. Откройте ссылку выше вручную; проверьте, что Telegram Desktop установлен.");
        }
    }
    text
}

pub fn error_text(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    if text.contains("Access is denied") || text.contains("os error 5)") {
        return "Недостаточно прав для этого действия или проверки его результата.".into();
    }
    if text.contains("Invalid port list") {
        return "Неверный список портов. Укажите числа от 1 до 65535 или диапазоны через запятую."
            .into();
    }
    let first = text
        .split('{')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(':')
        .trim();
    let first = if first.is_empty() {
        "Не удалось выполнить действие. Подробности сохранены в журнале."
    } else {
        first
    };
    first.chars().take(450).collect()
}

pub fn fallback(_value: &Value) -> String {
    "Результат действия не подтверждён.".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_checks_do_not_become_disabled_settings_or_a_successful_service() {
        let ipv4 = text(
            &Context::platform("prefer-ipv4"),
            &json!({"known":false,"enabled":false}),
        );
        assert!(ipv4.contains("не подтверждён") && !ipv4.contains("отключено"));
        let integrity = text(
            &Context::platform("integrity"),
            &json!({"status":"Unavailable"}),
        );
        assert!(!integrity.contains("обнаружила изменённые"));
        let service = text(
            &Context::platform("service-install"),
            &json!({"known":false,"running":true}),
        );
        assert!(!service.contains("Служба установлена") && !service.contains("Обход запущен"));
    }

    #[test]
    fn autostart_does_not_turn_an_unknown_or_stopped_bypass_into_success() {
        let context = Context::platform("service-autostart");
        let unknown = text(
            &context,
            &json!({"known":false,"enabled":true,"running":true}),
        );
        assert!(unknown.contains("не подтверждён"));
        assert!(!unknown.contains("Автозапуск включён"));
        let stopped = text(
            &context,
            &json!({"known":true,"enabled":true,"running":false}),
        );
        assert!(stopped.contains("Автозапуск включён") && stopped.contains("Обход остановлен"));
        assert!(!stopped.contains("Обход запущен"));
    }

    #[test]
    fn task_removal_needs_confirmed_absence_not_just_a_successful_request() {
        let context = Context {
            operation: "task-remove".into(),
            kind: Some("notify".into()),
        };
        let unconfirmed = text(
            &context,
            &json!({"exit_code":0,"known":false,"exists":null}),
        );
        assert!(!unconfirmed.contains("отключены"));
        let done = text(&context, &json!({"known":true,"exists":false}));
        assert!(done.contains("Уведомления Windows отключены"));
    }

    #[test]
    fn telegram_port_change_distinguishes_saved_config_from_the_active_listener() {
        let value = json!({"saved":true,"current":true,"running":true,"requires_restart":true,
            "port":1443,"active_port":1443,"configured_port":2443,"configured_link":"inactive-link",
            "active_link":"working-link","ownership_error":null});
        let original = value.clone();
        let rendered = text(&Context::platform("telegram-config"), &value);
        assert!(
            rendered.contains("2443")
                && rendered.contains("1443")
                && rendered.contains("перезапуск")
        );
        assert!(!rendered.contains("inactive-link"));
        assert_eq!(value, original);
        let unknown = text(
            &Context::platform("telegram-start"),
            &json!({"running":true,"current":true,"ownership_error":"denied"}),
        );
        assert!(unknown.contains("не подтверждено") && !unknown.contains("Мост Telegram запущен"));
    }

    #[test]
    fn telegram_open_result_explains_confirmation_and_retains_manual_connection_after_shell_failure()
     {
        let mut value = json!({"current":true,"running":true,"active_port":1443,
            "active_link":"tg://proxy?server=127.0.0.1&port=1443&secret=fixture","link_opened":true});
        let context = Context::platform("telegram-start");
        let opened = text(&context, &value);
        assert!(opened.contains("Мост Telegram запущен"));
        assert!(
            opened.contains("Ссылка передана Telegram")
                && opened.contains("Подтвердите подключение")
        );
        value["link_opened"] = json!(false);
        value["link_open_error"] = json!("Windows 1155");
        let failed = text(&context, &value);
        assert!(failed.contains("Мост Telegram запущен") && failed.contains("tg://proxy?"));
        assert!(failed.contains("вручную") && failed.contains("Telegram Desktop установлен"));
        assert!(!failed.contains("Ссылка передана") && !failed.contains("Windows 1155"));
    }

    #[test]
    fn hosts_success_keeps_dns_refresh_failure_visible() {
        let rendered = text(
            &Context::platform("hosts-set"),
            &json!({"updated":true,"groups":["GitHub"],
            "flush_dns":{"exit_code":1,"timed_out":false}}),
        );
        assert!(rendered.contains("hosts обновлён"));
        assert!(rendered.contains("кэш DNS обновить не удалось"));
    }

    #[test]
    fn diagnostic_preview_and_failed_engine_do_not_look_completed_successfully() {
        let preview = text(
            &Context::platform("diag-plan"),
            &json!({"arguments":["--private-argument"],"log":"diagnostic.log"}),
        );
        assert!(preview.contains("не запускалась") && !preview.contains("--private-argument"));
        let failure = text(
            &Context::platform("diag-run"),
            &json!({"exit_code":1,"timed_out":false,"log":"diagnostic.log"}),
        );
        assert!(failure.contains("с ошибкой 1"));
        assert!(!failure.contains("Диагностика завершена по времени"));
    }

    #[test]
    fn missing_discord_cache_and_unknown_update_are_not_reported_as_success() {
        let empty = text(&Context::platform("discord-cache"), &json!([]));
        assert!(empty.contains("не найден") && !empty.contains("очищен"));
        let update = text(&Context::platform("update"), &json!({"known":false}));
        assert!(update.contains("не удалось проверить") && !update.contains("актуальная версия"));
    }

    #[test]
    fn fallback_does_not_dump_machine_fields_or_infer_success() {
        let rendered =
            fallback(&json!({"removed":true,"config_hash":"PRIVATE","processes":[{"pid":123}]}));
        assert!(!rendered.contains("PRIVATE") && !rendered.contains("123"));
        assert!(!rendered.contains("успешно") && !rendered.contains("выполнено"));
    }
}
