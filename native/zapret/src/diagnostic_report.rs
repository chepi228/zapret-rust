use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use zapret_core::{atomic_write, sha256};

fn text(value: &Value) -> &str {
    value
        .as_str()
        .filter(|value| *value != "Unknown")
        .unwrap_or("нет данных")
}

fn target_label(value: &Value) -> String {
    if let Some(url) = value["url"].as_str() {
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("");
        if !host.is_empty() {
            return host.to_owned();
        }
    }
    text(&value["name"]).to_owned()
}

fn observed(value: &Value) -> &'static str {
    match value.as_str() {
        Some("ObservedStable") => "подключение было стабильным",
        Some("ObservedChanged" | "Changed") => "подключение изменилось во время проверки",
        _ => "стабильность подключения не подтверждена",
    }
}

pub fn render(kind: &str, value: &Value) -> String {
    let title = match kind {
        "connection" => "DNS, TCP, TLS и HTTP",
        "web" => "Браузер и HTTP",
        "voice" => "Discord Voice",
        "latency" => "Задержка подключения",
        "provider" => "Провайдер",
        _ => "Проверка подключения",
    };
    let mut lines = vec![title.to_owned()];
    if let Some(state) = value["connection_state"].as_str() {
        lines.push(format!("Подключение: {}", observed(&json!(state))));
    }
    if let Some(targets) = value["targets"].as_array() {
        for target in targets {
            lines.push(format!(
                "{}: {}",
                target_label(target),
                if target["assessment"]["reachable_http"] == true {
                    "HTTP-ответ получен"
                } else {
                    match target["assessment"]["stage"].as_str() {
                        Some("Dns" | "DNS") => "имя сервера определить не удалось",
                        Some("Tcp" | "TCP") => "TCP-соединение не подтверждено",
                        Some("Tls" | "TLS") => "защищённое соединение не подтверждено",
                        _ => "доступность не подтверждена",
                    }
                }
            ));
        }
    }
    if kind == "web" {
        if let Some(rows) = value["rows"].as_array() {
            for row in rows {
                let mode = match row["mode"].as_str() {
                    Some("Http1") => "HTTP/1.1",
                    Some("Http2") => "HTTP/2",
                    Some("Http3") => "HTTP/3",
                    Some("BrowserAuto") => "Браузер",
                    Some("BrowserTcp") => "Браузер TCP",
                    _ => "Проверка",
                };
                let browser = matches!(row["mode"].as_str(), Some("BrowserAuto" | "BrowserTcp"));
                let verdict = if row["reason"] == "ControllerError" {
                    "проверку не удалось выполнить"
                } else if row["state"] == "UNAVAILABLE" || row["reason"] == "Unavailable" {
                    "недоступен на этом ПК"
                } else if row["reason"] == "Timeout" {
                    "превышено время ожидания"
                } else if row["state"] == "OK" && row["complete"] != true {
                    "проверка не завершена"
                } else if browser && row["cleanup_complete"] != true {
                    "завершение временного браузера не подтверждено"
                } else if row["state"] == "OK" && row["complete"] == true {
                    "проверка пройдена"
                } else {
                    "доступность не подтверждена"
                };
                lines.push(format!("{} · {mode}: {verdict}", target_label(row),));
            }
        }
    }
    if kind == "voice" {
        lines.push(format!(
            "UDP: {} · STUN: {} · звук: {}",
            match value["assessment"]["traffic"].as_str() {
                Some("NoUdpObserved") => "пакеты не обнаружены",
                Some("Bidirectional" | "BidirectionalUdpObserved") =>
                    "есть входящие и исходящие пакеты",
                Some("SeparateDirectionsObserved") => "оба направления видны в разных соединениях",
                Some("OutboundOnly") => "наблюдались только исходящие пакеты",
                Some("InboundOnly") => "наблюдались только входящие пакеты",
                _ => "наблюдение не подтверждено",
            },
            match value["assessment"]["control"].as_str() {
                Some("NoResponseObserved") => "ответ не обнаружен",
                Some("ResponseObserved" | "ObservedResponse" | "StunResponseObserved" | "OK") =>
                    "ответ получен",
                _ => "результат не подтверждён",
            },
            match value["audio_observation"].as_str() {
                Some("Both") => "слышны оба участника",
                Some("OnlyReceive") => "слышит только пользователь",
                Some("OnlySend") => "слышит только собеседник",
                Some("None") => "пользователь сообщил об отсутствии звука",
                _ => "пользователь не проверял",
            }
        ));
        lines.push(format!(
            "Результат: {}",
            match value["assessment"]["outcome"].as_str() {
                Some("ConsistentBidirectional" | "ConfirmedWorking" | "WorkingObserved") =>
                    "наблюдения подтверждают обмен пакетами",
                Some("AudioReportedWorking" | "UserReportedBoth") => "пользователь подтвердил звук",
                Some("UserReportedIssue") => "пользователь сообщил о проблеме со звуком",
                Some("NeedsAudioCheck") =>
                    "обмен пакетами есть; качество звука нужно проверить вручную",
                Some("ContextChanged") => "подключение менялось; повторите проверку",
                _ => "данных недостаточно для вывода",
            }
        ));
        lines.push(
            "Эти наблюдения не устанавливают причину сбоя или срабатывание стратегии.".into(),
        );
    }
    if kind == "provider" {
        if let Some(rows) = value["rows"].as_array() {
            for row in rows {
                let provider = &row["provider"];
                lines.push(format!(
                    "{} · {} · {} · {}",
                    if row["state"] == "OK" {
                        "провайдер определён"
                    } else {
                        "провайдера определить не удалось"
                    },
                    text(&provider["masked_ip"]),
                    text(&provider["country"]),
                    text(&provider["isp"])
                ));
            }
        }
    }
    if kind == "latency" {
        if let Some(rows) = value["summaries"].as_array() {
            for row in rows {
                let summary = &row["summary"];
                let median = summary["median_ms"]
                    .as_f64()
                    .map(|value| format!("{value:.1} мс"))
                    .unwrap_or_else(|| "нет ответа".into());
                lines.push(format!(
                    "{} · {}: {} · ответов {}/{}",
                    text(&row["address"]),
                    text(&row["kind"]),
                    median,
                    summary["success_count"]
                        .as_u64()
                        .map_or_else(|| "нет данных".into(), |number| number.to_string()),
                    summary["count"]
                        .as_u64()
                        .map_or_else(|| "нет данных".into(), |number| number.to_string())
                ));
            }
        }
        lines.push(
            "Измерены ICMP или подключение TCP к указанному адресу. Игровой пинг не измерялся."
                .into(),
        );
    }
    lines.join("\r\n") + "\r\n"
}

fn previous(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn restore(path: &Path, bytes: Option<Vec<u8>>) -> Result<()> {
    if let Some(bytes) = bytes {
        atomic_write(path, &bytes)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn publish(root: &Path, kind: &str, mut value: Value) -> Result<Value> {
    ensure!(
        ["connection", "web", "voice", "provider", "latency"].contains(&kind),
        "Неизвестный вид отчёта"
    );
    ensure!(value.is_object(), "Отчёт должен быть объектом");
    let _guard = publication_lease(root, kind)?;
    for key in [
        "run_id",
        "text_file",
        "text_sha256",
        "TextFile",
        "JsonFile",
        "text",
    ] {
        value.as_object_mut().expect("checked object").remove(key);
    }
    let report = render(kind, &value);
    let run_id = sha256(format!("{}|{}", chrono::Utc::now().to_rfc3339(), value).as_bytes())[..32]
        .to_ascii_lowercase();
    let stem = format!("{kind}-check-{run_id}");
    let immutable_text = crate::runtime_file(root, &format!("{stem}.txt"))?;
    let immutable_json = crate::runtime_file(root, &format!("{stem}.json"))?;
    value["run_id"] = json!(run_id);
    value["text_file"] = json!(format!("{stem}.txt"));
    value["text_sha256"] = json!(sha256(report.as_bytes()));
    value["TextFile"] = json!(immutable_text);
    value["JsonFile"] = json!(immutable_json);
    value["text"] = json!(report);
    let encoded = serde_json::to_vec_pretty(&value)?;
    ensure!(
        encoded.len() <= 16 * 1024 * 1024,
        "Отчёт превышает бюджет 16 МиБ"
    );
    atomic_write(&immutable_text, report.as_bytes())?;
    atomic_write(&immutable_json, &encoded)?;
    let last_text = crate::runtime_file(root, &format!("{kind}-check-last.txt"))?;
    let last_json = crate::runtime_file(root, &format!("{kind}-check-last.json"))?;
    let old_text = previous(&last_text)?;
    let old_json = previous(&last_json)?;
    let result = atomic_write(&last_text, report.as_bytes())
        .and_then(|()| atomic_write(&last_json, &encoded));
    if let Err(error) = result {
        restore(&last_text, old_text)?;
        // A failed atomic replacement leaves the existing JSON intact. Avoid
        // rewriting a locked but unchanged alias during rollback.
        if previous(&last_json)? != old_json {
            restore(&last_json, old_json)?;
        }
        return Err(error);
    }
    Ok(value)
}

fn publication_lease(root: &Path, kind: &str) -> Result<File> {
    let path = crate::runtime_file(root, &format!("{kind}-report.lock"))?;
    fs::create_dir_all(path.parent().expect("runtime file has parent"))?;
    let started = Instant::now();
    loop {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        match options.open(&path) {
            Ok(file) => return Ok(file),
            Err(error)
                if matches!(error.raw_os_error(), Some(32 | 33))
                    && started.elapsed() < Duration::from_secs(2) =>
            {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_unavailable_diagnostics_are_readable_without_positive_inference() {
        let web = render(
            "web",
            &json!({"connection_state":"Unknown","rows":[
                {"name":"target1","group":"Custom","url":"https://example.com/private?token=hidden", "mode":"BrowserAuto","state":"UNKNOWN","reason":"ControllerError","complete":false,"cleanup_complete":true},
                {"name":"target1","group":"Custom","mode":"Http3","state":"UNAVAILABLE","reason":"Unavailable"}
            ]}),
        );
        for phrase in [
            "не удалось выполнить",
            "недоступен на этом ПК",
            "example.com",
        ] {
            assert!(web.contains(phrase), "{web}");
        }
        for field in [
            "ControllerError",
            "UNAVAILABLE",
            "ObservedStable",
            "token=hidden",
        ] {
            assert!(!web.contains(field), "{web}");
        }
        let incomplete = render(
            "web",
            &json!({"rows":[{"name":"fixture","mode":"Http2","state":"OK","reason":"Completed","complete":false,"protocol_confirmed":true}]}),
        );
        assert!(!incomplete.contains("проверка пройдена"));
        assert!(incomplete.contains("не завершена"));
    }

    #[test]
    fn no_observed_voice_packets_is_not_reported_as_a_broken_voice_connection() {
        let text = render(
            "voice",
            &json!({"audio_observation":"Unknown","assessment":{
            "traffic":"NoUdpObserved","control":"NoResponseObserved","outcome":"InsufficientEvidence"}}),
        );
        assert!(text.contains("пакеты не обнаружены"));
        assert!(text.contains("данных недостаточно"));
        assert!(!text.contains("голос не работает") && !text.contains("InsufficientEvidence"));
    }

    #[test]
    fn last_alias_references_an_immutable_matching_text_report() {
        let root = tempfile::tempdir().unwrap();
        let first = publish(root.path(), "web", json!({"rows":[]})).unwrap();
        let second = publish(root.path(), "web", json!({"rows":[],"quic":"Unconfirmed"})).unwrap();
        assert_ne!(first["run_id"], second["run_id"]);
        for value in [&first, &second] {
            let bytes = fs::read(value["TextFile"].as_str().unwrap()).unwrap();
            assert_eq!(sha256(&bytes), value["text_sha256"]);
            assert!(Path::new(value["JsonFile"].as_str().unwrap()).is_file());
        }
        let last: Value = serde_json::from_slice(
            &fs::read(root.path().join("runtime/web-check-last.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(last["run_id"], second["run_id"]);
    }

    #[cfg(windows)]
    #[test]
    fn failed_second_alias_preserves_the_previous_complete_pair() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let first = publish(root.path(), "web", json!({"rows":[]})).unwrap();
        let path = root.path().join("runtime/web-check-last.json");
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .unwrap();
        assert!(publish(root.path(), "web", json!({"rows":[],"changed":true})).is_err());
        drop(held);
        let last: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(last["run_id"], first["run_id"]);
        assert_eq!(
            fs::read(root.path().join("runtime/web-check-last.txt")).unwrap(),
            first["text"].as_str().unwrap().as_bytes()
        );
    }
}
