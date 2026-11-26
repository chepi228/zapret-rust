use super::{App, Journal, measurement_network, verify_measurement_network};
use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fmt, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zapret_platform::NetworkEvents;

#[derive(Debug)]
struct Interrupted(PathBuf);

impl fmt::Display for Interrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Автоподбор прерван. Отчёт {}", self.0.display())
    }
}

/// An observed path change invalidates all measurements in that run. Only a new
/// run may use the recovered connection, with a new baseline and journal.
pub(super) fn run_with_recovery(
    original: &Value,
    mut run: impl FnMut() -> Result<Value>,
    mut observe: impl FnMut() -> Result<Value>,
    mut pause: impl FnMut() -> Result<()>,
    mut announce: impl FnMut() -> Result<()>,
) -> Result<Value> {
    let started = Instant::now();
    let first = match run() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let Some(interrupted) = first.downcast_ref::<Interrupted>() else {
        return Err(first);
    };
    let Some(key) = original["key"].as_str().filter(|key| !key.is_empty()) else {
        return Err(first);
    };
    let mut consecutive = 0;
    for _ in 0..6 {
        pause()?;
        if observe().is_ok_and(|v| v["known"] == true && v["key"] == key) {
            consecutive += 1;
            if consecutive == 2 {
                announce()?;
                let before_restart = started.elapsed();
                let mut report = run().with_context(|| {
                    format!("Повторный автоподбор завершился ошибкой. Первая остановка: {first:#}")
                })?;
                report["network_recovery"] = json!({"restarted":true,
                    "prior_elapsed_ms":before_restart.as_millis(),
                    "previous_report":interrupted.0.file_name().and_then(|name| name.to_str())});
                if report["elapsed_ms"].is_number() {
                    report["elapsed_ms"] = json!(started.elapsed().as_secs_f64() * 1000.);
                }
                return Ok(report);
            }
        } else {
            consecutive = 0;
        }
    }
    Err(first)
}

/// Only include the cause, time and generated file name in a shareable report.
/// Older builds left their last interruption only in the menu log.
pub(crate) fn last_interruption(root: &Path) -> Result<Option<(DateTime<Utc>, String)>> {
    let menu = crate::runtime_file(root, "menu-errors.log")?;
    let mut last = None;
    if menu.is_file() {
        let tail = crate::maintenance::read_tail_text(&menu, 128 * 1024, 250)?;
        for line in tail.lines().rev() {
            let Some((time, "Подключение изменилось во время измерения")) =
                line.trim().split_once(' ')
            else {
                continue;
            };
            if let Ok(time) = DateTime::parse_from_rfc3339(time) {
                last = Some((
                    time.to_utc(),
                    "Изменение подключения. В этом журнале подробности не записаны.".to_owned(),
                ));
                break;
            }
        }
    }
    let dir = root.join("runtime");
    if !dir.is_dir() {
        return Ok(last);
    }
    let mut files = Vec::new();
    for item in fs::read_dir(dir)?.flatten() {
        let Ok(name) = item.file_name().into_string() else {
            continue;
        };
        let id = name
            .strip_prefix("test-native-")
            .and_then(|s| s.strip_suffix(".network.json"));
        if !id.is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
            continue;
        }
        if let Ok(modified) = item.metadata().and_then(|m| m.modified()) {
            files.push((modified, name));
        }
    }
    files.sort_unstable_by(|a, b| b.cmp(a));
    for (_, name) in files.into_iter().take(8) {
        let Ok(path) = crate::runtime_file(root, &name) else {
            continue;
        };
        let Ok(bytes) = zapret_core::read_bounded(&path, 64 * 1024) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Some(time) = record["ObservedUtc"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        else {
            continue;
        };
        let time = time.to_utc();
        if record["Stage"] != "network-interrupted"
            || last.as_ref().is_some_and(|(old, _)| *old >= time)
        {
            continue;
        }
        let changes = super::NETWORK_PARTS
            .iter()
            .filter(|(key, _)| {
                record["before"][*key].is_string()
                    && record["after"][*key].is_string()
                    && record["before"][*key] != record["after"][*key]
            })
            .map(|(_, label)| *label)
            .collect::<Vec<_>>();
        let cause = if !record["after"].is_object() {
            "Windows не подтвердила состояние сети".into()
        } else if changes.is_empty() {
            "Изменилось подключение".into()
        } else {
            format!("Изменились параметры подключения: {}", changes.join(", "))
        };
        last = Some((time, format!("{cause}. Отчёт {name}.")));
    }
    Ok(last.map(|(time, reason)| {
        (
            time,
            format!(
                "{} — {reason}",
                time.with_timezone(&Local).format("%d.%m.%Y %H:%M:%S")
            ),
        )
    }))
}

pub(super) struct Monitor {
    original: Value,
    events: Option<NetworkEvents>,
    previous: Cell<Option<(Instant, u64)>>,
    reads: Cell<u64>,
    skipped: Cell<u64>,
    duration: Cell<Duration>,
}

fn needs_read(fresh: bool, age: Duration, watched: bool, changed: bool) -> bool {
    // DNS, proxy policy and NLM changes need not emit a route notification.
    fresh || changed || age >= Duration::from_secs(if watched { 5 } else { 1 })
}

impl Monitor {
    pub(super) fn new(original: &Value) -> Self {
        Self {
            original: original.clone(),
            events: NetworkEvents::subscribe(),
            previous: Cell::new(None),
            reads: Cell::new(0),
            skipped: Cell::new(0),
            duration: Cell::new(Duration::ZERO),
        }
    }

    pub(super) fn generation(&self) -> Option<u64> {
        self.events.as_ref().map(NetworkEvents::generation)
    }

    pub(super) fn check(&self, app: &App, journal: &Path, fresh: bool) -> Result<()> {
        let generation = self.generation().unwrap_or(0);
        if self.previous.get().is_some_and(|(last, old)| {
            !needs_read(
                fresh,
                last.elapsed(),
                self.events.is_some(),
                old != generation,
            )
        }) {
            self.skipped.set(self.skipped.get() + 1);
            return Ok(());
        }
        let start = Instant::now();
        let current = measurement_network(app);
        self.reads.set(self.reads.get() + 1);
        self.duration.set(self.duration.get() + start.elapsed());
        let checked = current
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e:#}"))
            .and_then(|value| {
                let result = verify_measurement_network(
                    self.original["key"].as_str().unwrap_or(""),
                    &self.original["key_parts"],
                    value,
                );
                if result.is_err() && value["gateway_hash"] != self.original["gateway_hash"] {
                    result.context("Изменился шлюз по умолчанию")
                } else {
                    result
                }
            });
        if let Err(error) = checked {
            let record = json!({"Stage":"network-interrupted","ObservedUtc":chrono::Utc::now(),"reason":format!("{error:#}"),
                "before":self.original["key_parts"],"after":current.as_ref().ok().map(|v| &v["key_parts"]),
                "network_monitor":self.metrics(),"journal":journal.file_name().and_then(|name| name.to_str())});
            let log = journal.with_extension("network.json");
            zapret_core::atomic_write(&log, &serde_json::to_vec_pretty(&record)?).with_context(
                || {
                    format!(
                        "{error:#}. Не удалось сохранить причину в {}",
                        log.display()
                    )
                },
            )?;
            Journal::open(journal)
                .and_then(|mut file| file.append(&record))
                .with_context(|| format!("{error:#}. Не удалось дополнить журнал замеров"))?;
            return Err(error.context(Interrupted(log)));
        }
        self.previous.set(Some((start, generation)));
        Ok(())
    }

    pub(super) fn metrics(&self) -> Value {
        json!({"notifications":self.events.is_some(),"reads":self.reads.get(),"cached_checks":self.skipped.get(),
            "read_ms":self.duration.get().as_secs_f64()*1000.})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn interrupted() -> anyhow::Error {
        anyhow::anyhow!("sample changed").context(Interrupted(PathBuf::from("trial.network.json")))
    }

    #[test]
    fn transient_change_discards_the_run_and_requires_two_matching_samples() {
        let home = json!({"known":true,"key":"home"});
        let away = json!({"known":true,"key":"other"});
        let mut samples = [
            away,
            home.clone(),
            json!({"known":false,"key":"home"}),
            home.clone(),
            home.clone(),
        ]
        .into_iter();
        let mut runs = [
            Err(interrupted()),
            Ok(json!({"run_id":"fresh", "rows":[2],"elapsed_ms":30})),
        ]
        .into_iter();
        let mut pauses = 0;
        let mut restarts = 0;
        let report = run_with_recovery(
            &home,
            || runs.next().unwrap(),
            || Ok(samples.next().unwrap()),
            || {
                pauses += 1;
                Ok(())
            },
            || {
                restarts += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((pauses, restarts), (5, 1));
        assert_eq!(report["rows"], json!([2]));
        assert_eq!(
            report["network_recovery"]["previous_report"],
            "trial.network.json"
        );
    }

    #[test]
    fn persistent_change_unavailable_state_and_cancellation_never_restart() {
        let home = json!({"known":true,"key":"home"});
        for current in [
            Ok(json!({"known":true,"key":"away"})),
            Ok(json!({"known":false})),
            Err("read error"),
        ] {
            let mut reads = 0;
            let result = run_with_recovery(
                &home,
                || Err(interrupted()),
                || {
                    reads += 1;
                    current.clone().map_err(anyhow::Error::msg)
                },
                || Ok(()),
                || panic!("unstable connection must not restart"),
            );
            assert!(result.unwrap_err().is::<Interrupted>());
            assert_eq!(reads, 6);
        }
        let cancelled = run_with_recovery(
            &home,
            || Err(interrupted()),
            || panic!(),
            || anyhow::bail!("cancelled"),
            || panic!(),
        );
        assert_eq!(cancelled.unwrap_err().to_string(), "cancelled");
    }

    #[test]
    fn unrelated_errors_are_returned_and_a_second_interruption_is_terminal() {
        let home = json!({"known":true,"key":"home"});
        let original = run_with_recovery(
            &home,
            || anyhow::bail!("engine stopped"),
            || panic!(),
            || panic!(),
            || panic!(),
        );
        assert_eq!(original.unwrap_err().to_string(), "engine stopped");
        let mut runs = 0;
        let failed = run_with_recovery(
            &home,
            || {
                runs += 1;
                Err(interrupted())
            },
            || Ok(home.clone()),
            || Ok(()),
            || Ok(()),
        );
        assert!(format!("{:#}", failed.unwrap_err()).contains("Повторный автоподбор"));
        assert_eq!(runs, 2);
    }

    #[test]
    fn interruption_summary_reads_legacy_menu_and_sanitizes_newer_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::write(
            runtime.join("menu-errors.log"),
            "2026-01-01T00:00:00Z Подключение изменилось во время измерения\n",
        )
        .unwrap();
        assert!(
            last_interruption(temp.path())
                .unwrap()
                .unwrap()
                .1
                .contains("подробности не записаны")
        );
        let name = "test-native-00000000000000000000000000000001.network.json";
        let data = json!({"Stage":"network-interrupted","ObservedUtc":"2026-01-02T01:02:03Z","reason":"PRIVATE","before":{"dns":"PRIVATE"},"after":{"dns":"other"}});
        fs::write(runtime.join(name), serde_json::to_vec(&data).unwrap()).unwrap();
        fs::write(runtime.join("test-native-invalid.network.json"), b"{}").unwrap();
        let (time, reason) = last_interruption(temp.path()).unwrap().unwrap();
        assert_eq!(time.to_rfc3339(), "2026-01-02T01:02:03+00:00");
        assert!(
            reason.contains("настройки DNS")
                && reason.contains(name)
                && !reason.contains("PRIVATE")
        );
    }

    #[test]
    fn notifications_polling_and_commit_each_invalidate_the_cache() {
        let short = Duration::from_millis(50);
        assert!(!needs_read(false, short, true, false));
        assert!(needs_read(true, short, true, false));
        assert!(needs_read(false, short, true, true));
        assert!(needs_read(false, Duration::from_secs(5), true, false));
        assert!(needs_read(false, Duration::from_secs(1), false, false));
    }
}
