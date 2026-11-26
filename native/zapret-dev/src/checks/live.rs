//! Explicitly opted-in native service/menu/startup regression harness.
use super::*;

#[derive(Clone)]
struct Case {
    name: &'static str,
    command: Vec<&'static str>,
    running: bool,
    changed: bool,
    menu_input: Option<&'static str>,
}
fn cases(network: bool) -> Vec<Case> {
    let mut cases = vec![
        Case {
            name: "start",
            command: vec!["start"],
            running: true,
            changed: false,
            menu_input: None,
        },
        Case {
            name: "stop",
            command: vec!["stop"],
            running: false,
            changed: false,
            menu_input: None,
        },
        Case {
            name: "repeat-stop",
            command: vec!["stop"],
            running: false,
            changed: false,
            menu_input: None,
        },
        Case {
            name: "start-again",
            command: vec!["start"],
            running: true,
            changed: false,
            menu_input: None,
        },
        Case {
            name: "restart",
            command: vec!["restart"],
            running: true,
            changed: true,
            menu_input: None,
        },
        Case {
            name: "bat-menu-stop",
            command: vec!["menu"],
            running: false,
            changed: false,
            menu_input: Some("2\n\n0\n"),
        },
        Case {
            name: "bat-menu-start",
            command: vec!["menu"],
            running: true,
            changed: false,
            menu_input: Some("1\n\n0\n"),
        },
        Case {
            name: "bat-menu-restart",
            command: vec!["menu"],
            running: true,
            changed: true,
            menu_input: Some("1\n\n0\n"),
        },
        Case {
            name: "settings-apply",
            command: vec!["settings", "alt"],
            running: true,
            changed: true,
            menu_input: None,
        },
    ];
    if network {
        cases.push(Case {
            name: "connection-check",
            command: vec![
                "connection-check",
                "--timeout-ms",
                "5000",
                "https://www.youtube.com",
                "https://discord.com",
                "https://store.steampowered.com",
            ],
            running: true,
            changed: false,
            menu_input: None,
        });
        cases.push(Case {
            name: "webcheck",
            command: vec![
                "webcheck",
                "--timeout-ms",
                "10000",
                "https://www.youtube.com",
            ],
            running: true,
            changed: false,
            menu_input: None,
        });
    }
    cases
}
fn assert_state(state: &Value, running: bool) -> Result<()> {
    ensure!(
        state["known"] == true && state["ownership_known"] == true,
        "Unknown bypass ownership/state"
    );
    ensure!(
        state["running"] == running,
        "Requested bypass state was not confirmed"
    );
    let processes = state["processes"]
        .as_array()
        .context("Unknown process list")?;
    if running {
        ensure!(
            processes.len() == 1
                && processes[0]["pid"].as_u64().is_some_and(|n| n > 0)
                && processes[0]["created_filetime"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "A single exact engine was not confirmed"
        );
    } else {
        ensure!(processes.is_empty(), "Engine remains after stop");
    }
    if state["service"]["installed"] == true {
        let service = &state["service"];
        ensure!(
            service["owned"] == true && service["state"] == if running { 4 } else { 1 },
            "Service ownership/state mismatch"
        );
        ensure!(
            service["pid"]
                == if running {
                    processes[0]["pid"].clone()
                } else {
                    json!(0)
                },
            "Service PID mismatch"
        );
    }
    Ok(())
}
fn no_game(runner: &Runner) -> Result<()> {
    let games = runner.json(&["system", "games"])?;
    ensure!(
        games.is_null() || games.as_array().is_some_and(Vec::is_empty),
        "Game protection: close the game before a live check"
    );
    Ok(())
}
fn state(runner: &Runner) -> Result<Value> {
    let value = runner.json(&["status"])?;
    ensure!(
        value["known"] == true && value["ownership_known"] == true,
        "Unknown bypass ownership/state"
    );
    Ok(value)
}

struct Restore<'a> {
    runner: &'a Runner,
    initial: Value,
    pending: bool,
}
impl Restore<'_> {
    fn finish(&mut self) -> Result<Value> {
        let current = state(self.runner)?;
        if current["running"] != self.initial["running"] {
            no_game(self.runner)?;
            self.runner.json(&[if self.initial["running"] == true {
                "start"
            } else {
                "stop"
            }])?;
        }
        let final_state = state(self.runner)?;
        assert_state(&final_state, self.initial["running"] == true)?;
        self.pending = false;
        Ok(final_state)
    }
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        if self.pending {
            if let Err(error) = self.finish() {
                eprintln!("Live-check restoration: {error:#}");
            }
        }
    }
}

pub(crate) fn run(
    root: &Path,
    allow: bool,
    network: bool,
    validate_only: bool,
    output: Option<&Path>,
) -> Result<()> {
    let cases = cases(network);
    if validate_only {
        let value = json!({"Root":root,"Cases":cases.iter().map(|case|case.name).collect::<Vec<_>>(),"RestoresInitialState":true,"live_changes":false});
        if let Some(output) = output {
            atomic_write(
                &std::path::absolute(output)?,
                &serde_json::to_vec_pretty(&value)?,
            )?;
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    ensure!(
        allow,
        "Use --allow-live-changes: this check starts/stops the real bypass and restores its initial running state"
    );
    ensure!(
        zapret_platform::is_admin()?,
        "An administrator token is required for live checks"
    );
    let runner = Runner::new(root);
    no_game(&runner)?;
    let initial = state(&runner)?;
    assert_state(&initial, initial["running"] == true)?;
    let directory = root.join(format!(
        "dist/native/live-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    ));
    fs::create_dir_all(&directory)?;
    let output = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| directory.join("result.json"));
    let mut restore = Restore {
        runner: &runner,
        initial: initial.clone(),
        pending: true,
    };
    let mut events = Vec::new();
    let result = (|| {
        for case in cases {
            no_game(&runner)?;
            let before = state(&runner)?;
            let started = Instant::now();
            let mut command = case.command;
            let settings = if case.name == "settings-apply" {
                Some(runner.json(&["settings"])?)
            } else {
                None
            };
            if let Some(settings) = settings.as_ref() {
                let alt = settings["alt"]
                    .as_str()
                    .context("Unknown current strategy")?;
                ensure!(
                    !alt.is_empty() && alt.bytes().all(|b| b.is_ascii_digit()),
                    "Invalid current strategy"
                );
                command.push(alt);
            }
            let result = if let Some(input) = case.menu_input {
                invoke(
                    &root.join("zapret-rust.exe"),
                    &["menu".into()],
                    Some(root),
                    0,
                    Some(input.as_bytes().into()),
                )?
            } else {
                runner.raw(&command, true, 0, None)?
            };
            fs::write(
                directory.join(format!("{}.out.txt", case.name)),
                &result.stdout,
            )?;
            fs::write(
                directory.join(format!("{}.err.txt", case.name)),
                &result.stderr,
            )?;
            let data = serde_json::from_slice::<Value>(&result.stdout).unwrap_or(Value::Null);
            let after = state(&runner)?;
            assert_state(&after, case.running)?;
            if case.changed && before["running"] == true {
                ensure!(
                    before["processes"][0]["pid"] != after["processes"][0]["pid"],
                    "Restart did not replace the engine process"
                );
            }
            let startup = if case.name == "settings-apply" {
                &data["restart"]
            } else {
                &data
            };
            for field in ["watcher_error", "watch_task_error", "confirmation_warning"] {
                ensure!(
                    startup[field].is_null() || startup[field] == "",
                    "{field}: {}",
                    startup[field]
                );
            }
            for component in ["gamepins", "telegram"] {
                let hook = &startup["post_start"][component];
                ensure!(
                    hook["enabled"] != true || hook["ok"] == true,
                    "{component}: {}",
                    hook["error"]
                );
            }
            if case.name == "connection-check" {
                ensure!(
                    data["targets"]
                        .as_array()
                        .is_some_and(|rows| rows.len() == 3
                            && rows
                                .iter()
                                .all(|row| row["assessment"]["reachable_http"] == true)),
                    "HTTPS target verification failed"
                );
            }
            if case.name == "webcheck" {
                let rows = data["rows"]
                    .as_array()
                    .context("Missing browser rows")?
                    .iter()
                    .filter(|row| row["mode"] == "BrowserAuto" || row["mode"] == "BrowserTcp")
                    .collect::<Vec<_>>();
                ensure!(
                    rows.len() == 4
                        && rows.iter().all(|row| row["state"] == "OK"
                            && row["complete"] == true
                            && row["cleanup_complete"] == true),
                    "Browser navigation/cleanup failed"
                );
            }
            let elapsed = started.elapsed().as_millis();
            events.push(json!({"case":case.name,"passed":true,"elapsed_ms":elapsed,"running":after["running"],"processes":after["processes"],"service":after["service"]}));
            println!("{}: PASS ({elapsed} ms)", case.name);
        }
        let telegram = runner.json(&["telegram", "status"])?;
        ensure!(
            telegram["ownership_error"].is_null(),
            "Telegram ownership failed"
        );
        ensure!(
            telegram["enabled"] != "on"
                || (telegram["running"] == true && telegram["requires_restart"] == false),
            "Enabled Telegram component is not ready"
        );
        Ok(())
    })();
    let restored = restore.finish();
    let report = json!({"schema":1,"completed":result.is_ok() && restored.is_ok(),"binary_sha256":sha256_file(&runner.executable)?,"events":events,"initial":initial,
        "final":restored.as_ref().ok(),"error":result.as_ref().err().map(|e:&anyhow::Error|format!("{e:#}")),"restore_error":restored.as_ref().err().map(|e|format!("{e:#}"))});
    atomic_write(
        &std::path::absolute(&output)?,
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("Report: {}", output.display());
    result?;
    restored?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_keeps_explicit_menu_and_restore_cases_and_unknown_state_never_passes() {
        let plan = cases(false);
        assert_eq!(plan.len(), 9);
        assert_eq!(cases(true).len(), 11);
        assert_eq!(
            plan.iter()
                .find(|case| case.name == "bat-menu-stop")
                .unwrap()
                .menu_input,
            Some("2\n\n0\n")
        );
        assert!(
            assert_state(
                &json!({"known":false,"ownership_known":false,"running":false,"processes":[]}),
                false
            )
            .is_err()
        );
        let state = json!({"known":true,"ownership_known":true,"running":true,"processes":[{"pid":42,"created_filetime":1}],"service":{"installed":true,"owned":true,"state":4,"pid":43}});
        assert!(assert_state(&state, true).is_err());
    }
}
