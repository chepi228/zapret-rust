//! Drives the production console menu with a fixture for machine-wide actions.
#![cfg(not(test))]

#[allow(dead_code)]
#[path = "../src/cli.rs"]
mod cli;
#[path = "../src/confirmation.rs"]
mod confirmation;
#[allow(dead_code)]
#[path = "../src/console.rs"]
mod console;
#[allow(dead_code)]
#[path = "../src/menu.rs"]
mod menu;
#[path = "../src/presentation.rs"]
mod presentation;

use anyhow::{Context, Result, bail, ensure};
use cli::Action;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    io::{self, Write},
    path::{Path, PathBuf},
};

const VERSION: &str = "fixture";

struct App {
    root: PathBuf,
    running: Cell<bool>,
    telegram: Cell<bool>,
    port: Cell<u16>,
    configured_port: Cell<u16>,
}

fn event(action: &str, arguments: Value) -> Value {
    println!("FIXTURE {}", json!({"action":action,"arguments":arguments}));
    json!({"text":"Действие проверено."})
}

fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("Fixture root required")?,
    )
    .canonicalize()?;
    let parent = root.parent().context("Fixture parent required")?;
    ensure!(
        parent.parent() == Some(std::env::temp_dir().canonicalize()?.as_path())
            && parent
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("zapret-menu-fixture-"))
            && root.file_name().is_some_and(|name| name == "zapret-rust")
            && root.join("runtime/menu-fixture").is_file(),
        "Refusing to run the fixture outside its private TEMP package"
    );
    menu::run(&App {
        root,
        running: Cell::new(false),
        telegram: Cell::new(false),
        port: Cell::new(1443),
        configured_port: Cell::new(1443),
    })
}

impl App {
    fn platform(&self, action: &str, args: Value) -> Result<Value> {
        Ok(match action {
            "admin" => json!({"is_admin":true}),
            "unblock-package" | "protect-package" => json!({"known":true}),
            "legacy-status" => json!({"known":true,"migration_required":false}),
            "status" => match std::fs::read(self.root.join("runtime/menu-status-fixture.json")) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    json!({"known":true,"ownership_known":true,"running":self.running.get(),
                        "service":{"known":true,"ownership_known":true,"installed":false}})
                }
                Err(error) => return Err(error.into()),
            },
            "task-status" => json!({"known":true,"exists":false}),
            "telegram-status" => self.telegram_state(),
            "hosts-set" | "prefer-ipv4" | "discord-cache" => event(action, args),
            _ => bail!("Unsupported fixture platform action: {action}"),
        })
    }

    fn run_platform(&self, action: &str, args: Value) -> Result<()> {
        self.print(&self.platform(action, args)?)
    }

    fn run_action(&self, action: Action) -> Result<()> {
        let context = presentation::for_action(&action);
        self.print_context(&context, &self.execute(action)?)
    }

    fn execute(&self, action: Action) -> Result<Value> {
        Ok(match action {
            Action::Start => {
                self.running.set(true);
                event("start", json!({}))
            }
            Action::Restart => {
                ensure!(
                    self.running.get(),
                    "Fixture engine must be running before restart"
                );
                event("restart", json!({}))
            }
            Action::Stop => {
                self.running.set(false);
                event("stop-all", json!({}))
            }
            Action::Test(config) => event(
                "test",
                json!({
                    "apply":config.apply,"full":config.full,"webcheck":config.webcheck,"last":config.last,
                    "compare_a":config.compare_a,"compare_b":config.compare_b
                }),
            ),
            Action::Telegram { action, port } => {
                event(&format!("telegram-{action}"), json!({"port":port}));
                match action.as_str() {
                    "start" => {
                        self.telegram.set(true);
                        self.port.set(self.configured_port.get());
                    }
                    "stop" => self.telegram.set(false),
                    "config" => self
                        .configured_port
                        .set(port.context("Telegram fixture port")?),
                    _ => bail!("Unexpected Telegram fixture action"),
                }
                self.telegram_state()
            }
            Action::Track { process, seconds } => {
                event("track", json!({"process":process,"seconds":seconds}))
            }
            Action::Scan {
                process,
                seconds,
                apply,
            } => event(
                "scan",
                json!({"process":process,"seconds":seconds,"apply":apply}),
            ),
            Action::Exclude { apply } => event("exclude", json!({"apply":apply})),
            Action::Report { output } => event("report", json!({"output":output})),
            Action::Diag { run, seconds } => event("diag", json!({"run":run,"seconds":seconds})),
            Action::Lists { update } => event("lists", json!({"update":update})),
            Action::Update {
                install,
                from,
                sha256,
                recover,
            } => {
                event(
                    "update",
                    json!({"install":install,"from":from,"sha256":sha256,"recover":recover}),
                );
                json!({"available":!install,"text":"Проверено обновление."})
            }
            Action::DirectRules { output } => event("direct-rules", json!({"output":output})),
            Action::System { action, args } => {
                return self.platform(&action, json!({"args":args}));
            }
            Action::ProviderCheck(args) => network("provider-check", args),
            Action::Latency(args) => network("latency", args),
            Action::Webcheck(args) => network("webcheck", args),
            Action::ConnectionCheck(args) => network("connection-check", args),
            Action::Voicecheck(args) => {
                network("voicecheck", args);
                json!({"capture":{},"control":{},"connection_state":"Unknown"})
            }
            Action::Uninstall => {
                ensure!(
                    self.confirm("Удалить службу и задачи zapret-rust из Windows?")?,
                    "Удаление отменено"
                );
                event("uninstall", json!({}))
            }
            _ => bail!("Unexpected action in the interactive menu fixture"),
        })
    }

    fn telegram_state(&self) -> Value {
        json!({"running":self.telegram.get(),"current":self.telegram.get(),
            "active_port":self.port.get(),"configured_port":self.configured_port.get(),
            "requires_restart":self.telegram.get() && self.port.get() != self.configured_port.get()})
    }

    fn confirm(&self, message: &str) -> Result<bool> {
        loop {
            print!("{message} [y/n] ");
            io::stdout().flush()?;
            let mut line = String::new();
            if io::stdin().read_line(&mut line)? == 0 {
                return Ok(false);
            }
            if let Some(value) = confirmation::answer(&line) {
                return Ok(value);
            }
        }
    }

    fn print(&self, value: &Value) -> Result<()> {
        println!("{}", value["text"].as_str().unwrap_or(""));
        Ok(())
    }

    fn print_context(&self, context: &presentation::Context, value: &Value) -> Result<()> {
        println!("{}", presentation::text(context, value));
        Ok(())
    }

    fn game_check(&self, _: &str) -> Result<()> {
        Ok(())
    }

    fn toggle_startup(&self) -> Result<Value> {
        Ok(event("service-autostart", json!({})))
    }

    fn toggle_task(&self, kind: &str) -> Result<Value> {
        Ok(event("task-configure", json!({"kind":kind})))
    }

    fn mutate_setting(&self, key: &str, value: &str) -> Result<Value> {
        self.change_settings(&[(key, value)])
    }

    fn change_settings(&self, changes: &[(&str, &str)]) -> Result<Value> {
        let mut settings = zapret_core::read_settings(&self.root)?;
        for (key, value) in changes {
            settings.set(key, value)?;
        }
        zapret_core::save_settings(&self.root, &settings)?;
        Ok(event("settings", json!(changes)))
    }
}

fn network(name: &str, args: cli::NetworkArgs) -> Value {
    event(
        name,
        json!({"urls":args.urls,"timeout_ms":args.timeout_ms,"args":args.args}),
    )
}

fn ensure_controller_current() -> Result<()> {
    Ok(())
}

fn runtime_file(root: &Path, name: &str) -> Result<PathBuf> {
    Ok(root.join("runtime").join(name))
}

fn control_feedback(_: &Value, message: &str) -> String {
    message.into()
}

mod interrupt {
    pub fn check() -> anyhow::Result<()> {
        Ok(())
    }
    pub fn action_completed() {}
}

mod selection_learning {
    pub const QUICK_STRATEGY_LIMIT: usize = 18;
}

mod diagnostic_report {
    use super::*;
    pub fn publish(_: &Path, kind: &str, result: Value) -> Result<Value> {
        let mut result = result;
        event(
            "publish",
            json!({"kind":kind, "audio":result["audio_observation"]}),
        );
        result["text"] = json!("Отчёт сохранён.");
        Ok(result)
    }
}

mod maintenance {
    use super::*;
    pub fn recover_start(_: &App) -> Result<()> {
        Ok(())
    }
    pub mod first_run {
        use super::*;

        pub fn lists_status(_: &Path) -> String {
            "локальные копии".into()
        }

        pub fn run(_: &App, mut notify: impl FnMut(&str)) -> Result<Value> {
            event("first-run", json!({}));
            notify("Проверяю совместимость…");
            Ok(json!({"complete":true,"text":"Первая настройка завершена."}))
        }
    }
    pub fn start_background_maintenance(_: &App, _: bool) {}
    pub fn notices(_: &App) -> Result<Value> {
        event("notices", json!({}));
        Ok(json!({"notices":[{"text":"Тестовое уведомление"}]}))
    }
    pub fn pc_check(_: &App) -> Result<Value> {
        event("pc-check", json!({}));
        Ok(json!({"text":"Тестовая диагностика","fixes":[
            {"action":"hosts-set","text":"Проверить правку hosts","arguments":{"enabled":true}},
            {"action":"prefer-ipv4","text":"Проверить приоритет IPv4","arguments":{"enabled":true}}
        ]}))
    }
}
