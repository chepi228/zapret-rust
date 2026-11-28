mod cli;
mod comparison;
mod confirmation;
mod console;
mod diagnostic_report;
mod interrupt;
mod lab;
mod maintenance;
mod menu;
mod presentation;
mod provider_report;
mod selection;
mod selection_decision;
mod selection_latency;
mod selection_learning;
mod selection_ui;
mod settings_control;
mod snapshot;
mod telegram_control;
mod updates;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use cli::{Action, Cli, NetworkArgs};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
use zapret_core::{
    ComposeOptions, compose, find_strategy, list_strategies, read_settings, save_settings,
    strategy_index_by_name,
};

pub const VERSION: &str = zapret_core::PACKAGE_VERSION;
struct ControllerIdentity {
    path: PathBuf,
    hash: String,
}
static CONTROLLER_IDENTITY: std::sync::OnceLock<std::result::Result<ControllerIdentity, String>> =
    std::sync::OnceLock::new();

fn controller_identity() -> Result<&'static ControllerIdentity> {
    CONTROLLER_IDENTITY
        .get_or_init(|| {
            std::env::current_exe()
                .map_err(anyhow::Error::from)
                .and_then(|path| {
                    let hash = zapret_core::sha256_file(&path)?;
                    Ok(ControllerIdentity { path, hash })
                })
                .map_err(|error| format!("{error:#}"))
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!(error.clone()))
}

pub fn ensure_controller_current() -> Result<()> {
    verify_controller_current(controller_identity()?)
}

pub(crate) fn controller_hash() -> Result<&'static str> {
    Ok(&controller_identity()?.hash)
}

fn verify_controller_current(identity: &ControllerIdentity) -> Result<()> {
    verify_controller_hash(identity, &zapret_core::sha256_file(&identity.path)?)
}

fn verify_controller_hash(identity: &ControllerIdentity, current: &str) -> Result<()> {
    // Windows changes current_exe() to the backup name after File.Replace.
    // Keep checking the original entry point so an old menu cannot control a
    // package that another window has updated.
    ensure!(
        identity.hash == current,
        "Файл программы обновлён другим окном. Откройте zapret-rust заново"
    );
    Ok(())
}

pub(crate) fn ensure_snapshot_current(snapshot: &snapshot::Snapshot) -> Result<()> {
    snapshot.assert_current()?;
    let identity = controller_identity()?;
    #[cfg(windows)]
    if let Some(hash) = snapshot.pinned_source_hash(&identity.path) {
        return verify_controller_hash(identity, hash);
    }
    verify_controller_current(identity)
}

pub struct App {
    pub root: PathBuf,
    pub yes: bool,
    pub json: bool,
}

fn main() {
    if let Err(error) = run() {
        if std::env::args().any(|argument| argument == "--json") {
            eprintln!("zapret-rust: {error:#}");
        } else {
            eprintln!("zapret-rust: {}", presentation::error_text(&error));
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let action = cli.action.unwrap_or(Action::Menu);
    if let Action::TelegramCore {
        config,
        config_sha256,
    } = action
    {
        // Use the same bounded, reparse-aware reader as the supervisor. The
        // secret stays in the config file instead of the process command line.
        return zapret_platform::run_telegram_core(&config, &config_sha256);
    }
    if let Action::MenuPreview {
        screen,
        width,
        height,
        wait,
        png,
    } = action
    {
        if let Some(output) = png {
            let report = menu::preview_frame(&screen, width, height).save_png(&output)?;
            if cli.json {
                println!("{}", report)
            } else {
                println!("{}", output.display())
            }
        } else {
            menu::preview(&screen, width, height)?;
        }
        if wait {
            console::prompt("Enter — закрыть предпросмотр")?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
        }
        return Ok(());
    }
    if let Action::Probe {
        parallel,
        deadline_ms,
        ca_file,
        post_file,
    } = action
    {
        let result = (|| {
            zapret_net::run_stdio(zapret_net::BatchOptions {
                parallel,
                deadline_ms,
                ca_file,
                post_body: post_file
                    .map(|path| zapret_core::read_bounded(&path, 65536))
                    .transpose()?,
            })
        })();
        if let Err(error) = result {
            eprintln!("zapret-rust probe: {error:#}");
            std::process::exit(2);
        }
        return Ok(());
    }
    let app = App {
        root: find_root(cli.root)?,
        yes: cli.yes,
        json: cli.json || matches!(action, Action::PlatformWorker { .. }),
    };
    if matches!(action, Action::Menu) {
        controller_identity()?;
        return menu::run(&app);
    }
    app.run_action(action)
}

fn find_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        // BAT uses "%~dp0." to avoid a quoted path ending in a backslash.
        // Resolve ordinary Win32 dot components before deriving engine paths
        // used for exact process/service ownership checks.
        let path = std::path::absolute(path).context("Не удалось определить путь папки пакета")?;
        ensure!(path.is_dir(), "Папка пакета недоступна");
        return Ok(path);
    }
    let executable = std::env::current_exe()?;
    let current = std::env::current_dir()?;
    for path in executable.ancestors().chain(current.ancestors()) {
        if path.join("tools/upstream.txt").is_file() {
            return Ok(path.to_owned());
        }
    }
    bail!("Папка zapret-rust не найдена. Укажите --root")
}

fn strategy_id(root: &Path, choice: &str) -> Result<String> {
    if choice.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(choice.to_owned());
    }
    let strategies = list_strategies(root)?;
    let index = strategy_index_by_name(&strategies, choice)?.context("Стратегия недоступна")?;
    Ok(strategies[index].id.clone())
}

impl App {
    pub fn run_action(&self, action: Action) -> Result<()> {
        let context = presentation::for_action(&action);
        let value = self.execute(action)?;
        self.print_context(&context, &value)
    }

    pub fn run_platform(&self, name: &str, arguments: Value) -> Result<()> {
        let value = self.platform(name, arguments)?;
        self.print_context(&presentation::Context::platform(name), &value)
    }
    pub fn platform(&self, name: &str, arguments: Value) -> Result<Value> {
        zapret_platform::command(&self.root, name, &arguments)
    }

    pub fn print(&self, value: &Value) -> Result<()> {
        self.print_context(&presentation::Context::platform("result"), value)
    }

    pub fn print_context(&self, context: &presentation::Context, value: &Value) -> Result<()> {
        if let Some(frame) = (!self.json)
            .then(|| {
                selection_ui::result_frame_mode(
                    value,
                    console::Viewport::current(),
                    context.operation == "test-last",
                )
            })
            .flatten()
        {
            if context.operation == "test" {
                frame.append()?;
            } else {
                frame.show()?;
            }
        } else if !self.json {
            println!("{}", presentation::text(context, value));
        } else {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        if value["restart_required"] == true {
            io::stdout().flush()?;
            std::process::exit(0);
        }
        Ok(())
    }

    pub fn confirm(&self, text: &str) -> Result<bool> {
        if self.yes {
            return Ok(true);
        }
        loop {
            print!("{text} [y/n] ");
            io::stdout().flush()?;
            let mut input = String::new();
            if io::stdin().read_line(&mut input)? == 0 {
                return Ok(false);
            }
            if let Some(answer) = confirmation::answer(&input) {
                return Ok(answer);
            }
            console::line("Введите y или n. Enter — n.", console::Tone::Warning)?;
        }
    }

    pub fn game_check(&self, text: &str) -> Result<()> {
        let games = self.platform("games", json!({}))?;
        let active = games.as_array().is_some_and(|games| !games.is_empty())
            || games
                .get("processes")
                .and_then(Value::as_array)
                .is_some_and(|games| !games.is_empty());
        ensure!(
            !active || self.confirm(&format!("Запущена игра. {text}. Продолжить?"))?,
            "Действие отменено"
        );
        Ok(())
    }

    pub fn mutate_setting(&self, key: &str, value: &str) -> Result<Value> {
        self.change_settings(&[(key, value)])
    }

    pub fn change_settings(&self, changes: &[(&str, &str)]) -> Result<Value> {
        ensure_controller_current()?;
        let _guard = zapret_platform::ControlGuard::acquire(&self.root, "settings")?;
        let previous = read_settings(&self.root)?;
        let mut settings = previous.clone();
        for (key, value) in changes {
            if key.eq_ignore_ascii_case("alt") {
                let id = strategy_id(&self.root, value)?;
                settings.set(key, &id)?;
                ensure!(
                    find_strategy(&self.root, &id)?.is_some_and(|strategy| strategy.is_valid()),
                    "Стратегия недоступна"
                );
            } else {
                settings.set(key, value)?;
            }
        }
        let selected = settings.get("game").eq_ignore_ascii_case("selected");
        let affects_engine = changes.iter().any(|(key, _)| {
            engine_setting(key)
                && previous.get(key) != settings.get(key)
                && (!key.eq_ignore_ascii_case("gameapps") || selected)
        });
        let running = if affects_engine {
            let state = self.platform("status", json!({}))?;
            ensure!(
                state["known"] == true && state["ownership_known"] == true,
                "Состояние рабочего обхода неизвестно"
            );
            state["running"]
                .as_bool()
                .context("Состояние рабочего обхода неизвестно")?
        } else {
            false
        };
        if running {
            self.game_check("Изменение настроек перезапустит обход")?;
        }
        if affects_engine {
            zapret_core::prepare_runtime(&self.root, &settings)?;
            let options = ComposeOptions {
                dry_run: true,
                persistence: false,
                native_identity: Some(controller_hash()?.to_owned()),
                ..Default::default()
            };
            let arguments = compose(&self.root, &settings, &options)?;
            maintenance::check_engine_args(&self.root, &arguments)?;
        }
        save_settings(&self.root, &settings)?;
        let mut restart_result = Value::Null;
        if running {
            let outcome = self
                .platform("restart", json!({"game_approved":true}))
                .and_then(|outcome| {
                    require_requested_start(&outcome, &settings, &read_settings(&self.root)?)?;
                    verified_control_state(&self.platform("status", json!({}))?, true)?;
                    Ok(outcome)
                });
            match outcome {
                Ok(outcome) => restart_result = outcome,
                Err(error) => {
                    // A checked fallback may already have restored the previous
                    // engine and settings. Keep that healthy process in place.
                    if read_settings(&self.root)? == previous
                        && self
                            .platform("status", json!({}))
                            .and_then(|state| verified_control_state(&state, true))
                            .is_ok()
                    {
                        return Err(error.context(
                            "Запрошенные настройки не применены; прежний обход восстановлен",
                        ));
                    }
                    save_settings(&self.root, &previous)?;
                    let restored = self.platform("restart", json!({"game_approved":true}));
                    let description = match restored {
                        Ok(_) => match self
                            .platform("status", json!({}))
                            .and_then(|state| verified_control_state(&state, true))
                        {
                            Ok(()) => "прежний обход восстановлен".to_owned(),
                            Err(_) => "восстановление обхода не подтверждено".to_owned(),
                        },
                        Err(cause) => format!(
                            "восстановление не удалось: {}",
                            presentation::error_text(&cause)
                        ),
                    };
                    return Err(error.context(format!("Настройки возвращены; {description}")));
                }
            }
        }
        let message = if running {
            "Настройки сохранены. Обход перезапущен."
        } else {
            "Настройки сохранены."
        };
        let text = control_feedback(&restart_result, message);
        Ok(
            json!({"saved":true,"settings":settings.values,"restarted":running,
            "restart":restart_result,"text":text}),
        )
    }

    pub fn execute(&self, action: Action) -> Result<Value> {
        ensure_controller_current()?;
        match action {
            Action::Menu => bail!("Меню запускается отдельным входом"),
            Action::FirstRun => maintenance::first_run::run(self, |_| {}),
            Action::MenuPreview { .. } => bail!("Предпросмотр запускается отдельным входом"),
            Action::Probe { .. } => bail!("Probe использует стандартный ввод и вывод"),
            Action::Status => self.platform("status", json!({})),
            Action::Start | Action::Restart => {
                let restarting = matches!(action, Action::Restart);
                self.game_check("Запуск может прервать соединение матча")?;
                let recovery = updates::recover(&self.root)?;
                if recovery["restart_required"] == true {
                    return Ok(recovery);
                }
                let mut result = self.platform(
                    if restarting { "restart" } else { "start" },
                    json!({"game_approved":true}),
                )?;
                verified_control_state(&self.platform("status", json!({}))?, true)?;
                let message = if result["restored"] == true {
                    "Новая конфигурация не запустилась. Обход работает на восстановленной конфигурации."
                } else if restarting {
                    "Обход перезапущен."
                } else {
                    "Обход запущен."
                };
                result["text"] = json!(control_feedback(&result, message));
                maintenance::clear_restart_intent(self)?;
                let pending = runtime_file(&self.root, "test-restore-pending.txt")?;
                if pending.is_file() {
                    std::fs::remove_file(pending)?;
                }
                Ok(result)
            }
            Action::Stop => {
                self.game_check("Все экземпляры zapret будут остановлены")?;
                let mut result = self.platform("stop-all", json!({"game_approved":true}))?;
                let mut message = "Все экземпляры обхода zapret остановлены.".to_owned();
                if let Some(warning) = result["driver"]["warning"].as_str() {
                    message.push_str(&format!("\nWinDivert: {warning}"));
                }
                result["text"] = json!(message);
                Ok(result)
            }
            Action::Strategies => {
                let mut strategies = list_strategies(&self.root)?;
                for strategy in &mut strategies {
                    strategy.name = strategy.display_name().to_owned();
                }
                Ok(serde_json::to_value(strategies)?)
            }
            Action::Settings { key, value } => match (key, value) {
                (Some(key), Some(value)) => self.mutate_setting(&key, &value),
                (Some(key), None) => {
                    Ok(json!({"key":key,"value":read_settings(&self.root)?.get(&key)}))
                }
                (None, None) => Ok(serde_json::to_value(read_settings(&self.root)?.values)?),
                _ => bail!("Для значения настройки нужен ключ"),
            },
            Action::Compose {
                alt,
                no_auto,
                ipset,
                dry_run,
                validate,
                debug_file,
            } => {
                let settings = read_settings(&self.root)?;
                let alt = alt
                    .as_deref()
                    .map(|choice| strategy_id(&self.root, choice))
                    .transpose()?;
                let network_key = if !no_auto
                    && settings.get("auto").eq_ignore_ascii_case("on")
                    && self.root.join("runtime/test-rank.txt").exists()
                {
                    let network = self.platform("network", json!({}))?;
                    network["key"]
                        .as_str()
                        .filter(|_| network["known"] == true)
                        .map(str::to_owned)
                } else {
                    None
                };
                let arguments = compose(
                    &self.root,
                    &settings,
                    &ComposeOptions {
                        alt,
                        no_auto,
                        ipset_mode: ipset,
                        dry_run,
                        debug_file,
                        persistence: false,
                        network_key,
                        native_identity: Some(controller_hash()?.to_owned()),
                    },
                )?;
                let validation = if validate {
                    Some(maintenance::check_engine_args(&self.root, &arguments)?)
                } else {
                    None
                };
                Ok(
                    json!({"executable":self.root.join("bin/winws2.exe"),"arguments":arguments,"validation":validation}),
                )
            }
            Action::Integrity => maintenance::integrity(&self.root),
            Action::Test(arguments) => selection::run(self, &arguments),
            Action::Lab(arguments) => lab::run(self, &arguments),
            Action::ComparisonReport {
                file,
                plan_file,
                journal_file,
                output,
            } => {
                if let (Some(plan), Some(journal)) = (plan_file, journal_file) {
                    return zapret_core::legacy_comparison::replay(
                        &plan,
                        &journal,
                        output.as_deref(),
                    );
                }
                let file = file.context("Не указан файл сравнения")?;
                let record: Value =
                    serde_json::from_slice(&zapret_core::read_bounded(&file, 32 * 1024 * 1024)?)?;
                let assessment = comparison::assess_saved(&record)?;
                if let Some(output) = output {
                    zapret_core::atomic_write(
                        &std::path::absolute(output)?,
                        &serde_json::to_vec_pretty(&assessment)?,
                    )?;
                }
                Ok(json!({"source":file,"text":assessment["text"],"assessment":assessment}))
            }
            Action::Autotune { force } => maintenance::autotune(self, force),
            Action::ConnectionCheck(arguments) => self.network("connection", arguments),
            Action::Webcheck(arguments) => self.network("webcheck", arguments),
            Action::YoutubeCheck => {
                let result = zapret_net::diagnostics(
                    &self.root,
                    "webcheck",
                    &json!({
                        "url": "https://www.youtube.com/watch?v=jNQXAC9IVRw",
                        "modes": ["BrowserPlayback"], "visits": 1, "timeout_ms": 30000
                    }),
                )?;
                diagnostic_report::publish(&self.root, "youtube", result)
            }
            Action::Voicecheck(arguments) => self.network("voice", arguments),
            Action::Latency(arguments) => self.network("latency", arguments),
            Action::ProviderCheck(arguments) => provider_report::run(self, &arguments),
            Action::ProviderInfo(arguments) => self.network("provider", arguments),
            Action::Track { process, seconds } => {
                maintenance::track(self, &process, seconds, false)
            }
            Action::Scan {
                process,
                seconds,
                apply,
            } => maintenance::scan(self, &process, seconds, apply),
            Action::Exclude { apply } => maintenance::exclude(self, apply),
            Action::Report { output } => maintenance::report(self, output.as_deref()),
            Action::Lists { update } => maintenance::lists(self, update),
            Action::Update {
                install,
                from,
                sha256,
                recover,
            } => {
                if recover {
                    updates::recover(&self.root)
                } else {
                    updates::update(self, install, from.as_deref(), sha256.as_deref())
                }
            }
            Action::Package {
                output,
                compatibility,
            } => updates::package(&self.root, &output, compatibility),
            Action::Service { action } => {
                if action != "status" {
                    self.game_check("Изменение службы может прервать обход")?;
                }
                self.platform(&format!("service-{action}"), json!({"game_approved":true}))
            }
            Action::Task { action, kind } => {
                if matches!(action.as_str(), "install" | "remove") {
                    self.game_check("Изменить фоновую задачу во время игры")?;
                    self.platform(
                        "task-configure",
                        json!({"kind":kind,"enabled":action=="install","game_approved":true}),
                    )
                } else {
                    self.platform(&format!("task-{action}"), json!({"kind":kind}))
                }
            }
            Action::Telegram { action, port } => self.telegram(&action, port),
            Action::TelegramCore { .. } => unreachable!("core worker handled before package setup"),
            Action::Hosts { action, args } => {
                self.platform(&format!("hosts-{action}"), parse_arguments(args)?)
            }
            Action::System { action, args } => self.platform(&action, parse_arguments(args)?),
            Action::DirectRules { output } => maintenance::direct_rules(self, output.as_deref()),
            Action::Diag { run, seconds } => maintenance::diagnostic_engine(self, run, seconds),
            Action::Notify { watch } => maintenance::notify(self, watch),
            Action::Watch => maintenance::watch(self),
            Action::Uninstall => maintenance::uninstall(self),
            Action::PlatformWorker {
                action,
                arguments_json,
            } => self.platform(&action, parse_arguments(Some(arguments_json))?),
        }
    }

    fn network(&self, kind: &str, arguments: NetworkArgs) -> Result<Value> {
        let mut parameters = parse_arguments(arguments.args)?;
        if kind == "latency" {
            if !arguments.urls.is_empty() {
                let addresses = arguments
                    .urls
                    .iter()
                    .map(|text| text.parse::<std::net::IpAddr>())
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                parameters["addresses"] = json!(addresses);
            } else if parameters.get("ip").is_none() && parameters.get("addresses").is_none() {
                let adapters = self.platform("adapters", json!({}))?;
                let gateway = adapters
                    .as_array()
                    .context("Недоступен список адаптеров")?
                    .iter()
                    .filter(|adapter| adapter["if_type"] == 71 && adapter["up"] == true)
                    .find_map(|adapter| {
                        adapter["gateways"]
                            .as_array()?
                            .iter()
                            .find_map(Value::as_str)
                    })
                    .context("Не найден шлюз активного Wi-Fi. Укажите IP-адрес явно")?;
                parameters["ip"] = json!(gateway);
                parameters["protocol"] = json!("icmp");
            }
        } else {
            parameters["urls"] = json!(arguments.urls);
        }
        parameters["timeout_ms"] = json!(arguments.timeout_ms);
        let result = zapret_net::diagnostics(&self.root, kind, &parameters)?;
        diagnostic_report::publish(
            &self.root,
            if kind == "webcheck" { "web" } else { kind },
            result,
        )
    }
}

fn parse_arguments(text: Option<String>) -> Result<Value> {
    let value: Value = text
        .map(|text| serde_json::from_str(&text))
        .transpose()?
        .unwrap_or_else(|| json!({}));
    ensure!(value.is_object(), "Аргументы должны быть JSON-объектом");
    Ok(value)
}

fn engine_setting(key: &str) -> bool {
    [
        "alt", "auto", "game", "gameapps", "ipset", "gametcp", "gameudp", "autolist",
    ]
    .iter()
    .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

fn require_requested_start(
    outcome: &Value,
    requested: &zapret_core::Settings,
    actual: &zapret_core::Settings,
) -> Result<()> {
    ensure!(
        outcome["running"] == true,
        "Работа обхода после перезапуска не подтверждена"
    );
    ensure!(
        outcome["restored"] != true && requested == actual,
        "Новая конфигурация не запущена; применена прежняя подтверждённая конфигурация"
    );
    Ok(())
}

fn control_feedback(result: &Value, message: &str) -> String {
    let mut text = message.to_owned();
    for (field, label) in [
        ("watcher_error", "Фоновый контроль не запущен"),
        (
            "watch_task_error",
            "Автозапуск фонового контроля не настроен",
        ),
        (
            "confirmation_warning",
            "Подтверждённая конфигурация не сохранена",
        ),
    ] {
        if let Some(error) = result[field].as_str().filter(|error| !error.is_empty()) {
            text.push_str(&format!("\n{label}: {error}"));
        }
    }
    for (name, label) in [
        ("telegram", "Telegram"),
        ("gamepins", "Закрепление игровых адресов"),
    ] {
        let state = &result["post_start"][name];
        if state["enabled"] == true && state["ok"] != true {
            text.push_str(&format!(
                "\n{label}: {}",
                state["error"].as_str().unwrap_or("работа не подтверждена")
            ));
        }
    }
    text
}

fn verified_control_state(status: &Value, running: bool) -> Result<()> {
    ensure!(
        status["known"] == true && status["ownership_known"] == true,
        "Не удалось подтвердить состояние и владельца обхода"
    );
    ensure!(
        status["running"] == running,
        "Запрошенное состояние обхода не подтверждено"
    );
    let processes = status["processes"]
        .as_array()
        .context("Недоступен список процессов обхода")?;
    let service = &status["service"];
    let foreign_service_stopped = service["owned"] == false
        && service["ownership_known"] == true
        && service["state"] == 1
        && service["pid"] == 0;
    let check_service = service["installed"] == true && !foreign_service_stopped;
    if running {
        ensure!(
            processes.len() == 1,
            "Не удалось подтвердить единственный процесс обхода"
        );
        let identity = &processes[0];
        ensure!(
            identity["pid"].as_u64().is_some_and(|pid| pid > 0)
                && identity["created_filetime"]
                    .as_u64()
                    .is_some_and(|time| time > 0)
                && identity["executable"]
                    .as_str()
                    .is_some_and(|path| !path.is_empty()),
            "Идентичность процесса обхода не подтверждена"
        );
        if check_service {
            ensure!(
                service["owned"] == true
                    && service["state"] == 4
                    && service["pid"] == identity["pid"],
                "Работа службы обхода не подтверждена"
            );
        }
    } else {
        ensure!(
            processes.is_empty(),
            "После остановки остались процессы обхода"
        );
        if check_service {
            ensure!(
                service["owned"] == true && service["state"] == 1 && service["pid"] == 0,
                "Остановка службы обхода не подтверждена"
            );
        }
    }
    Ok(())
}

pub fn runtime_file(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = root
        .join("runtime")
        .join(snapshot::relative_path(relative)?);
    let mut current = root.to_owned();
    for part in path.strip_prefix(root)?.components() {
        current.push(part);
        if current.exists() {
            snapshot::check_plain(&current)?;
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn controller_guard_checks_the_original_entry_after_mapped_image_rename() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("zapret-rust.exe");
        let backup = directory.path().join("previous.old");
        std::fs::write(&path, b"original controller").unwrap();
        let identity = super::ControllerIdentity {
            hash: zapret_core::sha256_file(&path).unwrap(),
            path: path.clone(),
        };
        assert!(super::verify_controller_current(&identity).is_ok());
        std::fs::rename(&path, &backup).unwrap();
        std::fs::write(&path, b"replacement controller").unwrap();
        assert_eq!(zapret_core::sha256_file(&backup).unwrap(), identity.hash);
        assert!(super::verify_controller_current(&identity).is_err());
    }
    #[test]
    fn control_feedback_exposes_enabled_component_failures_after_engine_start() {
        let result = serde_json::json!({"watch_task_error":"registration failed", "post_start":{
            "telegram":{"enabled":true,"ok":false,"error":"listener not ready"},
            "gamepins":{"enabled":false,"error":"should not be shown"}}});
        let text = super::control_feedback(&result, "Обход запущен.");
        assert!(text.starts_with("Обход запущен."));
        assert!(text.contains("Автозапуск фонового контроля не настроен: registration failed"));
        assert!(text.contains("Telegram: listener not ready"));
        assert!(!text.contains("should not be shown"));
        assert_eq!(
            super::control_feedback(&serde_json::json!({}), "Обход запущен."),
            "Обход запущен."
        );
    }
    #[test]
    fn control_success_requires_a_confirmed_owned_engine_and_service() {
        let healthy = serde_json::json!({"known":true,"ownership_known":true,"running":true,
            "processes":[{"pid":42,"created_filetime":100,"executable":"C:/package/bin/winws2.exe"}],
            "service":{"installed":true,"owned":true,"state":4,"pid":42}});
        assert!(super::verified_control_state(&healthy, true).is_ok());
        for (field, value) in [
            ("known", serde_json::json!(false)),
            ("ownership_known", serde_json::json!(false)),
            ("processes", serde_json::json!([])),
            ("processes", serde_json::json!([{"pid":42},{"pid":43}])),
            (
                "service",
                serde_json::json!({"installed":true,"owned":false,"state":4,"pid":42}),
            ),
            (
                "service",
                serde_json::json!({"installed":true,"owned":true,"state":2,"pid":42}),
            ),
            (
                "service",
                serde_json::json!({"installed":true,"owned":true,"state":4,"pid":43}),
            ),
        ] {
            let mut status = healthy.clone();
            status[field] = value;
            assert!(
                super::verified_control_state(&status, true).is_err(),
                "Unconfirmed status was accepted: {status}"
            );
        }
        let mut standalone = healthy;
        standalone["service"] = serde_json::json!({"installed":false,"owned":false});
        assert!(super::verified_control_state(&standalone, true).is_ok());
        standalone["service"] = serde_json::json!({
            "installed":true,"owned":false,"ownership_known":true,"state":1,"pid":0
        });
        assert!(super::verified_control_state(&standalone, true).is_ok());
        standalone["service"]["pid"] = serde_json::json!(42);
        assert!(super::verified_control_state(&standalone, true).is_err());
    }

    #[test]
    fn stop_success_requires_no_owned_processes_and_a_stopped_service() {
        let stopped = serde_json::json!({"known":true,"ownership_known":true,"running":false,"processes":[],
            "service":{"installed":true,"owned":true,"state":1,"pid":0}});
        assert!(super::verified_control_state(&stopped, false).is_ok());
        for (field, value) in [
            ("known", serde_json::json!(false)),
            (
                "processes",
                serde_json::json!([{"pid":42,"created_filetime":100}]),
            ),
            (
                "service",
                serde_json::json!({"installed":true,"owned":true,"state":3,"pid":42}),
            ),
        ] {
            let mut status = stopped.clone();
            status[field] = value;
            assert!(super::verified_control_state(&status, false).is_err());
        }
    }

    #[test]
    fn bat_root_spelling_keeps_the_same_engine_path_for_ownership_checks() {
        let temporary = tempfile::tempdir().unwrap();
        let package = temporary.path().join("package with spaces");
        std::fs::create_dir_all(package.join("child")).unwrap();
        let expected_engine = package.join("bin/winws2.exe");
        for spelling in [
            package.join("."),
            package.join(r"child\.."),
            package.join(r".\child\..\."),
        ] {
            let root = super::find_root(Some(spelling.clone())).unwrap();
            // Ownership comparisons inspect the raw Windows path spelling.
            // Path equality alone already ignores some dot components.
            assert_eq!(
                root.join("bin/winws2.exe").as_os_str(),
                expected_engine.as_os_str(),
                "Root spelling: {}",
                spelling.display()
            );
        }
        let other_package = temporary.path().join("other package");
        std::fs::create_dir(&other_package).unwrap();
        assert_ne!(
            super::find_root(Some(other_package))
                .unwrap()
                .join("bin/winws2.exe"),
            expected_engine
        );
    }

    #[test]
    fn setting_case_cannot_bypass_the_engine_restart_and_game_guard() {
        for key in [
            "ALT", "aUtO", "GAME", "IPSET", "GameTcp", "GAMEUDP", "AutoList",
        ] {
            assert!(super::engine_setting(key), "{key}");
        }
        assert!(!super::engine_setting("future-unknown"));
    }
    #[test]
    fn checked_fallback_cannot_claim_that_requested_settings_were_applied() {
        let previous = zapret_core::Settings::default();
        let mut requested = previous.clone();
        requested.set("alt", "13").unwrap();
        assert!(
            super::require_requested_start(
                &serde_json::json!({"running":true,"restored":true}),
                &requested,
                &previous
            )
            .is_err()
        );
        assert!(
            super::require_requested_start(
                &serde_json::json!({"running":true,"restored":false}),
                &requested,
                &previous
            )
            .is_err()
        );
        assert!(
            super::require_requested_start(
                &serde_json::json!({"running":true,"restored":false}),
                &requested,
                &requested
            )
            .is_ok()
        );
    }
}
