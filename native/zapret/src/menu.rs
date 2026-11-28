use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::io::{self, Write};
use zapret_core::{
    Settings, Strategy, find_strategy, list_strategies, read_settings, strategy_index_by_name,
};

use crate::{
    App, VERSION,
    cli::{Action, NetworkArgs, TestArgs},
    console::{self, Frame, Tone, Viewport},
    maintenance, presentation,
    selection_learning::QUICK_STRATEGY_LIMIT,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Back,
    Displayed,
}

fn action(app: &App, action: Action) -> Result<Outcome> {
    app.run_action(action)?;
    Ok(Outcome::Displayed)
}

fn show(app: &App, value: &Value) -> Result<Outcome> {
    app.print(value)?;
    Ok(Outcome::Displayed)
}

fn show_platform(app: &App, name: &str, value: &Value) -> Result<Outcome> {
    app.print_context(&presentation::Context::platform(name), value)?;
    Ok(Outcome::Displayed)
}

fn finish(app: &App, result: Result<Outcome>) -> Result<()> {
    crate::interrupt::action_completed();
    let result = match result {
        Ok(Outcome::Back) => Ok(()),
        Ok(Outcome::Displayed) => pause(),
        Err(error) => {
            if [
                "Действие отменено",
                "Удаление отменено",
                "Обновление отменено",
                "Очистка отменена",
                "Автоподбор отложен",
            ]
            .contains(&error.to_string().as_str())
            {
                return Ok(());
            }
            if let Ok(path) = crate::runtime_file(&app.root, "menu-errors.log") {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = writeln!(file, "{} {error:#}", chrono::Utc::now().to_rfc3339());
                }
            }
            eprintln!("{}", presentation::error_text(&error));
            pause()
        }
    };
    crate::interrupt::action_completed();
    result
}

pub fn run(app: &App) -> Result<()> {
    if !app.platform("admin", json!({}))?["is_admin"]
        .as_bool()
        .unwrap_or(false)
    {
        app.platform("elevate", json!({"parameters":["--root",app.root,"menu"]}))?;
        return Ok(());
    }
    app.platform("unblock-package", json!({}))?;
    let protection = app.platform("protect-package", json!({}))?;
    if protection["known"] != true {
        eprintln!("Защита файлов пакета не подтверждена. Управление может быть недоступно.");
    }
    maintenance::recover_start(app)?;
    let legacy = app.platform("legacy-status", json!({}))?;
    if legacy["migration_required"] == true {
        if legacy["known"]==true&&app.confirm("Найдена прежняя регистрация zapret-rust. Перенести службу и автонастройку в нативную версию?")? {
            app.game_check("Перенос прежней регистрации может перезапустить обход")?;
            app.run_platform("legacy-migrate",json!({"game_approved":true}))?;
        }else{eprintln!("Прежняя регистрация сохранена. Управление обходом доступно после подтверждённого переноса.");}
    }
    let setup = maintenance::first_run::run(app, |message| eprintln!("{message}"));
    let already_prepared = setup.as_ref().is_ok_and(|v| v["already_complete"] == true);
    let mut setup_notice = match setup {
        Ok(value) if !already_prepared => value["text"].as_str().map(str::to_owned),
        Ok(_) => None,
        Err(error) => Some(format!("Первая настройка отложена. {error:#}")),
    };
    crate::interrupt::action_completed();
    maintenance::start_background_maintenance(app, already_prepared);
    loop {
        main_frame(&MenuView::load(app)?, Viewport::current()).show()?;
        if let Some(text) = setup_notice.take() {
            println!("{text}");
        }
        let Some(choice) = input("Выбор")? else {
            return Ok(());
        };
        if matches!(choice.as_str(), "0" | "") {
            return Ok(());
        }
        let result = (|| -> Result<Outcome> {
            match choice.as_str() {
                "1" => {
                    let state = app.platform("status", json!({}))?;
                    action(
                        app,
                        if state["running"] == true {
                            Action::Restart
                        } else {
                            Action::Start
                        },
                    )
                }
                "2" => action(app, Action::Stop),
                "3" => choose_test(app),
                "4" => telegram(app),
                "5" => choose_strategy(app),
                "6" => pc_check(app).map(|_| Outcome::Displayed),
                "7" => settings(app).map(|_| Outcome::Back),
                "8" => tools(app).map(|_| Outcome::Back),
                "9" => notices(app).map(|_| Outcome::Displayed),
                _ => match shortcut(app, &choice) {
                    Some(result) => result,
                    None => {
                        anyhow::bail!("Нет такого пункта меню. Выберите номер или 0 для выхода.")
                    }
                },
            }
        })();
        finish(app, result)?;
    }
}

struct MenuView {
    settings: Settings,
    status: Value,
    strategy: String,
}

impl MenuView {
    fn load(app: &App) -> Result<Self> {
        let settings = read_settings(&app.root)?;
        let strategy = find_strategy(&app.root, settings.get("alt"))?
            .map(|strategy| strategy.display_name().to_owned())
            .unwrap_or_else(|| format!("ALT{} (нет файла)", settings.get("alt")));
        Ok(Self {
            settings,
            status: app.platform("status", json!({}))?,
            strategy,
        })
    }

    fn state(&self) -> (&'static str, Tone) {
        let service = &self.status["service"];
        if service["running"] == true
            && service["ownership_known"] == true
            && service["owned"] == false
        {
            ("Обход запущен из другой папки", Tone::Warning)
        } else if self.status["known"] != true || self.status["ownership_known"] != true {
            ("Состояние обхода не подтверждено", Tone::Warning)
        } else if self.status["running"] == true {
            ("Обход запущен", Tone::Good)
        } else {
            ("Обход остановлен", Tone::Secondary)
        }
    }

    fn startup(&self) -> &'static str {
        let service = &self.status["service"];
        if service["known"] == false || service["ownership_known"] == false {
            "не подтверждён"
        } else if service["installed"] == false || service["exists"] == false {
            "выкл"
        } else if service["owned"] != true {
            "не подтверждён"
        } else {
            match service["start_type"].as_u64() {
                Some(2) => "с Windows",
                Some(3) => "выкл",
                Some(4) => "служба отключена",
                _ => "не подтверждён",
            }
        }
    }

    fn summary(&self, viewport: Viewport, compact: bool) -> Frame {
        let mut frame = Frame::new(viewport, &format!("zapret-rust v{VERSION}"));
        let (state, tone) = self.state();
        frame.row(&format!("  {state}"), tone);
        frame.row(
            &format!(
                "  Стратегия: {} · автосмена {}",
                self.strategy,
                on_off(self.settings.get("auto"))
            ),
            Tone::Primary,
        );
        if !compact {
            let telegram = if self.settings.get("telegram") == "on" {
                "включён в настройках"
            } else {
                "выкл"
            };
            frame.row(
                &format!("  Автозапуск: {} · Telegram: {telegram}", self.startup()),
                Tone::Text,
            );
        }
        frame
    }

    fn header(&self, viewport: Viewport, screen: &str, compact: bool) -> Frame {
        let mut frame = self.summary(viewport, compact);
        frame.separator(&screen.to_uppercase());
        frame
    }
}

fn on_off(value: &str) -> &'static str {
    if value == "on" { "вкл" } else { "выкл" }
}

fn main_frame(view: &MenuView, viewport: Viewport) -> Frame {
    let build = |compact| {
        let mut frame = if compact {
            view.summary(viewport, true)
        } else {
            view.header(viewport, "Главная", false)
        };
        if !compact {
            frame.row("  УПРАВЛЕНИЕ", Tone::Secondary);
        }
        frame.item(
            1,
            if view.status["running"] == true {
                "Перезапустить обход"
            } else {
                "Запустить обход"
            },
            Tone::Primary,
        );
        frame.item(2, "Остановить все экземпляры zapret", Tone::Text);
        frame.item(3, "Автоподбор стратегии", Tone::Text);
        frame.item(4, "Мост Telegram", Tone::Text);
        frame.item(5, "Выбрать стратегию вручную", Tone::Text);
        frame.item(6, "Проверка подключения и конфликтов", Tone::Text);
        if !compact {
            frame.separator("");
        }
        frame.item(7, "Настройки", Tone::Text);
        frame.item(8, "Инструменты", Tone::Text);
        frame.item(9, "Уведомления", Tone::Text);
        frame.item(0, "Выйти из меню", Tone::Secondary);
        frame
    };
    let full = build(false);
    if full.height() + 2 > viewport.rows {
        build(true)
    } else {
        full
    }
}

fn settings_frame(view: &MenuView, viewport: Viewport, tune: &str, lists: &str) -> Frame {
    let saved = &view.settings;
    let mut frame = view.header(viewport, "Настройки", viewport.rows < 28);
    frame.row("  ПОДКЛЮЧЕНИЕ", Tone::Secondary);
    let game = match saved.get("game") {
        "all" => "TCP и UDP",
        "selected" => "адреса выбранных игр",
        "tcp" => "только TCP",
        "udp" => "только UDP",
        _ => "выкл",
    };
    let ipset = match saved.get("ipset") {
        "loaded" => "по IP-спискам",
        "any" => "все IP",
        _ => "выключен",
    };
    for (key, text) in [
        (1, format!("Стратегия: {}", view.strategy)),
        (
            2,
            format!("Автосмена при сбое: {}", on_off(saved.get("auto"))),
        ),
        (3, format!("Game Filter: {game}")),
        (4, format!("IPSet: {ipset}")),
        (
            5,
            format!("Автосписок сайтов: {}", on_off(saved.get("autolist"))),
        ),
    ] {
        frame.item(key, &text, Tone::Text);
    }
    frame.separator("ПРИЛОЖЕНИЕ");
    for (key, text) in [
        (6, format!("Автозапуск: {}", view.startup())),
        (7, format!("Автонастройка по расписанию: {tune}")),
        (8, format!("Обновить списки ({lists})")),
        (9, format!("Обновить zapret-rust: у вас {VERSION}")),
        (
            10,
            format!(
                "Уведомления Windows: {}",
                if saved.get("notify") == "off" {
                    "выкл"
                } else {
                    "вкл"
                }
            ),
        ),
    ] {
        frame.item(key, &text, Tone::Text);
    }
    frame.item(11, "Удалить zapret-rust из Windows", Tone::Secondary);
    frame.separator("");
    frame.item(0, "Назад", Tone::Secondary);
    frame
}

fn tools_frame(view: &MenuView, viewport: Viewport) -> Frame {
    let mut frame = view.header(viewport, "Инструменты", viewport.rows < 28);
    frame.row("  ДИАГНОСТИКА И ОТЧЁТЫ", Tone::Secondary);
    for (key, text) in [
        (1, "Трекер матча"),
        (2, "Сканер адресов игры"),
        (3, "Полная проверка провайдера"),
        (4, "Настройки и логи одним файлом"),
        (5, "Диагностика winws2"),
    ] {
        frame.item(key, text, Tone::Text);
    }
    frame.separator("ПОДКЛЮЧЕНИЕ И ПРИЛОЖЕНИЯ");
    for (key, text) in [
        (6, "Исключить игру по последнему трекеру"),
        (7, "Правила напрямую для Happ"),
        (8, "Очистить кэш Discord"),
        (9, "Задержка подключения"),
        (10, "Браузер, HTTP/2 и HTTP/3"),
        (11, "DNS, TCP, TLS и HTTP"),
        (12, "Discord Voice"),
        (13, "Воспроизведение YouTube"),
    ] {
        frame.item(key, text, Tone::Text);
    }
    frame.separator("");
    frame.item(0, "Назад", Tone::Secondary);
    frame
}

fn dialog(title: &str) -> Frame {
    let mut frame = Frame::new(Viewport::current(), &format!("zapret-rust v{VERSION}"));
    frame.separator(&title.to_uppercase());
    frame
}

fn choices(title: &str, options: &[&str]) -> Result<()> {
    let mut frame = dialog(title);
    for (index, text) in options.iter().enumerate() {
        frame.item(index + 1, text, Tone::Text);
    }
    frame.separator("");
    frame.item(0, "Назад", Tone::Secondary);
    frame.show()?;
    Ok(())
}

fn notices(app: &App) -> Result<()> {
    let value = maintenance::notices(app)?;
    notices_frame(Viewport::current(), &value).show()?;
    Ok(())
}

fn notices_frame(viewport: Viewport, value: &Value) -> Frame {
    let mut frame = Frame::new(viewport, &format!("zapret-rust v{VERSION}"));
    frame.separator("УВЕДОМЛЕНИЯ");
    if let Some(items) = value["notices"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        for item in items {
            frame.row(
                &format!("  {}", item["text"].as_str().unwrap_or("Уведомление")),
                Tone::Accent,
            );
            frame.row("", Tone::Text);
        }
    } else {
        frame.row("  Новых уведомлений нет.", Tone::Text);
    }
    frame
}

// Uses fixture data only: no root lookup, elevation, maintenance or bypass control.
pub fn preview(screen: &str, width: Option<usize>, height: Option<usize>) -> Result<()> {
    preview_frame(screen, width, height).show()?;
    Ok(())
}

pub fn preview_frame(screen: &str, width: Option<usize>, height: Option<usize>) -> Frame {
    let mut viewport = Viewport::current();
    if let Some(width) = width {
        viewport.columns = width.clamp(8, 240);
    }
    if let Some(height) = height {
        viewport.rows = height.clamp(8, 100);
    }
    let view = preview_view();
    match screen {
        "settings" => settings_frame(&view, viewport, "выкл", "локальные копии"),
        "tools" => tools_frame(&view, viewport),
        "test" => test_frame(viewport),
        "notifications" => notices_frame(viewport, &json!({"notices":[]})),
        _ => main_frame(&view, viewport),
    }
}

fn preview_view() -> MenuView {
    MenuView {
        settings: Settings::default(),
        status: json!({"known":false,"ownership_known":false,"running":false,"service":{"known":false}}),
        strategy: "WHITE-01".into(),
    }
}

pub fn input(label: &str) -> Result<Option<String>> {
    crate::interrupt::check()?;
    crate::ensure_controller_current()?;
    console::prompt(label)?;
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Ok(None);
    }
    Ok(Some(value.trim().to_owned()))
}

fn pause() -> Result<()> {
    input("Enter — продолжить")?;
    Ok(())
}

fn pc_check(app: &App) -> Result<()> {
    let result = maintenance::pc_check(app)?;
    app.print(&result)?;
    if let Some(fixes) = result["fixes"].as_array() {
        for fix in fixes {
            let Some(action) = fix["action"]
                .as_str()
                .filter(|action| ["hosts-set", "prefer-ipv4"].contains(action))
            else {
                continue;
            };
            let label = fix["text"].as_str().unwrap_or("Применить исправление");
            if app.confirm(label)? {
                app.run_platform(action, fix["arguments"].clone())?;
            }
        }
    }
    Ok(())
}

fn shortcut_name(key: &str) -> Option<&'static str> {
    match key.to_uppercase().as_str() {
        "C" | "С" | "H" | "Р" => Some("check"),
        "S" | "Ы" => Some("service"),
        "U" | "Г" => Some("autotune"),
        "A" | "Ф" => Some("autolist"),
        "P" | "З" => Some("provider"),
        "R" | "К" => Some("report"),
        "D" | "В" => Some("diag"),
        "N" | "Т" => Some("settings"),
        "I" | "Ш" => Some("tools"),
        _ => None,
    }
}

fn shortcut(app: &App, key: &str) -> Option<Result<Outcome>> {
    let name = shortcut_name(key)?;
    Some((|| match name {
        "check" => pc_check(app).map(|_| Outcome::Displayed),
        "service" => show_platform(app, "service-autostart", &app.toggle_startup()?),
        "autotune" => task_toggle(app, "autotune"),
        "autolist" => autolist(app),
        "provider" => action(app, Action::ProviderCheck(network_arguments())),
        "report" => action(app, Action::Report { output: None }),
        "diag" => {
            if app.confirm("Запустить диагностический обход на 60 секунд?")?
            {
                action(
                    app,
                    Action::Diag {
                        run: true,
                        seconds: 60,
                    },
                )
            } else {
                Ok(Outcome::Back)
            }
        }
        "settings" => settings(app).map(|_| Outcome::Back),
        "tools" => tools(app).map(|_| Outcome::Back),
        _ => Ok(Outcome::Back),
    })())
}

fn choose_strategy(app: &App) -> Result<Outcome> {
    let strategies: Vec<_> = list_strategies(&app.root)?
        .into_iter()
        .filter(|strategy| strategy.missing.is_empty())
        .collect();
    if let Some(index) = select_strategy(&strategies, "Выбрать стратегию")? {
        return show(app, &app.mutate_setting("alt", &strategies[index].id)?);
    }
    Ok(Outcome::Back)
}

fn select_strategy(strategies: &[Strategy], title: &str) -> Result<Option<usize>> {
    let mut page = 0usize;
    loop {
        let viewport = Viewport::current();
        let detailed = viewport.columns >= 60 && viewport.rows >= 28;
        let page_size =
            (viewport.rows.saturating_sub(10) / if detailed { 4 } else { 2 }).clamp(1, 8);
        let pages = strategies.len().div_ceil(page_size).max(1);
        page = page.min(pages - 1);
        let mut frame = dialog(title);
        frame.row(
            &format!("  Доступно стратегий: {}", strategies.len()),
            Tone::Secondary,
        );
        for (index, strategy) in strategies
            .iter()
            .enumerate()
            .skip(page * page_size)
            .take(page_size)
        {
            frame.item(index + 1, strategy.display_name(), Tone::Primary);
            if detailed && !strategy.desc.is_empty() {
                frame.row(&format!("     {}", strategy.desc), Tone::Text);
            }
        }
        frame.separator("");
        if pages > 1 {
            frame.row(
                &format!("  Страница {} из {pages} · N — далее · P — назад", page + 1),
                Tone::Secondary,
            );
        }
        frame.item(0, "Назад в меню", Tone::Secondary);
        frame.show()?;
        let Some(choice) = input("Номер или код стратегии")? else {
            return Ok(None);
        };
        match choice.to_uppercase().as_str() {
            "" | "0" => return Ok(None),
            "N" | "Т" => {
                page = (page + 1).min(pages - 1);
                continue;
            }
            "P" | "З" => {
                page = page.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        let Ok(number) = choice.parse::<usize>() else {
            let message = match strategy_index_by_name(strategies, &choice) {
                Ok(Some(index)) => return Ok(Some(index)),
                Ok(None) => "Введите номер или код стратегии из списка.".to_owned(),
                Err(error) => error.to_string(),
            };
            console::line(&message, Tone::Warning)?;
            pause()?;
            continue;
        };
        if number == 0 || number > strategies.len() {
            console::line(
                "Такой стратегии нет в списке. Выберите другой номер.",
                Tone::Warning,
            )?;
            pause()?;
            continue;
        }
        return Ok(Some(number - 1));
    }
}

fn test_frame(viewport: Viewport) -> Frame {
    let mut frame = Frame::new(viewport, "Автоподбор стратегии");
    frame.row(
        " Выберет самый быстрый вариант с подтверждённой доступностью.",
        Tone::Text,
    );
    frame.separator("");
    let quick_label = format!("Быстрый подбор и применение (до {QUICK_STRATEGY_LIMIT} стратегий)");
    for (index, text) in [
        quick_label.as_str(),
        "Все стратегии (расширенная проверка, долго)",
        "Подбор и проверка в браузере",
        "Сравнить две стратегии",
        "Последний результат",
    ]
    .into_iter()
    .enumerate()
    {
        frame.item(index + 1, text, Tone::Text);
    }
    frame.separator("");
    frame.item(0, "Назад", Tone::Secondary);
    frame
}

fn choose_test(app: &App) -> Result<Outcome> {
    test_frame(Viewport::current()).show()?;
    let Some(choice) = input("Выбор")? else {
        return Ok(Outcome::Back);
    };
    if !matches!(choice.as_str(), "1" | "2" | "3" | "4" | "5") {
        return Ok(Outcome::Back);
    }
    let mut arguments = TestArgs {
        last: choice == "5",
        apply: matches!(choice.as_str(), "1" | "2" | "3"),
        full: choice == "2",
        webcheck: choice == "3",
        ..Default::default()
    };
    if choice == "4" {
        let all = list_strategies(&app.root)?;
        let Some(first) = select_strategy(&all, "Сравнение · первая стратегия")?
        else {
            return Ok(Outcome::Back);
        };
        let Some(second) = select_strategy(&all, "Сравнение · вторая стратегия")?
        else {
            return Ok(Outcome::Back);
        };
        ensure!(first != second, "Нужны две разные стратегии");
        arguments.compare_a = Some(all[first].id.clone());
        arguments.compare_b = Some(all[second].id.clone());
    }
    action(app, Action::Test(arguments))
}

fn settings(app: &App) -> Result<()> {
    loop {
        let view = MenuView::load(app)?;
        let task = app.platform("task-status", json!({"kind":"autotune"}))?;
        let tune = if task["known"] != true || (task["exists"] == true && task["owned"] != true) {
            "не подтверждена"
        } else if task["exists"] == true && task["enabled"] == true {
            "раз в неделю"
        } else {
            "выкл"
        };
        settings_frame(
            &view,
            Viewport::current(),
            tune,
            &maintenance::first_run::lists_status(&app.root),
        )
        .show()?;
        let saved = view.settings;
        let Some(choice) = input("Выбор")? else {
            return Ok(());
        };
        if matches!(choice.as_str(), "0" | "") {
            return Ok(());
        }
        if shortcut_name(&choice) == Some("settings") {
            continue;
        }
        let result = (|| -> Result<Outcome> {
            match choice.as_str() {
                "1" => choose_strategy(app),
                "2" => app
                    .mutate_setting(
                        "auto",
                        if saved.get("auto") == "on" {
                            "off"
                        } else {
                            "on"
                        },
                    )
                    .and_then(|value| show(app, &value)),
                "3" => game_filter(app),
                "4" => {
                    choices(
                        "Режим IPSet",
                        &[
                            "IP-списки",
                            "Все IP",
                            "Только домены и пользовательский список",
                        ],
                    )?;
                    let Some(value) = input("Выбор")? else {
                        return Ok(Outcome::Back);
                    };
                    let mode = match value.as_str() {
                        "1" => "loaded",
                        "2" => "any",
                        "3" => "none",
                        "0" | "" => return Ok(Outcome::Back),
                        _ => anyhow::bail!("Выберите режим из списка или 0 для возврата."),
                    };
                    app.mutate_setting("ipset", mode)
                        .and_then(|value| show(app, &value))
                }
                "5" => autolist(app),
                "6" => show_platform(app, "service-autostart", &app.toggle_startup()?),
                "7" => task_toggle(app, "autotune"),
                "8" => action(app, Action::Lists { update: true }),
                "9" => {
                    let release = app.execute(Action::Update {
                        install: false,
                        from: None,
                        sha256: None,
                        recover: false,
                    })?;
                    app.print_context(&presentation::Context::platform("update"), &release)?;
                    if release["available"] == true
                        && app.confirm("Установить доступное обновление?")?
                    {
                        action(
                            app,
                            Action::Update {
                                install: true,
                                from: None,
                                sha256: None,
                                recover: false,
                            },
                        )
                    } else {
                        Ok(Outcome::Displayed)
                    }
                }
                "10" => task_toggle(app, "notify"),
                "11" => action(app, Action::Uninstall),
                _ => match shortcut(app, &choice) {
                    Some(result) => result,
                    None => anyhow::bail!(
                        "Нет такого пункта настроек. Выберите номер или 0 для возврата."
                    ),
                },
            }
        })();
        finish(app, result)?;
    }
}

fn task_toggle(app: &App, kind: &str) -> Result<Outcome> {
    show_platform(app, "task-configure", &app.toggle_task(kind)?)
}

fn game_filter(app: &App) -> Result<Outcome> {
    choices(
        "Фильтр игры",
        &[
            "TCP и UDP, все игровые порты",
            "Только порты NBA 2K и Steam",
            "Только TCP",
            "Только UDP",
            "Свои порты",
            "Выключить",
            "Выбранные игры (по именам EXE)",
        ],
    )?;
    let Some(value) = input("Выбор")? else {
        return Ok(Outcome::Back);
    };
    let result = match value.as_str() {
        "1" => app.change_settings(&[
            ("game", "all"),
            ("gametcp", "1024-65535"),
            ("gameudp", "1024-65535"),
        ]),
        "2" => app.change_settings(&[
            ("game", "all"),
            ("gametcp", "20000-27200"),
            ("gameudp", "27000-27200,30000-30100"),
        ]),
        "3" => app.mutate_setting("game", "tcp"),
        "4" => app.mutate_setting("game", "udp"),
        "5" => {
            let Some(tcp) = input("TCP-порты (0 — отмена)")? else {
                return Ok(Outcome::Back);
            };
            if tcp.trim() == "0" {
                return Ok(Outcome::Back);
            }
            let Some(udp) = input("UDP-порты (0 — отмена)")? else {
                return Ok(Outcome::Back);
            };
            if udp.trim() == "0" || (tcp.trim().is_empty() && udp.trim().is_empty()) {
                return Ok(Outcome::Back);
            }
            let current = zapret_core::read_settings(&app.root)?;
            let mode = if current.get("game").eq_ignore_ascii_case("selected") {
                "selected"
            } else {
                "all"
            };
            app.change_settings(&[("game", mode), ("gametcp", &tcp), ("gameudp", &udp)])
        }
        "6" => app.mutate_setting("game", "off"),
        "7" => {
            let current = zapret_core::read_settings(&app.root)?;
            console::line(
                &format!("Выбрано: {}", current.get("gameapps")),
                Tone::Secondary,
            )?;
            console::line(
                "Для новой игры запишите адреса при входе в матч через Инструменты → 2.",
                Tone::Secondary,
            )?;
            let Some(typed) = input("Имена EXE через | (Enter — оставить, 0 — назад)")?
            else {
                return Ok(Outcome::Back);
            };
            if typed == "0" {
                return Ok(Outcome::Back);
            }
            let names = if typed.trim().is_empty() {
                current.get("gameapps")
            } else {
                typed.trim()
            };
            ensure!(
                !zapret_core::selected_game_names(names)?.is_empty(),
                "Укажите хотя бы одну игру"
            );
            app.change_settings(&[("gameapps", names), ("game", "selected")])
        }
        "0" | "" => return Ok(Outcome::Back),
        _ => anyhow::bail!("Выберите фильтр из списка или 0 для возврата."),
    }?;
    show(app, &result)
}

fn autolist(app: &App) -> Result<Outcome> {
    let path = app.root.join("lists/autohostlist.txt");
    let content = if path.is_file() {
        zapret_core::read_text(&path, 16 * 1024 * 1024)?
    } else {
        String::new()
    };
    let mut frame = dialog("Автосписок сайтов");
    for line in content.lines() {
        frame.row(&format!("  {line}"), Tone::Text);
    }
    frame.separator("");
    frame.item(1, "Включить", Tone::Text);
    frame.item(2, "Выключить", Tone::Text);
    frame.item(3, "Очистить", Tone::Text);
    frame.item(0, "Назад", Tone::Secondary);
    frame.show()?;
    match input("Выбор")?.unwrap_or_default().as_str() {
        "1" => show(app, &app.mutate_setting("autolist", "on")?),
        "2" => show(app, &app.mutate_setting("autolist", "off")?),
        "3" => {
            if !app.confirm("Очистить накопленный автосписок?")? {
                return Ok(Outcome::Back);
            }
            app.game_check("Очистка автосписка может изменить работу обхода")?;
            let _guard = zapret_platform::ControlGuard::acquire(&app.root, "autolist")?;
            zapret_core::atomic_write(&path, b"# zapret-rust automatic host list\r\n")?;
            console::line("Автосписок очищен.", Tone::Good)?;
            Ok(Outcome::Displayed)
        }
        "0" | "" => Ok(Outcome::Back),
        _ => anyhow::bail!("Выберите действие из списка или 0 для возврата."),
    }
}

fn tools(app: &App) -> Result<()> {
    loop {
        tools_frame(&MenuView::load(app)?, Viewport::current()).show()?;
        let Some(choice) = input("Выбор")? else {
            return Ok(());
        };
        if matches!(choice.as_str(), "0" | "") {
            return Ok(());
        }
        if shortcut_name(&choice) == Some("tools") {
            continue;
        }
        let result = (|| -> Result<Outcome> {
            let command = match choice.as_str() {
                "1" | "2" => {
                    let saved = zapret_core::read_settings(&app.root)?;
                    let names = if saved.get("game").eq_ignore_ascii_case("selected") {
                        zapret_core::selected_game_names(saved.get("gameapps"))?
                    } else {
                        Vec::new()
                    };
                    let default = names.first().map(String::as_str).unwrap_or("NBA2K*");
                    let Some(process) = input(&format!("Имя EXE (Enter — {default}, 0 — назад)"))?
                    else {
                        return Ok(Outcome::Back);
                    };
                    if process == "0" {
                        return Ok(Outcome::Back);
                    }
                    let process = if process.is_empty() {
                        default.to_owned()
                    } else {
                        process
                    };
                    if choice == "1" {
                        Action::Track {
                            process,
                            seconds: 60,
                        }
                    } else {
                        Action::Scan {
                            process,
                            seconds: 60,
                            apply: app.confirm("Сохранить адреса, с которыми связалась игра?")?,
                        }
                    }
                }
                "3" => Action::ProviderCheck(network_arguments()),
                "4" => Action::Report { output: None },
                "5" => {
                    if !app.confirm("Запустить диагностический обход на 60 секунд?")?
                    {
                        return Ok(Outcome::Back);
                    }
                    Action::Diag {
                        run: true,
                        seconds: 60,
                    }
                }
                "6" => Action::Exclude {
                    apply: app.confirm("Добавить найденные адреса в исключения?")?,
                },
                "7" => Action::DirectRules { output: None },
                "8" => {
                    if !app.confirm("Для очистки кэша Discord будет закрыт. Продолжить?")?
                    {
                        return Ok(Outcome::Back);
                    }
                    Action::System {
                        action: "discord-cache".into(),
                        args: None,
                    }
                }
                "9" => Action::Latency(network_arguments()),
                "10" => Action::Webcheck(network_arguments()),
                "11" => Action::ConnectionCheck(network_arguments()),
                "12" => return voice_dialog(app),
                "13" => Action::YoutubeCheck,
                _ => {
                    return shortcut(app, &choice).unwrap_or_else(|| {
                        Err(anyhow::anyhow!(
                            "Нет такого инструмента. Выберите номер или 0 для возврата."
                        ))
                    });
                }
            };
            action(app, command)
        })();
        finish(app, result)?;
    }
}

fn network_arguments() -> NetworkArgs {
    NetworkArgs {
        urls: Vec::new(),
        timeout_ms: 5000,
        args: None,
    }
}

fn voice_dialog(app: &App) -> Result<Outcome> {
    let mut frame = dialog("Discord Voice");
    frame.row(
        "  Войдите в голосовой канал Discord вместе с собеседником.",
        Tone::Accent,
    );
    frame.row(
        "  Во время проверки скажите фразу и попросите собеседника повторить её.",
        Tone::Text,
    );
    frame.row(
        "  Затем повторите его фразу и уточните, услышал ли он ответ.",
        Tone::Text,
    );
    frame.show()?;
    let Some(start) = input("Enter — начать, 0 — назад")? else {
        return Ok(Outcome::Back);
    };
    if start == "0" {
        return Ok(Outcome::Back);
    }
    ensure!(
        start.is_empty(),
        "Нажмите Enter для начала или 0 для возврата."
    );
    let mut result = zapret_net::diagnostics(&app.root, "voice", &json!({"timeout_ms": 5000}))?;
    let mut frame = dialog("Как работал звук");
    for (index, text) in [
        "Слышны оба участника",
        "Слышу только я",
        "Слышит только собеседник",
        "Звука нет",
    ]
    .iter()
    .enumerate()
    {
        frame.item(index + 1, text, Tone::Text);
    }
    frame.row("  Enter — не проверял", Tone::Secondary);
    frame.show()?;
    let audio = match input("Как работал звук во время наблюдения")?
        .unwrap_or_default()
        .as_str()
    {
        "1" => "Both",
        "2" => "OnlyReceive",
        "3" => "OnlySend",
        "4" => "None",
        _ => "Unknown",
    };
    result["audio_observation"] = json!(audio);
    result["audio_reported_utc_ms"] = if audio == "Unknown" {
        Value::Null
    } else {
        json!(chrono::Utc::now().timestamp_millis().to_string())
    };
    result["assessment"] = zapret_net::assess_voice(
        &result["capture"],
        &result["control"],
        audio,
        result["connection_state"].as_str().unwrap_or("Unknown"),
    )?;
    let result = crate::diagnostic_report::publish(&app.root, "voice", result)?;
    show_platform(app, "voice", &result)
}

fn telegram(app: &App) -> Result<Outcome> {
    choices(
        "Мост Telegram",
        &[
            "Включить и открыть Telegram",
            "Остановить",
            "Изменить порт",
            "Проверить мост и загрузку медиа",
        ],
    )?;
    app.run_platform("telegram-status", json!({}))?;
    let action = match input("Выбор")?.unwrap_or_default().as_str() {
        "1" => Action::Telegram {
            action: "start".into(),
            port: None,
        },
        "2" => Action::Telegram {
            action: "stop".into(),
            port: None,
        },
        "4" => Action::Telegram {
            action: "media".into(),
            port: None,
        },
        "3" => {
            let Some(port) = input("Новый порт (0 — назад)")? else {
                return Ok(Outcome::Back);
            };
            if port.is_empty() || port == "0" {
                return Ok(Outcome::Back);
            }
            Action::Telegram {
                action: "config".into(),
                port: Some(
                    port.parse()
                        .map_err(|_| anyhow::anyhow!("Введите номер порта от 1 до 65535."))?,
                ),
            }
        }
        "0" | "" => return Ok(Outcome::Back),
        _ => anyhow::bail!("Выберите действие Telegram из списка или 0 для возврата."),
    };
    let context = presentation::for_action(&action);
    let result = app.execute(action)?;
    app.print_context(&context, &result)?;
    if result["requires_restart"] == true
        && result["running"] == true
        && app.confirm("Применить новый порт, перезапустив мост Telegram?")?
    {
        app.run_action(Action::Telegram {
            action: "start".into(),
            port: None,
        })?;
    }
    Ok(Outcome::Displayed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn selection_menu_explains_modes_and_can_show_the_previous_result() {
        let text = test_frame(Viewport {
            columns: 55,
            rows: 16,
        })
        .plain();
        for label in [
            "Быстрый подбор и применение (до 18 стратегий)",
            "Все стратегии",
            "Последний результат",
            "Назад",
        ] {
            assert!(text.contains(label), "{text}");
        }
        assert!(!text.contains("семейств"));
        assert!(text.lines().all(|line| line.chars().count() <= 53));
    }
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn main_frame_fits_the_reported_small_window_and_keeps_every_action() {
        let viewport = Viewport {
            columns: 55,
            rows: 16,
        };
        let text = main_frame(&preview_view(), viewport).plain();
        assert!(text.lines().count() + 2 <= viewport.rows, "{text}");
        assert!(text.starts_with('╭'));
        assert!(text.contains(&format!("zapret-rust v{}", crate::VERSION)));
        assert!(!text.contains("Rust"));
        assert!(text.contains("Состояние обхода не подтверждено"));
        assert!(!text.contains("NBA City"));
        for key in [1, 2, 3, 4, 5, 6, 7, 8, 9, 0] {
            assert!(
                text.contains(&format!(" {key:>2}  ")),
                "Missing action {key}"
            );
        }
        assert!(
            text.lines()
                .all(|line| line.chars().count() == viewport.inner_width() + 2)
        );
    }

    #[test]
    fn unknown_status_never_looks_like_a_running_or_stopped_bypass() {
        let mut view = preview_view();
        assert_eq!(view.state().1, Tone::Warning);
        view.status = json!({"known":true,"ownership_known":true,"running":true});
        assert_eq!(view.state(), ("Обход запущен", Tone::Good));
        let text = main_frame(
            &view,
            Viewport {
                columns: 80,
                rows: 30,
            },
        )
        .plain();
        assert!(text.contains("Перезапустить обход"));
        view.status["ownership_known"] = json!(false);
        assert_eq!(view.state().1, Tone::Warning);
    }

    #[test]
    fn menu_shows_a_foreign_running_service_and_system_wide_stop() {
        let mut view = preview_view();
        view.status = json!({"known":true,"ownership_known":true,"running":false,"service":{"running":true,"owned":false,"ownership_known":true}});
        assert_eq!(
            view.state(),
            ("Обход запущен из другой папки", Tone::Warning)
        );
        let text = main_frame(
            &view,
            Viewport {
                columns: 55,
                rows: 16,
            },
        )
        .plain();
        assert!(text.contains("Остановить все экземпляры zapret"), "{text}");
    }

    #[test]
    fn settings_and_tools_keep_sections_and_all_menu_entries() {
        let viewport = Viewport {
            columns: 80,
            rows: 30,
        };
        let view = preview_view();
        let settings = settings_frame(&view, viewport, "выкл", "локальные копии").plain();
        assert!(settings.contains("локальные копии"));
        let tools = tools_frame(&view, viewport).plain();
        for (text, count) in [(&settings, 11), (&tools, 13)] {
            for key in 0..=count {
                assert!(text.contains(&format!(" {key:>2}  ")));
            }
            assert!(text.lines().all(|line| line.chars().count() == 76));
        }
        assert!(settings.contains("ПРИЛОЖЕНИЕ"));
        assert!(tools.contains("ДИАГНОСТИКА И ОТЧЁТЫ"));
        assert!(settings.contains("Game Filter: TCP и UDP"));
        assert!(settings.contains("Автозапуск: не подтверждён"));
    }
    #[test]
    fn native_cli_exposes_every_existing_tool_entry() {
        let command = crate::cli::Cli::command();
        for name in [
            "menu",
            "status",
            "start",
            "stop",
            "test",
            "settings",
            "compose",
            "strategies",
            "track",
            "scan",
            "provider-check",
            "report",
            "diag",
            "exclude",
            "direct-rules",
            "telegram",
            "latency",
            "webcheck",
            "youtube-check",
            "connection-check",
            "voicecheck",
            "service",
            "task",
            "lists",
            "update",
            "uninstall",
        ] {
            assert!(command.find_subcommand(name).is_some(), "{name}");
        }
    }
    #[test]
    fn legacy_shortcuts_work_with_both_keyboard_layouts() {
        for (left, right) in [
            ("c", "с"),
            ("h", "р"),
            ("s", "ы"),
            ("u", "г"),
            ("a", "ф"),
            ("p", "з"),
            ("r", "к"),
            ("d", "в"),
            ("n", "т"),
            ("i", "ш"),
        ] {
            assert_eq!(super::shortcut_name(left), super::shortcut_name(right));
            assert!(super::shortcut_name(left).is_some());
        }
        assert!(super::shortcut_name("t").is_none());
        assert!(super::shortcut_name("е").is_none());
        assert!(super::shortcut_name("123").is_none());
    }
    #[test]
    fn completing_a_cancelled_menu_action_allows_the_next_action() {
        let output = zapret_platform::run_owned(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "menu::tests::cancelled_menu_action_child".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            &zapret_platform::RunOptions::default(),
        )
        .unwrap();
        assert_eq!(
            output.exit_code,
            0,
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("menu cancellation recovered"));
    }

    #[test]
    #[ignore = "Runs in its own process to isolate the global cancellation flag"]
    fn cancelled_menu_action_child() {
        let temporary = tempfile::tempdir().unwrap();
        let app = App {
            root: temporary.path().to_owned(),
            yes: true,
            json: false,
        };
        crate::interrupt::request_for_test();
        assert!(crate::interrupt::check().is_err());
        finish(&app, Ok(Outcome::Back)).unwrap();
        crate::interrupt::check().expect("the next menu action must be able to run");
        println!("menu cancellation recovered");
    }
}
