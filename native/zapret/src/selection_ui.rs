use crate::console::{Frame, Tone, Viewport};
use serde_json::Value;

fn primary_answer(text: &str) -> Option<bool> {
    crate::confirmation::answer(text)
}

fn trial_tone(qualified: bool, response_delta: Option<i64>) -> Tone {
    match response_delta {
        Some(delta) if qualified => match delta.cmp(&0) {
            std::cmp::Ordering::Greater => Tone::Good,
            std::cmp::Ordering::Less => Tone::Bad,
            std::cmp::Ordering::Equal => Tone::Text,
        },
        _ => Tone::Warning,
    }
}

fn final_status(report: &Value, id: &str) -> (&'static str, Tone) {
    match report["final_checks"][id]["confirmed"].as_bool() {
        Some(false) => ("финал не пройден", Tone::Bad),
        _ if report["strategy_quality"][id] == false => ("нестабильно", Tone::Warning),
        Some(true) => ("финал пройден", Tone::Good),
        None => ("без финала", Tone::Text),
    }
}

pub struct RunState {
    pub qualified: bool,
    pub leader: bool,
    pub response_delta: Option<i64>,
    pub details: bool,
    pub position: usize,
    pub total: usize,
}

pub fn primary_frame(report: &Value, viewport: Viewport) -> Frame {
    let mut frame = Frame::new(viewport, "Выбор основной стратегии");
    let best = report["best"]["id"].as_str().unwrap_or("");
    let primary = report["primary"].as_str().unwrap_or("");
    frame.row(" Рабочая конфигурация рекомендации проверена.", Tone::Good);
    frame.row(
        &format!(" Рекомендация: {}", name(report, best)),
        Tone::Good,
    );
    frame.row(
        &format!(" Сейчас сохранена: {}", name(report, primary)),
        Tone::Text,
    );
    if let Some(reason) = report["decision_reason"].as_str() {
        frame.row(reason, Tone::Text);
    }
    if let Some(reason) = speed_reason(report) {
        frame.row(&reason, Tone::Good);
    }
    explain_service_score(&mut frame, report);
    frame.separator("РЕЗУЛЬТАТЫ");
    let rows = display_order(
        report,
        report["rows"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default(),
        best,
    );
    for row in rows.into_iter().take(3) {
        let id = row["id"].as_str().unwrap_or("");
        let (label, tone) = final_status(report, id);
        let label = label.to_uppercase();
        frame.row(
            &format!(
                " {label}: {} · балл {}",
                name(report, id),
                displayed_score(report, row)
            ),
            tone,
        );
    }
    frame.separator("ДЕЙСТВИЕ");
    frame.item(
        'y',
        &format!("Применить {}", name(report, best)),
        Tone::Good,
    );
    frame.item(
        'n',
        &format!("Оставить {}", name(report, primary)),
        Tone::Text,
    );
    frame.row(
        " Enter — n, оставить текущую. Применение — y.",
        Tone::Secondary,
    );
    frame
}

pub fn choose_primary(app: &crate::App, report: &Value) -> anyhow::Result<bool> {
    if app.yes {
        return Ok(true);
    }
    primary_frame(report, Viewport::current()).append()?;
    let stdin = std::io::stdin();
    loop {
        crate::console::prompt("Выбор [y/n]")?;
        let mut text = String::new();
        if stdin.read_line(&mut text)? == 0 {
            return Ok(false);
        }
        if let Some(answer) = primary_answer(&text) {
            return Ok(answer);
        }
        crate::console::line("Введите y или n. Enter — n.", Tone::Bad)?;
    }
}

pub fn heading(app: &crate::App, text: &str) -> anyhow::Result<()> {
    if !app.json {
        crate::console::status(text, Tone::Accent)?;
    }
    Ok(())
}

pub fn validation_notice(
    app: &crate::App,
    name: &str,
    error: Option<&str>,
    details: bool,
) -> anyhow::Result<()> {
    if !app.json {
        match error {
            Some(error) => crate::console::line(
                &format!(
                    "  ФИНАЛ НЕ ПРОЙДЕН: {name}{}",
                    if details {
                        format!(". {error}")
                    } else {
                        String::new()
                    }
                ),
                Tone::Bad,
            )?,
            None => {
                crate::console::line(&format!("  РАБОЧИЙ РЕЖИМ ПОДТВЕРЖДЁН: {name}"), Tone::Good)?
            }
        }
    }
    Ok(())
}

pub fn points(value: f64) -> String {
    if !value.is_finite() {
        "—".into()
    } else if value.fract().abs() < 0.001 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}").replace('.', ",")
    }
}

fn name(report: &Value, id: &str) -> String {
    report["strategy_names"][id]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Стратегия {id}"))
}

fn family_of<'a>(report: &'a Value, id: &str) -> Option<&'a str> {
    report["strategy_families"]
        .as_object()?
        .iter()
        .find_map(|(family, ids)| {
            ids.as_array()?
                .iter()
                .any(|value| value == id)
                .then_some(family.as_str())
        })
}

fn relative_points(points: f64) -> String {
    format!("{points:+.2}").replace('.', ",")
}

fn has_service_scores(report: &Value) -> bool {
    report["trial_service_scores"]
        .as_object()
        .is_some_and(|scores| !scores.is_empty())
}

fn displayed_score(report: &Value, row: &Value) -> String {
    if has_service_scores(report) {
        let id = row["id"].as_str().unwrap_or("");
        return report["trial_service_scores"][id]
            .as_f64()
            .map(relative_points)
            .unwrap_or_else(|| "—".into());
    }
    row["score"]
        .as_f64()
        .map(points)
        .unwrap_or_else(|| "—".into())
}

fn display_order<'a>(report: &Value, rows: &'a [Value], best: &str) -> Vec<&'a Value> {
    let mut sorted: Vec<_> = rows.iter().collect();
    let score = |id: &str| {
        report["trial_service_scores"][id]
            .as_f64()
            .unwrap_or(f64::NEG_INFINITY)
    };
    sorted.sort_by(|a, b| {
        let a = a["id"].as_str().unwrap_or("");
        let b = b["id"].as_str().unwrap_or("");
        (a != best)
            .cmp(&(b != best))
            .then_with(|| score(b).total_cmp(&score(a)))
    });
    sorted
}

fn explain_service_score(frame: &mut Frame, report: &Value) {
    if !has_service_scores(report) {
        return;
    }
    let anchor = report["trial_score_reference"].as_str().unwrap_or("");
    frame.row(
        &format!(" Пробный балл относительно {} (0).", name(report, anchor)),
        Tone::Secondary,
    );
    let p = &report["connection_selection"];
    let Some(candidate) = p["candidate"].as_str() else {
        let scores = report["trial_service_scores"].as_object().unwrap();
        if scores.len() == 1 {
            frame.row(
                " Сопоставимый балл есть только у опорного профиля.",
                Tone::Secondary,
            );
        } else if scores.values().all(|v| v.as_f64().is_none_or(|s| s <= 0.)) {
            frame.row(
                " В пробном замере никто не опередил опорный профиль.",
                Tone::Secondary,
            );
        }
        return;
    };
    let reference = p["reference"].as_str().unwrap_or(anchor);
    frame.row(
        &format!(
            " {} против {} · порог +{} в каждом из двух финалов.",
            name(report, candidate),
            name(report, reference),
            crate::selection_latency::MIN_WORKING_POINTS
        ),
        Tone::Text,
    );
    for (key, label) in [("working", "Первый финал"), ("repeat", "Повтор")] {
        if let Ok(pair) =
            serde_json::from_value::<crate::selection_latency::Comparison>(p[key].clone())
            && let Some(score) = &pair.service_score
        {
            frame.row(
                &format!(
                    " {label} {} балла · {} адресов.",
                    relative_points(score.points),
                    pair.targets
                ),
                Tone::Text,
            );
            if let Some(reason) = pair.service_rejection() {
                frame.row(&format!(" {reason}"), Tone::Warning);
            }
        }
    }
    if let Some(points) = p["repeatable_points"].as_f64() {
        frame.row(
            &format!(
                " Повторяемый выигрыш по сервисам {} · порог +{}.",
                relative_points(points),
                crate::selection_latency::MIN_WORKING_POINTS
            ),
            if points >= crate::selection_latency::MIN_WORKING_POINTS {
                Tone::Text
            } else {
                Tone::Warning
            },
        );
    }
    if p["confirmed"] != true && report["report_only"] != true && report["choice"] != "kept" {
        frame.row(
            " Преимущество в двух финалах не подтверждено.",
            Tone::Secondary,
        );
    }
}

fn speed_reason(report: &Value) -> Option<String> {
    let selection = &report["connection_selection"];
    if selection["confirmed"] != true || selection["trial"]["service_score"].is_object() {
        return None;
    }
    let working = &selection["working"];
    let ms = working["gain_ms"].as_f64()?;
    if working["scope"] == crate::selection_latency::SERVICE_SCOPE {
        let repeat = selection["repeat"]["gain_ms"].as_f64()?;
        return Some(format!(
            " Запросы к сервисам быстрее на {} и {} мс в двух проверках.",
            points(ms),
            points(repeat)
        ));
    }
    if working["scope"] == "AllTargets" {
        return Some(format!(
            " При близком балле полный запрос быстрее на ~{ms:.0} мс (адресов: {}).",
            working["targets"].as_u64().unwrap_or(0)
        ));
    }
    Some(format!(
        " При близком балле подключение {} быстрее на ~{ms:.0} мс (адресов: {}).",
        if working["scope"] == "GameServices" {
            "к 2K/EAC"
        } else {
            "к сервисам"
        },
        working["targets"].as_u64().unwrap_or(0)
    ))
}

fn full_request_policy(report: &Value) -> bool {
    service_policy(report)
        || matches!(
            report["selection_policy"].as_str(),
            Some(
                "availability-then-full-request-latency-v2"
                    | crate::selection_latency::PREVIOUS_POLICY
            )
        )
}

fn service_policy(report: &Value) -> bool {
    matches!(
        report["selection_policy"].as_str(),
        Some(
            "service-availability-then-paired-latency-v4"
                | "service-availability-then-paired-latency-v5"
                | "service-availability-then-group-score-v6"
                | "confirmed-service-availability-then-group-score-v7"
                | crate::selection_latency::POLICY
        )
    )
}

fn working_timing(report: &Value, id: &str) -> Option<crate::selection_latency::Timing> {
    let check = &report["final_checks"][id];
    if check["confirmed"] != true {
        return None;
    }
    Some(crate::selection_latency::timing(
        check["details"].as_array()?,
    ))
}

fn connection_timing(report: &Value, id: &str) -> Option<(f64, f64)> {
    let preference = &report["connection_selection"];
    if preference["confirmed"] == true {
        let prefix = if preference["reference"] == id {
            Some("reference")
        } else if preference["candidate"] == id {
            Some("candidate")
        } else {
            None
        };
        if let Some(prefix) = prefix {
            let working = preference
                .get("repeat")
                .filter(|c| c.is_object())
                .unwrap_or(&preference["working"]);
            if let Some(pair) = working[format!("{prefix}_tcp_ms")]
                .as_f64()
                .zip(working[format!("{prefix}_tls_ms")].as_f64())
            {
                return Some(pair);
            }
        }
    }
    if let Some(pair) = working_timing(report, id).and_then(|t| t.tcp_ms.zip(t.tls_ms)) {
        return Some(pair);
    }
    let timing = &report["timings"][id];
    timing["overall"]["tcp_ms"]
        .as_f64()
        .zip(timing["overall"]["tls_ms"].as_f64())
        .or_else(|| {
            timing["game"]["tcp_ms"]
                .as_f64()
                .zip(timing["game"]["tls_ms"].as_f64())
        })
}

fn request_timing(report: &Value, id: &str) -> Option<(f64, f64, &'static str)> {
    let preference = &report["connection_selection"];
    if preference["confirmed"] == true
        && matches!(
            preference["working"]["scope"].as_str(),
            Some("AllTargets" | crate::selection_latency::SERVICE_SCOPE)
        )
    {
        let prefix = if preference["reference"] == id {
            Some("reference")
        } else if preference["candidate"] == id {
            Some("candidate")
        } else {
            None
        };
        if let Some(prefix) = prefix {
            let working = preference
                .get("repeat")
                .filter(|c| c.is_object())
                .unwrap_or(&preference["working"]);
            if let Some(pair) = working[format!("{prefix}_total_ms")]
                .as_f64()
                .zip(working[format!("{prefix}_p95_ms")].as_f64())
            {
                return Some((pair.0, pair.1, "В рабочем режиме"));
            }
        }
    }
    if let Some((total, p95)) = working_timing(report, id).and_then(|t| t.total_ms.zip(t.p95_ms)) {
        return Some((total, p95, "В рабочем режиме"));
    }
    let timing = &report["timings"][id]["overall"];
    Some((
        timing["total_ms"].as_f64()?,
        timing["p95_ms"].as_f64()?,
        "В отдельном тесте",
    ))
}

fn final_targets(report: &Value, error: &str) -> String {
    let Some((names, _)) = error
        .strip_prefix("Финальная комбинация не подтвердила ")
        .and_then(|message| message.split_once(": "))
    else {
        return error.into();
    };
    let mut targets: Vec<_> = names.split(", ").map(str::to_owned).collect();
    // Older reports recorded only the first error, but kept both measured panels.
    fn key(row: &Value) -> Option<(&str, &str, &str)> {
        Some((
            row["group"].as_str()?,
            row["name"].as_str()?,
            row["url"].as_str()?,
        ))
    }
    let failed: std::collections::BTreeSet<_> = report["final_details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| matches!(row["state"].as_str(), Some("FAIL" | "FREEZE")))
        .filter_map(key)
        .collect();
    for row in report["working_reference"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| {
            !service_policy(report)
                && row["state"] == "OK"
                && (row["group"] != "DPI" || row["flaky"] != true)
        })
    {
        let Some((group, name, _)) = key(row).filter(|target| failed.contains(target)) else {
            continue;
        };
        let label = format!("{group}/{name}");
        if !targets.contains(&label) {
            targets.push(label);
        }
    }
    let shown = targets.len().min(3);
    let mut summary = targets[..shown].join(", ");
    if targets.len() > shown {
        summary.push_str(&format!(" и ещё {}", targets.len() - shown));
    }
    summary
}

fn label(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.into()
    } else {
        text.chars()
            .take(width.saturating_sub(1))
            .chain(['…'])
            .collect()
    }
}

pub fn result_frame(report: &Value, viewport: Viewport) -> Option<Frame> {
    result_frame_mode(report, viewport, false)
}

pub fn result_frame_mode(report: &Value, viewport: Viewport, historical: bool) -> Option<Frame> {
    if report["protocol"] == "finalists-native-v1" || report["scope"] == "observed-https-tls" {
        return Some(comparison_frame(report, viewport));
    }
    let rows = report["rows"].as_array()?;
    let best = report["best"]["id"].as_str()?;
    if report["presentation"] == "compact" {
        return Some(compact_result(report, rows, best, viewport, historical));
    }
    let mut shown = rows.len();
    loop {
        let frame = ranking_frame(report, rows, best, shown, viewport, historical);
        if frame.height() <= viewport.rows || shown <= 1 {
            return Some(frame);
        }
        shown -= 1;
    }
}

fn compact_result(
    report: &Value,
    rows: &[Value],
    best: &str,
    viewport: Viewport,
    historical: bool,
) -> Frame {
    let mut frame = Frame::new(
        viewport,
        if historical {
            "Результат прошлой проверки"
        } else {
            "Итог автоподбора"
        },
    );
    let primary = report["primary"].as_str().unwrap_or("");
    let restored = report["startup"]["restored"] == true;
    let accepted = report["accepted"] == true && !restored;
    let report_only = report["report_only"] == true;
    let retained = report["retained_check"]["confirmed"].as_bool();
    let (status, tone) = if restored {
        ("НЕ ПРИМЕНЕНО", Tone::Warning)
    } else if accepted && report["startup_error"].is_string() {
        ("СОХРАНЕНО", Tone::Warning)
    } else if report_only {
        ("ТОЛЬКО ОТЧЁТ", Tone::Text)
    } else if accepted && report["primary_changed"] == true {
        ("ПРИМЕНЕНО", Tone::Good)
    } else if accepted || retained == Some(true) {
        ("ОСТАВЛЕНО", Tone::Good)
    } else {
        ("НЕ ПРИМЕНЕНО", Tone::Bad)
    };
    frame.row(&format!(" {status}: {}", name(report, primary)), tone);
    network_summary(&mut frame, report);
    media_summary(&mut frame, report);
    if let Some(reason) = report["decision_reason"].as_str() {
        frame.row(reason, Tone::Text);
    }
    if let Some(family) = family_of(report, primary) {
        frame.row(
            &format!(" Семейство текущей стратегии — {family}."),
            Tone::Secondary,
        );
    }
    if restored {
        frame.row(
            " Новый обход не запустился. Восстановлен прежний.",
            Tone::Warning,
        );
    } else if report_only {
        frame.row(" Настройки не менялись: выбран режим отчёта.", Tone::Text);
    } else if accepted && report["primary_changed"] != true {
        frame.row(
            if primary == best && report["recommendation_status"] == "confirmed" {
                " Текущая стратегия — лучший подтверждённый вариант."
            } else if report["choice"] == "kept" {
                " По вашему выбору сохранена текущая стратегия."
            } else {
                " Смена основной не требовалась; результаты сохранены."
            },
            Tone::Text,
        );
    } else if !accepted {
        if retained == Some(true) {
            frame.row(
                " Прежний порядок автосмены прошёл повторную проверку.",
                Tone::Good,
            );
        } else if retained == Some(false) {
            frame.row(
                " Прежний порядок автосмены тоже не прошёл проверку.",
                Tone::Warning,
            );
        }
        if let Some(error) = report["validation_error"].as_str() {
            frame.row(
                &format!(
                    " Сбой финальной проверки — {}.",
                    final_targets(report, error)
                ),
                Tone::Warning,
            );
        } else if report["quality_eligible"] == false {
            frame.row(
                " Измерения нестабильны. Настройки сохранены без изменений.",
                Tone::Warning,
            );
        } else {
            frame.row(" Проверка не меняла основную стратегию.", Tone::Text);
        }
    }
    let partial: Vec<_> = report["final_details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["peer_comparison"]["shared_failure"] == true)
        .map(|row| {
            format!(
                "{}/{}",
                row["group"].as_str().unwrap_or(""),
                row["name"].as_str().unwrap_or("")
            )
        })
        .collect();
    if !partial.is_empty() {
        frame.row(
            &format!(
                " Доступность зависит от IP сервера. В обоих режимах был сбой для {}.",
                partial.join(", ")
            ),
            Tone::Warning,
        );
    }
    if report["startup"]["requested"] == false && report["startup"]["reason"] == "BypassWasStopped"
    {
        frame.row(
            " Обход выключен. Включить — пункт 1 главного меню.",
            Tone::Secondary,
        );
    } else if report["startup_error"].is_string() {
        frame.row(
            " Настройки сохранены, но запуск обхода не подтверждён.",
            Tone::Warning,
        );
    } else if report["startup"]["running"] == true {
        let message = match (historical, accepted) {
            (true, _) => " После проверки обход был запущен.",
            (false, false) => " Обход запущен с прежними настройками.",
            (false, true) => " Обход работает.",
        };
        frame.row(message, Tone::Good);
    }
    if accepted {
        if let Some(actual) = report["final_details"]
            .as_array()
            .filter(|rows| !rows.is_empty())
        {
            let ok = actual.iter().filter(|row| row["state"] == "OK").count();
            frame.row(
                &format!(" Рабочий режим: ответили {ok}/{} адресов.", actual.len()),
                Tone::Text,
            );
            if ok < actual.len() {
                frame.row(
                    &format!(
                        " {} адресов остались недоступны; подробности в отчёте.",
                        actual.len() - ok
                    ),
                    Tone::Warning,
                );
            }
        }
    }
    if let Some(reason) = speed_reason(report) {
        frame.row(&reason, Tone::Good);
    }
    let stages = quick_stages(report, rows.len());
    if let Some(summary) = &stages {
        frame.row(summary, Tone::Text);
    }
    if let Some(ms) = report["elapsed_ms"].as_f64() {
        let seconds = (ms / 1000.).round() as u64;
        let label = if stages.is_some() {
            " Время проверки".into()
        } else {
            format!(" Проверено стратегий — {}", rows.len())
        };
        frame.row(
            &format!("{label} · {} мин {:02} с.", seconds / 60, seconds % 60),
            Tone::Secondary,
        );
    }
    frame.separator("ЛУЧШИЕ ИЗ ПРОВЕРЕННЫХ");
    explain_service_score(&mut frame, report);
    let ordered = display_order(report, rows, best);
    for row in ordered.into_iter().take(3) {
        let id = row["id"].as_str().unwrap_or("");
        let (flag, tone) = final_status(report, id);
        frame.row(
            &format!(
                " {} · {} · {}{}{}",
                name(report, id),
                displayed_score(report, row),
                flag,
                connection_timing(report, id)
                    .map(|(tcp, tls)| format!(" · TCP {tcp:.0} / TLS {tls:.0} мс"))
                    .unwrap_or_default(),
                request_timing(report, id)
                    .map(|(total, _, _)| format!(" · всего {total:.0} мс"))
                    .unwrap_or_default()
            ),
            tone,
        );
    }
    if full_request_policy(report) {
        frame.row(
            if service_policy(report) {
                " Выбор по доступности сервисов и задержке на общих адресах."
            } else {
                " Задержка по всем группам; всего = DNS → ответ и данные."
            },
            Tone::Secondary,
        );
        if let Some((_, p95, stage)) = request_timing(report, best) {
            frame.row(
                &format!(
                    " {stage} {} P95 успешных запросов ~{p95:.0} мс.",
                    name(report, best)
                ),
                Tone::Secondary,
            );
        }
    } else if report["selection_policy"] == "availability-then-paired-connections-v1" {
        frame.row(
            " TCP/TLS — подключение к сервисам; игровой пинг не измерялся.",
            Tone::Secondary,
        );
    }
    frame.separator("");
    if let Some(path) = report["report_file"].as_str() {
        let file = path.rsplit(['\\', '/']).next().unwrap_or(path);
        frame.row(&format!(" Подробности: runtime\\{file}"), Tone::Secondary);
    }
    frame
}

fn comparison_frame(report: &Value, viewport: Viewport) -> Frame {
    let assessment = if report["protocol"] == "finalists-native-v1" {
        &report["assessment"]
    } else {
        report
    };
    let mut frame = Frame::new(viewport, "Сравнение стратегий");
    if let (Some(first), Some(second)) = (report["a_name"].as_str(), report["b_name"].as_str()) {
        frame.row(&format!(" A: {first}"), Tone::Text);
        frame.row(&format!(" B: {second}"), Tone::Text);
        frame.separator("");
    }
    let (conclusion, tone) = match assessment["status"].as_str() {
        Some("ConsistentImprovement") => (
            " Вторая стратегия быстрее подключалась к части адресов; ухудшений не обнаружено.",
            Tone::Good,
        ),
        Some("NoClearDifference") => (" Устойчивой разницы не обнаружено.", Tone::Text),
        _ => (
            " Данных недостаточно для вывода. Есть пропуски или нестабильные измерения.",
            Tone::Warning,
        ),
    };
    frame.row(conclusion, tone);
    if assessment["resources"]["status"] == "Ready" {
        for arm in ["a", "b"] {
            if let Some(percent) =
                assessment["resources"][arm]["cpu_percent_one_core_weighted"].as_f64()
            {
                frame.row(
                    &format!(
                        " Нагрузка на одно ядро {}: {}%",
                        arm.to_uppercase(),
                        points(percent)
                    ),
                    Tone::Text,
                );
            }
        }
    }
    frame.separator("");
    frame.row(
        " Проверялось соединение с сайтами. Пинг игры не измерялся.",
        Tone::Text,
    );
    frame.row(" Сравнение не меняет основную стратегию.", Tone::Secondary);
    frame
}

fn ranking_frame(
    report: &Value,
    rows: &[Value],
    best: &str,
    shown: usize,
    viewport: Viewport,
    historical: bool,
) -> Frame {
    let mut frame = Frame::new(
        viewport,
        if historical {
            "Результат прошлой проверки"
        } else {
            "Автоподбор завершён"
        },
    );
    let summary = quick_stages(report, rows.len())
        .unwrap_or_else(|| format!(" Проверено стратегий: {}", rows.len()));
    frame.row(&summary, Tone::Text);
    if let Some(ms) = report["elapsed_ms"].as_f64() {
        frame.row(
            &format!(" Время проверки: {} с", points(ms / 1000.)),
            Tone::Secondary,
        );
    }
    let has_counts = report["availability"].is_object();
    network_summary(&mut frame, report);
    media_summary(&mut frame, report);
    if let Some(reason) = report["decision_reason"].as_str() {
        frame.row(reason, Tone::Text);
    }
    let has_timing = report["timings"]
        .as_object()
        .is_some_and(|map| !map.is_empty());
    let recommendation_confirmed = report["recommendation_status"] == "confirmed"
        && report["final_checks"][best]["confirmed"] == true;
    let name_width = viewport
        .inner_width()
        .saturating_sub(if has_counts { 20 } else { 11 })
        .saturating_sub(if has_timing { 18 } else { 0 })
        .max(1);
    frame.separator("");
    frame.row(
        &(if has_counts {
            format!(
                " {:<name_width$} {:>7} {:>7}",
                "Стратегия", "Ответы", "Оценка"
            )
        } else {
            format!(" {:<name_width$} {:>7}", "Стратегия", "Оценка")
        } + if has_timing {
            "   TCP мс   TLS мс"
        } else {
            ""
        }),
        Tone::Secondary,
    );
    let display = if service_policy(report) {
        display_order(report, rows, best)
    } else {
        rows.iter().collect()
    };
    for row in display.into_iter().take(shown) {
        let id = row["id"].as_str().unwrap_or("");
        let unconfirmed = report["strategy_quality"][id] == false;
        let failed_final = report["final_checks"][id]["confirmed"] == false;
        let display_name = if failed_final {
            format!("! {}", name(report, id))
        } else if unconfirmed {
            format!("{} *", name(report, id))
        } else if id == best {
            format!("> {}", name(report, id))
        } else {
            name(report, id)
        };
        let name = label(&display_name, name_width);
        let score = displayed_score(report, row);
        let mut text = if has_counts {
            let counts = &report["availability"][id];
            let responses = counts["ok"]
                .as_u64()
                .zip(counts["total"].as_u64())
                .map(|(ok, total)| format!("{ok}/{total}"))
                .unwrap_or_else(|| "—".into());
            format!(" {name:<name_width$} {responses:>7} {score:>7}")
        } else {
            format!(" {name:<name_width$} {score:>7}")
        };
        if has_timing {
            let timing = &report["timings"][id];
            let pair = connection_timing(report, id)
                .or_else(|| timing["tcp_ms"].as_f64().zip(timing["tls_ms"].as_f64()));
            match pair {
                Some((tcp, tls)) => text.push_str(&format!(" {tcp:>8.0} {tls:>8.0}")),
                None => text.push_str(&format!(" {:>8} {:>8}", "—", "—")),
            }
        }
        frame.row(&text, final_status(report, id).1);
    }
    if shown < rows.len() {
        frame.row(
            &format!(" Показаны лучшие: {shown} из {}.", rows.len()),
            Tone::Secondary,
        );
    }
    frame.row(
        if service_policy(report) {
            " Приоритет у стабильных сервисов и подтверждённой низкой задержки."
        } else {
            " Выше оценка — лучше результат с учётом повторов и замедлений."
        },
        Tone::Text,
    );
    frame.row(
        " Зелёный — финал пройден. Красный — финал не пройден.",
        Tone::Secondary,
    );
    frame.separator("");
    let excluded = rows
        .iter()
        .filter(|row| {
            row["id"]
                .as_str()
                .is_some_and(|id| report["strategy_quality"][id] == false)
        })
        .count();
    if report["quality_eligible"] == false {
        frame.row(
            " Проверка получилась нестабильной. Результат не применён.",
            Tone::Warning,
        );
    } else if excluded > 0 {
        frame.row(
            &format!(
                " Нестабильные измерения исключены: {excluded} из {}.",
                rows.len()
            ),
            Tone::Warning,
        );
    }
    if excluded > 0 {
        let reasons: std::collections::BTreeSet<_> = report["quality_reasons"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.values())
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for reason in reasons.iter().take(3) {
            frame.row(&format!(" {reason}"), Tone::Warning);
        }
        if reasons.len() > 3 {
            frame.row(
                " Остальные причины сохранены в отчёте JSON.",
                Tone::Secondary,
            );
        }
    }
    let best_label = if recommendation_confirmed {
        "Рекомендация"
    } else if report["validation_error"].is_string() || report["recommendation_status"].is_string()
    {
        "Лидер отдельного теста"
    } else if report["quality_eligible"] == false {
        "Лучший предварительный результат"
    } else if excluded > 0 {
        "Лучший из подтверждённых"
    } else {
        "Лучший результат"
    };
    frame.row(
        &format!(" {best_label}: {}", name(report, best)),
        if recommendation_confirmed {
            Tone::Good
        } else if report["quality_eligible"] == false
            || report["validation_error"].is_string()
            || report["recommendation_status"] == "unconfirmed"
        {
            Tone::Warning
        } else {
            Tone::Text
        },
    );
    if recommendation_confirmed {
        frame.row(" Рабочий режим рекомендации подтверждён.", Tone::Good);
        if let Some(reason) = speed_reason(report) {
            frame.row(&reason, Tone::Good);
        }
        if let Some(trial) = report["trial_best"]["id"].as_str().filter(|id| *id != best) {
            frame.row(
                &format!(" Лидер отдельного теста: {}", name(report, trial)),
                Tone::Secondary,
            );
        }
    }
    explain_service_score(&mut frame, report);
    if let Some(checks) = report["final_checks"].as_object() {
        for (id, check) in checks
            .iter()
            .filter(|(_, check)| check["confirmed"] == false)
        {
            frame.row(
                &format!(" ФИНАЛ НЕ ПРОЙДЕН: {}", name(report, id)),
                Tone::Bad,
            );
            if let Some(error) = check["error"].as_str() {
                frame.row(&format!(" {error}"), Tone::Bad);
            }
        }
    }
    let primary = report["primary"].as_str().unwrap_or("");
    let restored = report["startup"]["restored"] == true;
    let changed = report["primary_changed"] == true && report["accepted"] == true;
    let state = if historical && restored {
        "Прежний обход был восстановлен; основная после проверки"
    } else if historical {
        "Основная после проверки"
    } else if restored {
        "Прежний обход восстановлен"
    } else if changed {
        "Основная изменена"
    } else {
        "Основная сохранена"
    };
    frame.row(
        &format!(" {state}: {}", name(report, primary)),
        if changed && !restored {
            Tone::Good
        } else if restored {
            Tone::Warning
        } else {
            Tone::Secondary
        },
    );
    if report["choice"] == "kept" && recommendation_confirmed && best != primary {
        frame.row(
            " По вашему выбору оставлена текущая основная стратегия.",
            Tone::Text,
        );
    } else if report["choice"] == "unconfirmed" {
        frame.row(
            " Лучшие варианты не подтвердили рабочий режим. Основная сохранена.",
            Tone::Warning,
        );
    }
    if report["accepted"] == false && !restored {
        frame.row(
            if historical {
                " Настройки тогда не изменялись."
            } else {
                " Настройки не изменены."
            },
            Tone::Text,
        );
    }
    if let Some(error) = report["validation_error"].as_str() {
        frame.row(
            " Финальная проверка не пройдена. Прежние настройки сохранены.",
            Tone::Bad,
        );
        frame.row(&format!(" {error}"), Tone::Bad);
    }
    if let Some(passed) = report["retained_check"]["confirmed"].as_bool() {
        if passed {
            frame.row(
                " Прежний порядок автосмены прошёл повторную проверку.",
                Tone::Good,
            );
        } else if let Some(error) = report["retained_check"]["error"].as_str() {
            frame.row(
                &format!(" Проверка прежнего порядка автосмены — {error}"),
                Tone::Warning,
            );
        }
    }
    if report["cache_error"].is_string() {
        frame.row(
            " Не удалось сохранить историю пропусков; следующий подбор проверит весь быстрый пул.",
            Tone::Warning,
        );
    }
    if let Some(deferred) = report["deferred_history"]
        .as_array()
        .filter(|ids| !ids.is_empty())
    {
        frame.row(
            &format!(
                " По истории отложены слабые стратегии: {}. Полный тест проверяет все.",
                deferred.len()
            ),
            Tone::Secondary,
        );
    }
    if let Some(path) = report["report_file"].as_str() {
        frame.row(&format!(" Подробный отчёт: {path}"), Tone::Secondary);
    }
    if report["startup_error"].is_string() {
        frame.row(
            " Запуск обхода после проверки не подтверждён.",
            Tone::Warning,
        );
    }
    if let Some(rows) = report["webcheck"]["rows"].as_array() {
        let browser: Vec<_> = rows
            .iter()
            .filter(|row| matches!(row["mode"].as_str(), Some("BrowserAuto" | "BrowserTcp")))
            .collect();
        let passed = !browser.is_empty()
            && browser.iter().all(|row| {
                row["state"] == "OK" && row["complete"] == true && row["cleanup_complete"] == true
            });
        frame.row(
            if passed {
                " Браузер: проверка пройдена."
            } else {
                " Браузер: есть ошибки, смотрите отчёт проверки."
            },
            if passed { Tone::Good } else { Tone::Warning },
        );
    } else if report["webcheck"].is_object() {
        frame.row(" Проверка браузера не завершена.", Tone::Warning);
    }
    frame
}

fn quick_stages(report: &Value, full_count: usize) -> Option<String> {
    let stage = &report["quick_screen"];
    let screened = stage["screened"].as_u64()?;
    let targets = stage["targets"].as_array()?.len();
    Some(format!(
        " Короткий этап — профилей {screened}, адресов {targets}. Полный этап — {full_count}."
    ))
}

fn network_summary(frame: &mut Frame, report: &Value) {
    if let Some(sampled) = report["retry_batches"]["sampled"]
        .as_u64()
        .filter(|n| *n > 0)
    {
        let expanded = report["retry_batches"]["expanded"].as_u64().unwrap_or(0);
        frame.row(
            &format!(" Серии с массовыми ошибками: {sampled}. Расширенных повторов: {expanded}."),
            Tone::Secondary,
        );
    }
    if report["repeated_baseline_rounds"]
        .as_array()
        .is_some_and(|rounds| !rounds.is_empty())
    {
        frame.row(
            " Исходный замер повторён из-за недоступности контрольных серверов.",
            Tone::Secondary,
        );
    }
    if let Some(failed) = report["failed_profiles"]
        .as_object()
        .filter(|rows| !rows.is_empty())
    {
        let labels = failed
            .keys()
            .map(|id| format!("ALT{id}"))
            .collect::<Vec<_>>()
            .join(", ");
        frame.row(
            &format!(
                " Движок завершился во время проверки {labels}. Эти профили исключены из выбора."
            ),
            Tone::Warning,
        );
    }
    if let Some(reason) = report["later_interruption"].as_str() {
        frame.row(
            &format!(" Более поздний подбор прервался. {reason}"),
            Tone::Warning,
        );
    } else if report["network_recovery"]["restarted"] == true {
        frame.row(
            " После восстановления подключения все замеры выполнены заново.",
            Tone::Text,
        );
    }
}

fn media_summary(frame: &mut Frame, report: &Value) {
    if !report["telegram_media"].is_object() {
        return;
    }
    for (group, target, label) in [
        ("Discord", "media_file", "Медиа Discord"),
        ("Roblox", "game_icon", "Иконка Roblox"),
    ] {
        if let Some(r) = report["final_details"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["group"] == group && r["name"] == target)
        {
            if r["state"] == "OK" {
                frame.row(
                    &format!(" {label} — {} байт, файл проверен.", r["body_bytes"]),
                    Tone::Good,
                );
            } else {
                frame.row(
                    &format!(
                        " {label} — сбой (HTTP {}, {}).",
                        r["code"].as_str().unwrap_or("000"),
                        r["termination"].as_str().unwrap_or("")
                    ),
                    Tone::Warning,
                );
            }
        }
    }
    for line in crate::presentation::telegram_media_text(&report["telegram_media"]).lines() {
        frame.row(&format!(" {line}"), Tone::Text);
    }
}

pub fn result_text(report: &Value) -> Option<String> {
    let mut complete = report.clone();
    complete["presentation"] = Value::String("detailed".into());
    let mut text = result_frame(
        &complete,
        Viewport {
            columns: 80,
            rows: usize::MAX,
        },
    )
    .map(Frame::plain)?;
    if let Some(failed) = report["failed_profiles"].as_object() {
        for (id, reason) in failed {
            if let Some(reason) = reason.as_str() {
                text.push_str(&format!("\r\nALT{id} — {reason}\r\n"));
            }
        }
    }
    if report["network_monitor"].is_object() {
        let m = &report["network_monitor"];
        text.push_str(&format!("\r\nСостояние сети Windows: чтений {}, повторных вызовов пропущено {}, суммарно {:.0} мс.\r\n",
            m["reads"],m["cached_checks"],m["read_ms"].as_f64().unwrap_or(0.)));
    }
    if let Some(boundaries) = report["shared_controls"].as_array() {
        let saved: u64 = boundaries
            .iter()
            .filter_map(|b| b["requests_saved"].as_u64())
            .sum();
        text.push_str(&format!(
            "Общие контрольные замеры между профилями {}. Сэкономлено запросов {}.\r\n",
            boundaries.len(),
            saved
        ));
    }
    if let Some(families) = report["strategy_families"].as_object() {
        text.push_str("\r\n\r\nСемейства установленных стратегий\r\n");
        for (family, ids) in families {
            let names: Vec<_> = ids
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|id| format!("ALT{id}"))
                .collect();
            text.push_str(&format!("{family} — {}\r\n", names.join(", ")));
        }
        if let Some(followups) = report["family_selection"]["followups"]
            .as_array()
            .filter(|ids| !ids.is_empty())
        {
            let names: Vec<_> = followups
                .iter()
                .filter_map(Value::as_str)
                .map(|id| name(report, id))
                .collect();
            text.push_str(&format!(
                "После сравнения представителей в первую очередь проверялись {}.\r\n",
                names.join(", ")
            ));
        }
    }
    if report["timings"].is_object() {
        text.push_str("\r\n\r\nСводка по стратегиям\r\n");
        if full_request_policy(report) {
            text.push_str("Время запроса включает DNS, подключение и чтение до конца ответа или лимита адреса. Медиана и P95 учитывают стабильные успешные запросы всех групп. Для HTTP/3 измеряется рукопожатие QUIC через UDP.\r\n");
        }
        if service_policy(report) {
            text.push_str("При выборе по задержке сравниваются стабильные ответы сервисов, включая три адреса Steam. Подтверждение требует двух парных сравнений в рабочем режиме при смене порядка профилей. Балл покрытия включает также цели DPI.\r\n");
        }
        for row in report["rows"].as_array().into_iter().flatten() {
            let id = row["id"].as_str().unwrap_or("");
            let n = |v: &Value| {
                v.as_f64()
                    .filter(|v| v.is_finite())
                    .map(points)
                    .unwrap_or_else(|| "—".into())
            };
            let phases = if report["timings"][id]["overall"].is_object() {
                &report["timings"][id]["overall"]
            } else {
                &report["timings"][id]
            };
            text.push_str(&format!("{}: балл {} | ответили {}/{} | вред {} | зависаний {} | TCP ~{} мс | TLS ~{} мс | время {} с\r\n",
                name(report,id),n(&row["score"]),n(&report["availability"][id]["ok"]),n(&report["availability"][id]["total"]),n(&row["harm"]),n(&row["freeze"]),
                n(&phases["tcp_ms"]),n(&phases["tls_ms"]),report["timings"][id]["elapsed_ms"].as_f64().map(|v|points(v/1000.)).unwrap_or_else(||"—".into())));
            let overall = &report["timings"][id]["overall"];
            if overall.is_object() {
                text.push_str(&format!("  Все группы: DNS {} мс | TCP {} мс | TLS {} мс | первый ответ {} мс | всего {} мс | P95 {} мс | стабильных замеров {} | ошибок {} | со второй попытки {}\r\n",
                    n(&overall["dns_ms"]), n(&overall["tcp_ms"]), n(&overall["tls_ms"]), n(&overall["first_byte_ms"]), n(&overall["total_ms"]), n(&overall["p95_ms"]), n(&overall["samples"]), n(&overall["errors"]), n(&overall["recovered"])));
                if let Some(groups) = overall["groups"].as_object() {
                    for (group, timing) in groups {
                        text.push_str(&format!("  {group}: ответили {}/{} | всего {} мс | P95 {} мс | стабильных замеров {}\r\n", n(&timing["ok"]), n(&timing["total"]), n(&timing["total_ms"]), n(&timing["p95_ms"]), n(&timing["samples"])));
                    }
                }
            }
            let mut parts = Vec::new();
            for (key, label) in [
                ("DPI", "16–20 КБ"),
                ("CDN", "файлы CDN"),
                ("QUIC", "HTTP/3"),
                ("Discord", "Discord"),
                ("YouTube", "YouTube"),
                ("SoundCloud", "SoundCloud"),
                ("NBA2K", "2K"),
                ("EAC", "EAC/Epic"),
                ("Clean", "обычные сайты"),
            ] {
                if row["group_totals"][key].is_number() {
                    parts.push(format!(
                        "{label} {}/{}",
                        n(&row["groups"][key]),
                        n(&row["group_totals"][key])
                    ));
                }
            }
            if !parts.is_empty() {
                text.push_str(&format!("  {}\r\n", parts.join(" | ")));
            }
        }
    }
    if let Some(details) = report["details"].as_object() {
        text.push_str("\r\n\r\nПодробные результаты. TCP/TLS — мс от начала DNS до подключения и завершения TLS; HTTP — код ответа. x2 — повтор, нестабильно — ответ только со второй попытки.\r\n");
        let mut order = vec!["0"];
        order.extend(
            report["rows"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|row| row["id"].as_str()),
        );
        for id in order {
            let Some(rows) = details.get(id).and_then(Value::as_array) else {
                continue;
            };
            text.push_str(&format!(
                "\r\n{}\r\n",
                if id == "0" {
                    "Без обхода".into()
                } else {
                    name(report, id)
                }
            ));
            for row in rows {
                text.push_str(&detail_line(row));
                text.push_str("\r\n");
            }
        }
        if let Some(rows) = report["final_details"]
            .as_array()
            .filter(|rows| !rows.is_empty())
        {
            text.push_str("\r\nФинальная комбинация\r\n");
            for row in rows {
                text.push_str(&detail_line(row));
                text.push_str("\r\n");
            }
        }
    }
    if let Some(reference) = report["working_reference"]
        .as_array()
        .filter(|rows| !rows.is_empty())
    {
        text.push_str("\r\n\r\nРабочий режим до применения (основа проверки регрессий)\r\n");
        for row in reference {
            text.push_str(&detail_line(row));
            text.push_str("\r\n");
        }
    }
    if let Some(checks) = report["final_checks"]
        .as_object()
        .filter(|map| !map.is_empty())
    {
        text.push_str("\r\n\r\nФинальные проверки кандидатов\r\n");
        for (id, check) in checks {
            text.push_str(&format!(
                "\r\nРабочий режим: {} — {}\r\n",
                name(report, id),
                if check["confirmed"] == true {
                    "ПОДТВЕРЖДЁН"
                } else {
                    "НЕ ПРОЙДЕН"
                }
            ));
            if let Some(error) = check["error"].as_str() {
                text.push_str(error);
                text.push_str("\r\n");
            }
            for row in check["details"].as_array().into_iter().flatten() {
                text.push_str(&detail_line(row));
                text.push_str("\r\n");
            }
        }
    }
    if let Some(rows) = report["retained_check"]["details"].as_array() {
        text.push_str("\r\nПовторная проверка прежнего порядка автосмены\r\n");
        for row in rows {
            text.push_str(&detail_line(row));
            text.push_str("\r\n");
        }
    }
    Some(text)
}

fn detail_line(row: &Value) -> String {
    let field = |key: &str| row[key].as_str().unwrap_or("—");
    let ms = |key: &str| {
        row[key]
            .as_f64()
            .filter(|v| v.is_finite())
            .map(|v| format!("{v:.0}"))
            .unwrap_or_else(|| "—".into())
    };
    let mut line = format!(
        "  {}/{} | {} | HTTP {} | DNS {} мс | TCP {} мс | TLS {} мс | всего {} мс | отправлено {} / получено {} байт{}{}",
        field("group"),
        field("name"),
        field("state"),
        field("code"),
        ms("dns_ms"),
        ms("tcp_ms"),
        ms("tls_ms"),
        ms("total_ms"),
        ms("up"),
        ms("down"),
        if row["tries"].as_u64().unwrap_or(1) > 1 {
            " | x2"
        } else {
            ""
        },
        if row["flaky"] == true {
            " | нестабильно"
        } else {
            ""
        }
    );
    if let Some(check) = row["peer_comparison"].as_object() {
        line.push_str(&format!(
            " | IP из DNS {}.",
            check["dns_peer"].as_str().unwrap_or("—")
        ));
        for (field, label) in [
            ("candidate_replays", "Кандидат"),
            ("previous_controls", "Прежний режим"),
        ] {
            for result in check[field].as_array().into_iter().flatten() {
                line.push_str(&format!(
                    " {} {} — {}.",
                    label,
                    result["remote_address"].as_str().unwrap_or("—"),
                    result["state"].as_str().unwrap_or("—")
                ));
            }
        }
    }
    line
}

pub fn run_summary(
    app: &crate::App,
    name: &str,
    summary: &zapret_core::RankRow,
    counts: &crate::selection::Availability,
    timing: &Value,
    rows: &[crate::selection::Row],
    state: RunState,
) -> anyhow::Result<()> {
    if app.json {
        return Ok(());
    }
    let ms = |key: &str| {
        timing[key]
            .as_f64()
            .filter(|v| v.is_finite())
            .map(|v| format!("{v:.0}"))
            .unwrap_or_else(|| "—".into())
    };
    let baseline = summary.id == "0";
    let tone = if baseline {
        Tone::Secondary
    } else {
        trial_tone(state.qualified, state.response_delta)
    };
    let change = match (baseline, state.response_delta) {
        (true, _) => String::new(),
        (_, Some(0)) => " (=)".into(),
        (_, Some(delta)) => format!(" ({delta:+})"),
        (_, None) => " (нет общей базы)".into(),
    };
    let marker = if baseline {
        ""
    } else if !state.qualified {
        " · нестабильно"
    } else if state.leader {
        " · лидер по доступности"
    } else {
        ""
    };
    if !state.details {
        let prefix = if state.position > 0 {
            format!("[{:02}/{:02}] ", state.position, state.total)
        } else {
            String::new()
        };
        crate::console::line(
            &format!(
                "{prefix}{} · {}/{}{change} · балл {} · TCP {} / TLS {} · всего {} мс{marker}",
                label(name, 24),
                counts.ok,
                counts.total(),
                points(summary.score),
                timing["overall"]["tcp_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.0}"))
                    .unwrap_or_else(|| ms("tcp_ms")),
                timing["overall"]["tls_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.0}"))
                    .unwrap_or_else(|| ms("tls_ms")),
                timing["overall"]["total_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.0}"))
                    .unwrap_or_else(|| "—".into())
            ),
            tone,
        )?;
        return Ok(());
    }
    crate::console::line(
        &format!(
            "  {name}: балл {} | ответили {}/{}{change} | зачёт {}/{} | вред {}/{} | зависаний {} | TCP ~{} мс | TLS ~{} мс | время {} с{marker}",
            points(summary.score),
            counts.ok,
            counts.total(),
            points(summary.ok),
            summary.total,
            summary.harm,
            summary.group_totals.get("Clean").copied().unwrap_or(0),
            summary.freeze,
            ms("tcp_ms"),
            ms("tls_ms"),
            timing["elapsed_ms"]
                .as_f64()
                .map(|v| points(v / 1000.))
                .unwrap_or_else(|| "—".into())
        ),
        tone,
    )?;
    let mut groups = Vec::new();
    for (key, label) in [
        ("DPI", "16–20 КБ"),
        ("CDN", "файлы CDN"),
        ("QUIC", "HTTP/3"),
        ("Discord", "Discord"),
        ("YouTube", "YouTube"),
        ("SoundCloud", "SoundCloud"),
        ("NBA2K", "2K"),
        ("EAC", "EAC/Epic"),
    ] {
        if let Some(total) = summary.group_totals.get(key) {
            groups.push(format!(
                "{label} {}/{total}",
                points(summary.groups.get(key).copied().unwrap_or(0.))
            ));
        }
    }
    crate::console::line(
        &format!(
            "  {} | повторено адресов: {}",
            groups.join(" | "),
            timing["retries"]
        ),
        Tone::Text,
    )?;
    let flaky: Vec<_> = rows
        .iter()
        .filter(|row| row.flaky)
        .map(|row| row.name.as_str())
        .collect();
    if !flaky.is_empty() {
        crate::console::line(
            &format!("  Открылись со второй попытки: {}", flaky.join(", ")),
            Tone::Warning,
        )?;
    }
    Ok(())
}

pub fn progress(app: &crate::App, text: &str) -> anyhow::Result<()> {
    if !app.json {
        crate::console::line(text, Tone::Text)?;
    }
    Ok(())
}

pub fn detail(app: &crate::App, enabled: bool, text: &str) -> anyhow::Result<()> {
    if enabled {
        progress(app, text)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_outcome_leads_with_the_saved_strategy_and_keeps_details_in_the_file() {
        let mut data = report();
        data["presentation"] = json!("compact");
        data["accepted"] = json!(true);
        data["primary_changed"] = json!(true);
        data["primary"] = json!("52");
        data["elapsed_ms"] = json!(95000.);
        data["final_checks"] = json!({"52":{"confirmed":true}});
        data["recommendation_status"] = json!("confirmed");
        let frame = result_frame(
            &data,
            Viewport {
                columns: 80,
                rows: 24,
            },
        )
        .unwrap();
        assert!(frame.has_tone(Tone::Good, "ПРИМЕНЕНО: ALT11 белый 3"));
        assert!(frame.height() <= 16);
        let text = frame.plain();
        assert!(text.contains("1 мин 35 с"));
        assert!(!text.contains("Настройки не изменены"));
    }

    #[test]
    fn compact_rejection_names_the_retained_primary_without_repeating_all_final_errors() {
        let mut data = report();
        data["presentation"] = json!("compact");
        data["validation_error"] =
            json!("Финальная комбинация не подтвердила DPI/Hetzner: FAIL, TCP 30 мс, TLS 0 мс");
        data["final_checks"] = json!({"52":{"confirmed":false,"error":data["validation_error"]}});
        let frame = result_frame(
            &data,
            Viewport {
                columns: 55,
                rows: 24,
            },
        )
        .unwrap();
        assert!(frame.has_tone(Tone::Bad, "НЕ ПРИМЕНЕНО:"));
        let text = frame.plain();
        assert!(text.contains("ALT11 белый 1") && text.contains("Hetzner"));
        assert!(!text.contains("TLS 0 мс"));
        assert!(text.lines().count() <= 18);
        assert!(result_text(&data).unwrap().contains("TLS 0 мс"));
    }

    #[test]
    fn cached_rejection_shows_all_working_losses_and_the_origin_of_the_latency() {
        let mut data = report();
        data["presentation"] = json!("compact");
        data["selection_policy"] = json!("availability-then-full-request-latency-v2");
        data["validation_error"] = json!("Финальная комбинация не подтвердила DPI/Hetzner: FAIL");
        data["working_reference"] = json!([
            {"group":"DPI","name":"Hetzner","url":"https://a.test/","state":"OK"},
            {"group":"DPI","name":"OVH","url":"https://b.test/","state":"OK"}]);
        data["final_details"] = json!([
            {"group":"DPI","name":"OVH","url":"https://b.test/","state":"FAIL"},
            {"group":"DPI","name":"Hetzner","url":"https://a.test/","state":"FAIL"}]);
        data["timings"] = json!({"52":{"overall":{"total_ms":281.,"p95_ms":1352.}}});
        let viewport = Viewport {
            columns: 100,
            rows: 36,
        };
        let text = result_frame_mode(&data, viewport, true).unwrap().plain();
        assert!(text.contains("DPI/Hetzner, DPI/OVH"));
        assert!(text.contains("В отдельном тесте") && !text.contains("У рекомендации"));
        data["retained_check"] = json!({"confirmed":true,"details":[]});
        let frame = result_frame(&data, viewport).unwrap();
        assert!(frame.has_tone(Tone::Good, "ОСТАВЛЕНО"));
        assert!(frame.plain().contains("Прежний порядок автосмены прошёл"));
    }

    #[test]
    fn primary_choice_rejects_an_accidental_russian_comma_instead_of_silently_keeping() {
        assert_eq!(primary_answer("б"), None);
        assert_eq!(primary_answer("y"), Some(true));
        assert_eq!(primary_answer("n"), Some(false));
        assert_eq!(primary_answer(""), Some(false));
    }

    #[test]
    fn full_latency_result_uses_all_targets_and_only_short_confirmation_labels() {
        let mut data = report();
        data["presentation"] = json!("compact");
        data["selection_policy"] = json!("availability-then-full-request-latency-v2");
        data["connection_selection"] = json!({"confirmed":true,"reference":"50","candidate":"52",
            "working":{"scope":"AllTargets","targets":50,"gain_ms":40.,"reference_tcp_ms":60.,"candidate_tcp_ms":40.,
                "reference_tls_ms":80.,"candidate_tls_ms":60.,"reference_total_ms":240.,"candidate_total_ms":200.,
                "reference_p95_ms":450.,"candidate_p95_ms":400.}});
        let text = result_frame(
            &data,
            Viewport {
                columns: 100,
                rows: 40,
            },
        )
        .unwrap()
        .plain();
        assert!(
            text.contains("полный запрос быстрее на ~40 мс") && text.contains("адресов: 50"),
            "{text}"
        );
        assert!(
            text.contains("всего 200 мс") && text.contains("400 мс"),
            "{text}"
        );
        assert!(!text.contains("к 2K/EAC"), "{text}");
        let prompt = primary_frame(
            &data,
            Viewport {
                columns: 100,
                rows: 40,
            },
        )
        .plain();
        assert!(prompt.contains("y") && prompt.contains("n"));
        assert!(!prompt.contains("yes") && !prompt.contains("no") && !prompt.contains("[д/Н]"));
    }

    #[test]
    fn service_reports_show_both_working_measurements_and_keep_v3_reports_readable() {
        let mut data = report();
        data["selection_policy"] = json!(crate::selection_latency::PREVIOUS_POLICY);
        assert!(full_request_policy(&data));
        data["selection_policy"] = json!("service-availability-then-paired-latency-v4");
        assert!(service_policy(&data) && full_request_policy(&data));
        data["selection_policy"] = json!(crate::selection_latency::POLICY);
        data["connection_selection"] = json!({"confirmed": true, "reference":"50","candidate":"70",
            "working":{"scope":"ServiceTargets","gain_ms":4.5,"candidate_total_ms":120.,"candidate_p95_ms":333.},
            "repeat":{"scope":"ServiceTargets","gain_ms":3.5,"candidate_total_ms":125.,"candidate_p95_ms":350.}});
        assert!(speed_reason(&data).unwrap().contains("4,5 и 3,5 мс"));
        assert_eq!(
            request_timing(&data, "70"),
            Some((125., 350., "В рабочем режиме"))
        );
        data["connection_selection"]["confirmed"] = json!(false);
        assert!(speed_reason(&data).is_none());
    }

    #[test]
    fn scoring_table_keeps_missing_evidence_distinct_from_the_reference_and_zero_gain() {
        let report =
            json!({"trial_score_reference":"31","trial_service_scores":{"31":0.,"52":-4.49}});
        let rows = [
            json!({"id":"other","score":60.}),
            json!({"id":"52","score":57.}),
            json!({"id":"31","score":56.}),
        ];
        let sorted = display_order(&report, &rows, "31");
        assert_eq!(
            sorted
                .iter()
                .map(|r| displayed_score(&report, r))
                .collect::<Vec<_>>(),
            ["+0,00", "-4,49", "—"]
        );
        let mut frame = Frame::new(
            Viewport {
                columns: 90,
                rows: 24,
            },
            "Тест",
        );
        explain_service_score(&mut frame, &report);
        assert!(frame.plain().contains("никто не опередил"));
        let old = json!({"selection_policy":"service-availability-then-paired-latency-v5"});
        assert!(service_policy(&old));
        assert_eq!(displayed_score(&old, &rows[0]), "60");
    }

    #[test]
    fn trial_colors_use_the_visible_response_change_with_control_failures_taking_priority() {
        assert_eq!(trial_tone(true, Some(1)), Tone::Good);
        assert_eq!(trial_tone(true, Some(-1)), Tone::Bad);
        assert_eq!(trial_tone(true, Some(0)), Tone::Text);
        assert_eq!(trial_tone(true, None), Tone::Warning);
        assert_eq!(trial_tone(false, Some(8)), Tone::Warning);
    }

    #[test]
    fn both_result_tables_keep_untested_finalists_neutral() {
        let mut data = report();
        data["final_checks"] = json!({"52":{"confirmed":true}});
        for mode in ["compact", "detailed"] {
            data["presentation"] = json!(mode);
            let frame = result_frame(
                &data,
                Viewport {
                    columns: 100,
                    rows: 80,
                },
            )
            .unwrap();
            assert!(frame.has_tone(Tone::Text, "ALT11 белый 1"));
            assert!(frame.has_tone(Tone::Good, "ALT11 белый 3"));
        }
    }
    use serde_json::json;

    #[test]
    fn history_does_not_present_the_previous_primary_as_the_current_setting() {
        let data = report();
        let original = data.clone();
        let text = result_frame_mode(
            &data,
            Viewport {
                columns: 80,
                rows: 30,
            },
            true,
        )
        .unwrap()
        .plain();
        assert!(text.contains("прошлой проверки"));
        assert!(text.contains("Основная после проверки"));
        assert!(!text.contains("Основная сохранена"));
        assert_eq!(data, original);
    }

    #[test]
    fn comparison_has_a_readable_conclusion_without_changing_its_signed_record() {
        let report = json!({"protocol":"finalists-native-v1","a_name":"ALT11 белый 1","b_name":"ALT11 белый 3",
            "completion_hash":"signed-record", "assessment":{"status":"NoClearDifference","reasons":[],"resources":{"status":"Unavailable"}}});
        let original = report.clone();
        let text = result_frame(
            &report,
            Viewport {
                columns: 55,
                rows: 16,
            },
        )
        .unwrap()
        .plain();
        assert!(text.contains("ALT11 белый 1") && text.contains("ALT11 белый 3"));
        assert!(text.contains("Устойчивой разницы не обнаружено"));
        assert!(!text.contains("NoClearDifference") && !text.contains("completion_hash"));
        assert_eq!(report, original);
    }

    fn report() -> Value {
        json!({"schema":1,"best":{"id":"52","score":48.,"total":54},
            "rows":[{"id":"52","score":48.,"total":54},{"id":"50","score":46.5,"total":54}],
            "availability":{"52":{"ok":49,"total":54},"50":{"ok":48,"total":54}},
            "strategy_names":{"52":"ALT11 белый 3","50":"ALT11 белый 1"},
            "primary":"50","primary_changed":false,"accepted":false,"quality_eligible":true,
            "rounds_measured":{"52":1,"50":1},
            "journal":"C:/private/runtime/test-internal.jsonl", "native_identity":"private-hash",
            "startup":{"running":true,"restored":false}})
    }

    #[test]
    fn final_winner_is_green_and_a_rejected_trial_leader_is_red() {
        let mut data = report();
        data["trial_best"] = json!({"id":"52"});
        data["best"] = json!({"id":"50","score":46.5});
        data["recommendation_status"] = json!("confirmed");
        data["final_checks"] =
            json!({"52":{"confirmed":false,"error":"Hetzner: TLS reset"},"50":{"confirmed":true}});
        let frame = result_frame(
            &data,
            Viewport {
                columns: 80,
                rows: 80,
            },
        )
        .unwrap();
        assert!(frame.has_tone(Tone::Bad, "ALT11 белый 3"));
        assert!(frame.has_tone(Tone::Good, "Рекомендация: ALT11 белый 1"));
        let text = frame.plain();
        assert!(text.contains("Hetzner: TLS reset"));
        assert!(text.contains("Лидер отдельного теста"));
        assert!(!text.contains("Основная изменена"));
    }

    #[test]
    fn failed_historical_report_does_not_call_its_trial_winner_a_working_recommendation() {
        let mut data = report();
        data["validation_error"] = json!("Hetzner: TLS reset");
        let frame = result_frame_mode(
            &data,
            Viewport {
                columns: 80,
                rows: 80,
            },
            true,
        )
        .unwrap();
        assert!(frame.has_tone(Tone::Warning, "Лидер отдельного теста"));
        assert!(!frame.has_tone(Tone::Good, "Рекомендация:"));
        let text = frame.plain();
        assert!(text.contains("Основная после проверки"));
        assert!(text.contains("Hetzner: TLS reset"));
    }

    #[test]
    fn primary_choice_names_both_actions_and_colors_the_verified_recommendation() {
        let mut data = report();
        data["final_checks"] = json!({"52":{"confirmed":true}});
        let frame = primary_frame(
            &data,
            Viewport {
                columns: 55,
                rows: 30,
            },
        );
        assert!(frame.has_tone(Tone::Good, "Рекомендация: ALT11 белый 3"));
        let text = frame.plain();
        assert!(text.contains("y  Применить ALT11 белый 3"));
        assert!(text.contains("n  Оставить ALT11 белый 1"));
        assert!(text.contains("Enter — n"));
        assert!(text.lines().all(|line| line.chars().count() <= 53));
    }

    #[test]
    fn text_report_retains_each_final_candidate_failure_and_probe_timing() {
        let mut data = report();
        data["final_checks"] = json!({"52":{"confirmed":false,"error":"Hetzner: TLS reset","details":[{"group":"DPI","name":"Hetzner","state":"FAIL","tcp_ms":36.,"tls_ms":0.}]},"50":{"confirmed":true,"details":[]}});
        let text = result_text(&data).unwrap();
        assert!(text.contains("Рабочий режим: ALT11 белый 3"));
        assert!(text.contains("Hetzner: TLS reset"));
        assert!(text.contains("TCP 36 мс"));
    }

    #[test]
    fn ordinary_result_explains_ranking_and_keeps_the_actual_primary_visible() {
        let mut report = report();
        report["timings"] = json!({"52":{"tcp_ms":42.,"tls_ms":93.,"elapsed_ms":12000.}});
        let original = report.clone();
        let text = result_frame(
            &report,
            Viewport {
                columns: 80,
                rows: 30,
            },
        )
        .unwrap()
        .plain();
        for expected in [
            "Автоподбор завершён",
            "ALT11 белый 3",
            "ALT11 белый 1",
            "49/54",
            "46,5",
            "Оценка",
            "Основная сохранена",
            "Настройки не изменены",
            "TCP",
            "42",
            "мс",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        for internal in [
            "quality_eligible",
            "native_identity",
            "C:/private",
            "private-hash",
            "{\n",
        ] {
            assert!(!text.contains(internal), "leaked {internal}");
        }
        assert_eq!(report, original);
    }

    #[test]
    fn partial_control_failure_explains_which_result_was_excluded() {
        let mut report = report();
        report["strategy_quality"] = json!({"52":true,"50":false});
        report["quality_reasons"] =
            json!({"50":["Контрольный адрес bing не ответил после измерения."]});
        let original = report.clone();
        let text = result_frame(
            &report,
            Viewport {
                columns: 80,
                rows: 40,
            },
        )
        .unwrap()
        .plain();
        assert!(
            text.contains("Нестабильные измерения исключены: 1 из 2"),
            "{text}"
        );
        assert!(text.contains("bing"), "{text}");
        assert!(text.contains("Лучший из подтверждённых"), "{text}");
        assert!(!text.contains("Проверка получилась нестабильной"));
        assert_eq!(report, original);
    }

    #[test]
    fn unstable_or_restored_results_never_claim_the_winner_was_applied() {
        let mut report = report();
        report["quality_eligible"] = json!(false);
        report["startup"]["restored"] = json!(true);
        let text = result_frame(
            &report,
            Viewport {
                columns: 80,
                rows: 30,
            },
        )
        .unwrap()
        .plain();
        assert!(text.contains("Проверка получилась нестабильной"));
        assert!(text.contains("Прежний обход восстановлен"));
        assert!(!text.contains("Основная изменена"));
    }

    #[test]
    fn result_fits_a_short_console_and_does_not_invent_coverage_for_an_old_record() {
        let mut report = report();
        report.as_object_mut().unwrap().remove("availability");
        let text = result_frame(
            &report,
            Viewport {
                columns: 55,
                rows: 16,
            },
        )
        .unwrap()
        .plain();
        assert!(
            text.lines().all(|line| line.chars().count() <= 53),
            "{text}"
        );
        assert!(!text.contains("49/54"));
        assert!(!text.contains("48/54"));
        assert!(
            result_frame(
                &json!({"settings":{}}),
                Viewport {
                    columns: 80,
                    rows: 30
                }
            )
            .is_none()
        );
    }
}
