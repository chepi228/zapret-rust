use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read},
    net::IpAddr,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde_json::{Value, json};
use zapret_core::{atomic_write, list_strategies, sha256};

use crate::{
    App, VERSION,
    cli::{NetworkArgs, TestArgs},
    runtime_file,
};

const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JOURNAL_LINE: u64 = 128 * 1024;
const MAX_OBSERVATIONS: usize = 65_536;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STRATEGIES: usize = 4096;

/// The full provider workflow owns no engine lifecycle. Selection returns only
/// after restoring the original running/stopped state, before lookup or export.
pub fn run(app: &App, arguments: &NetworkArgs) -> Result<Value> {
    run_with(
        app,
        arguments,
        |test| crate::selection::run(app, test),
        |timeout_ms| {
            zapret_net::diagnostics(&app.root, "provider", &json!({"timeout_ms":timeout_ms}))
        },
    )
}

fn test_arguments(arguments: &NetworkArgs) -> Result<TestArgs> {
    ensure!(
        arguments.urls.is_empty(),
        "Полная проверка использует встроенный набор целей. Для сведений об IP используйте provider-info"
    );
    ensure!(
        (1..=60_000).contains(&arguments.timeout_ms),
        "Время ожидания должно быть от 1 до 60000 мс"
    );
    let extra = if let Some(text) = &arguments.args {
        ensure!(text.len() <= 65_536, "Аргументы проверки слишком велики");
        serde_json::from_str::<Value>(text).context("Некорректные параметры проверки провайдера")?
    } else {
        json!({})
    };
    let extra = extra
        .as_object()
        .context("Параметры проверки должны быть JSON-объектом")?;
    ensure!(
        extra
            .keys()
            .all(|key| ["parallel", "rounds", "plan_only"].contains(&key.as_str())),
        "Допустимы parallel, rounds и plan_only. Для сведений об IP используйте provider-info"
    );
    let integer = |key: &str, maximum: usize| -> Result<Option<usize>> {
        match extra.get(key) {
            None => Ok(None),
            Some(value) => {
                let number = value
                    .as_u64()
                    .context("Число потоков и кругов должно быть целым")?;
                ensure!(
                    (1..=maximum as u64).contains(&number),
                    "Число потоков или кругов вне допустимых границ"
                );
                Ok(Some(number as usize))
            }
        }
    };
    let plan_only = match extra.get("plan_only") {
        None => false,
        Some(value) => value
            .as_bool()
            .context("plan_only должен быть true или false")?,
    };
    Ok(TestArgs {
        full: true,
        report_only: true,
        keep_primary: true,
        timeout_ms: arguments.timeout_ms,
        parallel: integer("parallel", 64)?,
        rounds: integer("rounds", 10)?.unwrap_or(1),
        plan_only,
        ..Default::default()
    })
}

fn run_with(
    app: &App,
    arguments: &NetworkArgs,
    test: impl FnOnce(&TestArgs) -> Result<Value>,
    provider: impl FnOnce(u64) -> Result<Value>,
) -> Result<Value> {
    let arguments = test_arguments(arguments)?;
    let privacy = ShareText::new(&app.root)?;
    let mut names: BTreeMap<_, _> = list_strategies(&app.root)
        .unwrap_or_default()
        .into_iter()
        .map(|strategy| {
            let name = privacy.clean(strategy.display_name(), 128);
            (strategy.id, name)
        })
        .collect();
    let tested = test(&arguments)?;
    if arguments.plan_only {
        return plan(&arguments, &tested, &privacy);
    }
    if let Some(captured) = tested["strategy_names"]
        .as_object()
        .filter(|names| names.len() <= MAX_STRATEGIES)
    {
        names = captured
            .iter()
            .map(|(id, name)| (id.clone(), privacy.clean(name.as_str().unwrap_or(""), 128)))
            .collect();
    }

    // Provider diagnostics has a separate 30-second per-request ceiling. Its
    // failure cannot discard a successfully restored, completed strategy test.
    let provider =
        provider(arguments.timeout_ms.min(30_000)).unwrap_or_else(|_| json!({"rows":[]}));
    let provider = provider_fields(&provider, &privacy);
    let journal = read_journal(&app.root, &tested, &privacy, &names);
    let (observations, complete) = match journal {
        Ok(rows) => (rows, true),
        Err(_) => (Vec::new(), false),
    };
    let mut result = combined(
        &arguments,
        &tested,
        provider,
        observations,
        complete,
        &privacy,
        &names,
    )?;
    let mut report = render(&result);
    if report.len() > MAX_REPORT_BYTES {
        result["test"]["observations"] = json!([]);
        result["test"]["observations_complete"] = json!(false);
        result["test"]["observation_reason"] = json!("ReportBudgetExceeded");
        report = render(&result);
    }
    ensure!(
        report.len() <= MAX_REPORT_BYTES,
        "Результат проверки превышает лимит отчёта"
    );
    let slug = result["provider"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| row["provider"]["isp"].as_str().unwrap_or(""))
        .find(|name| !name.is_empty() && *name != "[скрыто]")
        .unwrap_or("провайдер");
    let filename = format!(
        "zapret-rust-proverka-{}-{}-{}.txt",
        provider_slug(slug),
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        &result["run_id"].as_str().expect("validated run ID")[..8]
    );
    result["report_file"] = json!(filename);
    result["report_sha256"] = json!(sha256(report.as_bytes()));
    result["report_text"] = json!(report);
    // No engine action, settings write or second shutdown can follow selection.
    // If exporting fails, retain every safe result in the returned value and
    // print the complete text so the user can still copy it.
    let saved = (|| -> Result<_> {
        let path = runtime_file(&app.root, &filename)?;
        atomic_write(
            &path,
            result["report_text"]
                .as_str()
                .expect("report text")
                .as_bytes(),
        )?;
        Ok(path)
    })();
    match saved {
        Ok(path) => {
            result["report_saved"] = json!(true);
            result["path"] = json!(path);
            result["TextFile"] = result["path"].clone();
            result["text"] = json!(format!(
                "Проверка провайдера завершена.\nФайл с результатом: {}\nОсновная стратегия: {}.\nПерешлите этот файл тому, кто дал вам папку zapret-rust.",
                path.display(),
                display(&result["test"]["primary_name"])
            ));
        }
        Err(_) => {
            result["report_saved"] = json!(false);
            result["save_error"] = json!("ReportWriteFailed");
            result["text"] = json!(format!(
                "Проверка завершена, но файл отчёта сохранить не удалось. Скопируйте результат ниже:\n\n{}",
                result["report_text"].as_str().expect("report text")
            ));
        }
    }
    Ok(result)
}

fn plan(arguments: &TestArgs, tested: &Value, privacy: &ShareText) -> Result<Value> {
    let strategies = tested["strategies"]
        .as_array()
        .context("В плане нет списка стратегий")?;
    ensure!(
        strategies.len() <= MAX_STRATEGIES,
        "Слишком много стратегий в плане"
    );
    let strategies: Vec<_> = strategies.iter().map(|strategy| json!({
        "id":strategy_id(&strategy["id"]), "name":privacy.clean(strategy["name"].as_str().unwrap_or(""),128)
    })).collect();
    Ok(
        json!({"schema":1,"kind":"ProviderCheck","plan_only":true,"full":true,"report_only":true,"keep_primary":true,
        "rounds":arguments.rounds,"parallel":arguments.parallel(),"retry_parallel":arguments.retry_parallel(),"timeout_ms":arguments.timeout_ms,
        "steps":["FullReportOnlyTest","ProviderInfo","CombinedRedactedReport"],
        "target_count":tested["targets"].as_array().map_or(0,Vec::len),"strategy_count":strategies.len(),"strategies":strategies,
        "text":format!("План проверки провайдера: полный прогон {} стратегий, только отчёт. Измерения не запускались.",strategies.len())}),
    )
}

struct ShareText {
    private: Vec<String>,
    unsafe_text: Regex,
}
impl ShareText {
    fn new(root: &Path) -> Result<Self> {
        let mut private = vec![root.to_string_lossy().to_lowercase()];
        for key in ["USERPROFILE", "USERNAME", "USER"] {
            if let Ok(value) = std::env::var(key) {
                if !value.is_empty() {
                    private.push(value.to_lowercase());
                }
            }
        }
        Ok(Self {
            private,
            unsafe_text: Regex::new(
                r"(?i)(?:secret|password|token|authorization|tg:|://|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-f\d]{0,4}:){2,})",
            )?,
        })
    }

    fn clean(&self, text: &str, limit: usize) -> String {
        let bounded: String = text.chars().take(4096).collect();
        let folded = bounded.to_lowercase();
        if bounded.contains(['\\', '/'])
            || self.unsafe_text.is_match(&bounded)
            || self
                .private
                .iter()
                .any(|private| !private.is_empty() && folded.contains(private))
        {
            return "[скрыто]".into();
        }
        bounded
            .chars()
            .filter(|c| {
                c.is_alphanumeric()
                    || matches!(
                        c,
                        ' ' | '-' | '.' | ',' | '(' | ')' | '&' | '+' | '\'' | '#' | '_'
                    )
            })
            .take(limit)
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn provider_slug(name: &str) -> String {
    let mut slug = String::new();
    for c in name.chars() {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
        if slug.chars().count() == 40 {
            break;
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "провайдер".into()
    } else {
        slug.into()
    }
}

fn masked_address(value: &Value) -> String {
    let Some(ip) = value.as_str().and_then(|text| text.parse::<IpAddr>().ok()) else {
        return "неизвестно".into();
    };
    if !zapret_core::is_public_ip(&ip.to_string()) {
        return "[адрес скрыт]".into();
    }
    match ip {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("{}.{}.{}.x", b[0], b[1], b[2])
        }
        IpAddr::V6(ip) => {
            let b = ip.segments();
            format!("{:x}:{:x}:{:x}:...", b[0], b[1], b[2])
        }
    }
}

fn provider_fields(raw: &Value, privacy: &ShareText) -> Value {
    let rows: Vec<_> = raw["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .take(32)
        .map(|row| {
            let provider = &row["provider"];
            let mut safe = json!({"masked_ip":masked_address(&provider["ip"])});
            for key in ["isp", "as", "country", "city"] {
                safe[key] = json!(privacy.clean(provider[key].as_str().unwrap_or(""), 128));
            }
            let observed = row["state"] == "Observed" && provider.is_object();
            json!({"state":if observed{"Observed"}else{"Unknown"},"provider":safe})
        })
        .collect();
    json!({"kind":"Provider","rows":rows,"rows_complete":raw["rows"].as_array().is_some_and(|rows|rows.len()<=32),
        "source":"ExternalServiceObservation","route_confirmed":false})
}

fn strategy_id(value: &Value) -> String {
    value
        .as_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 32 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .unwrap_or("?")
        .to_owned()
}

fn strategy_name(id: &str, names: &BTreeMap<String, String>) -> String {
    if id == "0" {
        "Без обхода".into()
    } else {
        names
            .get(id)
            .filter(|name| !name.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("Стратегия {id}"))
    }
}

fn number(value: &Value) -> Value {
    value
        .as_f64()
        .filter(|n| n.is_finite() && n.abs() <= 1_000_000_000_000.)
        .map_or(Value::Null, |n| json!(n))
}

fn count(value: &Value) -> Value {
    value
        .as_u64()
        .filter(|n| *n <= 1_000_000_000)
        .map_or(Value::Null, |n| json!(n))
}

fn ranking(row: &Value, privacy: &ShareText, names: &BTreeMap<String, String>) -> Result<Value> {
    let id = strategy_id(&row["id"]);
    let mut safe = json!({"id":id,"name":strategy_name(&id,names)});
    for key in ["score", "ok"] {
        safe[key] = number(&row[key]);
    }
    for key in ["total", "harm", "freeze"] {
        safe[key] = count(&row[key]);
    }
    let groups = row["groups"].as_object();
    ensure!(
        groups.is_none_or(|groups| groups.len() <= 256),
        "Слишком много групп в результате"
    );
    safe["groups"] = json!(groups.into_iter().flatten().map(|(group,ok)|json!({
        "name":privacy.clean(group,64),"ok":number(ok),"total":count(&row["group_totals"][group])
    })).collect::<Vec<_>>());
    Ok(safe)
}

fn probe_fields(
    row: &Value,
    privacy: &ShareText,
    names: &BTreeMap<String, String>,
    baseline: bool,
) -> Value {
    let id = if baseline || row.get("StrategyId").is_none() {
        "0".to_owned()
    } else {
        strategy_id(&row["StrategyId"])
    };
    let stage = if baseline {
        "baseline"
    } else {
        row["Stage"]
            .as_str()
            .filter(|stage| ["main", "control-before", "control-after"].contains(stage))
            .unwrap_or("Unknown")
    };
    let state = row["State"]
        .as_str()
        .filter(|state| ["OK", "FAIL", "FREEZE", "NA"].contains(state))
        .unwrap_or("Unknown");
    let code = row["Code"]
        .as_str()
        .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or("???");
    // A digest lets identically named targets stay distinguishable without
    // publishing URLs, credentials, query strings or literal peer addresses.
    let target_id = sha256(format!("{}|{}|{}", row["Group"], row["Name"], row["Url"]).as_bytes());
    let termination = row["Termination"]
        .as_str()
        .filter(|reason| {
            [
                "Complete",
                "BodyLimit",
                "DnsFailure",
                "TcpFailure",
                "TlsFailure",
                "HttpFailure",
                "TransferError",
                "Timeout",
                "Deadline",
                "Cancelled",
            ]
            .contains(reason)
        })
        .unwrap_or("Unknown");
    let mut safe = json!({"strategy_id":id,"strategy":strategy_name(&id,names),"stage":stage,"termination":termination,
        "target_id":target_id[..16],"group":privacy.clean(row["Group"].as_str().unwrap_or(""),64),
        "name":privacy.clean(row["Name"].as_str().unwrap_or(""),128),"state":state,"code":code,
        "round":count(&row["Round"]),"attempt":count(&row["Attempt"]),
        "flaky":row["Flaky"].as_bool(),"target_reached":row["TargetReached"].as_bool(),"body_complete":row["BodyComplete"].as_bool()});
    for (public, source) in [
        ("dns_ms", "DnsMs"),
        ("tcp_ms", "ConnMs"),
        ("tls_ms", "TlsMs"),
        ("first_byte_ms", "FirstByteMs"),
        ("total_ms", "TotalMs"),
        ("upload_bytes", "Up"),
        ("download_bytes", "Down"),
        ("exit", "Exit"),
    ] {
        safe[public] = number(&row[source]);
    }
    for (public, source) in [
        ("body_bytes", "BodyBytes"),
        ("body_limit", "BodyLimit"),
        ("tries", "Tries"),
    ] {
        safe[public] = count(&row[source]);
    }
    safe
}

fn run_id(tested: &Value) -> Result<&str> {
    tested["run_id"]
        .as_str()
        .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("Некорректная идентичность прогона")
}

fn project_journal(
    reader: impl BufRead,
    expected: &str,
    privacy: &ShareText,
    names: &BTreeMap<String, String>,
) -> Result<Vec<Value>> {
    let mut reader = reader.take(MAX_JOURNAL_BYTES + 1);
    let mut used = 0;
    let mut rows = Vec::new();
    loop {
        let mut line = Vec::new();
        let bytes = reader
            .by_ref()
            .take(MAX_JOURNAL_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        used += bytes as u64;
        ensure!(
            bytes as u64 <= MAX_JOURNAL_LINE
                && used <= MAX_JOURNAL_BYTES
                && rows.len() < MAX_OBSERVATIONS,
            "Журнал превышает бюджет безопасного отчёта"
        );
        let row: Value = serde_json::from_slice(&line).context("Повреждена строка журнала")?;
        ensure!(
            row["RunId"] == expected,
            "Журнал относится к другому прогону"
        );
        rows.push(probe_fields(&row, privacy, names, false));
    }
    ensure!(!rows.is_empty(), "Журнал измерений пуст");
    Ok(rows)
}

fn read_journal(
    root: &Path,
    tested: &Value,
    privacy: &ShareText,
    names: &BTreeMap<String, String>,
) -> Result<Vec<Value>> {
    let id = run_id(tested)?;
    // Never follow the arbitrary journal path stored in a result. Only the
    // validated immutable run ID may select a plain file inside runtime.
    let path = runtime_file(root, &format!("test-native-{id}.jsonl"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let file: File = options.open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_JOURNAL_BYTES,
        "Журнал превышает бюджет отчёта"
    );
    project_journal(BufReader::new(file), id, privacy, names)
}

fn combined(
    arguments: &TestArgs,
    tested: &Value,
    provider: Value,
    observations: Vec<Value>,
    complete: bool,
    privacy: &ShareText,
    names: &BTreeMap<String, String>,
) -> Result<Value> {
    let id = run_id(tested)?;
    let rows = tested["rows"]
        .as_array()
        .context("В результате нет рейтинга стратегий")?;
    let base = tested["base"]
        .as_array()
        .context("В результате нет исходных проб")?;
    ensure!(
        !rows.is_empty() && rows.len() <= MAX_STRATEGIES && base.len() <= 256,
        "Некорректный размер результата проверки"
    );
    let primary = strategy_id(&tested["primary"]);
    let rows = rows
        .iter()
        .map(|row| {
            let mut projected = ranking(row, privacy, names)?;
            if let Some(eligible) = tested["strategy_quality"][strategy_id(&row["id"])].as_bool() {
                projected["quality_eligible"] = json!(eligible);
            }
            Ok(projected)
        })
        .collect::<Result<Vec<_>>>()?;
    let excluded = rows
        .iter()
        .filter(|row| row["quality_eligible"] == false)
        .count();
    Ok(
        json!({"schema":1,"kind":"ProviderCheck","version":VERSION,"run_id":id,
        "created":chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "full":true,"report_only":true,"keep_primary":true,"provider":provider,
        "test":{"rounds":arguments.rounds,"parallel":arguments.parallel(),"retry_parallel":arguments.retry_parallel(),"timeout_ms":arguments.timeout_ms,
            "quality_eligible":tested["quality_eligible"].as_bool(),"quality_excluded":excluded,"primary":primary,"primary_name":strategy_name(&primary,names),
            "best":ranking(&tested["best"],privacy,names)?,"rows":rows,
            "base":base.iter().map(|row|probe_fields(row,privacy,names,true)).collect::<Vec<_>>(),
            "observations_complete":complete,"observation_reason":if complete{"Complete"}else{"JournalUnavailableOrInvalid"},
            "observations":observations}}),
    )
}

fn display(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => "?".into(),
    }
}

fn render(value: &Value) -> String {
    let test = &value["test"];
    let mut lines = vec![
        format!("zapret-rust v{} — проверка провайдера", VERSION),
        format!("Дата: {}", display(&value["created"])),
        "Режим: полный прогон, только отчёт.".into(),
    ];
    let mut observed = false;
    for row in value["provider"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["state"] == "Observed")
    {
        let provider = &row["provider"];
        observed = true;
        lines.push(format!(
            "Провайдер: {} [{}]",
            display(&provider["isp"]),
            display(&provider["as"])
        ));
        lines.push(format!(
            "Где: {}, {}. IP: {}",
            display(&provider["city"]),
            display(&provider["country"]),
            display(&provider["masked_ip"])
        ));
    }
    if !observed {
        lines.push(
            "Провайдер: не удалось определить; полный результат проверки сохранён ниже.".into(),
        );
    }
    lines.push("Провайдер определён внешним сервисом; VPN, прокси и маршруты ОС могут влиять на наблюдение.".into());
    lines.push(format!(
        "Проверка: кругов {}, потоков {}, ожидание {} мс",
        test["rounds"], test["parallel"], test["timeout_ms"]
    ));
    lines.push(format!(
        "Контрольные пробы: {}",
        if test["quality_eligible"] == true && test["quality_excluded"].as_u64().unwrap_or(0) > 0 {
            "подтверждены не для всех стратегий; нестабильные измерения исключены"
        } else if test["quality_eligible"] == true {
            "стабильны"
        } else {
            "качество не подтверждено"
        }
    ));
    lines.push(format!(
        "Основная стратегия: {}",
        display(&test["primary_name"])
    ));
    lines.push(format!(
        "Лучший результат измерения: {} · балл {}",
        display(&test["best"]["name"]),
        display(&test["best"]["score"])
    ));
    lines.push("\r\nРейтинг всех стратегий\r\nСтратегия | Балл | Доступно | Ухудшений обычных сайтов | Зависаний | Группы".into());
    for row in test["rows"].as_array().into_iter().flatten() {
        let groups = row["groups"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|group| {
                format!(
                    "{}={}/{}",
                    display(&group["name"]),
                    display(&group["ok"]),
                    display(&group["total"])
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "{} | {} | {}/{} | {} | {} | {}",
            if row["quality_eligible"] == false {
                format!("{} [контроль не подтверждён]", display(&row["name"]))
            } else {
                display(&row["name"])
            },
            display(&row["score"]),
            display(&row["ok"]),
            display(&row["total"]),
            display(&row["harm"]),
            display(&row["freeze"]),
            groups
        ));
    }
    lines.push("\r\nБез обхода\r\nЦель | Состояние | HTTP | DNS мс | TCP мс | TLS мс | Всего мс | Байты | Причина завершения".into());
    for row in test["base"].as_array().into_iter().flatten() {
        lines.push(probe_line(row, false));
    }
    lines.push("\r\nВсе пробы, включая повторы и контрольные запросы\r\nКруг | Этап | Стратегия | Попытка | Цель | Состояние | HTTP | DNS мс | TCP мс | TLS мс | Всего мс | Байты | Причина завершения".into());
    if test["observations_complete"] != true {
        lines.push("Подробные пробы не включены: журнал недоступен, не подтверждён или превышает лимит отчёта. Рейтинг и исходные пробы приведены выше.".into());
    }
    for row in test["observations"].as_array().into_iter().flatten() {
        lines.push(probe_line(row, true));
    }
    lines.push("\r\nИзмерена доступность целей HTTPS. Игровая задержка и причина блокировки этими пробами не устанавливаются.".into());
    lines.join("\r\n") + "\r\n"
}

fn probe_line(row: &Value, detailed: bool) -> String {
    let target = format!(
        "{}/{} [{}]",
        display(&row["group"]),
        display(&row["name"]),
        display(&row["target_id"])
    );
    let result = format!(
        "{} | {} | {} | {} | {} | {} | {} | {}/{} | {}",
        target,
        display(&row["state"]),
        display(&row["code"]),
        display(&row["dns_ms"]),
        display(&row["tcp_ms"]),
        display(&row["tls_ms"]),
        display(&row["total_ms"]),
        display(&row["body_bytes"]),
        display(&row["body_limit"]),
        display(&row["termination"])
    );
    if detailed {
        format!(
            "{} | {} | {} | {} | {}",
            display(&row["round"]),
            display(&row["stage"]),
            display(&row["strategy"]),
            display(&row["attempt"]),
            result
        )
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs, io::Cursor};

    const RUN: &str = "0123456789abcdef0123456789abcdef";

    fn arguments(extra: Option<&str>) -> NetworkArgs {
        NetworkArgs {
            urls: vec![],
            timeout_ms: 5000,
            args: extra.map(str::to_owned),
        }
    }

    fn rank(id: &str) -> Value {
        json!({"id":id,"score":2.,"ok":2.,"total":3,"harm":0,"freeze":1,"groups":{"DPI":2.},"group_totals":{"DPI":3}})
    }

    fn probe() -> Value {
        json!({"RunId":RUN,"Stage":"main","Round":1,"Attempt":1,"StrategyId":"11","Group":"DPI","Name":"Fixture",
            "Url":"https://name:password@10.1.2.3/private?token=TOP_SECRET","State":"OK","Code":"200","DnsMs":1.,"ConnMs":2.,
            "TlsMs":3.,"TotalMs":4.,"BodyBytes":65536,"BodyLimit":65536,"TargetReached":true,"BodyComplete":false,"Tries":1,
            "CapturedNetworkKey":"wifi-PRIVATE","Raw":{"remote_address":"192.168.7.123","error":"C:\\Users\\PRIVATE_PERSON\\AppData token=TOP_SECRET"}})
    }

    fn tested() -> Value {
        json!({"run_id":RUN,"best":rank("11"),"rows":[rank("11"),rank("12")],"base":[probe()],"primary":"12",
            "strategy_names":{"11":"ALT11 из снимка","12":"ALT12"},
            "quality_eligible":true,"journal":"C:\\Users\\PRIVATE_PERSON\\ignored.jsonl","context":{"network_key":"private-net"}})
    }

    fn provider() -> Value {
        json!({"rows":[{"state":"Observed","query_ip":"92.1.2.77","provider":{"ip":"92.1.2.77","masked_ip":"malicious 10.1.2.3",
            "isp":"Провайдер Пример","as":"AS123 Example","city":"Город","country":"Россия","lat":55.1,"lon":37.1},
            "observations":[{"url":"https://service.example/query?token=TOP_SECRET","error":"PRIVATE_PERSON"}]}],
            "network_context":{"username":"PRIVATE_PERSON","addresses":["192.168.7.123"]}})
    }

    fn package() -> (tempfile::TempDir, App) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("strategies")).unwrap();
        for (id, name) in [("11", "ALT11"), ("12", "ALT12")] {
            fs::write(
                root.path().join(format!("strategies/alt{id}.txt")),
                format!("# name: {name}\n"),
            )
            .unwrap();
        }
        let app = App {
            root: root.path().to_owned(),
            yes: true,
            json: true,
        };
        (root, app)
    }

    #[test]
    fn full_workflow_restores_before_lookup_and_exports_every_safe_result() {
        let (_root, app) = package();
        fs::create_dir(app.root.join("runtime")).unwrap();
        let journal = [
            probe(),
            {
                let mut row = probe();
                row["StrategyId"] = json!("12");
                row["State"] = json!("FAIL");
                row
            },
            {
                let mut row = probe();
                row["Stage"] = json!("control-after");
                row["Attempt"] = json!(2);
                row
            },
        ];
        fs::write(
            app.root.join(format!("runtime/test-native-{RUN}.jsonl")),
            journal
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let restored = Cell::new(false);
        let result = run_with(
            &app,
            &arguments(Some(r#"{"parallel":4,"rounds":2}"#)),
            |args| {
                assert!(args.full && args.report_only && args.keep_primary && !args.plan_only);
                assert_eq!(
                    (args.timeout_ms, args.parallel(), args.rounds),
                    (5000, 4, 2)
                );
                restored.set(true);
                Ok(tested())
            },
            |timeout| {
                assert!(restored.get());
                assert_eq!(timeout, 5000);
                Ok(provider())
            },
        )
        .unwrap();
        assert_eq!(result["test"]["rows"].as_array().unwrap().len(), 2);
        assert_eq!(result["test"]["observations"].as_array().unwrap().len(), 3);
        assert_eq!(
            result["provider"]["rows"][0]["provider"]["masked_ip"],
            "92.1.2.x"
        );
        assert_eq!(result["test"]["primary_name"], "ALT12");
        assert_eq!(result["test"]["rows"][0]["name"], "ALT11 из снимка");
        assert_eq!(result["report_saved"], true);
        let report = fs::read_to_string(result["path"].as_str().unwrap()).unwrap();
        assert!(
            result["report_file"]
                .as_str()
                .unwrap()
                .starts_with("zapret-rust-proverka-Провайдер-Пример-")
        );
        assert!(
            report.contains("ALT11")
                && report.contains("ALT12")
                && report.contains("control-after")
                && report.contains("FAIL")
        );
        for private in [
            "92.1.2.77",
            "10.1.2.3",
            "192.168.7.123",
            "PRIVATE_PERSON",
            "TOP_SECRET",
            "https://",
            "private-net",
            "wifi-PRIVATE",
            "ignored.jsonl",
        ] {
            assert!(!report.contains(private), "leaked {private}");
            assert!(
                !result["test"].to_string().contains(private),
                "structured leak {private}"
            );
        }
        assert_eq!(sha256(report.as_bytes()), result["report_sha256"]);
    }

    #[test]
    fn shareable_report_retains_exclusion_of_an_unstable_strategy() {
        let (_root, app) = package();
        let mut tested = tested();
        tested["strategy_quality"] = json!({"11":true,"12":false});
        let result = run_with(&app, &arguments(None), |_| Ok(tested), |_| Ok(provider())).unwrap();
        assert_eq!(result["test"]["rows"][1]["quality_eligible"], false);
        assert_eq!(result["test"]["quality_excluded"], 1);
        let text = result["report_text"].as_str().unwrap();
        assert!(text.contains("контроль не подтверждён"), "{text}");
        assert!(!text.contains("Контрольные пробы: стабильны"));
    }

    #[test]
    fn plan_only_skips_lookup_and_file_publication() {
        let (_root, app) = package();
        let result=run_with(&app,&arguments(Some(r#"{"plan_only":true}"#)),|args| {
            assert!(args.full&&args.report_only&&args.keep_primary&&args.plan_only);
            Ok(json!({"strategies":[{"id":"11","name":"ALT11","file":"private path"}],"targets":[{"url":"private URL"}],"settings":{"token":"secret"}}))
        },|_|panic!("plan must not contact provider")).unwrap();
        assert_eq!(result["plan_only"], true);
        assert_eq!(result["parallel"], 32);
        assert_eq!(result["retry_parallel"], 8);
        assert_eq!(result["strategy_count"], 1);
        assert_eq!(result["target_count"], 1);
        assert!(!app.root.join("runtime").exists());
        assert!(!result.to_string().contains("private"));
    }

    #[test]
    fn save_failure_and_unknown_provider_retain_the_completed_report() {
        let (_root, app) = package();
        fs::write(app.root.join("runtime"), b"blocked destination").unwrap();
        let result = run_with(
            &app,
            &arguments(None),
            |_| Ok(tested()),
            |_| anyhow::bail!("secret error from provider"),
        )
        .unwrap();
        assert_eq!(result["report_saved"], false);
        assert_eq!(result["save_error"], "ReportWriteFailed");
        assert_eq!(result["test"]["observations_complete"], false);
        assert_eq!(result["test"]["rows"].as_array().unwrap().len(), 2);
        assert!(result["text"].as_str().unwrap().contains("ALT11"));
        assert!(!result.to_string().contains("secret error"));
    }

    #[test]
    fn failed_strategy_test_never_queries_provider_or_exports_an_old_result() {
        let (_root, app) = package();
        let result = run_with(
            &app,
            &arguments(None),
            |_| anyhow::bail!("test interrupted"),
            |_| panic!("test failed"),
        );
        assert!(result.is_err());
        assert!(!app.root.join("runtime").exists());
    }

    #[test]
    fn invalid_arguments_are_rejected_before_any_test() {
        let (_root, app) = package();
        for args in [
            r#"{"parallel":0}"#,
            r#"{"rounds":11}"#,
            r#"{"parallel":"4"}"#,
            r#"{"plan_only":"true"}"#,
            r#"{"report_only":false}"#,
            r#"{"ips":["8.8.8.8"]}"#,
            r#"[]"#,
        ] {
            assert!(
                run_with(
                    &app,
                    &arguments(Some(args)),
                    |_| panic!("invalid arguments"),
                    |_| panic!("invalid arguments")
                )
                .is_err()
            );
        }
        let mut args = arguments(None);
        args.urls.push("https://example.com".into());
        assert!(test_arguments(&args).is_err());
        for timeout in [0, 60_001, u64::MAX] {
            let mut args = arguments(None);
            args.timeout_ms = timeout;
            assert!(test_arguments(&args).is_err());
        }
    }

    #[test]
    fn export_labels_and_provider_addresses_hide_private_material_and_are_bounded() {
        let (_root, app) = package();
        let mut privacy = ShareText::new(&app.root).unwrap();
        privacy.private.push("private_person".into());
        for text in [
            "PRIVATE_PERSON",
            r"C:\Users\someone\file",
            "tg://proxy?secret=TOP_SECRET",
            "ISP secret=TOP_SECRET",
            "ISP 10.2.3.4",
            "ISP fd00::1234",
            "ISP https://private.example/path",
            "/home/another_user",
        ] {
            assert_eq!(privacy.clean(text, 128), "[скрыто]");
        }
        assert_eq!(privacy.clean(&"я".repeat(1000), 128).chars().count(), 128);
        assert!(
            !privacy
                .clean("Организация\n\u{202e}Тест", 128)
                .contains(['\n', '\u{202e}'])
        );
        for address in [
            "192.168.7.123",
            "10.2.3.4",
            "172.20.1.2",
            "127.0.0.1",
            "fd00::1234",
            "fe80::1234",
        ] {
            assert_eq!(masked_address(&json!(address)), "[адрес скрыт]");
        }
        assert_eq!(
            masked_address(&json!("2001:4860:1:2:3:4:5:6")),
            "2001:4860:1:..."
        );
        assert_eq!(provider_slug(" .. "), "провайдер");
        let slug = provider_slug(&format!("  Москва / {}", "я".repeat(100)));
        assert_eq!(slug.chars().count(), 40);
        assert!(!slug.contains(['.', '/', '\\', ' ']));
    }

    #[test]
    fn journal_identity_and_size_limits_are_checked_before_projection() {
        let (_root, app) = package();
        let privacy = ShareText::new(&app.root).unwrap();
        let names = BTreeMap::new();
        let mut other = probe();
        other["RunId"] = json!("foreign");
        assert!(project_journal(Cursor::new(format!("{other}\n")), RUN, &privacy, &names).is_err());
        assert!(
            project_journal(
                Cursor::new(vec![b'x'; MAX_JOURNAL_LINE as usize + 1]),
                RUN,
                &privacy,
                &names
            )
            .is_err()
        );
        assert!(project_journal(Cursor::new(b""), RUN, &privacy, &names).is_err());
        assert!(project_journal(Cursor::new(b"{broken}\n"), RUN, &privacy, &names).is_err());
        let mut invalid = tested();
        invalid["run_id"] = json!("../external");
        assert!(read_journal(&app.root, &invalid, &privacy, &names).is_err());
    }
}
