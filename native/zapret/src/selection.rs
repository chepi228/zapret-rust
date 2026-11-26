use crate::{
    App, VERSION, cli::TestArgs, interrupt, maintenance, runtime_file, selection_latency::Panel,
    snapshot::Snapshot,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{Local, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use zapret_core::{
    ComposeOptions, Coverage, ProbeState, RankRow, Settings, Strategy, TestRank, atomic_write,
    compose, list_strategies, prepare_runtime, read_settings, save_settings, sha256,
    test_result_context_with_identity, transfer_state,
};
use zapret_net::{Job, ProbeMode};
use zapret_platform::{ControlGuard, OwnedChild, RunOptions};

mod endpoints;
pub(crate) mod families;
mod gains;
mod network_monitor;
pub(crate) use network_monitor::last_interruption;
mod quick;
mod retries;
mod startup;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExpectedResponse {
    mode: ProbeMode,
    status: u16,
    min_bytes: usize,
    max_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

impl ExpectedResponse {
    fn parse(fields: &[&str]) -> Result<Option<Self>> {
        if fields.is_empty() {
            return Ok(None);
        }
        let [method, status, size, digest @ ..] = fields else {
            bail!("Ожидаются метод, HTTP-код и размер ответа")
        };
        let mode = match *method {
            "GET" => ProbeMode::FullGet,
            "ROBLOX_ICON" => ProbeMode::RobloxIcon,
            "H3" => ProbeMode::Http3Head,
            _ => bail!("Допустимы GET, ROBLOX_ICON и H3"),
        };
        let status = status.parse()?;
        let (min_bytes, max_bytes) = size.split_once("..").unwrap_or((size, size));
        let min_bytes = min_bytes.parse()?;
        let max_bytes = max_bytes.parse()?;
        let sha256 = match digest {
            [] => None,
            [hash]
                if mode == ProbeMode::FullGet
                    && hash.len() == 64
                    && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Some(hash.to_ascii_lowercase())
            }
            _ => bail!("Ожидается SHA-256 файла из 64 шестнадцатеричных цифр для GET"),
        };
        ensure!(
            (200..300).contains(&status)
                && min_bytes <= max_bytes
                && max_bytes < zapret_net::MAX_BODY_LIMIT
                && (mode != ProbeMode::Http3Head || max_bytes == 0),
            "Неверный HTTP-код или диапазон размеров ответа"
        );
        Ok(Some(Self {
            mode,
            status,
            min_bytes,
            max_bytes,
            sha256,
        }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    #[serde(alias = "Group")]
    pub group: String,
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "Url")]
    pub url: String,
    #[serde(default, alias = "Post")]
    pub post: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected: Option<ExpectedResponse>,
    #[serde(skip)]
    peer: Option<std::net::SocketAddr>,
}

impl Target {
    pub(crate) fn key(&self) -> String {
        format!("{}|{}|{}", self.group, self.name, self.url)
    }
    pub(crate) fn id(&self) -> String {
        sha256(self.key().as_bytes())
    }
    fn body_limit(&self) -> usize {
        // One extra byte distinguishes EOF at the expected size from a truncated prefix.
        self.expected
            .as_ref()
            .map_or(65536, |check| check.max_bytes + 1)
    }
    pub(crate) fn probe_mode(&self) -> ProbeMode {
        self.expected
            .as_ref()
            .map_or(ProbeMode::Range, |check| check.mode)
    }
    pub(crate) fn job(&self, timeout_ms: u64, control: bool) -> Job {
        let mode = self.probe_mode();
        let method = match mode {
            ProbeMode::Http3Head => "HEAD",
            ProbeMode::FullGet | ProbeMode::RobloxIcon => "GET",
            ProbeMode::Range if control => "HEAD",
            ProbeMode::Range if self.post => "POST",
            ProbeMode::Range => "GET",
        };
        Job {
            version: 1,
            id: self.id(),
            url: self.url.clone(),
            timeout_ms,
            body_limit: self.body_limit(),
            post_bytes: if method == "POST" { 65536 } else { 0 },
            method: Some(method.into()),
            mode,
            connect_ip: self.peer.map(|peer| peer.ip()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Row {
    pub group: String,
    pub name: String,
    pub url: String,
    pub state: String,
    pub code: String,
    pub exit: i32,
    pub up: f64,
    pub down: f64,
    pub conn_ms: f64,
    pub tls_ms: f64,
    pub dns_ms: f64,
    pub first_byte_ms: f64,
    pub total_ms: f64,
    pub started_utc: String,
    pub observed_utc: String,
    pub started_ms: f64,
    pub observed_ms: f64,
    pub body_bytes: usize,
    pub body_limit: usize,
    pub target_reached: bool,
    pub body_complete: bool,
    pub termination: String,
    pub tries: usize,
    pub flaky: bool,
    #[serde(skip)]
    failed_retry: Option<Value>,
    pub raw: Value,
}

impl Row {
    fn key(&self) -> String {
        format!("{}|{}|{}", self.group, self.name, self.url)
    }
    fn connection_ms(&self) -> f64 {
        if self.url.starts_with("http://") {
            self.conn_ms
        } else {
            self.tls_ms
        }
    }
    fn healthy_connection(&self, before: Option<f64>) -> bool {
        let ms = self.connection_ms();
        self.state == "OK"
            && ms.is_finite()
            && ms > 0.
            && before.is_none_or(|limit| ms <= limit + 500.)
    }
    fn healthy_control(&self, before: Option<f64>) -> bool {
        self.code.starts_with('2') && self.healthy_connection(before)
    }

    fn preserves_clean(&self, before: &Row) -> bool {
        self.healthy_connection(Some(before.connection_ms()))
            && (!before.code.starts_with('2') || self.code.starts_with('2'))
    }

    fn meets_baseline(&self, before: Option<f64>) -> bool {
        self.healthy_connection(before) && (before.is_none() || self.code.starts_with('2'))
    }

    fn dns_failure(&self) -> bool {
        self.state == "NA" && self.termination == "DnsFailure"
    }
}

fn read_targets(root: &Path, args: &TestArgs) -> Result<Vec<Target>> {
    let mut targets = read_targets_with_suite(root, &root.join("tools/dpi-suite.json"))?;
    if args.compare_a.is_some() || args.compare_b.is_some() {
        // The saved A/B protocol compares the TCP/TLS handshake under matched conditions.
        targets.retain(|t| {
            t.url.starts_with("https://")
                && !matches!(t.probe_mode(), ProbeMode::Http3Head | ProbeMode::RobloxIcon)
        });
        ensure!(
            !targets.is_empty(),
            "Для сравнения финалистов нужны HTTPS-адреса с TCP"
        );
    }
    Ok(targets)
}

pub(crate) fn read_targets_with_suite(root: &Path, suite: &Path) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    if suite.is_file() {
        let values: Vec<Value> =
            serde_json::from_slice(&zapret_core::read_bounded(suite, 1024 * 1024)?)?;
        for value in values {
            if let Some(host) = value["host"].as_str() {
                targets.push(Target {
                    group: "DPI".into(),
                    name: format!(
                        "{} {}",
                        value["id"].as_str().unwrap_or(""),
                        value["provider"].as_str().unwrap_or("")
                    )
                    .trim()
                    .to_owned(),
                    url: format!("https://{host}/"),
                    post: true,
                    expected: None,
                    peer: None,
                });
            }
        }
    }
    for line in zapret_core::read_text(&root.join("tools/targets.txt"), 1024 * 1024)?.lines() {
        let Some((identity, url)) = line.trim().split_once('=') else {
            continue;
        };
        let mut fields = identity.split_ascii_whitespace();
        let Some((group, name)) = fields.next().and_then(|key| key.split_once('.')) else {
            continue;
        };
        if group.is_empty() || !group.bytes().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let expected = ExpectedResponse::parse(&fields.collect::<Vec<_>>())
            .with_context(|| format!("tools/targets.txt, {group}.{name}"))?;
        ensure!(
            expected.as_ref().is_none_or(
                |e| e.mode != ProbeMode::Http3Head || url.trim().starts_with("https://")
            ),
            "HTTP/3 требует HTTPS для {group}.{name}"
        );
        targets.push(Target {
            group: group.into(),
            name: name.into(),
            url: url.trim().into(),
            post: false,
            expected,
            peer: None,
        });
    }
    let mut unique = BTreeSet::new();
    ensure!(
        !targets.is_empty()
            && targets.len() <= 256
            && targets.iter().all(|target| unique.insert(target.key())),
        "Набор адресов пуст, слишком велик или содержит дубликаты"
    );
    Ok(targets)
}

fn number(value: &Value, key: &str) -> f64 {
    value[key].as_f64().unwrap_or(0.)
}

fn convert(target: &Target, value: Value, started: chrono::DateTime<Utc>) -> Result<Row> {
    let observation: zapret_net::Observation = serde_json::from_value(value.clone())
        .context("Worker вернул неполную или некорректную запись")?;
    ensure!(
        observation.mode == target.probe_mode(),
        "Режим пробы не совпадает с заданием"
    );
    ensure!(
        value["version"] == 1 && value["id"] == target.id() && value["url"] == target.url,
        "Некорректная идентичность результата worker"
    );
    if let Some(peer) = target.peer {
        endpoints::verify_peer(&observation, peer)?;
    }
    let termination = value["termination"]
        .as_str()
        .context("Нет причины завершения пробы")?
        .to_owned();
    ensure!(
        !matches!(termination.as_str(), "Deadline" | "Cancelled"),
        "Пакет проб прерван, частичный результат не оценивается"
    );
    let bytes = value["body_bytes"]
        .as_u64()
        .context("Неизвестен объём тела")? as usize;
    let limit = value["body_limit"]
        .as_u64()
        .context("Неизвестен лимит тела")? as usize;
    ensure!(
        limit == target.body_limit() && bytes <= limit,
        "Неверный бюджет тела в результате"
    );
    let reached = value["target_reached"] == true;
    let complete = value["body_complete"] == true;
    ensure!(
        !reached || bytes == limit,
        "Достижение бюджета не подтверждено байтами"
    );
    ensure!(
        termination != "Complete" || complete,
        "Завершённый ответ не подтверждён"
    );
    ensure!(
        termination != "BodyLimit" || reached,
        "Остановка по бюджету не подтверждена"
    );
    ensure!(
        observation.received_body_bytes >= bytes
            && observation.request_body_bytes_provided <= observation.post_bytes,
        "Некорректный объём передачи worker"
    );
    ensure!(
        observation.total_ms.is_finite()
            && observation.total_ms >= 0.
            && [
                observation.dns_ms,
                observation.tcp_ms,
                observation.tls_ms,
                observation.headers_ms,
                observation.started_ms
            ]
            .into_iter()
            .flatten()
            .all(|number| number.is_finite() && number >= 0.),
        "Некорректные часы worker"
    );
    ensure!(
        observation
            .status_code
            .is_none_or(|code| (100..=999).contains(&code)),
        "Некорректный HTTP-код worker"
    );
    ensure!(
        observation.status_code.is_none()
            || !target.url.starts_with("https://")
            || (observation.certificate_validated && observation.tls_ms.is_some()),
        "HTTPS-ответ без проверки сертификата"
    );
    let code = value["status_code"]
        .as_u64()
        .map_or("000".into(), |code| format!("{code:03}"));
    let exit = match termination.as_str() {
        "Complete" => 0,
        "BodyLimit" => 23,
        "DnsFailure" => 6,
        "TcpFailure" => 7,
        "TlsFailure" => 35,
        "Timeout" => 28,
        _ => 56,
    };
    let up = number(&value, "request_body_bytes_provided");
    let down = value["received_body_bytes"]
        .as_f64()
        .unwrap_or(bytes as f64);
    let mut state = transfer_state(&code, Some(exit), up, down, target.post, reached);
    if let Some(check) = &target.expected {
        if state == ProbeState::Ok
            && (termination != "Complete"
                || !complete
                || reached
                || observation.status_code != Some(check.status)
                || !(check.min_bytes..=check.max_bytes).contains(&bytes)
                || check
                    .sha256
                    .as_ref()
                    .is_some_and(|hash| observation.body_sha256.as_ref() != Some(hash)))
        {
            state = ProbeState::Fail;
        }
    }
    let state = match state {
        ProbeState::Ok => "OK",
        ProbeState::Fail => "FAIL",
        ProbeState::Freeze => "FREEZE",
        ProbeState::Na => "NA",
    }
    .to_owned();
    let dns = number(&value, "dns_ms");
    let tcp = dns + number(&value, "tcp_ms");
    let tls = if value["tls_ms"].is_number() {
        tcp + number(&value, "tls_ms")
    } else {
        0.
    };
    let start_ms = number(&value, "started_ms");
    let total = number(&value, "total_ms");
    Ok(Row {
        group: target.group.clone(),
        name: target.name.clone(),
        url: target.url.clone(),
        state,
        code,
        exit,
        up,
        down,
        conn_ms: if observation.mode == ProbeMode::Http3Head {
            0.
        } else {
            tcp
        },
        tls_ms: tls,
        dns_ms: dns,
        first_byte_ms: if value["tls_ms"].is_number() {
            tls
        } else {
            tcp
        } + number(&value, "headers_ms")
            + observation.media_lookup_ms.unwrap_or_default(),
        total_ms: total,
        started_utc: (started + chrono::Duration::microseconds((start_ms * 1000.) as i64))
            .to_rfc3339(),
        observed_utc: Utc::now().to_rfc3339(),
        started_ms: start_ms,
        observed_ms: start_ms + total,
        body_bytes: bytes,
        body_limit: limit,
        target_reached: reached,
        body_complete: complete,
        termination,
        tries: 1,
        flaky: false,
        failed_retry: None,
        raw: value,
    })
}

struct RunContext<'a> {
    app: &'a App,
    snapshot: &'a Snapshot,
    network_key: String,
    network_monitor: &'a network_monitor::Monitor,
    failed_profiles: &'a RefCell<BTreeMap<String, String>>,
    sampled_batches: &'a Cell<usize>,
    expanded_batches: &'a Cell<usize>,
    native_hash: &'a str,
    journal: PathBuf,
    deadline: Option<Instant>,
    clock_origin: f64,
    approved_games: &'a BTreeSet<String>,
    details: bool,
}
impl RunContext<'_> {
    fn candidate<T>(&self, id: &str, primary: &str, result: Result<T>) -> Result<Option<T>> {
        optional_candidate(id, primary, result, |reason| {
            self.check_current(true)?;
            crate::selection_ui::progress(self.app, &format!("Пропускаю ALT{id}. {reason}"))?;
            self.failed_profiles
                .borrow_mut()
                .insert(id.to_owned(), reason);
            Ok(())
        })
    }

    fn assert_current(&self) -> Result<()> {
        self.check_current(false)
    }
    fn check_current(&self, fresh: bool) -> Result<()> {
        interrupt::check()?;
        ensure!(
            self.deadline
                .is_none_or(|deadline| Instant::now() < deadline),
            "Превышен общий лимит сравнения 30 минут"
        );
        ensure!(
            game_snapshot(self.app)?.is_subset(self.approved_games),
            "Во время измерения запущена новая игра"
        );
        crate::ensure_snapshot_current(self.snapshot)?;
        self.network_monitor.check(self.app, &self.journal, fresh)
    }
}

const NETWORK_PARTS: [(&str, &str); 5] = [
    ("interfaces", "сетевые интерфейсы"),
    ("routes", "маршруты"),
    ("profiles", "профиль сети Windows"),
    ("dns", "настройки DNS"),
    ("proxy", "настройки прокси"),
];

fn verify_measurement_network(key: &str, parts: &Value, current: &Value) -> Result<()> {
    if current["key"] == key {
        return Ok(());
    }
    let changed = NETWORK_PARTS
        .iter()
        .filter(|(name, _)| parts[*name] != current["key_parts"][*name])
        .map(|(_, label)| *label)
        .collect::<Vec<_>>();
    bail!(
        "Подключение изменилось во время измерения. Изменились параметры: {}.",
        changed.join(", ")
    )
}

fn measurement_network(app: &App) -> Result<Value> {
    read_measurement_network(
        || app.platform("network", json!({"identity_only":true})),
        || {
            interrupt::check()?;
            thread::sleep(Duration::from_millis(200));
            Ok(())
        },
    )
}

fn read_measurement_network(
    mut read: impl FnMut() -> Result<Value>,
    mut pause: impl FnMut() -> Result<()>,
) -> Result<Value> {
    let mut reading = read();
    for _ in 0..2 {
        if reading.as_ref().is_ok_and(|v| v["known"] == true) {
            break;
        }
        pause()?;
        reading = read();
    }
    let value =
        reading.context("Не удалось прочитать состояние сети Windows после трёх попыток")?;
    if value["known"] != true {
        let missing = NETWORK_PARTS
            .iter()
            .filter(|(name, _)| {
                value["unavailable"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(*name)))
            })
            .map(|(_, label)| *label)
            .collect::<Vec<_>>();
        bail!(
            "Windows не подтвердила состояние сети после трёх попыток ({})",
            if missing.is_empty() {
                "нет полного снимка".into()
            } else {
                missing.join(", ")
            }
        )
    }
    Ok(value)
}

fn probe_batch(
    context: &RunContext<'_>,
    targets: &[Target],
    parallel: usize,
    timeout_ms: u64,
    engine: &mut Option<OwnedChild>,
    metadata: &Value,
    attempt: usize,
) -> Result<Vec<Row>> {
    context.assert_current()?;
    let deadline = batch_budget(targets.len(), parallel, timeout_ms)?;
    let mut input = Vec::new();
    let control = metadata["Stage"]
        .as_str()
        .is_some_and(|stage| stage.starts_with("control-"));
    for target in targets {
        serde_json::to_writer(&mut input, &target.job(timeout_ms, control))?;
        input.push(b'\n');
    }
    let executable = std::env::current_exe()?;
    let started = Utc::now();
    let batch_started = zapret_platform::monotonic_ms()?;
    let mut worker = OwnedChild::spawn(
        &executable,
        &[
            "probe".into(),
            "--parallel".into(),
            parallel.to_string().into(),
            "--deadline-ms".into(),
            deadline.to_string().into(),
        ],
        &RunOptions {
            cwd: Some(context.snapshot.root().into()),
            timeout: Duration::from_millis(deadline + 5000),
            stdin: Some(input),
            max_output_bytes: 16 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    let mut checked = Instant::now();
    let waiting_started = Instant::now();
    let mut progress_at = Instant::now();
    while worker.is_running()? {
        interrupt::check()?;
        engine_alive(engine)?;
        if checked.elapsed() >= Duration::from_secs(1) {
            context.assert_current()?;
            checked = Instant::now();
        }
        if progress_at.elapsed() >= Duration::from_secs(5) {
            crate::selection_ui::detail(
                context.app,
                context.details,
                &format!(
                    "  Ожидаю пакет ответов ({} адресов), прошло {} с…",
                    targets.len(),
                    waiting_started.elapsed().as_secs()
                ),
            )?;
            progress_at = Instant::now();
        }
        worker.wait_for_exit(Duration::from_millis(20))?;
    }
    let output = worker.finish()?;
    ensure!(
        !output.timed_out && !output.output_truncated && output.exit_code == 0,
        "Worker не завершил пакет\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut rows = parse_observations(targets, &output.stdout, started)?;
    align_observations(
        &mut rows,
        context.clock_origin,
        batch_started,
        zapret_platform::monotonic_ms()?,
    )?;
    let mut journal = Journal::open(&context.journal)?;
    for row in &rows {
        let mut record = metadata.clone();
        record["Attempt"] = json!(attempt);
        record["ObservedUtc"] = json!(Utc::now().to_rfc3339());
        let object = record
            .as_object_mut()
            .context("Метаданные журнала должны быть объектом")?;
        for (key, value) in serde_json::to_value(row)?
            .as_object()
            .context("Строка журнала")?
        {
            object.insert(key.clone(), value.clone());
        }
        journal.append(&record)?;
    }
    drop(journal);
    context.assert_current()?;
    engine_alive(engine)?;
    Ok(rows)
}

fn batch_budget(count: usize, parallel: usize, timeout_ms: u64) -> Result<u64> {
    ensure!(
        (1..=256).contains(&count)
            && (1..=64).contains(&parallel)
            && (1..=60000).contains(&timeout_ms),
        "Неверный бюджет проб"
    );
    let budget = count.div_ceil(parallel) as u64 * (timeout_ms + 1000) + 5000;
    ensure!(
        budget <= 1_800_000,
        "Один пакет проб превышает 30 минут. Увеличьте --parallel или уменьшите --timeout-ms"
    );
    Ok(budget)
}

fn align_observations(
    rows: &mut [Row],
    origin: f64,
    batch_started: f64,
    batch_finished: f64,
) -> Result<()> {
    for row in rows {
        let start = row.raw["started_monotonic_ms"]
            .as_f64()
            .context("Worker не подтвердил общие монотонные часы")?;
        let end = row.raw["finished_monotonic_ms"]
            .as_f64()
            .context("Worker не подтвердил общие монотонные часы")?;
        ensure!(
            start.is_finite()
                && end.is_finite()
                && start >= batch_started
                && end >= start
                && end <= batch_finished,
            "Монотонные часы пробы выходят за границы пакета"
        );
        row.started_ms = start - origin;
        row.observed_ms = end - origin;
    }
    Ok(())
}

fn engine_budget(count: usize, arguments: &TestArgs, warmup: bool) -> Result<u64> {
    let main = batch_budget(count, arguments.parallel(), arguments.timeout_ms)?;
    let retry = batch_budget(count, arguments.retry_parallel(), arguments.timeout_ms)?;
    let extra_batch = if count > retries::FAILURE_LIMIT {
        batch_budget(1, arguments.retry_parallel(), arguments.timeout_ms)?
    } else {
        0
    };
    Ok((main + retry + extra_batch + if warmup { main } else { 0 } + 30000).max(120000))
}

#[derive(Debug)]
struct TrialExit {
    phase: &'static str,
    code: u32,
}

impl std::fmt::Display for TrialExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Тестовый движок завершился {} (код {}).",
            self.phase, self.code
        )
    }
}
impl std::error::Error for TrialExit {}

fn optional_candidate<T>(
    id: &str,
    primary: &str,
    result: Result<T>,
    report: impl FnOnce(String) -> Result<()>,
) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if id != primary && error.is::<TrialExit>() => {
            report(format!("{error:#}"))?;
            Ok(None)
        }
        Err(error) => Err(error.context(format!("При проверке ALT{id}"))),
    }
}

fn engine_alive(engine: &mut Option<OwnedChild>) -> Result<()> {
    if let Some(child) = engine
        && !child.is_running()?
    {
        let output = engine.take().expect("observed child").finish()?;
        ensure!(!output.timed_out, "Истёк срок работы тестового движка");
        return Err(TrialExit {
            phase: "во время измерения",
            code: output.exit_code,
        }
        .into());
    }
    Ok(())
}

fn stop_trial(mut engine: Option<OwnedChild>) -> Result<()> {
    engine_alive(&mut engine)?;
    if let Some(mut child) = engine {
        child.terminate()?;
        let output = child.finish()?;
        ensure!(!output.timed_out, "Истёк срок работы тестового движка");
    }
    Ok(())
}

fn finish_trial<T>(engine: Option<OwnedChild>, measured: Result<T>) -> Result<T> {
    match (measured, stop_trial(engine)) {
        (result, Ok(())) => result,
        (Ok(_), Err(stop)) => Err(stop),
        (Err(error), Err(stop)) if stop.is::<TrialExit>() => Err(error.context(stop.to_string())),
        (Err(error), Err(stop)) => Err(stop.context(format!(
            "Замер прерван: {error:#}. Не удалось завершить тестовый процесс"
        ))),
    }
}

fn run_trial<T>(
    child: Result<OwnedChild>,
    measure: impl FnOnce(&mut Option<OwnedChild>) -> Result<T>,
) -> Result<T> {
    let mut engine = Some(child?);
    let result = measure(&mut engine);
    finish_trial(engine, result)
}

pub(crate) fn parse_observations(
    targets: &[Target],
    bytes: &[u8],
    started: chrono::DateTime<Utc>,
) -> Result<Vec<Row>> {
    let map: HashMap<_, _> = targets.iter().map(|target| (target.id(), target)).collect();
    ensure!(map.len() == targets.len(), "Повторная цель worker");
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let value: Value = serde_json::from_str(line)?;
        let id = value["id"].as_str().context("Нет id результата")?;
        ensure!(seen.insert(id.to_owned()), "Повторный результат worker");
        let target = map.get(id).context("Посторонний результат worker")?;
        rows.push(convert(target, value, started)?);
    }
    ensure!(
        rows.len() == targets.len(),
        "Worker вернул неполный пакет проб"
    );
    Ok(rows)
}

struct Journal {
    output: fs::File,
    size: u64,
    bytes: Vec<u8>,
}

impl Journal {
    fn open(path: &Path) -> Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Each run owns its journal. Other processes can tail it while this
            // batch writes, but cannot change the length used for its budget.
            options.share_mode(1);
        }
        let output = options.open(path)?;
        let size = output.metadata()?.len();
        Ok(Self {
            output,
            size,
            bytes: Vec::new(),
        })
    }

    fn append(&mut self, record: &Value) -> Result<()> {
        self.bytes.clear();
        serde_json::to_writer(&mut self.bytes, record)?;
        self.bytes.push(b'\n');
        let size = self.size.saturating_add(self.bytes.len() as u64);
        ensure!(size <= 64 * 1024 * 1024, "Журнал измерения превысил бюджет");
        self.output.write_all(&self.bytes)?;
        self.output.flush()?;
        self.size = size;
        Ok(())
    }
}

fn merge_retry(rows: &mut [Row], retry: &[Row]) {
    let usable =
        |row: &Row| row.state == "OK" && (row.group != "Clean" || row.code.starts_with('2'));
    for row in rows {
        let Some(next) = retry.iter().find(|next| next.key() == row.key()) else {
            continue;
        };
        row.tries = 2;
        let first_ok = usable(row);
        if !usable(next) {
            if !first_ok
                && (row.dns_failure() && !next.dns_failure()
                    || next.state == "FREEZE" && row.state != "FREEZE")
            {
                let mut replacement = next.clone();
                replacement.tries = 2;
                replacement.failed_retry = Some(row.raw.clone());
                *row = replacement;
                continue;
            }
            row.failed_retry = Some(next.raw.clone());
            if first_ok {
                row.flaky = true;
            }
            continue;
        }
        if !first_ok || next.connection_ms() < row.connection_ms() {
            // The remote peer, clocks and durations must come from the same request.
            let mut replacement = next.clone();
            replacement.tries = 2;
            replacement.flaky |= row.flaky || !first_ok;
            *row = replacement;
        }
    }
}

// Keep connectivity checks independent of the applications being compared.
fn select_controls(targets: &[Target], base: &[Row]) -> Vec<Target> {
    let measured: BTreeMap<_, _> = base
        .iter()
        .filter(|r| r.group == "Clean" && r.tries == 1 && !r.flaky && r.healthy_control(None))
        .map(|r| (r.key(), r))
        .collect();
    let mut candidates = targets
        .iter()
        .filter(|t| t.group == "Clean" && t.probe_mode() != ProbeMode::Http3Head)
        .filter_map(|t| Some((t, *measured.get(&t.key())?)))
        .collect::<Vec<_>>();
    candidates.sort_by_cached_key(|(t, r)| {
        let purpose = match t.url.as_str() {
            "http://www.msftconnecttest.com/connecttest.txt"
            | "https://detectportal.firefox.com/success.txt" => 0,
            _ if crate::selection_latency::steam_target(&t.name) => 2,
            _ => 1,
        };
        (purpose, (r.connection_ms() * 1000.) as u64)
    });
    let mut hosts = BTreeSet::new();
    candidates
        .into_iter()
        .filter(|(target, _)| control_host(target).is_some_and(|host| hosts.insert(host)))
        .take(4)
        .map(|(t, _)| t.clone())
        .collect()
}

fn control_host(target: &Target) -> Option<String> {
    hostname(&target.url)
}

fn hostname(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    Some(url.host_str()?.trim_end_matches('.').to_ascii_lowercase())
}

struct RoundBaseline {
    rows: Vec<Row>,
    eligible: bool,
    controls: Vec<Target>,
    repeated: bool,
}

fn round_baseline(
    targets: &[Target],
    report_only: bool,
    mut measure: impl FnMut(bool) -> Result<(Vec<Row>, bool)>,
) -> Result<RoundBaseline> {
    let configured = targets
        .iter()
        .filter(|t| t.group == "Clean" && t.probe_mode() != ProbeMode::Http3Head)
        .filter_map(control_host)
        .collect::<BTreeSet<_>>()
        .len();
    ensure!(
        report_only || configured >= 2,
        "Для выбора стратегии нужны два контрольных сервера с разными именами в tools/targets.txt"
    );
    let mut sample = |repeated| -> Result<RoundBaseline> {
        let (rows, eligible) = measure(repeated)?;
        Ok(RoundBaseline {
            controls: select_controls(targets, &rows),
            rows,
            eligible,
            repeated,
        })
    };
    let first = sample(false)?;
    if first.controls.len() >= 2 || configured < 2 {
        return Ok(first);
    }
    let second = sample(true)?;
    let dns = second.rows.iter().filter(|r| r.dns_failure()).count();
    ensure!(
        second.controls.len() >= 2 || report_only && second.rows.iter().any(|r| r.state == "OK"),
        "После двух исходных замеров пригодных контрольных серверов {} из {configured}. Ошибок DNS в последнем замере: {dns}. Подбор остановлен до переключения профилей.",
        second.controls.len()
    );
    Ok(second)
}

fn baseline(rows: &[Row]) -> BTreeMap<String, f64> {
    let mut result = BTreeMap::<String, f64>::new();
    for row in rows
        .iter()
        .filter(|row| row.group == "Clean" && row.healthy_control(None))
    {
        result
            .entry(row.name.clone())
            .and_modify(|value| *value = value.min(row.connection_ms()))
            .or_insert_with(|| row.connection_ms());
    }
    result
}

pub(crate) struct Availability {
    pub ok: usize,
    targets: Vec<String>,
}

impl Availability {
    pub fn total(&self) -> usize {
        self.targets.len()
    }

    fn counts(&self) -> Value {
        json!({"ok":self.ok, "total":self.total()})
    }

    fn change_from(&self, baseline: &Self) -> Option<i64> {
        (!self.targets.is_empty() && self.targets == baseline.targets)
            .then(|| self.ok as i64 - baseline.ok as i64)
    }
}

fn availability(rows: &[Row]) -> Availability {
    let mut targets = Vec::new();
    let mut ok = 0;
    for row in rows
        .iter()
        .filter(|row| row.group != "Clean" && row.state != "NA")
    {
        targets.push(row.key());
        ok += usize::from(row.state == "OK");
    }
    targets.sort_unstable();
    Availability { ok, targets }
}

fn summary(id: &str, rows: &[Row], clean: &BTreeMap<String, f64>) -> RankRow {
    let mut result = RankRow {
        id: id.into(),
        ..Default::default()
    };
    for row in rows.iter().filter(|row| row.state != "NA") {
        *result.group_totals.entry(row.group.clone()).or_default() += 1;
        let points = if row.state == "OK" {
            if row.flaky { 0.5 } else { 1. }
        } else {
            0.
        };
        *result.groups.entry(row.group.clone()).or_default() += points;
        if row.group != "Clean" {
            result.ok += points;
            result.total += 1;
            result.freeze += usize::from(row.state == "FREEZE");
        } else if id != "0"
            && clean
                .get(&row.name)
                .is_some_and(|before| !row.healthy_control(Some(*before)))
        {
            result.harm += 1;
        }
    }
    result.score = result.ok - result.harm as f64;
    result
}

fn shuffle<T>(values: &mut [T], seed: &mut u64) {
    for index in (1..values.len()).rev() {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        values.swap(index, (*seed as usize) % (index + 1));
    }
}

fn final_check<'a>(expected: impl IntoIterator<Item = &'a Row>, actual: &[Row]) -> Result<()> {
    let mut required = expected
        .into_iter()
        .filter(|row| row.state == "OK")
        .peekable();
    ensure!(
        required.peek().is_some(),
        "Нет подтверждённых адресов для финальной проверки"
    );
    let actual: HashMap<_, _> = actual.iter().map(|row| (row.key(), row)).collect();
    let mut reported = BTreeSet::new();
    let mut targets = Vec::new();
    let mut reasons = Vec::new();
    for row in required {
        let key = row.key();
        let reason = match actual.get(&key) {
            Some(next)
                if next.state == "OK" && (row.group != "Clean" || next.preserves_clean(row)) =>
            {
                continue;
            }
            Some(next)
                if row.group == "Clean"
                    && row.code.starts_with('2')
                    && next.code != "000"
                    && !next.code.starts_with('2') =>
            {
                format!("HTTP {}, ранее HTTP {}", next.code, row.code)
            }
            Some(next) if next.termination == "TlsFailure" && next.raw["mode"] == "http3_head" => {
                "сбой рукопожатия QUIC".to_owned()
            }
            Some(next) if next.termination == "TlsFailure" => {
                format!("сбой TLS после подключения TCP за {:.0} мс", next.conn_ms)
            }
            Some(next) if row.url.starts_with("http://") => format!(
                "{} (TCP {:.0} мс, ранее {:.0} мс)",
                next.state, next.conn_ms, row.conn_ms
            ),
            Some(next) => format!(
                "{} (TCP {:.0} мс, TLS {:.0} мс, ранее TLS {:.0} мс)",
                next.state, next.conn_ms, next.tls_ms, row.tls_ms
            ),
            None => "адрес отсутствует в финальном пакете".into(),
        };
        if reported.insert(key) {
            let target = format!("{}/{}", row.group, row.name);
            reasons.push(format!("{target} — {reason}"));
            targets.push(target);
        }
    }
    ensure!(
        targets.is_empty(),
        "Финальная комбинация не подтвердила {}: {}",
        targets.join(", "),
        reasons.join(". ")
    );
    Ok(())
}

fn final_reference(
    working: &[Row],
    measured: &[Row],
    baseline: &[Row],
    panel: crate::selection_latency::Panel,
) -> Vec<Row> {
    // User services and clean sites keep their independent working requirements.
    // A coverage-only panel also protects stable synthetic successes.
    working
        .iter()
        .filter(|row| {
            row.group != "DPI" || (panel == crate::selection_latency::Panel::All && !row.flaky)
        })
        .chain(measured.iter().filter(|row| row.group != "DPI"))
        .chain(baseline.iter().filter(|row| row.group == "Clean"))
        .cloned()
        .collect()
}

fn accept_candidate(
    validation: Result<()>,
    commit: impl FnOnce() -> Result<()>,
) -> Result<Option<String>> {
    if let Err(error) = validation {
        return Ok(Some(format!("{error:#}")));
    }
    commit()?;
    Ok(None)
}

fn learning_key(
    context: &zapret_core::TestResultContext,
    arguments: &TestArgs,
    targets: &[Target],
) -> Result<String> {
    let retry_parallel = arguments.retry_parallel();
    Ok(sha256(
        format!(
            "native-quick-learning-v1-connect-v4\n{}\n{}\n{}\n{}\n{retry_parallel}\n{}",
            context.network_key,
            context.inputs_hash,
            arguments.timeout_ms,
            arguments.parallel(),
            serde_json::to_string(targets)?
        )
        .as_bytes(),
    ))
}

fn updates_quick_history(arguments: &TestArgs) -> bool {
    // A full run with a different request budget would replace the quick cache.
    !arguments.report_only
        && (!arguments.full
            || (arguments.parallel() == TestArgs::QUICK_PARALLEL
                && arguments.retry_parallel() == TestArgs::QUICK_RETRY_PARALLEL))
}

fn recent_latency(
    app: &App,
    arguments: &TestArgs,
    context: Option<&zapret_core::TestResultContext>,
    primary: &str,
) -> Vec<String> {
    if arguments.full || arguments.compare_a.is_some() || arguments.compare_b.is_some() {
        return Vec::new();
    }
    context
        .map(|c| {
            crate::selection_learning::recent_candidates(
                &app.root,
                c,
                primary,
                arguments.timeout_ms,
            )
        })
        .unwrap_or_default()
}

fn strategy_hashes(all: &[Strategy]) -> Result<BTreeMap<String, String>> {
    all.iter()
        .map(|strategy| Ok((strategy.id.clone(), strategy.fingerprint()?)))
        .collect()
}

fn timing_summary(rows: &[Row], elapsed_ms: f64) -> Value {
    let successful: Vec<_> = rows
        .iter()
        .filter(|row| row.state == "OK" && row.group != "Clean")
        .collect();
    let average = |get: fn(&Row) -> Option<f64>| {
        let values: Vec<_> = successful
            .iter()
            .filter_map(|row| get(row))
            .filter(|v| v.is_finite() && *v >= 0.)
            .collect();
        if values.is_empty() {
            Value::Null
        } else {
            json!(values.iter().sum::<f64>() / values.len() as f64)
        }
    };
    json!({"overall":crate::selection_latency::overall_timing(&probe_details(rows)),"tcp_ms":average(|r|(r.raw["mode"] != "http3_head").then_some(r.conn_ms)),"tls_ms":average(|r|Some(r.tls_ms)),"elapsed_ms":elapsed_ms,
        "retries":rows.iter().filter(|r|r.tries>1).count(),"flaky":rows.iter().filter(|r|r.flaky).count()})
}

fn probe_details(rows: &[Row]) -> Vec<Value> {
    rows.iter()
        .map(|r| {
            json!({"group":r.group,"name":r.name,"state":r.state,"code":r.code,
        "tls_peer_retry":endpoints::multiple_tls_peers(&r.raw),
        "url":r.url,"remote_address":r.raw["remote_address"],"certificate_validated":r.raw["certificate_validated"],"media_url":r.raw["media_url"],"error":r.raw["error"],
        "mode":r.raw["mode"],"dns_source":r.raw["dns_source"],"dns_ms":r.dns_ms,"tcp_ms":if r.raw["mode"] == "http3_head" {None}else{Some(r.conn_ms)},"tls_ms":r.tls_ms,"first_byte_ms":r.first_byte_ms,"total_ms":r.total_ms,
        "body_bytes":r.body_bytes,"body_limit":r.body_limit,"body_complete":r.body_complete,"body_sha256":r.raw["body_sha256"],"target_reached":r.target_reached,"post_bytes":r.raw["post_bytes"],
        "tries":r.tries,"flaky":r.flaky,"up":r.up,"down":r.down,"termination":r.termination})
        })
        .collect()
}

fn save_report(app: &App, report: &mut Value) -> Result<()> {
    let id = report["run_id"]
        .as_str()
        .context("Нет идентификатора проверки")?
        .to_owned();
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Некорректный идентификатор проверки"
    );
    let text_path = runtime_file(&app.root, &format!("test-native-{id}.txt"))?;
    let json_path = runtime_file(&app.root, &format!("test-native-{id}.json"))?;
    report["report_file"] = json!(text_path);
    report["report_json"] = json!(json_path);
    let text = crate::selection_ui::result_text(report).context("Нет результата для отчёта")?;
    report["text_sha256"] = json!(sha256(text.as_bytes()));
    let mut bytes = serde_json::to_vec_pretty(report)?;
    if bytes.len() > 16 * 1024 * 1024 {
        report["details"] = Value::Null;
        report["details_complete"] = json!(false);
        bytes = serde_json::to_vec_pretty(report)?;
    }
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "Сводка проверки превышает размер отчёта"
    );
    atomic_write(&text_path, text.as_bytes())?;
    atomic_write(&json_path, &bytes)?;
    atomic_write(&runtime_file(&app.root, "test-native-last.json")?, &bytes)?;
    atomic_write(&runtime_file(&app.root, "test-last.txt")?, text.as_bytes())?;
    if report["quality_eligible"] == true {
        if let Some(best) = report["best"]["id"].as_str() {
            atomic_write(
                &runtime_file(&app.root, "test-best.txt")?,
                format!("{best}\r\n").as_bytes(),
            )?;
        }
    }
    Ok(())
}

fn game_identities(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .context("Неизвестен список работающих игр")?
        .iter()
        .map(|row| {
            let identity = &row["identity"];
            ensure!(
                identity["pid"].as_u64().is_some_and(|pid| pid > 0)
                    && identity["created_filetime"]
                        .as_u64()
                        .is_some_and(|time| time > 0)
                    && identity["executable"]
                        .as_str()
                        .is_some_and(|path| !path.is_empty()),
                "Не удалось подтвердить идентичность работающей игры"
            );
            Ok(serde_json::to_string(identity)?)
        })
        .collect()
}

pub(crate) fn game_snapshot(app: &App) -> Result<BTreeSet<String>> {
    game_identities(&app.platform("games", json!({}))?)
}

pub(crate) struct Restore<'a> {
    pub(crate) app: &'a App,
    pub(crate) needed: bool,
    pub(crate) approved_games: BTreeSet<String>,
}
impl Restore<'_> {
    pub(crate) fn finish(&mut self) -> Result<Option<Value>> {
        if self.needed {
            self.needed = false;
            if !game_snapshot(self.app)?.is_subset(&self.approved_games) {
                let message = "После начала автотеста запущена новая игра. Прежний обход нужно запустить пунктом 1 после закрытия игры.";
                atomic_write(
                    &runtime_file(&self.app.root, "test-restore-pending.txt")?,
                    message.as_bytes(),
                )?;
                bail!("{message}");
            }
            return self
                .app
                .platform("start", json!({"game_approved":true}))
                .map(Some);
        }
        Ok(None)
    }
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("Не удалось восстановить рабочий обход: {error:#}");
        }
    }
}

fn launch(
    context: &RunContext<'_>,
    settings: &Settings,
    alt: &str,
    final_mode: bool,
    lifetime: u64,
) -> Result<OwnedChild> {
    let args = prepare_trial_command(context, settings, alt, final_mode)?;
    start_trial(context.snapshot.root(), &args, lifetime)
}

fn prepare_trial_inputs(root: &Path, settings: &Settings) -> Result<()> {
    reset_trial_autolist(root)?;
    prepare_runtime(root, settings)
}

fn prepare_trial_command(
    context: &RunContext<'_>,
    settings: &Settings,
    alt: &str,
    final_mode: bool,
) -> Result<Vec<String>> {
    let root = context.snapshot.root();
    prepare_trial_inputs(root, settings)?;
    let options = ComposeOptions {
        alt: Some(alt.into()),
        no_auto: !final_mode,
        ipset_mode: if final_mode { None } else { Some("any".into()) },
        persistence: false,
        network_key: Some(context.network_key.clone()),
        native_identity: Some(context.native_hash.into()),
        ..Default::default()
    };
    zapret_core::checked_command_line(root, &compose(root, settings, &options)?)
}

fn start_trial(root: &Path, arguments: &[String], lifetime: u64) -> Result<OwnedChild> {
    maintenance::check_engine_args(root, arguments)?;
    let args: Vec<_> = arguments.iter().map(OsString::from).collect();
    let mut attempt = 1;
    loop {
        let mut options = RunOptions {
            cwd: Some(root.join("bin")),
            timeout: Duration::from_millis(lifetime),
            ..Default::default()
        };
        let signal = startup::Signal::for_child(&mut options);
        let mut child = OwnedChild::spawn(&root.join("bin/winws2.exe"), &args, &options)?;
        if startup::wait(&mut child, signal.as_ref())? {
            return Ok(child);
        }
        let output = child.finish()?;
        eprintln!(
            "Движок завершился при старте: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(!output.timed_out, "Истёк срок запуска тестового движка");
        if attempt == 3 {
            return Err(TrialExit {
                phase: "при запуске после трёх попыток",
                code: output.exit_code,
            }
            .into());
        }
        interrupt::check()?;
        thread::sleep(Duration::from_millis(700));
        attempt += 1;
    }
}

fn capture_trial_autolist(root: &Path) -> Result<()> {
    let original = root.join("lists/autohostlist.txt");
    let seed = if original.is_file() {
        zapret_core::read_bounded(&original, 16 * 1024 * 1024)?
    } else {
        b"# zapret-rust automatic host list\r\n".to_vec()
    };
    atomic_write(&root.join("runtime/trial-autohostlist-seed.txt"), &seed)
}

fn reset_trial_autolist(root: &Path) -> Result<()> {
    let seed = zapret_core::read_bounded(
        &root.join("runtime/trial-autohostlist-seed.txt"),
        16 * 1024 * 1024,
    )?;
    atomic_write(&root.join("lists/autohostlist.txt"), &seed)
}

fn measured(
    context: &RunContext<'_>,
    targets: &[Target],
    arguments: &TestArgs,
    engine: &mut Option<OwnedChild>,
    metadata: &Value,
    clean: &BTreeMap<String, f64>,
    hopeless: &BTreeSet<String>,
) -> Result<(Vec<Row>, bool)> {
    let parallel = arguments.parallel();
    crate::selection_ui::detail(
        context.app,
        arguments.details,
        &format!(
            "  Первый проход: {} адресов, одновременно {}.",
            targets.len(),
            parallel
        ),
    )?;
    let mut rows = probe_batch(
        context,
        targets,
        parallel,
        arguments.timeout_ms,
        engine,
        metadata,
        1,
    )?;
    let plan = retries::Plan::new(
        &rows,
        clean,
        hopeless,
        arguments.retry_parallel() < parallel,
    );
    let mut eligible = rows.iter().all(|row| {
        matches!(row.state.as_str(), "OK" | "FAIL" | "FREEZE")
            && !row.flaky
            && (row.group != "Clean" || row.meets_baseline(clean.get(&row.name).copied()))
    });
    if !plan.first.is_empty() {
        let retry_parallel = arguments.retry_parallel();
        let mut batch = |keys: &BTreeSet<String>| {
            let requests = targets
                .iter()
                .filter(|t| keys.contains(&t.key()))
                .cloned()
                .collect::<Vec<_>>();
            probe_batch(
                context,
                &requests,
                retry_parallel,
                arguments.timeout_ms,
                engine,
                metadata,
                2,
            )
        };
        if !plan.sampled.is_empty() {
            context
                .sampled_batches
                .set(context.sampled_batches.get() + 1);
        }
        crate::selection_ui::detail(
            context.app,
            arguments.details,
            &format!(
                "  Повторная попытка: {} адресов, одновременно {}.",
                plan.first.len(),
                retry_parallel
            ),
        )?;
        thread::sleep(Duration::from_millis(250));
        let mut retry = batch(&plan.first)?;
        if plan.expand(&retry) {
            context
                .expanded_batches
                .set(context.expanded_batches.get() + 1);
            crate::selection_ui::detail(
                context.app,
                arguments.details,
                &format!(
                    "  Несколько сервисов ответили при меньшей нагрузке. Повторяю ещё {} запросов.",
                    plan.reserve.len()
                ),
            )?;
            retry.extend(batch(&plan.reserve)?);
        }
        eligible &= retry.iter().all(|row| {
            rows.iter()
                .find(|first| first.key() == row.key())
                .is_some_and(|first| first.state == row.state)
                && (row.group != "Clean" || row.meets_baseline(clean.get(&row.name).copied()))
        });
        merge_retry(&mut rows, &retry);
    }
    Ok((rows, eligible))
}

struct ControlBoundary {
    strategy: String,
    finished: Instant,
    generation: u64,
    rows: Vec<Row>,
}

impl ControlBoundary {
    fn current(&self, now: Instant, generation: Option<u64>) -> bool {
        now.duration_since(self.finished) <= Duration::from_secs(2)
            && generation == Some(self.generation)
    }
}

struct Trial {
    control_source: Option<String>,
    replacement_controls: Option<Vec<String>>,
    rows: Vec<Row>,
    eligible: bool,
    failures: Vec<String>,
    elapsed_ms: f64,
}

fn trial_order(targets: &[Target], baseline: &[Row], parallel: usize) -> Vec<Target> {
    let mut order = targets.to_vec();
    if order.len() > parallel {
        let costs: BTreeMap<_, _> = baseline.iter().map(|r| (r.key(), r.total_ms)).collect();
        order.sort_by_cached_key(|t| {
            let micros = costs.get(&t.key()).copied().unwrap_or(0.) * 1000.;
            std::cmp::Reverse(micros as u64)
        });
    }
    order
}

#[allow(clippy::too_many_arguments)]
fn measure_profile(
    context: &RunContext<'_>,
    settings: &Settings,
    strategy: &Strategy,
    targets: &[Target],
    control_targets: &[Target],
    boundary: &mut Option<ControlBoundary>,
    arguments: &TestArgs,
    metadata: &Value,
    clean: &BTreeMap<String, f64>,
    hopeless: &BTreeSet<String>,
) -> Result<Trial> {
    let start = Instant::now();
    context.assert_current()?;
    let mut info = metadata.clone();
    info["StrategyId"] = json!(strategy.id);
    info["StrategyHash"] = json!(strategy.fingerprint()?);
    let previous = boundary
        .take()
        .filter(|last| last.current(Instant::now(), context.network_monitor.generation()));
    let (before, control_source) = match previous {
        Some(last) => (last.rows, Some(last.strategy)),
        None => (
            controls(context, control_targets, arguments, &info, "before")?,
            None,
        ),
    };
    // Fix the panel before the candidate starts. A failure appearing only
    // after the trial must remain visible, even if the spare later succeeds.
    let panel = controls_for_trial(control_targets, &before, clean);
    let replacement_controls = (panel
        .iter()
        .map(Target::key)
        .ne(control_targets.iter().take(3).map(Target::key)))
    .then(|| panel.iter().map(|t| t.name.clone()).collect());
    let child = launch(
        context,
        settings,
        &strategy.id,
        false,
        engine_budget(targets.len(), arguments, false)?,
    );
    let (rows, eligible) = run_trial(child, |engine| {
        measured(context, targets, arguments, engine, &info, clean, hopeless)
    })?;
    let generation = context.network_monitor.generation();
    let after = controls(context, control_targets, arguments, &info, "after")?;
    let selected: BTreeSet<_> = panel.iter().map(Target::key).collect();
    let failures = control_failures(&panel, &before, &after);
    if let Some(generation) = generation
        && context.network_monitor.generation() == Some(generation)
        && failures.is_empty()
        && after
            .iter()
            .filter(|r| selected.contains(&r.key()))
            .all(|r| r.healthy_control(clean.get(&r.name).copied()))
    {
        *boundary = Some(ControlBoundary {
            strategy: strategy.id.clone(),
            finished: Instant::now(),
            generation,
            rows: after,
        });
    }
    Ok(Trial {
        rows,
        eligible,
        failures,
        control_source,
        replacement_controls,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.,
    })
}

fn controls_for_trial(
    targets: &[Target],
    before: &[Row],
    clean: &BTreeMap<String, f64>,
) -> Vec<Target> {
    let wanted = targets.len().min(3);
    if targets.len() > wanted {
        let healthy: Vec<_> = targets
            .iter()
            .filter(|target| {
                let key = target.key();
                let samples: Vec<_> = before.iter().filter(|r| r.key() == key).collect();
                samples.len() == 2
                    && samples
                        .iter()
                        .all(|r| r.healthy_control(clean.get(&target.name).copied()))
            })
            .take(wanted)
            .cloned()
            .collect();
        if healthy.len() == wanted {
            return healthy;
        }
    }
    targets.iter().take(wanted).cloned().collect()
}

fn controls(
    context: &RunContext<'_>,
    targets: &[Target],
    arguments: &TestArgs,
    metadata: &Value,
    phase: &str,
) -> Result<Vec<Row>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut metadata = metadata.clone();
    metadata["Stage"] = json!(format!("control-{phase}"));
    let mut rows = Vec::new();
    for attempt in 1..=2 {
        rows.extend(probe_batch(
            context,
            targets,
            arguments.parallel().min(TestArgs::QUICK_RETRY_PARALLEL),
            arguments.timeout_ms,
            &mut None,
            &metadata,
            attempt,
        )?);
    }
    Ok(rows)
}

fn control_failures(targets: &[Target], before: &[Row], after: &[Row]) -> Vec<String> {
    let mut failures = Vec::new();
    if targets
        .iter()
        .filter_map(control_host)
        .collect::<BTreeSet<_>>()
        .len()
        < 2
    {
        failures.push("Доступно меньше двух независимых контрольных серверов.".into());
    }
    // The batches can include a standby. Each selected control must still have
    // exactly two observations on each side of the trial.
    for target in targets {
        let first: Vec<_> = before
            .iter()
            .filter(|row| row.key() == target.key())
            .collect();
        let last: Vec<_> = after
            .iter()
            .filter(|row| row.key() == target.key())
            .collect();
        if first.len() != 2 || last.len() != 2 {
            failures.push(format!(
                "Контрольный адрес {}: не хватает измерений.",
                target.name
            ));
            continue;
        }
        let healthy = |rows: &[&Row]| rows.iter().all(|row| row.healthy_control(None));
        if !healthy(&first) {
            failures.push(format!(
                "Контрольный адрес {} не подтвердил доступность до измерения.",
                target.name
            ));
        }
        if !healthy(&last) {
            failures.push(format!(
                "Контрольный адрес {} не подтвердил доступность после измерения.",
                target.name
            ));
        }
        if healthy(&first)
            && healthy(&last)
            && (first.iter().map(|row| row.connection_ms()).sum::<f64>()
                - last.iter().map(|row| row.connection_ms()).sum::<f64>())
            .abs()
                / 2.
                > 500.
        {
            failures.push(format!(
                "Контрольный адрес {}: время подключения изменилось более чем на 500 мс.",
                target.name
            ));
        }
    }
    failures
}

fn qualified_scores(rows: &[RankRow], quality: &BTreeMap<String, bool>) -> Vec<RankRow> {
    rows.iter()
        .filter(|row| quality.get(&row.id) == Some(&true))
        .cloned()
        .collect()
}

fn missing_comparison(primary: &str, candidates: &[Strategy], qualified: &[RankRow]) -> bool {
    candidates.iter().any(|strategy| strategy.id != primary)
        && !qualified.iter().any(|row| row.id != primary)
}

fn fully_covered(base: &[Row], actual: &[Row]) -> bool {
    let base_keys: BTreeSet<_> = base.iter().map(Row::key).collect();
    let actual_keys: BTreeSet<_> = actual.iter().map(Row::key).collect();
    !base.is_empty()
        && base_keys.len() == base.len()
        && actual_keys.len() == actual.len()
        && base_keys == actual_keys
        && base.iter().all(|row| {
            matches!(row.state.as_str(), "OK" | "FAIL" | "FREEZE")
                && !row.flaky
                && (row.group != "Clean" || row.healthy_connection(None))
        })
        && actual.iter().all(|row| {
            row.state == "OK"
                && !row.flaky
                && (row.group != "Clean"
                    || base
                        .iter()
                        .find(|before| before.key() == row.key())
                        .is_some_and(|before| row.preserves_clean(before)))
        })
        && actual.iter().any(|row| row.group == "Clean")
        && actual.iter().any(|row| row.group != "Clean")
}

#[derive(Clone, Debug)]
struct ScoreRecord {
    date: String,
    id: String,
    name: String,
    score: f64,
    context: String,
    fingerprint: String,
}

fn compatible_history(root: &Path) -> Result<(Vec<String>, Vec<ScoreRecord>)> {
    let path = root.join("runtime/test-scores.txt");
    if !path.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let text = zapret_core::read_text(&path, 8 * 1024 * 1024)?;
    let now = Local::now().naive_local();
    let oldest = now - chrono::Duration::days(30);
    let mut legacy = Vec::new();
    let mut records = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() == 4 {
            legacy.push(line.into());
            continue;
        }
        if fields.len() != 6 {
            continue;
        }
        let Ok(date) = chrono::NaiveDateTime::parse_from_str(fields[0], "%Y-%m-%d %H:%M") else {
            continue;
        };
        let Ok(score) = fields[3].parse::<f64>() else {
            continue;
        };
        if date < oldest || date > now + chrono::Duration::minutes(1) || !score.is_finite() {
            continue;
        }
        if !fields[1].bytes().all(|b| b.is_ascii_digit())
            || fields[1].is_empty()
            || fields[4].is_empty()
            || fields[4].len() > 64
            || !fields[4]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || fields[5].len() != 64
            || !fields[5].bytes().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }
        records.push(ScoreRecord {
            date: fields[0].into(),
            id: fields[1].into(),
            name: fields[2].into(),
            score,
            context: fields[4].into(),
            fingerprint: fields[5].into(),
        });
    }
    Ok((legacy, records))
}

type ScoreAverages = BTreeMap<String, (f64, usize)>;
fn score_history(
    root: &Path,
    sums: &[RankRow],
    all: &[Strategy],
    context: &str,
) -> Result<(ScoreAverages, Vec<u8>)> {
    let (legacy, mut history) = compatible_history(root)?;
    let date = Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut averages = BTreeMap::new();
    for row in sums {
        let strategy = all
            .iter()
            .find(|strategy| strategy.id == row.id)
            .context("Стратегия истории отсутствует")?;
        let fingerprint = strategy.fingerprint()?;
        history.push(ScoreRecord {
            date: date.clone(),
            id: row.id.clone(),
            name: strategy.name.clone(),
            score: row.score,
            context: context.into(),
            fingerprint: fingerprint.clone(),
        });
        let values: Vec<_> = history
            .iter()
            .rev()
            .filter(|record| {
                record.id == row.id
                    && record.name == strategy.name
                    && record.context == context
                    && record.fingerprint.eq_ignore_ascii_case(&fingerprint)
            })
            .take(3)
            .collect();
        averages.insert(
            row.id.clone(),
            (
                values.iter().map(|record| record.score).sum::<f64>() / values.len() as f64,
                values.len(),
            ),
        );
    }
    let mut counts = BTreeMap::<(String, String, String, String), usize>::new();
    let mut retained = Vec::new();
    for record in history.into_iter().rev() {
        let count = counts
            .entry((
                record.id.clone(),
                record.name.clone(),
                record.context.clone(),
                record.fingerprint.clone(),
            ))
            .or_default();
        if *count < 3 {
            retained.push(record);
            *count += 1;
        }
    }
    retained.reverse();
    let mut lines = vec!["# История: дата|номер|имя|балл|контекст|SHA256 стратегии".into()];
    lines.extend(legacy);
    lines.extend(retained.iter().map(|record| {
        format!(
            "{}|{}|{}|{}|{}|{}",
            record.date, record.id, record.name, record.score, record.context, record.fingerprint
        )
    }));
    Ok((averages, format!("{}\r\n", lines.join("\r\n")).into_bytes()))
}

fn read_last(app: &App) -> Result<Value> {
    let path = runtime_file(&app.root, "test-native-last.json")?;
    let interruption = last_interruption(&app.root).ok().flatten();
    if !path.is_file() {
        if let Some((_, reason)) = interruption {
            bail!("Последний автоподбор прерван. {reason} Завершённых результатов ещё нет.");
        }
        bail!("Результатов ещё нет. Сначала запустите подбор.");
    }
    let mut report: Value =
        serde_json::from_slice(&zapret_core::read_bounded(&path, 16 * 1024 * 1024)?)
            .context("Сохранённый результат повреждён. Запустите подбор заново.")?;
    ensure!(
        report["schema"] == 1
            && report["best"].is_object()
            && report["rows"].is_array()
            && report["primary"].is_string(),
        "Сохранённый результат повреждён. Запустите подбор заново."
    );
    if let Some((time, reason)) = interruption {
        if path
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| chrono::DateTime::<Utc>::from(t) < time)
        {
            report["later_interruption"] = json!(reason);
        }
    }
    Ok(report)
}

pub fn run(app: &App, arguments: &TestArgs) -> Result<Value> {
    if arguments.last {
        return read_last(app);
    }
    ensure!(
        !arguments.apply || (!arguments.report_only && !arguments.keep_primary),
        "Применение несовместимо с режимом отчёта и сохранением прежней основной"
    );
    ensure!(
        (1..=10).contains(&arguments.rounds)
            && (1..=64).contains(&arguments.parallel())
            && (1..=60000).contains(&arguments.timeout_ms),
        "Неверные параметры автоподбора"
    );
    let settings = read_settings(&app.root)?;
    let targets = read_targets(&app.root, arguments)?;
    let native_hash = crate::controller_hash()?;
    let local_network = app.platform("network", json!({"identity_only":true}))?;
    let local_context = local_network["key"]
        .as_str()
        .filter(|_| local_network["known"] == true)
        .and_then(|key| {
            test_result_context_with_identity(&app.root, &settings, key, native_hash).ok()
        });
    let all = list_strategies(&app.root)?;
    let local_rank = zapret_core::read_rank(&app.root, local_context.as_ref(), &all)?;
    let local_cover = match (&local_rank, &local_context) {
        (Some(rank), Some(context)) => zapret_core::read_cover(&app.root, rank, context)?,
        _ => None,
    };
    let initial = zapret_core::test_strategy_ids(
        &app.root,
        &settings,
        &all,
        local_rank.as_ref(),
        local_cover.as_ref(),
        arguments.full,
    )?;
    if arguments.plan_only {
        let hashes = strategy_hashes(&all)?;
        let cache = match &local_context {
            Some(context) => crate::selection_learning::Cache::load(
                &app.root,
                &learning_key(context, arguments, &targets)?,
            ),
            None => crate::selection_learning::Cache::new("unknown-network"),
        };
        let primary = settings.get("alt");
        let recent = recent_latency(app, arguments, local_context.as_ref(), primary);
        let plan = cache.plan(
            &initial,
            primary,
            arguments.full,
            &hashes,
            Utc::now().timestamp(),
            &recent,
        );
        let representatives = if !arguments.full
            && arguments.rounds == 1
            && arguments.compare_a.is_none()
            && arguments.compare_b.is_none()
        {
            Some(
                families::schedule(
                    &plan.strategies,
                    &all,
                    primary,
                    local_rank.as_ref(),
                    local_cover.as_ref(),
                    plan.latency_candidates
                        .iter()
                        .chain(plan.lighter_candidate.iter())
                        .cloned(),
                )
                .0
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        return Ok(
            json!({"schema":1,"policy":"native-quick-service-screen-v8","quick_screen_requested":!arguments.full && arguments.rounds==1 && arguments.compare_a.is_none() && arguments.compare_b.is_none(),"preferred_selection_policy":crate::selection_latency::POLICY,"context":local_context,"targets":targets,"strategies":plan.strategies,"deferred_history":plan.deferred,"queued_candidates":plan.queued,"latency_candidates":plan.latency_candidates,"lighter_candidate":plan.lighter_candidate,"strategy_families":families::catalog(&initial),"family_representatives":representatives,"settings":settings,
            "rounds":arguments.rounds,"parallel":arguments.parallel(),"retry_parallel":arguments.retry_parallel(),"timeout_ms":arguments.timeout_ms,"report_only":arguments.report_only}),
        );
    }
    interrupt::install()?;
    ensure!(
        app.platform("admin", json!({}))?["is_admin"] == true,
        "Автоподбор требует прав администратора"
    );
    let approved_games = game_snapshot(app)?;
    ensure!(
        approved_games.is_empty()
            || app.confirm("Запущена игра. Автоподбор временно остановит обход. Продолжить?")?,
        "Автоподбор отложен"
    );
    let conflicts = app.platform("conflicts", json!({}))?;
    let interfering = conflicts["foreign_bypass"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
        || conflicts["tun_adapters"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
        || conflicts["proxy"]["proxy"]
            .as_str()
            .is_some_and(|proxy| !proxy.is_empty());
    ensure!(
        !interfering || app.confirm("Другой обход или прокси влияет на измерения. Продолжить?")?,
        "Автоподбор отложен"
    );
    ensure!(
        zapret_core::verify_package(&app.root)?.is_empty(),
        "Файлы движка изменены"
    );
    let _guard = ControlGuard::acquire(&app.root, "strategy-test")?;
    let _quick_edit = crate::console::QuickEditGuard::suspend()
        .context("Не удалось настроить ввод консоли на время автоподбора")?;
    crate::ensure_controller_current()?;
    let network = measurement_network(app)?;
    let status = app.platform("status", json!({}))?;
    ensure!(
        status["known"] == true && status["ownership_known"] == true,
        "Состояние рабочего обхода неизвестно"
    );
    let was_running = status["running"]
        .as_bool()
        .context("Состояние рабочего обхода неизвестно")?;
    ensure!(
        game_snapshot(app)?.is_subset(&approved_games),
        "После подтверждения запущена новая игра. Автоподбор отложен"
    );
    let mut restore = Restore {
        app,
        needed: was_running,
        approved_games: approved_games.clone(),
    };
    app.platform("stop", json!({"game_approved":true}))?;
    let mut result = network_monitor::run_with_recovery(
        &network,
        || run_inner(app, arguments, &network, approved_games.clone()),
        || app.platform("network", json!({"identity_only":true})),
        || {
            interrupt::check()?;
            thread::sleep(Duration::from_millis(250));
            interrupt::check()
        },
        || {
            crate::selection_ui::heading(
                app,
                "Прежнее подключение восстановилось. Начинаю подбор заново с замера без обхода.",
            )
        },
    );
    if let Ok(report) = &result {
        restore.needed |= selection_start_requested(arguments, report);
    }
    let restart = restore.finish();
    if let Ok(report) = result.as_mut() {
        if report["protocol"] != "finalists-native-v1" {
            let actual = read_settings(&app.root)?;
            reconcile_restart(
                report,
                &actual,
                restart
                    .as_ref()
                    .map(|outcome| outcome.as_ref())
                    .map_err(|error| format!("{error:#}")),
            );
        }
    }
    if restart.is_ok() && arguments.webcheck {
        if let Ok(report) = result.as_mut() {
            let check = zapret_net::diagnostics(&app.root, "webcheck", &json!({}));
            report["webcheck"] = match check {
                Ok(value) => match crate::diagnostic_report::publish(&app.root, "web", value) {
                    Ok(value) => value,
                    Err(error) => json!({"status":"Unknown","error":format!("{error:#}")}),
                },
                Err(error) => json!({"status":"Unknown","error":format!("{error:#}")}),
            };
        }
    }
    if let Ok(report) = result.as_mut() {
        if report["protocol"] != "finalists-native-v1" {
            if restart.is_ok() {
                report["telegram_media"] = app.platform("telegram-media",json!({})).unwrap_or_else(|e|
                    json!({"bridge":{"state":"unavailable","reason":format!("{e:#}")},"file":{"state":"unavailable","reason":"Состояние моста неизвестно"}}));
            }
            save_report(app, report)?;
        }
    }
    match (result, restart) {
        (Err(measurement), Err(restore)) => Err(measurement.context(format!(
            "Не удалось восстановить рабочий обход: {restore:#}. Автоподбор прерван"
        ))),
        (_, Err(restore)) => Err(restore),
        (result, Ok(_)) => result,
    }
}

fn selection_start_requested(arguments: &TestArgs, report: &Value) -> bool {
    !arguments.report_only
        && report["accepted"] == true
        && (arguments.apply || report["primary_changed"] == true)
}

fn reconcile_restart(
    report: &mut Value,
    actual: &Settings,
    restart: std::result::Result<Option<&Value>, String>,
) {
    let requested = report
        .get("primary_requested")
        .filter(|value| value.is_string())
        .unwrap_or(&report["primary"])
        .clone();
    report["primary_requested"] = requested.clone();
    report["primary"] = json!(actual.get("alt"));
    match restart {
        Ok(Some(outcome)) => {
            report["startup"] = outcome.clone();
            if outcome["restored"] == true || requested.as_str() != Some(actual.get("alt")) {
                report["primary_changed"] = json!(false);
            }
        }
        Ok(None) => {
            report["startup"] = json!({"requested":false,"reason":"BypassWasStopped"});
        }
        Err(error) => {
            report["startup_error"] = json!(error);
            report["running_restored"] = json!(false);
        }
    }
}

fn run_inner(
    app: &App,
    arguments: &TestArgs,
    network: &Value,
    approved_games: BTreeSet<String>,
) -> Result<Value> {
    let network_key = network["key"]
        .as_str()
        .context("Неизвестен контекст сети")?
        .to_owned();
    let test_started = Instant::now();
    let mut snapshot = Snapshot::package(&app.root)?;
    // Read the complete run from the pinned package, after acquiring control.
    // Prompts before the lock may have allowed another window to change inputs.
    let settings = read_settings(snapshot.root())?;
    let targets = read_targets(snapshot.root(), arguments)?;
    let all = list_strategies(snapshot.root())?;
    capture_trial_autolist(snapshot.root())?;
    let native_hash = crate::controller_hash()?;
    let run_id =
        sha256(format!("{}|{}", Utc::now().to_rfc3339(), snapshot.fingerprint()).as_bytes())[..32]
            .to_ascii_lowercase();
    let journal = runtime_file(&app.root, &format!("test-native-{run_id}.jsonl"))?;
    let mut random = arguments
        .seed
        .unwrap_or(Utc::now().timestamp_micros() as u64)
        .max(1);
    let failed_profiles = RefCell::new(BTreeMap::new());
    let sampled_batches = Cell::new(0);
    let expanded_batches = Cell::new(0);
    let network_monitor = network_monitor::Monitor::new(network);
    let context = RunContext {
        app,
        snapshot: &snapshot,
        network_key: network_key.clone(),
        network_monitor: &network_monitor,
        failed_profiles: &failed_profiles,
        sampled_batches: &sampled_batches,
        expanded_batches: &expanded_batches,
        native_hash,
        journal: journal.clone(),
        deadline: if arguments.compare_a.is_some() || arguments.compare_b.is_some() {
            Some(Instant::now() + Duration::from_secs(1800))
        } else {
            None
        },
        clock_origin: zapret_platform::monotonic_ms()?,
        approved_games: &approved_games,
        details: arguments.details,
    };
    let lifetime = engine_budget(targets.len(), arguments, false)?;
    let result_context =
        test_result_context_with_identity(snapshot.root(), &settings, &network_key, native_hash)
            .context("Подготовка контекста автоподбора из снимка пакета")?;
    let rank = zapret_core::read_rank(snapshot.root(), Some(&result_context), &all)?;
    let cover = match &rank {
        Some(rank) => zapret_core::read_cover(snapshot.root(), rank, &result_context)?,
        None => None,
    };
    let candidates = zapret_core::test_strategy_ids(
        snapshot.root(),
        &settings,
        &all,
        rank.as_ref(),
        cover.as_ref(),
        arguments.full,
    )?;
    if arguments.compare_a.is_some() || arguments.compare_b.is_some() {
        return comparison(&context, arguments, &settings, &targets, &all, &run_id);
    }
    let hashes = strategy_hashes(&all)?;
    let mut learning = crate::selection_learning::Cache::load(
        snapshot.root(),
        &learning_key(&result_context, arguments, &targets)?,
    );
    let recent = recent_latency(app, arguments, Some(&result_context), settings.get("alt"));
    let learned_plan = learning.plan(
        &candidates,
        settings.get("alt"),
        arguments.full,
        &hashes,
        Utc::now().timestamp(),
        &recent,
    );
    let candidates = learned_plan.strategies;
    let deferred_history = learned_plan.deferred;
    let queued_candidates = learned_plan.queued;
    let latency_candidates = learned_plan.latency_candidates;
    let lighter_candidate = learned_plan.lighter_candidate;
    crate::selection_ui::progress(
        app,
        &format!(
            "{} подбор: {} стратегий · {} адресов · Ctrl+C — отмена.",
            if arguments.full {
                "Расширенный"
            } else {
                "Быстрый"
            },
            candidates.len(),
            targets.len()
        ),
    )?;
    crate::selection_ui::progress(
        app,
        "Зелёный — ответило больше адресов, чем без обхода. Красный — меньше.",
    )?;
    crate::selection_ui::detail(
        app,
        arguments.details,
        &format!(
            "Ожидание адреса: {} мс · одновременно: {} (повторы: {}) · кругов: {}.",
            arguments.timeout_ms,
            arguments.parallel(),
            arguments.retry_parallel(),
            arguments.rounds
        ),
    )?;
    if !deferred_history.is_empty() {
        let names: Vec<_> = all
            .iter()
            .filter(|s| deferred_history.contains(&s.id))
            .map(Strategy::display_name)
            .collect();
        crate::selection_ui::detail(
            app,
            arguments.details,
            &format!(
                "По прошлым проверкам отложены явно слабые: {}. Полный тест проверяет все.",
                names.join(", ")
            ),
        )?;
    }
    let mut table = BTreeMap::<String, Vec<Row>>::new();
    let mut timings = BTreeMap::<String, Value>::new();
    let mut failure_runs = BTreeMap::<String, usize>::new();
    let mut eligible = BTreeMap::<String, bool>::new();
    let mut skipped = Vec::new();
    let mut family_selection = None;
    let mut quick_screen = None;
    let mut shared_controls = Vec::new();
    let mut control_substitutions = Vec::new();
    let mut strategy_quality = BTreeMap::<String, bool>::new();
    let mut quality_reasons = BTreeMap::<String, BTreeSet<String>>::new();
    let mut round_sums = BTreeMap::<String, Vec<RankRow>>::new();
    let mut repeated_baselines = Vec::new();
    for round in 1..=arguments.rounds {
        if arguments.rounds > 1 {
            crate::selection_ui::progress(app, &format!("Круг {round} из {}", arguments.rounds))?;
        }
        crate::selection_ui::heading(app, "Проверяю соединение без обхода…")?;
        let baseline_started = Instant::now();
        let mut round_ids = BTreeSet::<String>::new();
        let metadata = json!({"Schema":1,"RunId":run_id,"Stage":"main","Round":round,"CapturedNetworkKey":network_key,"CapturedInputsHash":snapshot.fingerprint(),"NativeIdentity":native_hash});
        let RoundBaseline {
            rows: base,
            eligible: base_eligible,
            controls: quick_controls,
            repeated,
        } = round_baseline(&targets, arguments.report_only, |again| {
            let mut baseline_meta = metadata.clone();
            if again {
                context.check_current(true)?;
                crate::selection_ui::progress(
                    app,
                    "В исходном замере мало надёжных контрольных серверов. Проверяю подключение ещё раз.",
                )?;
                baseline_meta["Stage"] = json!("baseline-recheck");
            }
            measured(
                &context,
                &targets,
                arguments,
                &mut None,
                &baseline_meta,
                &BTreeMap::new(),
                &BTreeSet::new(),
            )
        })?;
        if repeated {
            repeated_baselines.push(round);
        }
        let round_targets = endpoints::for_round(&targets, &base);
        let trial_targets = trial_order(&round_targets, &base, arguments.parallel());
        let clean = baseline(&base);
        let base_counts = availability(&base);
        let base_timing = timing_summary(&base, baseline_started.elapsed().as_secs_f64() * 1000.);
        crate::selection_ui::run_summary(
            app,
            "Без обхода",
            &summary("0", &base, &BTreeMap::new()),
            &base_counts,
            &base_timing,
            &base,
            crate::selection_ui::RunState {
                qualified: base_eligible,
                leader: false,
                response_delta: None,
                details: arguments.details,
                position: 0,
                total: candidates.len(),
            },
        )?;
        timings.insert("0".into(), base_timing);
        eligible.insert("0".into(), base_eligible);
        table.insert("0".into(), base);
        let mut control_targets = quick_controls.clone();
        let primary_id = settings.get("alt");
        let mut primary_trial = None;
        let mut short_targets = Vec::new();
        if !arguments.full && arguments.rounds == 1 && candidates.len() > 4 {
            let initial_panel = quick::panel(&round_targets, &table["0"], &[], &quick_controls);
            if initial_panel.len() * 2 < targets.len()
                && initial_panel.iter().filter(|t| t.group == "Clean").count() >= 2
            {
                if let Some(active) = candidates.iter().find(|s| s.id == primary_id) {
                    crate::selection_ui::heading(
                        app,
                        &format!(
                            "Полная проверка текущей стратегии {}",
                            active.display_name()
                        ),
                    )?;
                    let trial = measure_profile(
                        &context,
                        &settings,
                        active,
                        &trial_targets,
                        &control_targets,
                        &mut None,
                        arguments,
                        &metadata,
                        &clean,
                        &BTreeSet::new(),
                    )
                    .with_context(|| format!("При проверке текущей стратегии ALT{primary_id}"))?;
                    short_targets =
                        quick::panel(&round_targets, &table["0"], &trial.rows, &quick_controls);
                    primary_trial = Some(trial);
                }
            }
        }
        let staged = primary_trial
            .as_ref()
            .is_some_and(|trial| trial.failures.is_empty())
            && short_targets.len() * 2 < targets.len();
        let (mut initial, mut deferred) = if staged {
            let active = primary_trial.as_ref().expect("measured primary");
            let (finalists, confirmed_controls, report) = quick::screen(
                &context,
                &settings,
                &candidates,
                &short_targets,
                &quick_controls,
                &active.rows,
                active.failures.is_empty(),
                arguments,
                &metadata,
                &clean,
            )?;
            if confirmed_controls.len() >= 2 {
                control_targets = confirmed_controls;
            }
            skipped.extend(
                candidates
                    .iter()
                    .filter(|s| !finalists.iter().any(|f| f.id == s.id))
                    .map(|s| s.id.clone()),
            );
            crate::selection_ui::progress(
                app,
                &format!(
                    "Полная проверка: {} профилей из {}, {} адресов.",
                    finalists.len(),
                    candidates.len(),
                    targets.len()
                ),
            )?;
            quick_screen = Some(report);
            (finalists, Vec::new())
        } else if arguments.full || arguments.rounds > 1 {
            (candidates.clone(), Vec::new())
        } else {
            let plan = families::schedule(
                &candidates,
                &all,
                settings.get("alt"),
                rank.as_ref(),
                cover.as_ref(),
                latency_candidates
                    .iter()
                    .chain(lighter_candidate.iter())
                    .cloned(),
            );
            crate::selection_ui::progress(
                app,
                &format!(
                    "Сравниваю {} семейств. В первом этапе {} профилей.",
                    families::catalog(&candidates).len(),
                    plan.0.len()
                ),
            )?;
            plan
        };
        initial.retain(|s| !failed_profiles.borrow().contains_key(&s.id));
        deferred.retain(|s| !failed_profiles.borrow().contains_key(&s.id));
        shuffle(&mut initial, &mut random);
        let initial_len = initial.len();
        let total_scheduled = if staged {
            initial_len
        } else {
            candidates.len()
        };
        let mut schedule = initial;
        let mut boundary = None;
        let mut index = 0;
        while index < schedule.len() {
            if index == initial_len && !deferred.is_empty() {
                unreachable!("continuation is appended at boundary below")
            }
            let strategy = schedule[index].clone();
            crate::selection_ui::heading(
                app,
                &format!(
                    "[{} / {}] {}",
                    index + 1,
                    total_scheduled,
                    strategy.display_name()
                ),
            )?;
            let hopeless: BTreeSet<_> = failure_runs
                .iter()
                .filter(|(_, count)| **count >= 3)
                .map(|(key, _)| key.clone())
                .collect();
            let cached = if strategy.id == primary_id {
                primary_trial.take()
            } else {
                None
            };
            let result = match cached {
                Some(trial) => Ok(trial),
                None => measure_profile(
                    &context,
                    &settings,
                    &strategy,
                    &trial_targets,
                    &control_targets,
                    &mut boundary,
                    arguments,
                    &metadata,
                    &clean,
                    &hopeless,
                ),
            };
            if let Some(Trial {
                rows,
                eligible: can_skip,
                control_source,
                replacement_controls,
                failures,
                elapsed_ms,
            }) = context.candidate(&strategy.id, primary_id, result)?
            {
                if let Some(controls) = replacement_controls {
                    control_substitutions
                        .push(json!({"round":round, "strategy":strategy.id,"controls":controls}));
                }
                if let Some(source) = control_source {
                    shared_controls
                        .push(json!({"round":round, "before":strategy.id, "after":source,
                    "requests_saved":control_targets.len() * 2}));
                }
                let counts = availability(&rows);
                let run_summary = summary(&strategy.id, &rows, &clean);
                let timing = timing_summary(&rows, elapsed_ms);
                let stable = failures.is_empty();
                strategy_quality
                    .entry(strategy.id.clone())
                    .and_modify(|qualified| *qualified &= stable)
                    .or_insert(stable);
                let previous_best = round_ids
                    .iter()
                    .filter(|id| strategy_quality.get(*id) == Some(&true))
                    .map(|id| summary(id, &table[id], &clean).score)
                    .reduce(f64::max);
                let confirmed = strategy_quality.get(&strategy.id) == Some(&true);
                crate::selection_ui::run_summary(
                    app,
                    strategy.display_name(),
                    &run_summary,
                    &counts,
                    &timing,
                    &rows,
                    crate::selection_ui::RunState {
                        qualified: confirmed,
                        leader: confirmed
                            && previous_best.is_none_or(|score| run_summary.score >= score),
                        response_delta: counts.change_from(&base_counts),
                        details: arguments.details,
                        position: index + 1,
                        total: total_scheduled,
                    },
                )?;
                timings.insert(strategy.id.clone(), timing);
                if !stable {
                    crate::selection_ui::detail(
                        app,
                        arguments.details,
                        &format!("  Измерение вне выбора: {}", failures[0]),
                    )?;
                    quality_reasons
                        .entry(strategy.id.clone())
                        .or_default()
                        .extend(failures);
                }
                for row in &rows {
                    if matches!(row.state.as_str(), "FAIL" | "FREEZE") || row.dns_failure() {
                        *failure_runs.entry(row.key()).or_default() += 1;
                    } else {
                        failure_runs.remove(&row.key());
                    }
                }
                eligible.insert(strategy.id.clone(), can_skip);
                round_ids.insert(strategy.id.clone());
                table.insert(strategy.id.clone(), rows);
            } else {
                eligible.insert(strategy.id.clone(), false);
                strategy_quality.insert(strategy.id, false);
                boundary = None;
            }
            index += 1;
            if index == initial_len && !deferred.is_empty() {
                let clean_base = &table["0"];
                let controls_stable = schedule
                    .iter()
                    .all(|s| strategy_quality.get(&s.id) == Some(&true));
                let all_eligible =
                    controls_stable && eligible["0"] && schedule.iter().all(|s| eligible[&s.id]);
                let perfect = schedule
                    .iter()
                    .filter(|s| all_eligible && fully_covered(clean_base, &table[&s.id]))
                    .map(|s| s.id.clone())
                    .collect();
                let evidence = table
                    .iter()
                    .map(|(id, rows)| (id.clone(), probe_details(rows)))
                    .collect();
                let rows = schedule
                    .iter()
                    .filter(|s| strategy_quality.get(&s.id) == Some(&true))
                    .map(|s| summary(&s.id, &table[&s.id], &clean))
                    .collect();
                let baseline_stable = !clean.is_empty()
                    && clean_base
                        .iter()
                        .filter(|r| r.group != "DPI")
                        .all(|r| !r.flaky && matches!(r.state.as_str(), "OK" | "FAIL" | "FREEZE"));
                let (next, omitted, refinement) = families::refine(
                    &schedule,
                    std::mem::take(&mut deferred),
                    families::Evidence {
                        rows,
                        details: &evidence,
                        primary: settings.get("alt"),
                        controls_stable: controls_stable && baseline_stable,
                        perfect,
                    },
                );
                if !refinement.leaders.is_empty() {
                    let names = refinement
                        .leaders
                        .iter()
                        .map(|l| l.family.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    crate::selection_ui::progress(
                        app,
                        &format!(
                            "Уточняю варианты семейств {names}. Осталось проверить {}.",
                            next.len()
                        ),
                    )?;
                }
                skipped.extend(omitted);
                schedule.extend(next);
                family_selection = Some(refinement);
            }
        }
        collect_round_summaries(&table, &round_ids, &clean, &mut round_sums)?;
    }
    skipped.retain(|id| !round_sums.contains_key(id));
    skipped.sort();
    skipped.dedup();
    let rounds_measured: BTreeMap<_, _> = round_sums
        .iter()
        .map(|(id, rows)| (id.clone(), rows.len()))
        .collect();
    let mut sums: Vec<RankRow> = round_sums
        .into_values()
        .map(|values| {
            let mut row = values.last().expect("measured round").clone();
            row.score = values.iter().map(|row| row.score).sum::<f64>() / values.len() as f64;
            row.ok = values.iter().map(|row| row.ok).sum::<f64>() / values.len() as f64;
            for (group, points) in &mut row.groups {
                *points = values
                    .iter()
                    .map(|row| row.groups.get(group).copied().unwrap_or(0.))
                    .sum::<f64>()
                    / values.len() as f64;
            }
            row
        })
        .collect();
    ensure!(!sums.is_empty(), "Нет завершённых измерений стратегий");
    sums.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then((a.id != settings.get("alt")).cmp(&(b.id != settings.get("alt"))))
            .then(a.freeze.cmp(&b.freeze))
    });
    let qualified = qualified_scores(&sums, &strategy_quality);
    let no_comparison = missing_comparison(settings.get("alt"), &candidates, &qualified);
    let quality_ok = !qualified.is_empty() && !no_comparison;
    let best = qualified.first().unwrap_or(&sums[0]).clone();
    let history_context = sha256(
        format!(
            "native-score-v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            result_context.network_key,
            result_context.inputs_hash,
            serde_json::to_string(&targets)?,
            arguments.timeout_ms,
            arguments.parallel(),
            arguments.retry_parallel(),
            arguments.full
        )
        .as_bytes(),
    );
    let (averages, history) = score_history(&app.root, &qualified, &all, &history_context)?;
    let mut ordered_by_average = qualified.clone();
    ordered_by_average.sort_by(|a, b| {
        averages[&b.id]
            .0
            .total_cmp(&averages[&a.id].0)
            .then((a.id != settings.get("alt")).cmp(&(b.id != settings.get("alt"))))
            .then(a.freeze.cmp(&b.freeze))
    });
    let details: BTreeMap<_, _> = table
        .iter()
        .map(|(id, rows)| (id.clone(), probe_details(rows)))
        .collect();
    let use_history = app.yes && !arguments.apply;
    let mut order = if use_history {
        ordered_by_average
    } else {
        qualified.clone()
    };
    let panel = Panel::for_trials(&order, &details);
    panel.prioritize(&mut order, &details, settings.get("alt"));
    let proposed = order.first().unwrap_or(&best);
    let screening = crate::selection_latency::recommend(&order, &details, panel);
    let mut latency_preference = screening.preference;
    // Within an equal service tier prioritize() places the current primary first.
    let service_progress = panel == Panel::Services && proposed.id != settings.get("alt");
    let noise = app.yes
        && (strategy_quality.get(settings.get("alt")) != Some(&true)
            || averages.get(settings.get("alt")).is_some_and(|current| {
                averages.get(&proposed.id).is_none_or(|proposed| {
                    proposed.0 - current.0 < 2. && latency_preference.is_none() && !service_progress
                })
            }));
    let proposed = proposed.clone();
    let trial_best = if panel == crate::selection_latency::Panel::Services {
        latency_preference
            .as_ref()
            .and_then(|p| order.iter().find(|r| r.id == p.candidate))
            .unwrap_or(&proposed)
            .clone()
    } else {
        best
    };
    let mut best = trial_best.clone();
    let mut candidate = settings.clone();
    let mut select = false;
    let mut choice = if arguments.report_only {
        "report_only"
    } else if arguments.keep_primary {
        "kept"
    } else {
        "unchanged"
    };
    let mut recommendation_status = if arguments.report_only || arguments.keep_primary || noise {
        "trial_only"
    } else {
        "unconfirmed"
    };
    let base = summary("0", &table["0"], &BTreeMap::new());
    let rank = TestRank {
        date: Some(Local::now().format("%Y-%m-%d %H:%M").to_string()),
        version: VERSION.into(),
        base_ok: base.ok,
        base_total: base.total,
        base_groups: base.groups,
        base_group_totals: base.group_totals,
        rows: qualified.clone(),
        context: Some(result_context.clone()),
    };
    let cover: Coverage = table
        .iter()
        .filter(|(id, _)| id.as_str() == "0" || strategy_quality.get(*id) == Some(&true))
        .map(|(id, rows)| {
            (
                id.clone(),
                rows.iter()
                    .filter(|row| row.state == "OK")
                    .map(|row| format!("{}|{}", row.group, row.name))
                    .collect(),
            )
        })
        .collect();
    let mut accepted = false;
    let mut validation_error = no_comparison.then(|| {
        "Ни одна альтернативная стратегия не прошла проверку надёжности. Прежний рейтинг сохранён."
            .to_owned()
    });
    let mut final_details = Vec::new();
    let mut final_checks = BTreeMap::new();
    let mut latency_rechecks = Vec::new();
    let mut availability_checks = BTreeMap::new();
    let mut decision_reason = None;
    let names: BTreeMap<_, _> = all
        .iter()
        .map(|s| (s.id.clone(), s.display_name().to_owned()))
        .collect();
    let mut retained_check = None;
    let update_quick_history = updates_quick_history(arguments) && !no_comparison;
    if update_quick_history {
        learning.observe(&sums, &strategy_quality, &hashes, Utc::now().timestamp());
        if quick_screen.is_some() {
            learning.note_screened(&candidates, &hashes);
        }
    }
    let mut working_details = Vec::new();
    let network_metrics;
    if !arguments.report_only && quality_ok {
        crate::selection_ui::heading(app, "Проверяю текущий рабочий режим перед применением…")?;
        let primary = settings.get("alt");
        let original_command = prepare_trial_command(&context, &settings, primary, true)?;
        let mut reference_engine = Some(start_trial(snapshot.root(), &original_command, lifetime)?);
        let reference_result = measured(
            &context,
            &targets,
            arguments,
            &mut reference_engine,
            &json!({"Schema":1,"RunId":run_id,"Stage":"working-reference","StrategyId":settings.get("alt")}),
            &baseline(&table["0"]),
            &BTreeSet::new(),
        );
        let (working_reference, _) = finish_trial(reference_engine, reference_result)?;
        working_details = probe_details(&working_reference);
        zapret_core::save_rank(snapshot.root(), &rank)?;
        zapret_core::save_cover(snapshot.root(), &cover, &result_context)?;
        let mut check_index = 0;
        let mut measure_final = |id: &str,
                                 command: &[String],
                                 retained: bool|
         -> Result<crate::selection_decision::Check> {
            check_index += 1;
            context.assert_current()?;
            let name = all
                .iter()
                .find(|s| s.id == id)
                .map_or(id, Strategy::display_name);
            let stage = if retained { "retained" } else { "final" };
            let label = if retained {
                format!("{name} (прежний порядок автосмены)")
            } else {
                name.to_owned()
            };
            crate::selection_ui::heading(app, &format!("Проверяю рабочий режим: {label}"))?;
            let mut engine = Some(start_trial(snapshot.root(), command, lifetime)?);
            let actual = measured(
                &context,
                &targets,
                arguments,
                &mut engine,
                &json!({"Schema":1,"RunId":run_id,"Stage":stage,"StrategyId":id,"CandidateCheck":check_index}),
                &baseline(&table["0"]),
                &BTreeSet::new(),
            );
            let (actual, _) = finish_trial(engine, actual)?;
            // The retained command only needs to preserve its own working coverage.
            let expected = if retained {
                final_reference(
                    &working_reference,
                    &[],
                    &[],
                    crate::selection_latency::Panel::All,
                )
            } else {
                let measured = table
                    .get(id)
                    .context("Рабочая стратегия отсутствует в измерении")?;
                final_reference(&working_reference, measured, &table["0"], panel)
            };
            let check = endpoints::validate_final(
                &targets,
                &expected,
                &actual,
                |requests, previous| {
                    let cmd = if previous {
                        original_command.as_slice()
                    } else {
                        command
                    };
                    let mut stage_info = json!({"RunId":run_id, "Schema":1, "StrategyId":id, "CandidateCheck":check_index,
                        "Stage": if previous { "dns-peer-previous" } else { "dns-peer-final" }});
                    if previous {
                        stage_info["StrategyId"] = json!(primary);
                    }
                    prepare_trial_inputs(snapshot.root(), &settings)?;
                    let attempts = if previous { 2 } else { 1 };
                    let parallel = arguments.retry_parallel();
                    let budget = batch_budget(requests.len(), parallel, arguments.timeout_ms)?;
                    let mut trial = Some(start_trial(
                        snapshot.root(),
                        cmd,
                        budget * attempts + 30000,
                    )?);
                    let result = (|| {
                        let mut rows = Vec::new();
                        for attempt in 1..=attempts {
                            rows.extend(probe_batch(
                                &context,
                                requests,
                                parallel,
                                arguments.timeout_ms,
                                &mut trial,
                                &stage_info,
                                attempt as usize,
                            )?);
                        }
                        Ok(rows)
                    })();
                    finish_trial(trial, result)
                },
            )?;
            context.assert_current()?;
            crate::selection_ui::validation_notice(
                app,
                &label,
                check.error.as_deref(),
                arguments.details,
            )?;
            Ok(check)
        };
        let mut primary_command_changed = false;
        let mut validate = |id: &str| {
            let mut checked_settings = settings.clone();
            checked_settings.set("alt", id)?;
            let command = prepare_trial_command(&context, &checked_settings, id, true)?;
            if id == primary {
                primary_command_changed = command != original_command;
            }
            measure_final(id, &command, false)
        };
        if !arguments.keep_primary && (!noise || arguments.apply) {
            order.retain(|row| {
                row.id == proposed.id
                    || !app.yes
                    || arguments.apply
                    || panel == crate::selection_latency::Panel::Services
                    || averages
                        .get(settings.get("alt"))
                        .is_some_and(|current| averages[&row.id].0 - current.0 >= 2.)
                    || latency_preference
                        .as_ref()
                        .is_some_and(|_| crate::selection_latency::eligible(&proposed, row, panel))
            });
            let decision = crate::selection_decision::verified_preferred(
                &order,
                arguments.full,
                &details,
                panel,
                primary,
                |id, check| {
                    let clean = baseline(&table["0"]);
                    let mut working =
                        gains::improvements(&working_details, &check.details, &clean, panel);
                    let regressions =
                        gains::improvements(&check.details, &working_details, &clean, panel);
                    if !regressions.is_empty() {
                        working.clear();
                    }
                    let reference = details
                        .get(primary)
                        .map(Vec::as_slice)
                        .unwrap_or(&working_details);
                    let tested = gains::improvements(reference, &details[id], &clean, panel);
                    let mut proof = gains::verify(
                        &tested,
                        &working,
                        &targets,
                        &clean,
                        panel,
                        |requests, previous| {
                            let mut candidate_settings = settings.clone();
                            candidate_settings.set("alt", id)?;
                            let command = if previous {
                                prepare_trial_inputs(snapshot.root(), &settings)?;
                                original_command.clone()
                            } else {
                                prepare_trial_command(&context, &candidate_settings, id, true)?
                            };
                            let mut engine = Some(start_trial(
                                snapshot.root(),
                                &command,
                                engine_budget(requests.len(), arguments, false)?,
                            )?);
                            let metadata = json!({"Schema":1,"RunId":run_id,"Stage":"availability-repeat","StrategyId":if previous{primary}else{id}});
                            let result = measured(
                                &context,
                                requests,
                                arguments,
                                &mut engine,
                                &metadata,
                                &clean,
                                &BTreeSet::new(),
                            );
                            Ok(probe_details(&finish_trial(engine, result)?.0))
                        },
                    )?;
                    let confirmed = proof["confirmed"].as_array().is_some_and(|v| !v.is_empty());
                    proof["regressions"] = json!(regressions);
                    availability_checks.insert(id.to_owned(), proof);
                    Ok(confirmed)
                },
                &mut validate,
            )?;
            latency_preference = decision.preference;
            final_checks = decision.checks;
            latency_rechecks = decision.repeat_candidates;
            if let Some(recommended) = decision.recommended {
                best = recommended;
                decision_reason = gains::reason(&availability_checks, &best.id, primary, &names);
                recommendation_status = "confirmed";
                if best.id != settings.get("alt") {
                    let preview = json!({"best":best,"trial_best":trial_best,"rows":sums,"primary":settings.get("alt"),"final_checks":final_checks,"connection_selection":latency_preference,"timings":timings,
                        "trial_service_scores":screening.service_scores,"trial_score_reference":proposed.id,"decision_reason":decision_reason,
                        "strategy_names":all.iter().map(|s|(&s.id,s.display_name())).collect::<BTreeMap<_,_>>()});
                    select = arguments.apply || crate::selection_ui::choose_primary(app, &preview)?;
                    if select {
                        candidate.set("alt", &best.id)?;
                        choice = "apply";
                    } else {
                        choice = "kept";
                    }
                }
            } else {
                choice = "unconfirmed";
                crate::selection_ui::detail(
                    app,
                    arguments.details,
                    "Лучшие варианты не подтвердили рабочий режим. Основная стратегия сохранена.",
                )?;
            }
        }
        let selected = candidate.get("alt");
        let checked = match final_checks.get(selected) {
            Some(check) => check.clone(),
            None => validate(selected)?,
        };
        final_checks.insert(selected.into(), checked.clone());
        drop(validate);
        if !checked.confirmed && selected == primary && primary_command_changed {
            // The fresh rank can change the command even for the same primary.
            // Recheck the saved command without publishing the rejected rank.
            prepare_trial_inputs(snapshot.root(), &settings)?;
            retained_check = Some(measure_final(primary, &original_command, true)?);
        }
        final_details = checked.details.clone();
        if checked.confirmed && best.id == selected {
            recommendation_status = "confirmed";
        }
        context.check_current(true)?;
        snapshot.release_state_pins();
        let validation = if checked.confirmed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                checked
                    .error
                    .clone()
                    .unwrap_or_else(|| "Рабочий режим не подтверждён".into())
            ))
        };
        validation_error = accept_candidate(validation, || {
            publish(
                app,
                &settings,
                &candidate,
                &rank,
                &cover,
                &history,
                &all,
                || {
                    interrupt::check()?;
                    ensure!(
                        game_snapshot(app)?.is_subset(&approved_games),
                        "Во время сохранения запущена новая игра"
                    );
                    network_monitor.check(app, &journal, true)
                },
            )
        })?;
        network_metrics = network_monitor.metrics();
        accepted = validation_error.is_none();
        if let Some(error) = &validation_error {
            crate::selection_ui::detail(
                app,
                arguments.details,
                &format!(
                    "{error}. Прежние настройки сохранены; результаты проверки доступны в отчёте."
                ),
            )?;
        }
    } else {
        context.check_current(true)?;
        network_metrics = context.network_monitor.metrics();
        if !arguments.report_only {
            snapshot.release_state_pins();
        }
    }
    let cache_error = if update_quick_history {
        learning
            .save(&app.root)
            .err()
            .map(|error| format!("{error:#}"))
    } else {
        None
    };
    let availability: BTreeMap<_, _> = table
        .iter()
        .filter(|(id, _)| id.as_str() != "0")
        .map(|(id, rows)| (id.clone(), availability(rows).counts()))
        .collect();
    let primary = if accepted {
        candidate.get("alt")
    } else {
        settings.get("alt")
    };
    let next_quick_latency = if accepted && panel == Panel::Services {
        crate::selection_learning::next_candidates(&qualified, &details, &final_checks, primary)
    } else {
        Vec::new()
    };
    let mut report = json!({"schema":1,"run_id":run_id,"best":best,"trial_best":trial_best,"recommendation_status":recommendation_status,"final_checks":final_checks,"choice":choice,
        "selection_policy":if panel == crate::selection_latency::Panel::Services {crate::selection_latency::POLICY} else {crate::selection_latency::PREVIOUS_POLICY},"connection_selection":latency_preference,
        "primary_requested":candidate.get("alt"),"apply_requested":arguments.apply,"report_only":arguments.report_only,"presentation":if arguments.details{"detailed"}else{"compact"},"queued_candidates":queued_candidates,"rows":sums,"base":table["0"],"journal":journal,"availability":availability,
        "timings":timings,"elapsed_ms":test_started.elapsed().as_secs_f64()*1000.,"details":details,"working_reference":working_details,"final_details":final_details,"retained_check":retained_check,"validation_error":validation_error,"cache_error":cache_error,"deferred_history":deferred_history,
        "accepted":accepted,"quality_eligible":quality_ok,"strategy_quality":strategy_quality,"quality_reasons":quality_reasons,"averages":averages,"noise_margin":noise,"primary_changed":select&&accepted,"primary":primary,
        "skipped_ids":skipped,"rounds_measured":rounds_measured,"strategy_names":all.iter().map(|s|(&s.id,s.display_name())).collect::<BTreeMap<_,_>>(),"native_identity":native_hash,"context":result_context});
    report["latency_candidates"] = json!(latency_candidates);
    if panel == Panel::Services {
        report["trial_service_scores"] = json!(screening.service_scores);
        report["trial_score_reference"] = json!(proposed.id);
    }
    report["lighter_candidate"] = json!(lighter_candidate);
    report["next_quick_latency"] = json!(next_quick_latency);
    report["latency_rechecks"] = json!(latency_rechecks);
    report["availability_checks"] = json!(availability_checks);
    report["decision_reason"] = json!(decision_reason);
    report["family_selection"] = json!(family_selection);
    report["quick_screen"] = json!(quick_screen);
    report["strategy_families"] = json!(families::catalog(&all));
    report["parallel"] = json!(arguments.parallel());
    report["retry_parallel"] = json!(arguments.retry_parallel());
    report["endpoint_policy"] = json!("verified-baseline-peer-live-dns-final-v2");
    report["timeout_ms"] = json!(arguments.timeout_ms);
    report["network_monitor"] = network_metrics;
    report["shared_controls"] = json!(shared_controls);
    report["control_substitutions"] = json!(control_substitutions);
    report["retry_batches"] =
        json!({"sampled":sampled_batches.get(),"expanded":expanded_batches.get()});
    report["failed_profiles"] = json!(*failed_profiles.borrow());
    report["repeated_baseline_rounds"] = json!(repeated_baselines);
    Ok(report)
}

fn collect_round_summaries(
    table: &BTreeMap<String, Vec<Row>>,
    measured: &BTreeSet<String>,
    clean: &BTreeMap<String, f64>,
    sums: &mut BTreeMap<String, Vec<RankRow>>,
) -> Result<()> {
    for id in measured {
        let rows = table
            .get(id)
            .context("Нет измерений стратегии в текущем круге")?;
        sums.entry(id.clone())
            .or_default()
            .push(summary(id, rows, clean));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish(
    app: &App,
    previous: &Settings,
    candidate: &Settings,
    rank: &TestRank,
    cover: &Coverage,
    history: &[u8],
    all: &[Strategy],
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    let scope = rank.context.as_ref().context("Контекст рейтинга")?;
    let tested_path = runtime_file(&app.root, "tested-strategies.txt")?;
    let mut tested = zapret_core::list_lines(&tested_path)?;
    for row in &rank.rows {
        let strategy = all
            .iter()
            .find(|s| s.id == row.id)
            .context("Стратегия публикации отсутствует")?;
        let line = format!("{}|{}", strategy.id, strategy.name);
        if !tested.contains(&line) {
            tested.push(line);
        }
    }
    let mut written = Vec::new();
    let mut replace = |name: &str, write: &dyn Fn(&Path) -> Result<()>| -> Result<()> {
        let path = runtime_file(&app.root, name)?;
        let old = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        write(&path)?;
        written.push((path, old));
        Ok(())
    };
    check()?;
    ensure!(
        read_settings(&app.root)? == *previous,
        "Настройки изменились перед сохранением автоподбора"
    );
    let result = (|| {
        replace("test-rank.txt", &|_| {
            zapret_core::save_rank(&app.root, rank)
        })?;
        replace("test-cover.txt", &|_| {
            zapret_core::save_cover(&app.root, cover, scope)
        })?;
        if candidate != previous {
            replace("settings.ini", &|_| save_settings(&app.root, candidate))?;
        }
        replace("test-scores.txt", &|path| atomic_write(path, history))?;
        replace("tested-strategies.txt", &|path| {
            atomic_write(path, format!("{}\r\n", tested.join("\r\n")).as_bytes())
        })?;
        check()
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for (path, old) in written.into_iter().rev() {
            let restored = match old {
                Some(bytes) => atomic_write(&path, &bytes),
                None => match fs::remove_file(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    r => r.map_err(Into::into),
                },
            };
            if let Err(e) = restored {
                failures.push(format!("{}: {e:#}", path.display()));
            }
        }
        ensure!(
            failures.is_empty(),
            "{error:#}. Неполный откат автоподбора: {}",
            failures.join(", ")
        );
        return Err(error);
    }
    Ok(())
}

fn comparison(
    context: &RunContext<'_>,
    arguments: &TestArgs,
    settings: &Settings,
    targets: &[Target],
    all: &[Strategy],
    run_id: &str,
) -> Result<Value> {
    let journal = &context.journal;
    let a = arguments
        .compare_a
        .as_deref()
        .context("Для сравнения нужны --compare-a и --compare-b")?;
    let b = arguments
        .compare_b
        .as_deref()
        .context("Для сравнения нужны --compare-a и --compare-b")?;
    ensure!(
        a != b && (4..=12).contains(&arguments.compare_blocks) && arguments.compare_blocks % 2 == 0,
        "Неверные параметры сравнения"
    );
    ensure!(
        [a, b].iter().all(|id| all
            .iter()
            .any(|strategy| strategy.id == *id && strategy.is_valid())),
        "Стратегия сравнения отсутствует"
    );
    let mut rows = Vec::new();
    let seed = arguments
        .seed
        .unwrap_or_else(|| Utc::now().timestamp_micros() as u64);
    crate::selection_ui::progress(
        context.app,
        "Сравниваю две стратегии по очереди. Ctrl+C — остановить.",
    )?;
    for block in 0..arguments.compare_blocks + 2 {
        let calibration = block == 0 || block == arguments.compare_blocks + 1;
        let pattern = if (block + ((seed & 1) as usize)) % 2 == 0 {
            ['A', 'B', 'B', 'A']
        } else {
            ['B', 'A', 'A', 'B']
        };
        for (position, arm) in pattern.into_iter().enumerate() {
            let id = if calibration || arm == 'A' { a } else { b };
            let strategy_name = all
                .iter()
                .find(|strategy| strategy.id == id)
                .map(Strategy::display_name)
                .unwrap_or(id);
            let count = (arguments.compare_blocks + 2) * 4;
            crate::selection_ui::progress(
                context.app,
                &format!("[{} / {count}] {strategy_name}", block * 4 + position + 1),
            )?;
            let mut engine = Some(launch(
                context,
                settings,
                id,
                false,
                engine_budget(targets.len(), arguments, true)?,
            )?);
            let identity =
                serde_json::to_value(engine.as_ref().context("Движок сравнения")?.identity())?;
            let mut ready = context
                .app
                .platform("process-metrics", json!({"identity":identity}))?;
            ready["observed_monotonic_ms"] =
                json!(zapret_platform::monotonic_ms()? - context.clock_origin);
            let metadata = json!({"Schema":1,"RunId":run_id,"Stage":"comparison-warmup","ComparisonBlock":block,
                "ComparisonPosition":position,"ComparisonArm":arm,"StrategyId":id,"CapturedNetworkKey":context.network_key,
                "CapturedInputsHash":context.snapshot.fingerprint(),"NativeIdentity":context.native_hash});
            let warm = probe_batch(
                context,
                targets,
                arguments.parallel(),
                arguments.timeout_ms,
                &mut engine,
                &metadata,
                1,
            )?;
            let mut warm_metrics = context
                .app
                .platform("process-metrics", json!({"identity":identity}))?;
            warm_metrics["observed_monotonic_ms"] =
                json!(zapret_platform::monotonic_ms()? - context.clock_origin);
            let mut metadata = metadata;
            metadata["Stage"] = json!("comparison");
            let started_ms = zapret_platform::monotonic_ms()? - context.clock_origin;
            let result = measured(
                context,
                targets,
                arguments,
                &mut engine,
                &metadata,
                &baseline(&warm),
                &BTreeSet::new(),
            );
            let finished_ms = zapret_platform::monotonic_ms()? - context.clock_origin;
            let mut end = context
                .app
                .platform("process-metrics", json!({"identity":identity}))?;
            end["observed_monotonic_ms"] =
                json!(zapret_platform::monotonic_ms()? - context.clock_origin);
            let (probes, _) = finish_trial(engine, result)?;
            context.assert_current()?;
            let strategy_hash = all
                .iter()
                .find(|strategy| strategy.id == id)
                .context("Стратегия сравнения отсутствует")?
                .fingerprint()?;
            rows.push(json!({"block":block,"position":position,"arm":arm,"calibration":calibration,"strategy_id":id,"started_ms":started_ms,"finished_ms":finished_ms,
                "network_key":context.network_key,"inputs_hash":context.snapshot.fingerprint(),"native_hash":context.native_hash,
                "strategy_hash":strategy_hash,"context_validated":true,
                "probes":probes,"resources":{"ready":ready,"warm":warm_metrics,"end":end}}));
        }
    }
    context.check_current(true)?;
    let assessment = crate::comparison::assess(&rows, arguments.compare_blocks)?;
    let a_name = all
        .iter()
        .find(|strategy| strategy.id == a)
        .map(Strategy::display_name)
        .unwrap_or(a);
    let b_name = all
        .iter()
        .find(|strategy| strategy.id == b)
        .map(Strategy::display_name)
        .unwrap_or(b);
    let mut result = json!({"schema":1,"protocol":"finalists-native-v1","complete":true,"blocks":arguments.compare_blocks,"seed":seed,"a":a,"b":b,"a_name":a_name,"b_name":b_name,"run_id":run_id,"rows":rows,"text":assessment["text"],"assessment":assessment,"journal":journal});
    crate::comparison::seal_record(&mut result)?;
    let encoded = serde_json::to_vec_pretty(&result)?;
    atomic_write(
        &runtime_file(
            &context.app.root,
            &format!("comparison-native-{run_id}.json"),
        )?,
        &encoded,
    )?;
    atomic_write(
        &runtime_file(&context.app.root, "comparison-native-last.json")?,
        &encoded,
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    mod resilience;

    #[test]
    fn measurement_retries_unavailable_samples_and_reports_confirmed_changes() {
        let old = json!({"known":true,"key":"a","key_parts":{"proxy":"a"}});
        let new = json!({"known":true,"key":"b","key_parts":{"proxy":"b"}});
        let unavailable = json!({"known":false,"unavailable":["routes"]});
        let mut samples = [unavailable.clone(), old.clone()].into_iter();
        let mut pauses = 0;
        let current = read_measurement_network(
            || Ok(samples.next().unwrap()),
            || {
                pauses += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(pauses, 1);
        verify_measurement_network("a", &old["key_parts"], &current).unwrap();
        let current = read_measurement_network(
            || Ok(new.clone()),
            || panic!("confirmed samples need no retry"),
        )
        .unwrap();
        assert!(
            verify_measurement_network("a", &old["key_parts"], &current)
                .unwrap_err()
                .to_string()
                .contains("настройки прокси")
        );
        let mut attempts = 0;
        let err = read_measurement_network(
            || {
                attempts += 1;
                Ok(unavailable.clone())
            },
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(attempts, 3);
        assert!(err.to_string().contains("маршруты"));
        assert!(!err.to_string().contains("Подключение изменилось"));
    }
    fn final_reference(working: &[Row], measured: &[Row], baseline: &[Row]) -> Vec<Row> {
        super::final_reference(
            working,
            measured,
            baseline,
            crate::selection_latency::Panel::All,
        )
    }

    #[test]
    fn batch_journal_appends_existing_jsonl_and_leaves_prior_rows_readable_on_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("run.jsonl");
        fs::write(&path, b"{\"Attempt\":1}\n").unwrap();
        let mut journal = Journal::open(&path).unwrap();
        journal.append(&json!({"Attempt":2})).unwrap();
        // Exercise the limit without writing a 64 MiB fixture.
        journal.size = 64 * 1024 * 1024;
        assert!(journal.append(&json!({"Attempt":3})).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{\"Attempt\":1}\n{\"Attempt\":2}\n"
        );
    }

    #[test]
    fn previous_result_is_read_without_preparing_settings_or_controlling_the_bypass() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("runtime")).unwrap();
        fs::write(
            directory.path().join("runtime/settings.ini"),
            b"not valid settings\0",
        )
        .unwrap();
        let saved = json!({"schema":1,"best":{"id":"50"},"rows":[{"id":"50"}],"primary":"50"});
        fs::write(
            directory.path().join("runtime/test-native-last.json"),
            serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
        let app = App {
            root: directory.path().into(),
            yes: false,
            json: false,
        };
        let result = read_last(&app).unwrap();
        assert_eq!(result, saved);
        assert_eq!(
            fs::read(directory.path().join("runtime/settings.ini")).unwrap(),
            b"not valid settings\0"
        );
        fs::remove_file(directory.path().join("runtime/test-native-last.json")).unwrap();
        assert!(
            read_last(&app)
                .unwrap_err()
                .to_string()
                .contains("Результатов ещё нет")
        );
    }
    fn row(state: &str) -> Row {
        Row {
            group: "DPI".into(),
            name: "host".into(),
            url: "https://example.com/".into(),
            state: state.into(),
            code: "200".into(),
            exit: 0,
            up: 0.,
            down: 128.,
            conn_ms: 5.,
            tls_ms: 10.,
            dns_ms: 1.,
            first_byte_ms: 12.,
            total_ms: 15.,
            started_utc: String::new(),
            observed_utc: String::new(),
            started_ms: 0.,
            observed_ms: 15.,
            body_bytes: 128,
            body_limit: 65536,
            target_reached: false,
            body_complete: true,
            termination: "Complete".into(),
            tries: 1,
            flaky: false,
            failed_retry: None,
            raw: json!({}),
        }
    }
    #[test]
    fn retry_marks_recovered_results_flaky_and_final_replay_requires_actual_success() {
        let mut rows = vec![row("FAIL")];
        merge_retry(&mut rows, &[row("OK")]);
        assert!(rows[0].flaky);
        assert_eq!(summary("12", &rows, &BTreeMap::new()).score, 0.5);
        assert!(final_check(&rows, &[row("FAIL")]).is_err());
        assert!(final_check(&rows, &[row("OK")]).is_ok());
    }

    #[test]
    fn dns_rotation_requires_matched_success_and_reproduced_previous_failure() {
        let a = "192.0.2.134:443";
        let b = "192.0.2.130:443";
        let target: Target = serde_json::from_value(json!({
            "group":"Discord","name":"avatar","url":"https://cdn.example.test/avatar"
        }))
        .unwrap();
        let observed = |peer: &str, ok: bool| {
            let mut sample = row(if ok { "OK" } else { "FAIL" });
            sample.group = target.group.clone();
            sample.name = target.name.clone();
            sample.url = target.url.clone();
            sample.raw = json!({"remote_address":peer,"resolved_addresses":[a,b],
                "status_code":if ok {Some(200)} else {None},"body_bytes":if ok {128} else {0},
                "stage":if ok {"Complete"} else {"Tls"},"termination":if ok {"Complete"} else {"TlsFailure"}});
            sample
        };
        let targets = std::slice::from_ref(&target);
        let expected = [observed(a, true)];
        let actual = [observed(b, false)];
        let mut clean = row("OK");
        clean.group = "Clean".into();
        clean.name = "adobe".into();
        let mut slow = clean.clone();
        slow.tls_ms += 501.;
        let veto = endpoints::validate_final(
            targets,
            &[expected[0].clone(), clean],
            &[actual[0].clone(), slow],
            |_, _| panic!("peer replays cannot change the control veto"),
        )
        .unwrap();
        assert!(!veto.confirmed);
        assert_eq!(veto.details.len(), 2);
        let error = veto.error.unwrap();
        assert!(error.contains("Clean/adobe") && !error.contains("Discord/avatar"));
        assert!(endpoints::for_round(targets, &actual)[0].peer.is_none());
        let mut intermittent = observed(b, true);
        intermittent.flaky = true;
        intermittent.tries = 2;
        assert!(
            endpoints::for_round(targets, &[intermittent])[0]
                .peer
                .is_none()
        );
        let round = endpoints::for_round(targets, &[observed(b, true)]);
        let job = round[0].job(5000, false);
        assert_eq!(job.connect_ip, Some("192.0.2.130".parse().unwrap()));
        assert_eq!(job.url, target.url);
        assert!(target.job(5000, false).connect_ip.is_none());
        for (candidate_ok, old_ok, pass) in [
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            let (compared, details) =
                endpoints::compare_final(targets, &expected, &actual, |jobs, previous| {
                    assert_eq!(jobs.len(), 1);
                    assert_eq!(jobs[0].url, target.url);
                    let peer = if previous { b } else { a };
                    assert_eq!(jobs[0].peer.unwrap().to_string(), peer);
                    Ok(vec![
                        observed(
                            peer,
                            if previous { old_ok } else { candidate_ok }
                        );
                        if previous { 2 } else { 1 }
                    ])
                })
                .unwrap();
            assert_eq!(final_check(&expected, &compared).is_ok(), pass);
            assert_eq!(details[0]["state"], "FAIL");
            assert_eq!(details[0]["peer_comparison"]["shared_failure"], pass);
        }
        let mut retired = observed(b, false);
        retired.raw["resolved_addresses"] = json!([b]);
        let mut different_retry = observed(b, false);
        different_retry.failed_retry = Some(observed(a, false).raw);
        for unpaired in [observed(a, false), retired, different_retry] {
            let (compared, _) =
                endpoints::compare_final(targets, &expected, &[unpaired], |_, _| {
                    panic!("same-peer failure or stale address must not be replaced")
                })
                .unwrap();
            assert!(final_check(&expected, &compared).is_err());
        }
        let mut raw = observation(&round[0]);
        raw["dns_source"] = json!("connect_ip override");
        raw["resolved_addresses"] = json!([b]);
        raw["remote_address"] = json!(a);
        assert!(convert(&round[0], raw.clone(), Utc::now()).is_err());
        raw["remote_address"] = json!(b);
        assert!(convert(&round[0], raw, Utc::now()).is_ok());
    }

    #[test]
    fn final_application_compares_working_coverage_without_dropping_real_service_or_clean_regressions()
     {
        let mut dpi = row("OK");
        dpi.group = "DPI".into();
        dpi.name = "Hetzner".into();
        let mut service = row("OK");
        service.group = "YouTube".into();
        service.name = "web".into();
        let mut clean = row("OK");
        clean.group = "Clean".into();
        clean.name = "sony".into();
        let isolated = vec![dpi.clone(), service.clone(), clean.clone()];
        dpi.state = "FAIL".into();
        dpi.tls_ms = 0.;
        let working = vec![dpi, service, clean.clone()];
        let expected = final_reference(&working, &isolated, &[clean]);
        assert!(final_check(&expected, &working).is_ok());
        let mut broken = working.clone();
        broken[1].state = "FAIL".into();
        assert!(final_check(&expected, &broken).is_err());
        let mut broken = working.clone();
        broken[2].tls_ms += 501.;
        assert!(final_check(&expected, &broken).is_err());
        let mut recovered = working.clone();
        recovered[0].state = "OK".into();
        recovered[0].tls_ms = 50.;
        let expected = final_reference(&recovered, &isolated, &[]);
        assert!(final_check(&expected, &working).is_err());
        let services = super::final_reference(
            &recovered,
            &isolated,
            &[],
            crate::selection_latency::Panel::Services,
        );
        assert!(final_check(&services, &working).is_ok());
        assert!(final_check(&services, &broken).is_err());
    }

    #[test]
    fn flaky_oracle_reference_does_not_veto_a_working_candidate_or_hide_real_regressions() {
        let mut oracle = row("OK");
        oracle.name = "SG.OR-01 Oracle".into();
        oracle.url = "https://ged.com.sg/".into();
        oracle.conn_ms = 387.0705;
        oracle.tls_ms = 767.0383;
        oracle.tries = 2;
        oracle.flaky = true;
        let mut service = row("OK");
        service.group = "YouTube".into();
        service.name = "web".into();
        let mut clean = row("OK");
        clean.group = "Clean".into();
        clean.name = "sony".into();
        let working = vec![oracle.clone(), service.clone(), clean.clone()];
        let mut measured = working.clone();
        measured[0].flaky = false;
        measured[0].tries = 1;
        let mut actual = measured.clone();
        actual[0].state = "FAIL".into();
        actual[0].conn_ms = 402.2447;
        actual[0].tls_ms = 801.5965;
        actual[0].tries = 2;

        let expected = final_reference(&working, &measured, std::slice::from_ref(&clean));
        final_check(&expected, &actual).unwrap();
        assert_eq!(availability(&actual).ok, 1);
        assert_eq!(actual[0].state, "FAIL");

        let mut stable_reference = working.clone();
        stable_reference[0].flaky = false;
        let expected = final_reference(&stable_reference, &measured, &[]);
        assert!(final_check(&expected, &actual).is_err());

        for group in ["YouTube", "Clean"] {
            let mut reference = working.clone();
            reference[0].group = group.into();
            let mut regressed = actual.clone();
            regressed[0].group = group.into();
            let expected = final_reference(&reference, &measured, &[]);
            assert!(final_check(&expected, &regressed).is_err());
        }
        let mut regressed = actual.clone();
        regressed[1].state = "FAIL".into();
        assert!(final_check(&final_reference(&working, &measured, &[]), &regressed).is_err());
        let mut regressed = actual.clone();
        regressed[2].tls_ms = clean.tls_ms + 501.;
        assert!(final_check(&final_reference(&working, &measured, &[clean]), &regressed).is_err());
    }

    #[test]
    fn failed_final_validation_preserves_a_rejection_without_committing_settings() {
        let committed = std::cell::Cell::new(false);
        let result = accept_candidate(final_check(&[row("OK")], &[row("FAIL")]), || {
            committed.set(true);
            Ok(())
        });
        assert!(!committed.get());
        assert!(result.unwrap().unwrap().contains("Финальная комбинация"));
        assert!(accept_candidate(Ok(()), || anyhow::bail!("write failure")).is_err());
    }

    #[test]
    fn final_errors_identify_all_lost_targets_once_even_if_multiple_references_require_them() {
        let mut a = row("OK");
        a.name = "FI.HE-03 Hetzner".into();
        let mut b = row("OK");
        b.name = "FR.OVH-01 OVH".into();
        let expected = vec![a.clone(), b.clone(), a.clone()];
        a.state = "FAIL".into();
        a.termination = "TlsFailure".into();
        let error = final_check(&expected, &[a]).unwrap_err().to_string();
        assert!(error.starts_with(
            "Финальная комбинация не подтвердила DPI/FI.HE-03 Hetzner, DPI/FR.OVH-01 OVH: "
        ));
        assert!(error.contains("сбой TLS") && error.contains("адрес отсутствует"));
        // A separately measured original configuration can pass. The proposed rank still cannot publish.
        assert!(final_check(&expected, &expected).is_ok());
        assert!(
            accept_candidate(Err(anyhow::anyhow!(error)), || panic!(
                "rank must be preserved"
            ))
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn rejected_final_run_still_has_its_own_report_with_probe_timings() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("runtime")).unwrap();
        let app = App {
            root: root.path().into(),
            yes: false,
            json: false,
        };
        let mut report = json!({"schema":1,"run_id":"1234567890abcdef1234567890abcdef","best":{"id":"50"},"rows":[{"id":"50","score":49.,"total":54}],
            "primary":"50","accepted":false,"primary_changed":false,"validation_error":"Clean/sony: TLS 900 мс",
            "strategy_names":{"50":"ALT11 белый 1"},"timings":{"50":{"tcp_ms":42.,"tls_ms":93.}},
            "details":{"50":[{"group":"Clean","name":"sony","state":"OK","code":"302","tcp_ms":42.,"tls_ms":93.,"tries":2,"flaky":false}]}});
        save_report(&app, &mut report).unwrap();
        let path = PathBuf::from(report["report_file"].as_str().unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("sony") && text.contains("TCP 42 мс") && text.contains("TLS 93 мс"));
        assert!(text.contains("Прежние настройки сохранены"));
        let saved: Value = serde_json::from_slice(
            &fs::read(root.path().join("runtime/test-native-last.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["accepted"], false);
        assert_eq!(saved["validation_error"], report["validation_error"]);
        assert_eq!(saved["text_sha256"], sha256(text.as_bytes()));
        assert!(
            root.path()
                .join("runtime/test-native-1234567890abcdef1234567890abcdef.json")
                .is_file()
        );
        assert!(!root.path().join("runtime/settings.ini").exists());
    }
    #[test]
    fn response_counts_show_real_answers_instead_of_the_half_credit_score() {
        let mut recovered = row("OK");
        recovered.flaky = true;
        let timed_out = row("FREEZE");
        let mut control = row("OK");
        control.group = "Clean".into();
        let absent = row("NA");
        let rows = vec![recovered, timed_out, control, absent];
        assert_eq!(availability(&rows).counts(), json!({"ok":1,"total":2}));
        assert_eq!(summary("50", &rows, &BTreeMap::new()).ok, 0.5);
    }
    #[test]
    fn response_delta_uses_the_same_available_targets_in_any_worker_order() {
        let first = row("OK");
        let mut second = row("FAIL");
        second.name = "second".into();
        let baseline = availability(&[first.clone(), second.clone()]);
        second.state = "OK".into();
        second.flaky = true;
        assert_eq!(
            availability(&[second.clone(), first.clone()]).change_from(&baseline),
            Some(1)
        );
        let mut absent = first;
        absent.state = "NA".into();
        let before = availability(&[absent.clone(), second.clone()]);
        second.name = "different".into();
        assert_eq!(
            availability(&[absent.clone(), second]).change_from(&before),
            None
        );
        assert_eq!(
            availability(&[absent]).change_from(&availability(&[])),
            None
        );
    }
    #[test]
    fn one_unstable_trial_does_not_discard_other_confirmed_strategies() {
        let rows = vec![
            RankRow {
                id: "13".into(),
                score: 52.,
                ..Default::default()
            },
            RankRow {
                id: "58".into(),
                score: 49.5,
                ..Default::default()
            },
            RankRow {
                id: "31".into(),
                score: 49.,
                ..Default::default()
            },
        ];
        let quality = BTreeMap::from([
            ("13".into(), false),
            ("58".into(), true),
            ("31".into(), true),
        ]);
        let qualified = qualified_scores(&rows, &quality);
        assert_eq!(
            qualified
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["58", "31"]
        );
        assert_eq!(qualified[0].score, 49.5);
    }
    #[test]
    fn missing_or_failed_control_evidence_never_qualifies_a_score() {
        let rows = vec![RankRow {
            id: "58".into(),
            score: 49.5,
            ..Default::default()
        }];
        assert!(qualified_scores(&rows, &BTreeMap::new()).is_empty());
        assert!(qualified_scores(&rows, &BTreeMap::from([("58".into(), false)])).is_empty());
    }

    #[test]
    fn quick_search_can_finish_when_a_strategy_opens_previously_blocked_targets() {
        let mut blocked = row("FAIL");
        blocked.tls_ms = 0.;
        let mut clean = row("OK");
        clean.group = "Clean".into();
        assert!(fully_covered(
            &[blocked.clone(), clean.clone()],
            &[row("OK"), clean.clone()]
        ));
        assert!(!fully_covered(
            &[blocked.clone(), clean.clone()],
            &[row("FAIL"), clean.clone()]
        ));
        blocked.state = "NA".into();
        assert!(!fully_covered(
            &[blocked, clean.clone()],
            &[row("OK"), clean]
        ));
    }

    #[test]
    fn http_control_uses_tcp_latency_for_coverage_scoring_and_validation() {
        let mut clean = row("OK");
        clean.group = "Clean".into();
        clean.url = "http://example.test/connecttest.txt".into();
        clean.tls_ms = 0.;
        let baseline_rows = [row("OK"), clean.clone()];
        let baseline_times = baseline(&baseline_rows);
        assert_eq!(baseline_times[&clean.name], clean.conn_ms);
        assert!(fully_covered(&baseline_rows, &baseline_rows));
        let mut slow = baseline_rows.clone();
        slow[1].conn_ms += 501.;
        assert!(!fully_covered(&baseline_rows, &slow));
        assert_eq!(summary("1", &slow, &baseline_times).harm, 1);
        assert!(final_check(&baseline_rows, &slow).is_err());
        assert!(!crate::selection_latency::preserves_services(
            &probe_details(&baseline_rows[1..]),
            &probe_details(&slow[1..]),
            crate::selection_latency::Panel::All
        ));
    }
    #[test]
    fn family_normalization_retains_protocol_and_fooling_differences() {
        let mut first = Strategy {
            id: "12".into(),
            ..Default::default()
        };
        first.sections.insert(
            "general".into(),
            vec!["--lua-desync=multisplit:pos=1,2:fooling=md5sig".into()],
        );
        let mut second = first.clone();
        second.sections.get_mut("general").unwrap()[0] =
            "--lua-desync=multisplit:pos=3,4:fooling=md5sig".into();
        assert_eq!(families::signature(&first), families::signature(&second));
        second.sections.get_mut("general").unwrap()[0] =
            "--lua-desync=multisplit:pos=3,4:fooling=badsum".into();
        assert_ne!(families::signature(&first), families::signature(&second));
    }

    fn observation(target: &Target) -> Value {
        json!({"version":1,"worker_version":"fixture","id":target.id(),"url":target.url,
            "stage":"Complete","termination":"Complete","error":null,"status_code":200,
            "body_bytes":128,"received_body_bytes":128,"body_limit":65536,"body_complete":true,
            "target_reached":false,"post_bytes":0,"request_body_bytes_provided":0,"request_body_measurement":"fixture",
            "dns_source":"fixture","resolved_addresses":["127.0.0.1"],"tcp_attempts":[],"remote_address":"127.0.0.1:443",
            "tls_backend":"Schannel","tls_profile":"fixture","trust_source":"System","certificate_validated":true,
            "dns_ms":1.,"tcp_ms":2.,"tls_ms":3.,"headers_ms":4.,"started_ms":0.,"total_ms":15.})
    }

    #[test]
    fn file_checks_require_the_expected_http_status_size_and_eof() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("tools")).unwrap();
        let file = root.path().join("tools/targets.txt");
        fs::write(
            &file,
            "Game.store GET 200 91315 2c073e9176cd934933b5914534017ffe89607b91a4966fea392291026b0eb7f5 = https://example.test/file?id=1\n\
            QUIC.google H3 204 0 = https://example.test/check\n\
            Clean.basic = https://example.test/\n\
            Clean.plain GET 200 22 = http://example.test/connect.txt\n",
        )
        .unwrap();
        let targets = read_targets(root.path(), &parse_test(&[])).unwrap();
        let target = &targets[0];
        let job = target.job(3000, false);
        assert_eq!(job.body_limit, 91316);
        assert_eq!(job.mode, ProbeMode::FullGet);
        assert_eq!(job.url, "https://example.test/file?id=1");
        assert_eq!(targets[1].job(3000, false).method.as_deref(), Some("HEAD"));
        assert_eq!(targets[2].job(3000, true).mode, ProbeMode::Range);
        let ab = read_targets(
            root.path(),
            &parse_test(&["--compare-a", "1", "--compare-b", "2"]),
        )
        .unwrap();
        assert_eq!(
            ab.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["store", "basic"]
        );
        let hash = target.expected.as_ref().unwrap().sha256.as_ref().unwrap();

        for (code, size, termination, expected) in [
            (200, 91315, "Complete", "OK"),
            (403, 91315, "Complete", "FAIL"),
            (404, 128, "Complete", "FAIL"),
            (200, 16384, "Complete", "FAIL"),
            (200, 16384, "Timeout", "FREEZE"),
            (200, 91316, "BodyLimit", "FAIL"),
        ] {
            let mut value = observation(target);
            for (key, field) in [
                ("mode", json!("full_get")),
                ("status_code", json!(code)),
                ("body_limit", json!(job.body_limit)),
                ("body_bytes", json!(size)),
                ("received_body_bytes", json!(size)),
                ("body_sha256", json!(hash)),
                ("termination", json!(termination)),
                ("body_complete", json!(termination == "Complete")),
                ("target_reached", json!(termination == "BodyLimit")),
            ] {
                value[key] = field;
            }
            assert_eq!(convert(target, value, Utc::now()).unwrap().state, expected);
        }
        let mut substituted = observation(target);
        for (key, field) in [
            ("mode", json!("full_get")),
            ("body_limit", json!(91316)),
            ("body_bytes", json!(91315)),
            ("received_body_bytes", json!(91315)),
            ("body_sha256", json!("0".repeat(64))),
        ] {
            substituted[key] = field;
        }
        assert_eq!(
            convert(target, substituted, Utc::now()).unwrap().state,
            "FAIL"
        );
        assert!(convert(&targets[1], observation(&targets[1]), Utc::now()).is_err());
        for fields in [
            "GET 200 4..1",
            "H3 204 1",
            "GET 200 1048576",
            "GET 404 0",
            "GET 200 22 invalid-sha",
            "typo",
        ] {
            fs::write(
                &file,
                format!("Game.store {fields} = https://example.test/"),
            )
            .unwrap();
            assert!(
                read_targets(root.path(), &parse_test(&[])).is_err(),
                "{fields}"
            );
        }
    }

    #[test]
    fn worker_batch_requires_one_complete_typed_observation_per_target() {
        let target = Target {
            group: "Clean".into(),
            name: "fixture".into(),
            url: "https://fixture.invalid/".into(),
            post: false,
            expected: None,
            peer: None,
        };
        let value = observation(&target);
        let bytes = serde_json::to_vec(&value).unwrap();
        let targets = std::slice::from_ref(&target);
        assert_eq!(
            parse_observations(targets, &bytes, Utc::now()).unwrap()[0].state,
            "OK"
        );
        assert!(parse_observations(targets, b"", Utc::now()).is_err());
        let duplicate = format!("{value}\n{value}\n");
        assert!(parse_observations(targets, duplicate.as_bytes(), Utc::now()).is_err());
        for key in ["body_complete", "received_body_bytes", "tls_backend"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                convert(&target, missing, Utc::now()).is_err(),
                "missing {key}"
            );
        }
        let mut foreign = value.clone();
        foreign["id"] = json!("foreign");
        assert!(
            parse_observations(targets, &serde_json::to_vec(&foreign).unwrap(), Utc::now())
                .is_err()
        );
        for termination in ["Cancelled", "Deadline", "Invented"] {
            let mut interrupted = value.clone();
            interrupted["termination"] = json!(termination);
            assert!(
                convert(&target, interrupted, Utc::now()).is_err(),
                "{termination}"
            );
        }
    }

    #[test]
    fn worker_success_requires_verified_tls_and_consistent_transfer_evidence() {
        let target = Target {
            group: "Clean".into(),
            name: "fixture".into(),
            url: "https://fixture.invalid/".into(),
            post: false,
            expected: None,
            peer: None,
        };
        for (key, value) in [
            ("body_complete", json!(false)),
            ("certificate_validated", json!(false)),
            ("target_reached", json!(true)),
            ("received_body_bytes", json!(0)),
            ("request_body_bytes_provided", json!(1)),
            ("tls_ms", Value::Null),
            ("total_ms", json!(-1)),
        ] {
            let mut invalid = observation(&target);
            invalid[key] = value;
            assert!(convert(&target, invalid, Utc::now()).is_err(), "{key}");
        }
        let mut bounded = observation(&target);
        bounded["body_bytes"] = json!(65536);
        bounded["received_body_bytes"] = json!(70000);
        bounded["body_complete"] = json!(false);
        bounded["target_reached"] = json!(true);
        bounded["termination"] = json!("BodyLimit");
        bounded["stage"] = json!("Body");
        assert_eq!(convert(&target, bounded, Utc::now()).unwrap().state, "OK");
    }

    #[test]
    fn engine_lifetime_covers_serial_warmup_and_retry_and_rejects_impossible_batches() {
        let arguments = TestArgs {
            parallel: Some(1),
            timeout_ms: 5000,
            ..Default::default()
        };
        let main = batch_budget(68, 1, 5000).unwrap();
        assert!(main > 120000);
        assert!(engine_budget(68, &arguments, true).unwrap() > main * 3);
        assert!(batch_budget(256, 1, 60000).is_err());
        assert!(batch_budget(0, 1, 5000).is_err());
    }

    fn parse_test(flags: &[&str]) -> TestArgs {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(
            ["zapret-rust", "test"]
                .into_iter()
                .chain(flags.iter().copied()),
        )
        .unwrap();
        let Some(crate::cli::Action::Test(args)) = cli.action else {
            panic!("expected test arguments");
        };
        args
    }

    #[test]
    fn full_pick_defaults_use_wider_batches_without_overriding_explicit_parallelism() {
        let widths = |args: TestArgs| (args.parallel(), args.retry_parallel());
        assert_eq!(widths(parse_test(&[])), (16, 4));
        assert_eq!(widths(parse_test(&["--full"])), (32, 8));
        assert_eq!(widths(parse_test(&["--full", "--parallel", "16"])), (16, 4));
        assert_eq!(widths(parse_test(&["--full", "--parallel", "2"])), (2, 2));
        assert_eq!(widths(parse_test(&["--full", "--parallel", "64"])), (64, 8));
        assert!(updates_quick_history(&parse_test(&[])));
        assert!(!updates_quick_history(&parse_test(&["--full"])));
        assert!(updates_quick_history(&parse_test(&[
            "--full",
            "--parallel",
            "16"
        ])));
        assert!(!updates_quick_history(&parse_test(&["--report-only"])));
        assert_eq!(
            widths(parse_test(&[
                "--full",
                "--compare-a",
                "12",
                "--compare-b",
                "13"
            ])),
            (16, 4)
        );
        assert_eq!(
            widths(TestArgs {
                full: true,
                ..Default::default()
            }),
            (32, 8)
        );
    }

    #[test]
    fn worker_clocks_must_share_the_captured_batch_origin() {
        let mut rows = vec![row("OK")];
        assert!(align_observations(&mut rows, 100., 110., 150.).is_err());
        rows[0].raw = json!({"started_monotonic_ms":120.,"finished_monotonic_ms":130.});
        align_observations(&mut rows, 100., 110., 150.).unwrap();
        assert_eq!((rows[0].started_ms, rows[0].observed_ms), (20., 30.));
        for (start, end) in [(109., 130.), (120., 151.), (130., 120.)] {
            rows[0].raw = json!({"started_monotonic_ms":start,"finished_monotonic_ms":end});
            assert!(align_observations(&mut rows, 100., 110., 150.).is_err());
        }
    }

    #[test]
    fn a_new_game_or_reused_pid_does_not_inherit_an_earlier_approval() {
        let game = |pid, time| json!({"identity":{"pid":pid,"created_filetime":time,"executable":"C:/game.exe"}});
        let allowed = game_identities(&json!([game(10, 20)])).unwrap();
        assert!(
            game_identities(&json!([game(10, 20)]))
                .unwrap()
                .is_subset(&allowed)
        );
        assert!(
            !game_identities(&json!([game(10, 21)]))
                .unwrap()
                .is_subset(&allowed)
        );
        assert!(
            !game_identities(&json!([game(11, 20)]))
                .unwrap()
                .is_subset(&allowed)
        );
        assert!(game_identities(&json!([{"pid":10,"identity":null}])).is_err());
    }
    #[test]
    fn published_selection_reports_the_actual_primary_after_checked_fallback() {
        let mut actual = Settings::default();
        actual.set("alt", "12").unwrap();
        let mut report = json!({"accepted":true,"primary_changed":true,"primary":"13"});
        reconcile_restart(
            &mut report,
            &actual,
            Ok(Some(&json!({"running":true,"restored":true}))),
        );
        assert_eq!(report["primary"], "12");
        assert_eq!(report["primary_requested"], "13");
        assert_eq!(report["primary_changed"], false);
        assert_eq!(report["accepted"], true);
        reconcile_restart(&mut report, &actual, Err("start refused".into()));
        assert_eq!(report["running_restored"], false);
        assert_eq!(report["startup_error"], "start refused");
        assert_eq!(report["primary_requested"], "13");
    }
    #[test]
    fn explicit_apply_starts_an_accepted_unchanged_primary_and_never_starts_rejected_results() {
        let mut arguments = TestArgs {
            apply: true,
            ..Default::default()
        };
        let mut actual = Settings::default();
        actual.set("alt", "50").unwrap();
        let mut report = json!({"accepted":true,"primary_changed":false,"primary":"50"});
        assert!(selection_start_requested(&arguments, &report));
        reconcile_restart(&mut report, &actual, Ok(Some(&json!({"running":true}))));
        assert_eq!(report["startup"]["running"], true);

        report["accepted"] = json!(false);
        assert!(!selection_start_requested(&arguments, &report));
        report["accepted"] = json!(true);
        arguments.apply = false;
        assert!(!selection_start_requested(&arguments, &report));
        report["primary_changed"] = json!(true);
        assert!(selection_start_requested(&arguments, &report));
        arguments.report_only = true;
        assert!(!selection_start_requested(&arguments, &report));
    }
    #[test]
    fn learning_from_one_strategy_does_not_enter_the_next_trial() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("lists")).unwrap();
        let path = root.path().join("lists/autohostlist.txt");
        fs::write(&path, b"# original private seed\r\nknown.example\r\n").unwrap();
        capture_trial_autolist(root.path()).unwrap();
        fs::write(&path, b"learned-by-previous-strategy.example\n").unwrap();
        reset_trial_autolist(root.path()).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            b"# original private seed\r\nknown.example\r\n"
        );
    }

    #[test]
    fn recorded_control_failure_keeps_eight_confirmed_results_and_the_best_candidate() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/selection-controls.json"))
                .unwrap();
        let targets: Vec<_> = fixture["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| {
                let name = name.as_str().unwrap();
                Target {
                    group: "Clean".into(),
                    name: name.into(),
                    url: format!("https://{name}.invalid/"),
                    post: false,
                    expected: None,
                    peer: None,
                }
            })
            .collect();
        let rows = |values: &Value| {
            values
                .as_array()
                .unwrap()
                .iter()
                .map(|value| {
                    let mut row = row(value["state"].as_str().unwrap());
                    row.group = "Clean".into();
                    row.name = value["name"].as_str().unwrap().into();
                    row.url = format!("https://{}.invalid/", row.name);
                    row.tls_ms = value["tls_ms"].as_f64().unwrap();
                    row
                })
                .collect::<Vec<_>>()
        };
        let mut quality = BTreeMap::new();
        let mut failures = Vec::new();
        for trial in fixture["trials"].as_array().unwrap() {
            let reasons =
                control_failures(&targets, &rows(&trial["before"]), &rows(&trial["after"]));
            quality.insert(trial["id"].as_str().unwrap().to_owned(), reasons.is_empty());
            failures.extend(reasons);
        }
        let scores: Vec<_> = fixture["scores"]
            .as_array()
            .unwrap()
            .iter()
            .map(|score| RankRow {
                id: score["id"].as_str().unwrap().into(),
                score: score["score"].as_f64().unwrap(),
                ..Default::default()
            })
            .collect();
        let qualified = qualified_scores(&scores, &quality);
        assert_eq!(qualified.len(), 8);
        assert_eq!(qualified[0].id, "58");
        assert_eq!(quality.get("50"), Some(&false));
        assert!(failures.iter().any(|reason| reason.contains("bing")));
        assert!(!qualified.iter().any(|row| row.id == "50" || row.id == "13"));
    }

    #[test]
    fn explicit_connectivity_checks_take_priority_only_after_first_attempt_success() {
        let targets = [
            ("bing", "https://www.bing.com/"),
            ("adobe", "https://www.adobe.com/"),
            ("firefox", "https://detectportal.firefox.com/success.txt"),
            ("windows", "http://www.msftconnecttest.com/connecttest.txt"),
            ("steam", "https://steam.example/"),
        ]
        .map(|(name, url)| Target {
            group: "Clean".into(),
            name: name.into(),
            url: url.into(),
            post: false,
            expected: None,
            peer: None,
        });
        let mut observations = targets
            .iter()
            .map(|t| Row {
                group: t.group.clone(),
                name: t.name.clone(),
                url: t.url.clone(),
                ..row("OK")
            })
            .collect::<Vec<_>>();
        let names = |rows: &[Row]| {
            select_controls(&targets, rows)
                .into_iter()
                .map(|t| t.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&observations),
            ["windows", "firefox", "bing", "adobe"]
        );
        observations[3].tries = 2;
        observations[2].flaky = true;
        assert_eq!(names(&observations), ["bing", "adobe", "steam"]);
    }

    #[test]
    fn baseline_cost_orders_queued_targets_once_without_reordering_equal_costs() {
        let targets: Vec<_> = ["fast", "slow", "tie"]
            .into_iter()
            .map(|name| Target {
                name: name.into(),
                group: "Example".into(),
                url: format!("https://{name}.test/"),
                post: false,
                expected: None,
                peer: None,
            })
            .collect();
        let base: Vec<_> = targets
            .iter()
            .zip([10., 500., 10.])
            .map(|(t, ms)| Row {
                name: t.name.clone(),
                group: t.group.clone(),
                url: t.url.clone(),
                total_ms: ms,
                ..row("OK")
            })
            .collect();
        let names = |order: Vec<Target>| order.into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert_eq!(
            names(trial_order(&targets, &base, 2)),
            ["slow", "fast", "tie"]
        );
        assert_eq!(
            names(trial_order(&targets, &base, 3)),
            ["fast", "slow", "tie"]
        );
    }

    #[test]
    fn adjacent_controls_expire_on_age_or_any_network_event() {
        let now = Instant::now();
        let boundary = ControlBoundary {
            strategy: "1".into(),
            finished: now,
            generation: 9,
            rows: vec![],
        };
        assert!(boundary.current(now + Duration::from_secs(2), Some(9)));
        assert!(!boundary.current(now + Duration::from_millis(2001), Some(9)));
        assert!(!boundary.current(now, Some(10)));
        assert!(!boundary.current(now, None));
    }

    #[test]
    fn control_assessment_rejects_missing_samples_and_invalid_tls_timings() {
        let target = Target {
            group: "Clean".into(),
            name: "fixture".into(),
            url: "https://example.com/".into(),
            post: false,
            expected: None,
            peer: None,
        };
        let targets = [
            target.clone(),
            Target {
                name: "second".into(),
                url: "https://second.example.org/".into(),
                ..target
            },
        ];
        assert!(!control_failures(&targets, &[], &[]).is_empty());
        let rows: Vec<_> = targets
            .iter()
            .cycle()
            .take(4)
            .map(|target| {
                let mut row = row("OK");
                row.group = target.group.clone();
                row.name = target.name.clone();
                row.url = target.url.clone();
                row
            })
            .collect();
        assert!(control_failures(&targets, &rows, &rows).is_empty());
        for time in [0., f64::NAN, 1000.] {
            let mut changed = rows.clone();
            changed[0].tls_ms = time;
            changed[2].tls_ms = time;
            assert!(!control_failures(&targets, &rows, &changed).is_empty());
        }
    }
    #[test]
    fn skipped_rounds_do_not_duplicate_an_earlier_strategy_measurement() {
        let mut table = BTreeMap::from([
            ("12".into(), vec![row("OK")]),
            ("13".into(), vec![row("FAIL")]),
        ]);
        let mut sums = BTreeMap::new();
        collect_round_summaries(
            &table,
            &BTreeSet::from(["12".into(), "13".into()]),
            &BTreeMap::new(),
            &mut sums,
        )
        .unwrap();
        table.insert("13".into(), vec![row("OK")]);
        collect_round_summaries(
            &table,
            &BTreeSet::from(["13".into()]),
            &BTreeMap::new(),
            &mut sums,
        )
        .unwrap();
        assert_eq!(sums["12"].len(), 1);
        assert_eq!(sums["13"].len(), 2);
        assert_eq!(sums["13"][0].score, 0.);
        assert_eq!(sums["13"][1].score, 1.);
    }
}
