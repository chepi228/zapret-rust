mod queue;

use crate::{
    App,
    cli::LabArgs,
    interrupt,
    selection::{self, Restore, Row, Target},
    snapshot::{Snapshot, check_plain, package_inputs},
};
use anyhow::{Context, Result, ensure};
use chrono::Local;
use queue::Block;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use zapret_core::{atomic_write, read_bounded, sha256_file};
use zapret_platform::{ControlGuard, OwnedChild, RunOptions};

#[derive(Debug)]
struct Stopped(String);
impl std::fmt::Display for Stopped {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for Stopped {}

struct ContextRun<'a> {
    app: &'a App,
    snapshot: &'a Snapshot,
    dir: &'a Path,
    network: String,
    deadline: Instant,
}
impl ContextRun<'_> {
    fn check(&self) -> Result<()> {
        if interrupt::cancelled() {
            return Err(Stopped("отмена пользователем".into()).into());
        }
        if self.dir.join("stop").exists() {
            return Err(Stopped("файл stop".into()).into());
        }
        if Instant::now() >= self.deadline {
            return Err(Stopped("вышло время".into()).into());
        }
        if !selection::game_snapshot(self.app)?.is_empty() {
            return Err(Stopped("запущена игра".into()).into());
        }
        let adapters = self.app.platform("adapters", json!({}))?;
        ensure!(
            !adapters
                .as_array()
                .context("Недоступны сетевые адаптеры")?
                .iter()
                .any(|adapter| adapter["up"] == true && adapter["tun"] == true),
            "Поднялся VPN-туннель"
        );
        crate::ensure_snapshot_current(self.snapshot)?;
        let network = self.app.platform("network", json!({}))?;
        ensure!(
            network["known"] == true && network["key"] == self.network,
            "Подключение изменилось во время лаборатории"
        );
        Ok(())
    }

    fn wait(&self, duration: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(duration)
            .context("Слишком большая пауза лаборатории")?;
        loop {
            self.check()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            thread::sleep(remaining.min(Duration::from_millis(250)));
        }
    }
}

fn queues(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("queue"))
        {
            check_plain(&path)?;
            ensure!(path.is_file(), "Очередь должна быть файлом");
            paths.push(path);
            ensure!(paths.len() <= 1024, "Слишком много файлов очереди");
        }
    }
    paths.sort();
    Ok(paths)
}

fn targets(root: &Path) -> Result<Vec<Target>> {
    let fresh = root.join("runtime/dpi-suite.json");
    let suite = if fresh.is_file() {
        fresh
    } else {
        root.join("tools/dpi-suite.json")
    };
    selection::read_targets_with_suite(root, &suite)
}

pub fn run(app: &App, args: &LabArgs) -> Result<Value> {
    ensure!(
        (1..=64).contains(&args.parallel)
            && (1..=60).contains(&args.timeout_sec)
            && args.max_minutes > 0
            && args.max_minutes <= i32::MAX as u64
            && args.idle_minutes > 0
            && args.idle_minutes <= i32::MAX as u64,
        "Неверные параметры лаборатории"
    );
    let dir = fs::canonicalize(&args.dir).context("Папка лаборатории недоступна")?;
    check_plain(&dir)?;
    let prepared = queues(&dir)?
        .into_iter()
        .map(|path| {
            let blocks = queue::parse(&path)?;
            Ok(json!({"file":path,"blocks":blocks}))
        })
        .collect::<Result<Vec<_>>>()?;
    if args.plan_only {
        return Ok(
            json!({"plan_only":true,"queues":prepared,"targets":targets(&app.root)?,
            "parallel":args.parallel,"timeout_ms":args.timeout_sec*1000,"text":"План лаборатории готов."}),
        );
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.max_minutes * 60))
        .context("Слишком большой срок лаборатории")?;
    interrupt::install()?;
    ensure!(
        selection::game_snapshot(app)?.is_empty(),
        "Перед лабораторией закройте игру"
    );
    let _guard = ControlGuard::acquire(&app.root, "lab")?;
    app.platform("control-check", json!({"game_approved":true}))?;
    let state = app.platform("status", json!({}))?;
    ensure!(
        state["known"] == true && state["ownership_known"] == true,
        "Не подтверждено владение работающим обходом"
    );
    let was_running = state["running"] == true;
    let mut paths = package_inputs(&app.root)?;
    for name in ["runtime/dpi-suite.json", "runtime/post64k.bin"] {
        if app.root.join(name).is_file() {
            paths.push(name.into())
        }
    }
    paths.sort();
    paths.dedup();
    let mut snapshot = Snapshot::capture(&app.root, &paths, true)?;
    let network = app.platform("network", json!({}))?;
    let network = network["key"]
        .as_str()
        .filter(|_| network["known"] == true)
        .context("Не подтверждено подключение")?
        .to_owned();
    let mut restore = Restore {
        app,
        needed: false,
        approved_games: BTreeSet::new(),
    };
    let result = (|| {
        let context = ContextRun {
            app,
            snapshot: &snapshot,
            dir: &dir,
            network,
            deadline,
        };
        context.check()?;
        let body = context.snapshot.root().join("runtime/post64k.bin");
        if !body.is_file() {
            let mut bytes = vec![0; 65536];
            getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("{error}"))?;
            atomic_write(&body, &bytes)?;
        }
        ensure!(
            read_bounded(&body, 65536)?.len() == 65536,
            "POST-файл должен содержать ровно 65536 байт"
        );
        let extra = extra_blobs(&context, args.extra_blobs.as_deref())?;
        restore.needed = was_running;
        app.platform("stop", json!({"game_approved":true}))?;
        log(&dir, "лаборатория: старт")?;
        execute(&context, args, &body, &extra)
    })();
    snapshot.release_state_pins();
    let restoration = restore.finish();
    let result = match (result, restoration) {
        (Ok(result), Ok(_)) => Ok(result),
        (Err(error), Ok(_)) if error.is::<Stopped>() => {
            Ok(json!({"stopped":true,"reason":error.to_string()}))
        }
        (Err(error), Ok(_)) => Err(error),
        (result, Err(error)) => Err(error.context(format!(
            "Восстановление после лаборатории: {}",
            result
                .err()
                .map_or("проверка завершена".into(), |error| format!(
                    "{error:#}"
                ))
        ))),
    };
    atomic_write(
        &dir.join("finished"),
        Local::now().format("%H:%M:%S").to_string().as_bytes(),
    )?;
    log(&dir, "лаборатория: конец")?;
    result
}

fn log(dir: &Path, line: &str) -> Result<()> {
    let line = format!("{} {line}\r\n", Local::now().format("%H:%M:%S"));
    append(&dir.join("lab.log"), line.as_bytes())?;
    eprint!("{line}");
    Ok(())
}

fn append(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    ensure!(
        file.metadata()?.len() + bytes.len() as u64 <= 64 * 1024 * 1024,
        "Лабораторный отчёт превысил 64 МиБ"
    );
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn extra_blobs(context: &ContextRun<'_>, directory: Option<&Path>) -> Result<Vec<String>> {
    let mut arguments = Vec::new();
    let Some(directory) = directory.filter(|path| path.exists()) else {
        return Ok(arguments);
    };
    check_plain(directory)?;
    let destination = context.snapshot.root().join("runtime/lab-blobs");
    fs::create_dir_all(&destination)?;
    let mut names = BTreeSet::new();
    let mut total = 0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("bin"))
        {
            continue;
        }
        check_plain(&path)?;
        let stem = path
            .file_stem()
            .and_then(|name| name.to_str())
            .context("Неверное имя blob")?;
        let name = format!(
            "x_{}",
            stem.chars()
                .map(
                    |character| if character.is_ascii_alphanumeric() || character == '_' {
                        character
                    } else {
                        '_'
                    }
                )
                .collect::<String>()
        );
        ensure!(
            names.insert(name.clone()),
            "Совпадающие имена дополнительных blob"
        );
        let bytes = read_bounded(&path, 64 * 1024 * 1024)?;
        total += bytes.len();
        ensure!(
            total <= 128 * 1024 * 1024,
            "Дополнительные blob превышают 128 МиБ"
        );
        let copied = destination.join(format!("{name}.bin"));
        atomic_write(&copied, &bytes)?;
        arguments.push(format!("--blob={name}:@{}", copied.display()));
    }
    Ok(arguments)
}

#[derive(Debug)]
struct Resolved {
    target: Target,
    address: IpAddr,
    port: u16,
}

fn resolve(context: &ContextRun<'_>) -> Result<Vec<Resolved>> {
    let targets = targets(context.snapshot.root())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(16)
        .build()?;
    let result = runtime.block_on(async {
        let mut tasks = tokio::task::JoinSet::new();
        for target in targets {
            let url = url::Url::parse(&target.url)?;
            ensure!(
                matches!(url.scheme(), "https" | "http")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "Неверный URL лаборатории"
            );
            let host = url
                .host_str()
                .context("Нет имени узла")?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = url.port_or_known_default().context("Нет порта URL")?;
            tasks.spawn(async move {
                let resolved = tokio::time::timeout(Duration::from_millis(2500), async {
                    let mut addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
                    let address = addresses
                        .find(|address| address.is_ipv4())
                        .context("Нет IPv4 адреса")?;
                    tokio::net::TcpStream::connect(address).await?;
                    Ok::<_, anyhow::Error>(Resolved {
                        target: target.clone(),
                        address: address.ip(),
                        port,
                    })
                })
                .await;
                (target, resolved)
            });
        }
        let mut resolved = Vec::new();
        while let Some(task) = tasks.join_next().await {
            let (target, result) = task?;
            match result {
                Ok(Ok(target)) => resolved.push(target),
                result => log(
                    context.dir,
                    &format!("пропущен {}: {result:?}", target.key()),
                )?,
            }
        }
        resolved.sort_by_key(|target| target.target.key());
        Ok::<_, anyhow::Error>(resolved)
    });
    runtime.shutdown_background();
    context.check()?;
    result
}

fn arguments(
    root: &Path,
    filter: &Path,
    ports: &str,
    extra: &[String],
    lines: &[String],
) -> Result<Vec<String>> {
    let mut args = vec![
        format!("--wf-tcp-out={ports}"),
        format!("--wf-raw-filter=@{}", filter.display()),
    ];
    if zapret_core::uses_builtin_rules(root) {
        args.push("--builtin-rules".into());
    } else {
        for name in [
            "zapret-lib.lua",
            "zapret-antidpi.lua",
            "zapret-auto.lua",
            "fooling.lua",
            "ring-store.lua",
            "autoring.lua",
        ] {
            args.push(format!(
                "--lua-init=@{}",
                root.join("lua").join(name).display()
            ));
        }
    }
    for (name, file) in [
        ("quic_google", "quic_initial_www_google_com.bin"),
        ("quic_4pda", "quic_initial_4pda_to.bin"),
        ("stun_fs", "stun.bin"),
        ("stun2", "stun2.bin"),
        ("tls_google", "tls_clienthello_www_google_com.bin"),
        ("tls_4pda", "tls_clienthello_4pda_to.bin"),
        ("tls_sferum", "tls_clienthello_www_sferum_ru.bin"),
        ("tls_sochi", "tls_clienthello_sochi_park.bin"),
        ("discord_udp", "ACTIVE_DISCORD_UDP.bin"),
        ("game_udp", "ACTIVE_GAME_UDP.bin"),
    ] {
        args.push(format!(
            "--blob={name}:@{}",
            root.join("fake").join(file).display()
        ));
    }
    args.extend_from_slice(extra);
    args.push(format!("--filter-tcp={ports}"));
    args.extend(
        [
            "--payload=all",
            "--out-range=x",
            "--in-range=a",
            "--lua-desync=rst_guard",
            "--in-range=x",
            "--out-range=a",
            "--out-range=-d10",
        ]
        .map(str::to_owned),
    );
    args.extend_from_slice(lines);
    args.extend(["--payload=all", "--out-range=-d10", "--lua-desync=rst_mark"].map(str::to_owned));
    zapret_core::checked_command_line(root, &args)
}

fn start(context: &ContextRun<'_>, args: &[String], lifetime: Duration) -> Result<OwnedChild> {
    let root = context.snapshot.root();
    zapret_platform::validate_engine_args(root, args)?;
    for _ in 0..3 {
        context.check()?;
        let mut engine = OwnedChild::spawn(
            &root.join("bin/winws2.exe"),
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            &RunOptions {
                cwd: Some(root.join("bin")),
                timeout: lifetime.min(Duration::from_secs(24 * 3600)),
                ..Default::default()
            },
        )?;
        context.wait(Duration::from_millis(1200))?;
        if engine.is_running()? {
            return Ok(engine);
        }
        let output = engine.finish()?;
        log(
            context.dir,
            &format!(
                "движок завершился: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
    }
    anyhow::bail!("Тестовый движок не запустился после трёх попыток")
}

fn batch(
    context: &ContextRun<'_>,
    args: &LabArgs,
    targets: &[Resolved],
    body: &Path,
    engine: &mut Option<OwnedChild>,
) -> Result<Vec<Row>> {
    context.check()?;
    let timeout = args.timeout_sec * 1000;
    let budget = targets.len().div_ceil(args.parallel) as u64 * (timeout + 1000) + 5000;
    let budget = budget
        .min(
            context
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        )
        .max(1);
    let jobs=targets.iter().map(|target|json!({"version":1,"id":target.target.id(),"url":target.target.url,
        "connect_ip":target.address,"timeout_ms":timeout,"body_limit":65536,
        "post_bytes":if target.target.post{65536}else{0},"method":if target.target.post{"POST"}else{"GET"}})).collect::<Vec<_>>();
    let mut input = Vec::new();
    for job in jobs {
        serde_json::to_writer(&mut input, &job)?;
        input.push(b'\n');
    }
    let started = chrono::Utc::now();
    let mut worker = OwnedChild::spawn(
        &std::env::current_exe()?,
        &[
            "probe".into(),
            "--parallel".into(),
            args.parallel.to_string().into(),
            "--deadline-ms".into(),
            budget.to_string().into(),
            "--post-file".into(),
            body.as_os_str().into(),
        ],
        &RunOptions {
            cwd: Some(context.snapshot.root().into()),
            stdin: Some(input),
            timeout: Duration::from_millis(budget + 5000),
            max_output_bytes: 16 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    let mut checked = Instant::now();
    while worker.is_running()? {
        if interrupt::cancelled() {
            context.check()?;
        }
        if let Some(engine) = engine.as_mut() {
            ensure!(
                engine.is_running()?,
                "Тестовый движок завершился во время проб"
            )
        }
        if checked.elapsed() >= Duration::from_millis(500) {
            context.check()?;
            checked = Instant::now();
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = worker.finish()?;
    ensure!(
        output.exit_code == 0 && !output.timed_out && !output.output_truncated,
        "Пакет проб не завершён: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let targets = targets
        .iter()
        .map(|target| target.target.clone())
        .collect::<Vec<_>>();
    let rows = selection::parse_observations(&targets, &output.stdout, started)?;
    if let Some(engine) = engine.as_mut() {
        ensure!(
            engine.is_running()?,
            "Движок завершился до подтверждения результата"
        )
    }
    context.check()?;
    Ok(rows)
}

fn report(
    context: &ContextRun<'_>,
    base: &Path,
    name: &str,
    sequence: usize,
    rows: &[Row],
) -> Result<()> {
    let mut tsv = String::new();
    let mut groups: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut tls = Vec::new();
    let mut bad = Vec::new();
    for row in rows {
        let label = if row.group == "DPI" {
            row.name.split_whitespace().next().unwrap_or(&row.name)
        } else {
            &row.name
        };
        let key = format!("{}|{}", row.group, label);
        let state = match row.state.as_str() {
            "OK" => "+".into(),
            "FREEZE" => "F".into(),
            _ if row.exit == 28 => "H".into(),
            _ if row.exit == 35 => "5".into(),
            _ => format!("c{}", row.exit),
        };
        tsv.push_str(&format!(
            "{name}\t{sequence}\t{key}\t{state}\t{}\t{}\t{}\t{}\t{:.0}\t{:.0}\r\n",
            row.code, row.exit, row.up, row.down, row.conn_ms, row.tls_ms
        ));
        let counts = groups.entry(&row.group).or_default();
        counts.1 += 1;
        if state == "+" {
            counts.0 += 1;
            if row.tls_ms > 0. {
                tls.push(row.tls_ms)
            }
        } else {
            bad.push(format!("{label}:{state}"))
        }
    }
    tls.sort_by(f64::total_cmp);
    let median = tls.get(tls.len() / 2).copied().unwrap_or(0.);
    let summary = format!(
        "{name:<34} {} TLS~{median:.0} | {}",
        groups
            .into_iter()
            .map(|(group, (ok, total))| format!("{group} {ok}/{total}"))
            .collect::<Vec<_>>()
            .join(" "),
        bad.join(" ")
    );
    append(
        &PathBuf::from(format!("{}.tsv", base.display())),
        tsv.as_bytes(),
    )?;
    append(
        &PathBuf::from(format!("{}.summary", base.display())),
        format!("{summary}\r\n").as_bytes(),
    )?;
    log(context.dir, &summary)?;
    Ok(())
}

fn execute(
    context: &ContextRun<'_>,
    args: &LabArgs,
    body: &Path,
    extra: &[String],
) -> Result<Value> {
    let targets = resolve(context)?;
    ensure!(!targets.is_empty(), "Нет доступных IPv4 адресов проверки");
    let ips = targets
        .iter()
        .map(|target| target.address)
        .collect::<BTreeSet<_>>();
    let filter = context.snapshot.root().join("runtime/lab-filter.txt");
    let expression = format!(
        "ip and ({})",
        ips.iter()
            .map(|ip| format!("ip.DstAddr=={ip} or ip.SrcAddr=={ip}"))
            .collect::<Vec<_>>()
            .join(" or ")
    );
    zapret_platform::validate_capture_filter(context.snapshot.root(), expression.as_bytes())?;
    atomic_write(&filter, expression.as_bytes())?;
    let ports = targets
        .iter()
        .map(|target| target.port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let baseline = batch(context, args, &targets, body, &mut None)?;
    report(
        context,
        &context.dir.join("baseline"),
        "без обхода",
        0,
        &baseline,
    )?;
    let mut idle = Instant::now();
    let mut sequence = 0;
    loop {
        context.check()?;
        if idle.elapsed() >= Duration::from_secs(args.idle_minutes * 60) {
            return Ok(json!({"finished":true,"reason":"очередь пуста","trials":sequence}));
        }
        let Some(path) = queues(context.dir)?.into_iter().next() else {
            context.wait(Duration::from_secs(2))?;
            continue;
        };
        let input = OpenOptions::new().read(true).share_mode(1).open(&path)?;
        let before = sha256_file(&path)?;
        let blocks = queue::parse(&path)?;
        let base = path.with_extension("");
        log(
            context.dir,
            &format!("очередь {}", path.file_name().unwrap().to_string_lossy()),
        )?;
        for block in blocks {
            context.check()?;
            match block {
                Block::Sleep { seconds } => context.wait(Duration::from_secs(seconds))?,
                Block::Trial { name, lines } => {
                    sequence += 1;
                    let mut engine = if lines.is_empty() {
                        None
                    } else {
                        let command =
                            arguments(context.snapshot.root(), &filter, &ports, extra, &lines)?;
                        Some(start(
                            context,
                            &command,
                            context.deadline.saturating_duration_since(Instant::now()),
                        )?)
                    };
                    let rows = batch(context, args, &targets, body, &mut engine);
                    drop(engine);
                    report(context, &base, &name, sequence, &rows?)?;
                }
            }
        }
        ensure!(
            sha256_file(&path)? == before,
            "Очередь изменилась во время выполнения"
        );
        drop(input);
        let completed = PathBuf::from(format!("{}.done", path.display()));
        atomic_write(&completed, &read_bounded(&path, 1024 * 1024)?)?;
        fs::remove_file(path)?;
        idle = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_lab_arguments_include_caller_initializers_without_stock_scripts() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let filter = root.join("filter.txt");
        let custom = "--lua-init=fixture=1";
        let build = || arguments(root, &filter, "443", &[custom.into()], &[]).unwrap();
        assert_eq!(
            build()
                .iter()
                .filter(|arg| arg.starts_with("--lua-init=@"))
                .count(),
            6
        );
        crate::snapshot::write_builtin_manifest_fixture(root);
        let native = build();
        assert!(native.iter().any(|arg| arg == "--builtin-rules"));
        assert_eq!(
            native
                .iter()
                .map(String::as_str)
                .filter(|arg| arg.starts_with("--lua-init="))
                .collect::<Vec<_>>(),
            [custom]
        );
    }

    #[test]
    fn plan_reads_current_target_suite_and_queue_without_creating_runtime_or_touching_input() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("package");
        let dir = temporary.path().join("lab");
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(
            root.join("tools/dpi-suite.json"),
            r#"[{"id":"one","provider":"fixture","host":"example.com"}]"#,
        )
        .unwrap();
        fs::write(
            root.join("tools/targets.txt"),
            "GameServices.auth = https://example.org/auth\n",
        )
        .unwrap();
        let source = "@ first\n--payload=tls_client_hello\n--lua-desync=fake:blob=tls_google\n@sleep 1\n@ baseline\n";
        fs::write(dir.join("first.queue"), source).unwrap();
        let app = App {
            root: root.clone(),
            yes: false,
            json: true,
        };
        let args = LabArgs {
            dir: dir.clone(),
            extra_blobs: None,
            max_minutes: 1,
            idle_minutes: 10,
            timeout_sec: 5,
            parallel: 16,
            plan_only: true,
        };
        let value = run(&app, &args).unwrap();
        assert_eq!(value["queues"][0]["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(value["targets"].as_array().unwrap().len(), 2);
        assert_eq!(value["targets"][0]["post"], true);
        assert!(!root.join("runtime").exists());
        assert_eq!(fs::read_to_string(dir.join("first.queue")).unwrap(), source);
        assert!(!dir.join("lab.log").exists());
        fs::write(
            dir.join("first.queue"),
            "@ broken\n--lua-init=@arbitrary.lua",
        )
        .unwrap();
        assert!(run(&app, &args).is_err());
        assert!(!root.join("runtime").exists());
    }
}
