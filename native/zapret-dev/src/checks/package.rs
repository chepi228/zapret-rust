use super::*;
use std::net::{TcpListener, TcpStream, UdpSocket};
use zapret_platform::OwnedChild;

pub(crate) fn run(archive: &Path, output: &Path) -> Result<()> {
    let archive = std::path::absolute(archive)?;
    let mut evidence = Evidence::default();
    let result = (|| {
        let temporary = tempfile::Builder::new()
            .prefix("zapret-rust-native-smoke-")
            .tempdir()?;
        let stage = temporary.path().join("package with spaces");
        let root = stage.join("zapret-rust");
        let names = extract(&archive, &root, None)?;
        evidence.check(!names.is_empty(), "ZIP has a single safe package root")?;
        evidence.check(
            !names.iter().any(|name| {
                name.to_lowercase().ends_with(".ps1") || name.to_lowercase().ends_with(".cs")
            }),
            "ZIP excludes production PowerShell and C#",
        )?;
        evidence.check(
            names
                .iter()
                .filter(|name| name.contains("/runtime/"))
                .collect::<Vec<_>>()
                == ["zapret-rust/runtime/.keep"],
            "ZIP excludes machine runtime",
        )?;
        evidence.check(
            !names.iter().any(|name| {
                name.split('/')
                    .any(|part| matches!(part, "dev" | "native" | ".git" | "dist"))
            }),
            "ZIP excludes developer sources and tools",
        )?;
        evidence.check(
            ![
                "zapret.bat",
                "bin/zapret.exe",
                "bin/zapret-worker.exe",
                "bin/zapret-recovery.exe",
                "bin/tgws/TgWsProxy_windows.exe",
            ]
            .iter()
            .any(|name| names.contains(&format!("zapret-rust/{name}"))),
            "ZIP contains only current native entries",
        )?;
        evidence.check(
            root.join("zapret-rust.exe").is_file() && !root.join("zapret-rust.bat").exists(),
            "EXE is the only public launcher",
        )?;
        evidence.check(
            zapret_core::list_lines(&root.join("lists/ipset-all.txt"))?.len() >= 1000,
            "a clean offline installation includes the public IP list",
        )?;
        let runner = Runner::new(&root);
        let executable = &runner.executable;
        let catalog: Value =
            serde_json::from_slice(&fs::read(root.join("package-manifest.json"))?)?;
        let core = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
        let has_cygwin = core.schema == 1;
        evidence.check(
            root.join("licenses/LICENSE").is_file()
                && root.join("licenses/THIRD-PARTY-NOTICES.md").is_file()
                && !fs::read_dir(&root)?.any(|entry| {
                    entry.is_ok_and(|entry| {
                        let name = entry.file_name();
                        name.to_string_lossy().starts_with("LICENSE")
                            || name == "THIRD-PARTY-NOTICES.md"
                    })
                }),
            "Bundled licenses and third-party notices are grouped under licenses/",
        )?;
        if core.schema >= zapret_core::BUILTIN_RULES_SCHEMA {
            evidence.check(
                names.iter().all(|name| !name.ends_with(".lua")),
                "Native engine package has no Lua source files",
            )?;
        }
        if core.schema == zapret_core::RUST_LUA_SCHEMA {
            evidence.check(
                root.join("licenses/LICENSE-Luna.txt").is_file()
                    && !root.join("licenses/LICENSE-LuaJIT.txt").exists(),
                "The archive contains the Rust interpreter license",
            )?;
        }
        evidence.check(
            root.join(zapret_core::CYGWIN_DLL).is_file() == has_cygwin,
            "Cygwin DLL matches the engine manifest schema",
        )?;
        let expected_version = format!(
            "zapret-rust {}",
            catalog["version"].as_str().context("catalog version")?
        );
        evidence.check(
            serde_json::to_value(hashes(&root)?)? == catalog["files"]
                && fs::metadata(root.join("runtime/.keep"))?.len() == 0,
            "catalog authenticates payloads and the empty runtime placeholder",
        )?;
        let leftover = root.join("bin/.native-build-0123456789abcdef0123456789abcdef.tmp.old");
        fs::write(&leftover, b"previous open menu")?;
        let launch = zapret_platform::validate_launch(&root)
            .context("Prepare the packaged launch recipe")?;
        fs::remove_file(leftover)?;
        evidence.check(
            launch["ok"] == true && !root.join("runtime/launch-state/confirmed-native.json").exists(),
            "The packaged launch recipe ignores a build sidecar and validates without starting the bypass",
        )?;
        let preflight =
            zapret_platform::validate_engine_args(&root, &["--wf-raw=outbound and tcp".into()])?;
        evidence.check(
            preflight["ok"] == true
                && preflight["compiler"] == "WinDivertHelperCompileFilter"
                && preflight["filter_bytes"]
                    .as_u64()
                    .is_some_and(|bytes| bytes > 0),
            "The packaged engine exports a real WinDivert filter",
        )?;
        evidence.check(
            zapret_platform::validate_engine_args(
                &root,
                &["--wf-raw=outbound and zapret_unknown_field".into()],
            )
            .is_err(),
            "The packaged engine preflight rejects unknown filter fields",
        )?;
        let ranking_context = zapret_core::test_result_context_with_identity(
            &root,
            &zapret_core::read_settings(&root)?,
            &"a".repeat(64),
            &sha256_file(executable)?,
        )
        .context("Prepare the packaged strategy selection context")?;
        evidence.check(
            ranking_context.valid(),
            "Strategy selection can prepare its ranking inputs from the extracted package",
        )?;
        evidence.check(
            sha256_file(executable)? == sha256_file(&root.join("bin/zapret-rust-recovery.exe"))?,
            "recovery contains the same native application",
        )?;
        let background = root.join("bin/zapret-rust-worker.exe");
        let image = fs::read(&background)?;
        let pe =
            u32::from_le_bytes(image.get(0x3c..0x40).context("PE offset")?.try_into()?) as usize;
        evidence.check(
            image.get(pe + 24 + 68..pe + 24 + 70) == Some(&[2, 0]),
            "background host uses the Windows GUI subsystem",
        )?;
        let check = invoke(&background, &["--self-check".into()], Some(&root), 0, None)?;
        evidence.check(
            serde_json::from_slice::<Value>(&check.stdout)?["console_window"] == false,
            "background host starts without a console",
        )?;
        for (screen, last) in [("main", 9), ("settings", 11), ("tools", 13), ("test", 5)] {
            let missing = stage.join("missing-root");
            let preview = invoke(
                executable,
                &[
                    "--root".into(),
                    missing.into_os_string(),
                    "menu-preview".into(),
                    "--screen".into(),
                    screen.into(),
                    "--width".into(),
                    "55".into(),
                    "--height".into(),
                    "16".into(),
                ],
                Some(&stage),
                0,
                None,
            )?;
            let text = text(&preview)?;
            evidence.check(
                text.starts_with('╭')
                    && !text.contains('\x1b')
                    && text.lines().all(|line| line.chars().count() == 53)
                    && (0..=last).all(|key| text.contains(&format!(" {key:>2}  "))),
                format!("{screen} preview preserves all actions without a package root"),
            )?;
            if screen == "main" {
                evidence.check(
                    text.lines().count() + 2 <= 16,
                    "main menu fits a short console",
                )?;
            }
        }
        evidence.check(
            !root.join("runtime/settings.ini").exists() && !stage.join("missing-root").exists(),
            "previews do not initialize settings",
        )?;
        let task = runner.json(&[
            "platform-worker",
            "task-status",
            "--arguments-json",
            r#"{"kind":"telegram"}"#,
        ])?;
        evidence.check(
            task["known"] == true
                && task["exists"] == false
                && task["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("zapret telegram ")),
            "The private package selects its own Telegram task name",
        )?;
        for kind in ["notify", "telegram"] {
            let value = runner.json(&[
                "platform-worker",
                "task-spec",
                "--arguments-json",
                &json!({"kind":kind}).to_string(),
            ])?;
            let xml = value["xml"].as_str().context("task XML")?;
            let expected = background
                .to_string_lossy()
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            evidence.check(
                xml.contains(&format!("<Command>{expected}</Command>"))
                    && !xml.contains("conhost")
                    && !xml.contains("--headless"),
                format!("{kind} task uses the native host directly"),
            )?;
        }
        evidence.check(
            runner.json(&["integrity"])?["ok"] == true,
            "CLI verifies bundled engine integrity",
        )?;
        telegram(&runner, &background, &mut evidence)?;
        fs::remove_file(root.join("runtime/settings.ini"))?;
        let state = runner.json(&["status"])?;
        evidence.check(
            state["known"].is_boolean() && state["ownership_known"].is_boolean(),
            "status preserves unknown ownership",
        )?;
        evidence.observations.insert("status".into(), state);
        let ipv4 = runner.json(&["platform-worker", "prefer-ipv4", "--arguments-json", "{}"])?;
        evidence.check(
            ipv4["backend"] == "WindowsCim"
                && ipv4["known"].is_boolean()
                && ipv4["enabled"].is_boolean(),
            "IPv4 prefix policy is a typed read-only observation",
        )?;
        evidence.observations.insert("ipv4_preference".into(), ipv4);
        let timestamps = runner.json(&[
            "platform-worker",
            "tcp-timestamps-status",
            "--arguments-json",
            "{}",
        ])?;
        evidence.check(
            timestamps["backend"] == "WindowsCim"
                && timestamps["enabled"].is_boolean()
                && timestamps["changed"] == false,
            "TCP timestamp observation does not change settings",
        )?;
        evidence
            .observations
            .insert("tcp_timestamps".into(), timestamps);
        let settings = runner.json(&["settings"])?;
        evidence.check(
            settings["alt"] == "31" && settings["auto"] == "on",
            "fresh package defaults to SOFT-STUN2 with automatic rotation",
        )?;
        runner.json(&["settings", "FutureSetting", "preserved"])?;
        evidence.check(
            runner.json(&["settings", "futuresetting"])?["value"] == "preserved",
            "unknown INI edits remain accessible",
        )?;
        let settings_path = root.join("runtime/settings.ini");
        evidence.check(
            fs::read_to_string(&settings_path)?.contains("FutureSetting=preserved"),
            "unknown INI spelling survives publication",
        )?;
        let plan = runner.json(&["test", "--plan-only"])?;
        evidence.check(
            plan["targets"].as_array().is_some_and(|x| !x.is_empty())
                && plan["strategies"].as_array().is_some_and(|x| !x.is_empty())
                && plan["settings"]["values"]["FutureSetting"] == "preserved",
            "autopick plan reads the package without bypass control",
        )?;
        let laboratory = temporary.path().join("laboratory");
        fs::create_dir(&laboratory)?;
        let queue = laboratory.join("fixture.queue");
        let source = "@ first\n--payload=tls_client_hello\n--lua-desync=fake:blob=tls_google\n@sleep 1\n@ baseline\n";
        fs::write(&queue, source)?;
        let settings_before = fs::read(&settings_path)?;
        let lab = runner.json(&["lab", "--dir", laboratory.to_str().unwrap(), "--plan-only"])?;
        let selection_targets = plan["targets"]
            .as_array()
            .context("missing selection plan targets")?;
        evidence.check(
            selection_targets.iter().any(|target| {
                target["name"] == "game_icon" && target["expected"]["mode"] == "roblox_icon"
            }),
            "autopick plan includes the two-origin Roblox game icon",
        )?;
        let single_peer_targets: Vec<_> = selection_targets
            .iter()
            .filter(|target| {
                !matches!(
                    target["expected"]["mode"].as_str(),
                    Some("http3_head" | "roblox_icon")
                )
            })
            .collect();
        evidence.check(
            lab["plan_only"] == true
                && lab["queues"][0]["blocks"]
                    .as_array()
                    .is_some_and(|blocks| blocks.len() == 3)
                && lab["targets"] == json!(single_peer_targets)
                && fs::read_to_string(&queue)? == source
                && fs::read(&settings_path)? == settings_before
                && !laboratory.join("lab.log").exists(),
            "native lab plan parses trials and includes every single-peer TCP target in order",
        )?;
        fs::write(&queue, "@ invalid\n--lua-init=@arbitrary.lua\n")?;
        runner.raw(
            &["lab", "--dir", laboratory.to_str().unwrap(), "--plan-only"],
            true,
            1,
            None,
        )?;
        evidence.check(
            !laboratory.join("lab.log").exists() && fs::read(&settings_path)? == settings_before,
            "native lab rejects an entire invalid queue before control",
        )?;
        let saved = json!({"schema":1,"best":{"id":"50","score":48,"total":54},"rows":[{"id":"50","score":48,"total":54}],"availability":{"50":{"ok":49,"total":54}},"strategy_names":{"50":"ALT11 белый 1"},"primary":"50","primary_changed":false,"accepted":false,"quality_eligible":true});
        let saved_path = root.join("runtime/test-native-last.json");
        fs::write(&saved_path, serde_json::to_vec(&saved)?)?;
        let before = fs::read(&settings_path)?;
        evidence.check(
            runner.json(&["test", "--last"])? == saved,
            "cached JSON preserves the structured result",
        )?;
        let human = text(&runner.raw(&["test", "--last"], false, 0, None)?)?;
        evidence.check(
            human.starts_with('╭')
                && human.contains("ALT11 белый 1")
                && human.contains("49/54")
                && human.contains("Основная после проверки")
                && !human.contains("quality_eligible")
                && !human.contains("strategy_names"),
            "cached result has a readable table through the actual CLI",
        )?;
        evidence.check(
            fs::read(&settings_path)? == before
                && serde_json::from_slice::<Value>(&fs::read(saved_path)?)? == saved,
            "viewing history preserves settings and evidence",
        )?;
        let provider = runner.json(&["provider-check", "--args", r#"{"plan_only":true}"#])?;
        evidence.check(
            ["plan_only", "full", "report_only", "keep_primary"]
                .iter()
                .all(|key| provider[key] == true),
            "provider-check preserves report-only full planning",
        )?;
        let strategies = runner.json(&["strategies"])?;
        let strategies = strategies.as_array().context("strategy array")?;
        evidence.check(
            strategies.len() == 36,
            "all 36 bundled strategy records are available",
        )?;
        fs::write(
            root.join("lists/autohostlist.txt"),
            "# private smoke fixture\n",
        )?;
        fs::write(root.join("runtime/ipset-any.txt"), "0.0.0.0/0\n::/0\n")?;
        for strategy in strategies {
            let id = strategy["id"].as_str().context("strategy id")?;
            evidence.check(
                runner.json(&[
                    "compose",
                    "--alt",
                    id,
                    "--no-auto",
                    "--dry-run",
                    "--validate",
                ])?["validation"]["ok"]
                    == true,
                format!("native preflight validates {}", strategy["name"]),
            )?;
        }
        for mode in ["loaded", "any", "none"] {
            evidence.check(
                runner.json(&["compose", "--ipset", mode, "--dry-run", "--validate"])?["validation"]
                    ["ok"]
                    == true,
                format!("automatic rotation preflight passes IPSet {mode}"),
            )?;
        }
        if core.schema >= zapret_core::BUILTIN_RULES_SCHEMA {
            let recipe = runner.json(&["compose", "--ipset", "loaded"])?;
            let arguments = recipe["arguments"].as_array().context("engine arguments")?;
            let arguments = arguments
                .iter()
                .map(|value| value.as_str().context("engine argument"))
                .collect::<Result<Vec<_>>>()?;
            evidence.check(
                arguments.contains(&"--builtin-rules")
                    && arguments
                        .iter()
                        .all(|argument| !argument.starts_with("--lua-init=")),
                "The packaged controller composes built-in rule initialization",
            )?;
            let mut arguments = arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            arguments.push("--intercept=0".into());
            arguments.push("--lua-init=assert(type(circular)=='function' and type(fake)=='function');print('ok built-in startup')".into());
            let output = crate::ring::engine_case(&root.join("bin"), &arguments, 0, &[])?;
            evidence.check(
                output.contains("ok built-in startup"),
                "The extracted default profile initializes without script files or WinDivert capture",
            )?;
            if core.schema == zapret_core::RUST_LUA_SCHEMA {
                evidence.check(
                    output.contains("LUA v5.2 Luna (Rust)"),
                    "The archived engine starts the Rust Lua runtime",
                )?;
            }
        }
        let rules = runner.json(&["direct-rules"])?;
        evidence.check(
            !rules["text"].is_null() || !rules["output"].is_null(),
            "direct rules are generated natively",
        )?;
        let report = runner.json(&["report"])?;
        evidence.check(
            ["output", "file", "text"]
                .iter()
                .any(|key| !report[key].is_null()),
            "native report is generated",
        )?;
        evidence.check(
            runner.json(&[
                "update",
                "--from",
                archive.to_str().context("archive UTF-8")?,
            ])?["installable"]
                == true,
            "updater validates a local archive without installing",
        )?;
        let before = sha256_file(&settings_path)?;
        runner.raw(
            &[
                "update",
                "--from",
                archive.to_str().unwrap(),
                "--sha256",
                &"0".repeat(64),
            ],
            false,
            1,
            None,
        )?;
        evidence.check(
            sha256_file(&settings_path)? == before,
            "wrong archive digest is rejected without changing settings",
        )?;
        local_network(&runner, &mut evidence)?;
        let expected_engine = root.join("bin/winws2.exe");
        for architecture in ["System32", "SysWOW64"] {
            evidence.check(
                text(&runner.launcher_from_shell(&["--version"], architecture, 0)?)?.trim()
                    == expected_version,
                format!("{architecture} launcher starts the native application"),
            )?;
            let output = runner.launcher_from_shell(
                &["--json", "compose", "--no-auto", "--dry-run"],
                architecture,
                0,
            )?;
            evidence.check(
                Path::new(
                    serde_json::from_slice::<Value>(&output.stdout)?["executable"]
                        .as_str()
                        .context("engine path")?,
                ) == expected_engine,
                format!("{architecture} launcher resolves the exact engine path"),
            )?;
        }
        fs::rename(executable, root.join("bin/mapped-old-native.exe"))?;
        evidence.check(
            text(&runner.launcher_from_shell(&["--version"], "System32", 0)?)?.trim()
                == expected_version,
            "EXE executes recovery while the main image is absent",
        )?;
        let recovered: Value = serde_json::from_slice(
            &runner
                .launcher_from_shell(
                    &["--json", "compose", "--no-auto", "--dry-run"],
                    "System32",
                    0,
                )?
                .stdout,
        )?;
        evidence.check(
            Path::new(
                recovered["executable"]
                    .as_str()
                    .context("recovery engine")?,
            ) == expected_engine,
            "recovery preserves the exact engine path",
        )?;
        Ok(())
    })();
    evidence.save(output, Some(&archive), &result)?;
    result
}

fn telegram(runner: &Runner, background: &Path, evidence: &mut Evidence) -> Result<()> {
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let port = reservation.local_addr()?.port();
    drop(reservation);
    let root = &runner.root;
    let config = root.join("runtime/tgws/TgWsProxy/config.json");
    fs::create_dir_all(config.parent().unwrap())?;
    fs::write(config, r#"{"dc_ip":[],"cfproxy":false,"pool_size":0}"#)?;
    fs::write(root.join("runtime/settings.ini"), "telegram=on\n")?;
    fs::write(
        root.join("runtime/telegram.txt"),
        format!("port={port}\nsecret={}\n", "1".repeat(32)),
    )?;
    let mut supervisor = OwnedChild::spawn(
        background,
        &[
            "--root".into(),
            root.as_os_str().into(),
            "telegram".into(),
            "supervise".into(),
        ],
        &RunOptions {
            cwd: Some(root.clone()),
            timeout: Duration::from_secs(60),
            ..Default::default()
        },
    )?;
    let until = Instant::now() + Duration::from_secs(10);
    let telegram = loop {
        let value = runner.json(&["telegram", "status"])?;
        if value["running"] == true || !supervisor.is_running()? || Instant::now() >= until {
            break value;
        }
        thread::sleep(Duration::from_millis(100));
    };
    evidence.check(
        telegram["running"] == true
            && telegram["current"] == true
            && telegram["backend"] == "rust"
            && telegram["active_port"] == port
            && Path::new(telegram["process"]["executable"].as_str().unwrap_or(""))
                == runner.executable
            && telegram["process"]["pid"] != telegram["wrapper"]["pid"],
        "Telegram supervisor owns the Rust core and loopback listener",
    )?;
    evidence.check(
        rejected(port)?,
        "Telegram core rejects unauthenticated input",
    )?;
    let id = crate::install::installation_id()?;
    let id = format!("{id:032x}");
    let staged = root.join(format!("bin/.native-build-{id}.tmp"));
    let previous = root.join(format!(
        "dist/native/previous-controllers/zapret-rust.exe.{id}.old"
    ));
    fs::create_dir_all(previous.parent().unwrap())?;
    fs::copy(&runner.executable, &staged)?;
    crate::install::replace(&runner.executable, &staged, Some(&previous))?;
    let updated = runner.json(&["telegram", "status"])?;
    evidence.check(
        updated["running"] == true
            && updated["current"] == true
            && updated["requires_restart"] == true
            && updated["process"]["pid"] == telegram["process"]["pid"]
            && updated["active_port"] == port,
        "mapped update preserves Telegram identity and listener",
    )?;
    evidence.check(
        rejected(port)?,
        "Telegram listener still rejects invalid input after replacement",
    )?;
    let saved_config = root.join("runtime/tgws/TgWsProxy/config.json");
    let credentials = root.join("runtime/telegram.txt");
    let before_config = fs::read(&saved_config)?;
    let before_credentials = fs::read(&credentials)?;
    let configured = runner.json(&[
        "telegram",
        "config",
        "--port",
        &if port < 65535 { port + 1 } else { port - 1 }.to_string(),
    ]);
    match configured {
        Ok(configured) => evidence.check(
            configured["requires_restart"] == true && configured["active_port"] == port,
            "saving Telegram config preserves the active listener",
        )?,
        Err(error) => {
            ensure!(
                format!("{error:#}").contains("Действие отложено: запущена игра ("),
                "Unexpected Telegram configuration failure: {error:#}"
            );
            let state = runner.json(&["telegram", "status"])?;
            evidence.check(
                fs::read(saved_config)? == before_config
                    && fs::read(credentials)? == before_credentials
                    && state["running"] == true
                    && state["active_port"] == port
                    && state["process"]["pid"] == telegram["process"]["pid"],
                "active-game guard defers Telegram edits and preserves files and listener",
            )?;
            evidence.observations.insert(
                "telegram_config".into(),
                json!({"edit":"DeferredByActiveGameGuard","saved_files_unchanged":true,
                    "active_listener_preserved":true}),
            );
        }
    }
    // Kill the supervisor host itself. Its Job must independently reap the core.
    zapret_platform::terminate_owned(supervisor.identity())?;
    supervisor.finish()?;
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if runner.json(&["telegram", "status"])?["running"] != true || Instant::now() >= until {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    evidence.check(
        runner.json(&["telegram", "status"])?["running"] == false,
        "closing the background host reaps its core",
    )?;
    Ok(())
}
fn rejected(port: u16) -> Result<bool> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse()?,
        Duration::from_secs(3),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&[0; 64])?;
    Ok(stream.read(&mut [0])? == 0)
}

fn local_network(runner: &Runner, evidence: &mut Evidence) -> Result<()> {
    let fixture = http::Fixture::new(false, None)?;
    let url = format!("{}/smoke", fixture.url());
    let job = json!({"version":1,"id":"smoke","url":url,"body_limit":65536,"timeout_ms":2000});
    let row: Value = serde_json::from_slice(
        &runner
            .raw(&["probe"], false, 0, Some(format!("{job}\n").into_bytes()))?
            .stdout,
    )?;
    evidence.check(
        row["termination"] == "Complete" && row["body_bytes"] == 7,
        "integrated probe completes a loopback HTTP request",
    )?;
    evidence.check(
        row["finished_monotonic_ms"].as_f64() >= row["started_monotonic_ms"].as_f64()
            && row["started_monotonic_ms"].as_f64().is_some_and(|n| n > 0.),
        "probe emits shared monotonic target clocks",
    )?;
    let connection = runner.json(&["connection-check", &url, "--timeout-ms", "2000"])?;
    evidence.check(
        connection["targets"][0]["assessment"]["reachable_http"] == true,
        "connection-check reaches loopback HTTP",
    )?;
    let file = Path::new(
        connection["TextFile"]
            .as_str()
            .context("connection report")?,
    );
    evidence.check(
        sha256_file(file)? == connection["text_sha256"],
        "connection result references matching immutable text",
    )?;
    let web = runner.json(&[
        "webcheck",
        &url,
        "--args",
        r#"{"modes":["Http1"],"visits":1}"#,
        "--timeout-ms",
        "2000",
    ])?;
    evidence.check(
        web["rows"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["state"] == "OK")),
        "webcheck completes native HTTP/1.1",
    )?;
    let latency = runner.json(&[
        "latency",
        "127.0.0.1",
        "--args",
        &json!({"protocol":"tcp","port":fixture.address.port(),"count":2,"interval_ms":10})
            .to_string(),
    ])?;
    evidence.check(
        latency["game_latency_measured"] == false
            && latency["summaries"][0]["summary"]["success_count"] == 2,
        "latency reports TCP separately from game RTT",
    )?;
    let capabilities = runner.json(&[
        "webcheck",
        "--args",
        r#"{"capabilities_only":true,"browser_path":""}"#,
    ])?;
    evidence.check(
        capabilities["native_http3"] != capabilities["rust_http3"]
            && capabilities["curl_path"].is_null(),
        "default HTTP/3 has a built-in transport",
    )?;
    let (client, tls) = if capabilities["native_http3"] == true {
        ("Windows WinHTTP HTTP/3 HEAD", "Schannel")
    } else {
        ("Rust direct Quinn HTTP/3 HEAD", "rustls")
    };
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let started = Instant::now();
    let web = runner.json(&[
        "webcheck",
        &format!("https://{}/", socket.local_addr()?),
        "--args",
        r#"{"modes":["Http3"],"browser_path":""}"#,
        "--timeout-ms",
        "100",
    ])?;
    let row = &web["rows"][0];
    evidence.check(
        row["client"] == client
            && row["tls_backend"] == tls
            && row["trust_source"] == "System"
            && web["capabilities"]["curl_path"].is_null(),
        "webcheck uses the selected built-in HTTP/3 client",
    )?;
    evidence.check(
        row["reason"] == "Timeout"
            && row["complete"] == false
            && row["quic_confirmed"] == false
            && row["protocol_confirmed"] == false
            && started.elapsed() < Duration::from_secs(5),
        "silent QUIC obeys its deadline without confirming a protocol",
    )?;
    evidence
        .observations
        .insert("native_http3_timeout".into(), row.clone());
    Ok(())
}
