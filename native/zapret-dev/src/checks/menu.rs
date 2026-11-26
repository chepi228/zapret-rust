use super::*;

fn fixture() -> Value {
    json!({"schema":1,"run_id":"cached-result-fixture","best":{"id":"52","score":48.5,"total":54},
        "rows":[{"id":"52","score":48.5,"total":54},{"id":"50","score":46,"total":54}],
        "availability":{"52":{"ok":49,"total":54},"50":{"ok":48,"total":54}},
        "strategy_names":{"52":"ALT11 белый 3","50":"ALT11 белый 1"},"primary":"50",
        "primary_changed":false,"accepted":false,"quality_eligible":true,"startup":{"running":true,"restored":false},
        "native_identity":"must-not-be-shown","journal":"C:/internal/fixture.jsonl"})
}

// This test never launches the interactive menu: startup has deliberate live
// side effects. Keep the allowed read-only launcher routes explicit in this helper.
fn run_launcher(runner: &Runner, args: &[&str], expected: u32) -> Result<RunOutput> {
    ensure!(
        args.first() == Some(&"menu-preview")
            || matches!(
                args,
                ["--version"]
                    | ["test", "--last"]
                    | ["--json", "test", "--last"]
                    | ["status"]
                    | ["service", "status"]
                    | ["task", "status", "notify"]
                    | ["task", "status", "autotune"]
                    | ["telegram", "status"]
            ),
        "Mutating command in read-only menu fixture"
    );
    invoke(
        &runner.root.join("zapret-rust.exe"),
        &args.iter().map(OsString::from).collect::<Vec<_>>(),
        runner.root.parent(),
        expected,
        None,
    )
}

fn cached(
    runner: &Runner,
    evidence: &mut Evidence,
    report: &Value,
    before: &[u8],
) -> Result<String> {
    let path = runner.root.join("runtime/test-native-last.json");
    let encoded = serde_json::to_vec(report)?;
    fs::write(&path, &encoded)?;
    let structured: Value =
        serde_json::from_slice(&run_launcher(runner, &["--json", "test", "--last"], 0)?.stdout)?;
    evidence.check(
        structured == *report,
        "cached JSON preserves the exact measured record",
    )?;
    let human = text(&run_launcher(runner, &["test", "--last"], 0)?)?;
    evidence.check(
        human.starts_with('╭')
            && human.contains("ALT11 белый 3")
            && ![
                "must-not-be-shown",
                "C:/internal/",
                "\"quality_eligible\"",
                "\"native_identity\"",
            ]
            .iter()
            .any(|key| human.contains(key)),
        "cached human result shows names and hides internal fields",
    )?;
    evidence.check(
        fs::read(runner.root.join("runtime/settings.ini"))? == before && fs::read(path)? == encoded,
        "cached viewing preserves settings and measured bytes",
    )?;
    Ok(human)
}

pub(crate) fn run(archive: &Path, output: &Path) -> Result<()> {
    let archive = std::path::absolute(archive)?;
    let mut evidence = Evidence::default();
    let result = (|| {
        let temporary = tempfile::Builder::new()
            .prefix("zapret-rust-menu-")
            .tempdir()?;
        let root = temporary.path().join("пакет с пробелами");
        extract(
            &archive,
            &root,
            Some(&[
                "zapret-rust.exe",
                "bin/zapret-rust.exe",
                "bin/zapret-rust-recovery.exe",
            ]),
        )?;
        let runner = Runner::new(&root);
        evidence.check(
            !root.join("zapret-rust.bat").exists() && root.join("zapret-rust.exe").is_file(),
            "the public menu entry is a Windows executable",
        )?;
        for arch in ["System32", "SysWOW64"] {
            evidence.check(
                text(&runner.launcher_from_shell(&["--version"], arch, 0)?)?
                    .trim()
                    .starts_with("zapret-rust "),
                format!("{arch} opens the native launcher"),
            )?;
        }
        for (screen, last) in [("main", 9), ("settings", 11), ("tools", 12), ("test", 5)] {
            for width in [55, 80] {
                let human = text(&run_launcher(
                    &runner,
                    &[
                        "menu-preview",
                        "--screen",
                        screen,
                        "--width",
                        &width.to_string(),
                        "--height",
                        "16",
                    ],
                    0,
                )?)?;
                let expected = (width - 4).clamp(1, 74) + 2;
                evidence.check(
                    human.starts_with('╭')
                        && !human.contains('\x1b')
                        && human.lines().all(|line| line.chars().count() == expected)
                        && (0..=last).all(|key| human.contains(&format!(" {key:>2}  "))),
                    format!(
                        "{screen} at {width} columns preserves aligned borders and all actions"
                    ),
                )?;
            }
        }
        evidence.check(
            !root.join("runtime").exists(),
            "previews leave runtime uninitialized",
        )?;
        fs::create_dir(root.join("runtime"))?;
        let settings = root.join("runtime/settings.ini");
        let before = b"alt=12\r\nauto=off\r\nnotify=off\r\nFutureSetting=keep\r\n";
        fs::write(&settings, before)?;
        let binary_before = sha256_file(&runner.executable)?;
        let saved = root.join("runtime/test-native-last.json");
        let human = cached(&runner, &mut evidence, &fixture(), before)?;
        evidence.check(
            human.contains("49/54") && human.contains("48,5"),
            "real responses remain separate from localized score",
        )?;
        let lower = human.to_lowercase();
        evidence.check(
            ["последн", "сохранённ", "предыдущ", "прошл"]
                .iter()
                .any(|key| lower.contains(key)),
            "cached result is explicitly historical",
        )?;
        evidence.check(
            !human.contains("Основная изменена"),
            "historical primary does not imply a current setting change",
        )?;
        let mut value = fixture();
        value["quality_eligible"] = json!(false);
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.to_lowercase().contains("нестабил")
                && human.to_lowercase().contains("не примен")
                && !human.contains("Основная изменена"),
            "unstable measurements are not presented as applied",
        )?;
        let mut value = fixture();
        value["startup"]["restored"] = json!(true);
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.to_lowercase().contains("восстановлен") && !human.contains("Основная изменена"),
            "restoration is distinct from applying the best strategy",
        )?;
        let mut value = fixture();
        value["validation_error"] = json!("Hetzner: TLS reset");
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("Лидер отдельного теста")
                && !human.contains("Рекомендация:")
                && human.contains("Hetzner: TLS reset"),
            "rejected historical leader is never a working recommendation",
        )?;
        let mut value = fixture();
        value["trial_best"] = json!({"id":"52"});
        value["best"] = json!({"id":"50","score":46});
        value["recommendation_status"] = json!("confirmed");
        value["choice"] = json!("kept");
        value["final_checks"] = json!({"52":{"confirmed":false,"error":"Hetzner: TLS reset"},"50":{"confirmed":true,"error":null}});
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("Рекомендация: ALT11 белый 1")
                && human.contains("ФИНАЛ НЕ ПРОЙДЕН")
                && human.contains("Лидер отдельного теста: ALT11 белый 3")
                && !human.contains("Основная изменена"),
            "verified fallback preserves recorded primary and rejected leader",
        )?;
        let mut value = fixture();
        value["presentation"] = json!("compact");
        value["accepted"] = json!(true);
        value["primary_changed"] = json!(true);
        value["primary"] = json!("52");
        value["elapsed_ms"] = json!(95000);
        value["recommendation_status"] = json!("confirmed");
        value["final_checks"] = json!({"52":{"confirmed":true}});
        value["startup"] = json!({"requested":false,"reason":"BypassWasStopped"});
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("ПРИМЕНЕНО: ALT11 белый 3")
                && human.contains("1 мин 35 с")
                && human.contains("Обход выключен")
                && human.lines().count() <= 20,
            "compact result distinguishes applied strategy and stopped bypass",
        )?;
        value["accepted"] = json!(false);
        value["primary_changed"] = json!(false);
        value["primary"] = json!("50");
        value["validation_error"] =
            json!("Финальная комбинация не подтвердила DPI/Hetzner: FAIL, TCP 30 мс, TLS 0 мс");
        value["final_checks"] = json!({"52":{"confirmed":false}});
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("НЕ ПРИМЕНЕНО: ALT11 белый 1")
                && human.contains("Hetzner")
                && !human.contains("TLS 0 мс"),
            "compact rejection shows one reason and retained primary",
        )?;
        let mut value = fixture();
        value["presentation"] = json!("compact");
        value["selection_policy"] = json!("availability-then-paired-connections-v1");
        value["accepted"] = json!(true);
        value["primary_changed"] = json!(true);
        value["best"] = json!({"id":"50"});
        value["primary"] = json!("50");
        value["connection_selection"] = json!({"reference":"52","candidate":"50","confirmed":true,"working":{"scope":"GameServices","targets":4,"gain_ms":30,"reference_tcp_ms":60,"candidate_tcp_ms":40,"reference_tls_ms":80,"candidate_tls_ms":60}});
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("быстрее на ~30 мс")
                && human.contains("TCP 40 / TLS 60 мс")
                && human.contains("игровой пинг не измерялся"),
            "connection advantage does not claim measured game ping",
        )?;
        value["connection_selection"]["confirmed"] = json!(false);
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            !human.contains("быстрее на ~30 мс"),
            "unconfirmed connection advantage is not advertised",
        )?;
        value["selection_policy"] = json!("availability-then-full-request-latency-v2");
        value["connection_selection"] = json!({"reference":"52","candidate":"50","confirmed":true,"working":{"scope":"AllTargets","targets":50,"gain_ms":40,"reference_tcp_ms":60,"candidate_tcp_ms":40,"reference_tls_ms":80,"candidate_tls_ms":60,"reference_total_ms":240,"candidate_total_ms":200,"reference_p95_ms":450,"candidate_p95_ms":400}});
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            human.contains("полный запрос быстрее на ~40 мс")
                && human.contains("адресов: 50")
                && human.contains("всего 200 мс")
                && human.contains("400 мс")
                && !human.contains("к 2K/EAC"),
            "full request result includes all targets and P95",
        )?;
        value["connection_selection"]["confirmed"] = json!(false);
        let human = cached(&runner, &mut evidence, &value, before)?;
        evidence.check(
            !human.contains("полный запрос быстрее"),
            "unconfirmed full request advantage is not advertised",
        )?;
        for args in [
            vec!["status"],
            vec!["service", "status"],
            vec!["task", "status", "notify"],
            vec!["task", "status", "autotune"],
            vec!["telegram", "status"],
        ] {
            let human = text(&run_launcher(&runner, &args, 0)?)?;
            let human = human.trim();
            evidence.check(
                !human.is_empty()
                    && !human.starts_with(['{', '['])
                    && ![
                        "\"xml\":",
                        "\"arguments\":",
                        "\"processes\":",
                        "\"config_hash\":",
                    ]
                    .iter()
                    .any(|key| human.contains(key)),
                format!("read-only {} has human output", args.join(" ")),
            )?;
        }
        fs::remove_file(&saved)?;
        let missing = run_launcher(&runner, &["test", "--last"], 1)?;
        evidence.check(
            String::from_utf8_lossy(&missing.stderr).contains("Результатов ещё нет"),
            "missing history is readable and never starts selection",
        )?;
        let mut value = fixture();
        value["schema"] = json!(999);
        fs::write(&saved, serde_json::to_vec(&value)?)?;
        evidence.check(
            String::from_utf8_lossy(&run_launcher(&runner, &["test", "--last"], 1)?.stderr)
                .to_lowercase()
                .contains("повреждён"),
            "unsupported saved schema is readable",
        )?;
        fs::write(&saved, b"{broken")?;
        evidence.check(
            String::from_utf8_lossy(&run_launcher(&runner, &["test", "--last"], 1)?.stderr)
                .to_lowercase()
                .contains("повреждён"),
            "malformed saved JSON is readable",
        )?;
        evidence.check(
            fs::read(&settings)? == before
                && sha256_file(&runner.executable)? == binary_before
                && ![
                    "native-engine.json",
                    "manual-stop.txt",
                    "test-restore-pending.txt",
                ]
                .iter()
                .any(|name| root.join("runtime").join(name).exists()),
            "read-only launcher routes preserve engine intent and controller",
        )?;
        Ok(())
    })();
    evidence.save(output, Some(&archive), &result)?;
    result
}
