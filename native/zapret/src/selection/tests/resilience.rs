use super::*;

fn clean(name: &str, host: &str) -> Target {
    Target {
        group: "Clean".into(),
        name: name.into(),
        url: format!("https://{host}/{name}"),
        post: false,
        expected: None,
        peer: None,
    }
}

fn sample(target: &Target, state: &str, code: &str) -> Row {
    Row {
        group: target.group.clone(),
        name: target.name.clone(),
        url: target.url.clone(),
        code: code.into(),
        ..row(state)
    }
}

fn dns_failure(target: &Target) -> Row {
    Row {
        termination: "DnsFailure".into(),
        ..sample(target, "NA", "000")
    }
}

#[test]
fn standby_replaces_only_a_failure_observed_before_the_profile_starts() {
    let targets: Vec<_> = ["one", "two", "three", "spare"]
        .into_iter()
        .map(|n| clean(n, &format!("{n}.example")))
        .collect();
    let probes = |failed| {
        targets
            .iter()
            .flat_map(|t| {
                let row = sample(t, "OK", if t.name == failed { "503" } else { "200" });
                [row.clone(), row]
            })
            .collect::<Vec<_>>()
    };
    let before = probes("three");
    let panel = controls_for_trial(&targets, &before, &BTreeMap::new());
    assert_eq!(
        panel.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["one", "two", "spare"]
    );
    let first = probes("");
    let after = probes("three");
    let fixed = controls_for_trial(&targets, &first, &BTreeMap::new());
    assert_eq!(
        fixed.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["one", "two", "three"]
    );
    assert!(!control_failures(&fixed, &first[..6], &after[..6]).is_empty());
}

#[test]
fn controls_keep_their_content_check_and_require_distinct_successful_hosts() {
    let mut portal = clean("portal", "probe.example");
    portal.expected = ExpectedResponse::parse(&["GET", "200", "8"]).unwrap();
    let targets = [
        portal,
        clean("alias", "probe.example."),
        clean("error", "broken.example"),
        clean("redirect", "login.example"),
        clean("other", "healthy.example"),
    ];
    let rows: Vec<_> = targets
        .iter()
        .zip(["200", "200", "503", "302", "204"])
        .map(|(t, code)| sample(t, "OK", code))
        .collect();
    let selected = select_controls(&targets, &rows);
    assert_eq!(
        selected.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["portal", "other"]
    );
    let job = selected[0].job(200, true);
    assert_eq!(job.method.as_deref(), Some("GET"));
    assert_eq!(job.body_limit, 9);
    let pair = [targets[0].clone(), targets[1].clone()];
    let repeated = [
        rows[0].clone(),
        rows[1].clone(),
        rows[0].clone(),
        rows[1].clone(),
    ];
    assert!(!control_failures(&pair, &repeated, &repeated).is_empty());
    for code in ["302", "429", "503"] {
        let current = sample(&targets[0], "OK", code);
        assert_eq!(
            summary("1", std::slice::from_ref(&current), &baseline(&rows)).harm,
            1
        );
        assert!(final_check(&rows[..1], std::slice::from_ref(&current)).is_err());
        assert!(!crate::selection_latency::preserves_services(
            &probe_details(&rows[..1]),
            &probe_details(&[current]),
            Panel::All
        ));
    }
}

#[test]
fn dns_retries_are_bounded_and_recovery_stays_visible() {
    let mut targets = (0..20)
        .map(|n| clean(&n.to_string(), "service.example"))
        .collect::<Vec<_>>();
    for t in &mut targets {
        t.group = "Discord".into();
    }
    let mut rows = targets
        .iter()
        .map(|t| sample(t, "FAIL", "000"))
        .collect::<Vec<_>>();
    rows[0] = dns_failure(&targets[0]);
    let keys = retries::Plan::new(&rows, &BTreeMap::new(), &BTreeSet::new(), true).first;
    assert_eq!(keys, BTreeSet::from([targets[0].key()]));
    assert!(
        retries::Plan::new(&rows, &BTreeMap::new(), &keys, true)
            .first
            .is_empty()
    );
    merge_retry(&mut rows, &[sample(&targets[0], "OK", "200")]);
    assert!(rows[0].flaky && rows[0].tries == 2 && rows[0].state == "OK");
    let mut first = [dns_failure(&targets[0])];
    let mut tls = sample(&targets[0], "FAIL", "000");
    tls.termination = "TlsFailure".into();
    merge_retry(&mut first, &[tls]);
    assert_eq!(first[0].termination, "TlsFailure");
    assert!(!first[0].dns_failure());
}

#[test]
fn widespread_timeouts_expand_only_after_two_distinct_clean_recoveries() {
    let mut rows = (0..25)
        .map(|i| {
            let t = clean(&format!("site{i}"), &format!("host{}.example", i % 5));
            let mut row = sample(&t, "FAIL", "000");
            row.group = format!("Group{}", i % 5);
            row.termination = "Timeout".into();
            row
        })
        .collect::<Vec<_>>();
    // Another service name shares Group0's host and supplies no independent recovery.
    let mut same = rows[0].clone();
    same.group = "Alias".into();
    rows.push(same);
    let excluded = BTreeSet::from([rows[3].key()]);
    assert!(
        retries::Plan::new(&rows, &BTreeMap::new(), &excluded, false)
            .first
            .is_empty()
    );
    let plan = retries::Plan::new(&rows, &BTreeMap::new(), &excluded, true);
    assert_eq!(plan.sampled.len(), 4);
    assert!(plan.first.is_disjoint(&plan.reserve) && plan.reserve.is_disjoint(&excluded));
    let mut sample: Vec<_> = rows
        .iter()
        .filter(|r| plan.sampled.contains(&r.key()))
        .cloned()
        .collect();
    assert_eq!(
        sample
            .iter()
            .map(|r| hostname(&r.url))
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert!(!plan.expand(&sample));
    sample[0].state = "OK".into();
    sample[0].code = "200".into();
    assert!(!plan.expand(&[sample[0].clone(), sample[0].clone()]));
    sample[1].state = "OK".into();
    sample[1].code = "503".into();
    assert!(!plan.expand(&sample));
    sample[1].code = "204".into();
    assert!(plan.expand(&sample));
    rows.reverse();
    assert_eq!(
        plan.sampled,
        retries::Plan::new(&rows, &BTreeMap::new(), &excluded, true).sampled
    );
}

#[test]
fn baseline_recheck_replaces_the_whole_panel_or_stops_before_the_trials() {
    let targets = [clean("one", "one.example"), clean("two", "two.example")];
    let down: Vec<_> = targets.iter().map(dns_failure).collect();
    let up: Vec<_> = targets.iter().map(|t| sample(t, "OK", "200")).collect();
    let mut calls = Vec::new();
    let baseline = round_baseline(&targets, false, |again| {
        calls.push(again);
        Ok(if again {
            (up.clone(), true)
        } else {
            (down.clone(), false)
        })
    })
    .unwrap();
    assert_eq!(calls, [false, true]);
    assert!(baseline.eligible && baseline.repeated && baseline.controls.len() == 2);
    assert!(baseline.rows.iter().all(|r| !r.dns_failure()));
    calls.clear();
    for report_only in [false, true] {
        let failed = round_baseline(&targets, report_only, |again| {
            calls.push(again);
            Ok((down.clone(), false))
        });
        assert!(failed.err().unwrap().to_string().contains("Ошибок DNS"));
        assert_eq!(calls, [false, true]);
        calls.clear();
    }
    let observational = round_baseline(&targets[..1], true, |again| {
        assert!(!again);
        Ok((up[..1].to_vec(), false))
    })
    .unwrap();
    assert_eq!(observational.controls.len(), 1);
    assert!(
        round_baseline(&targets[..1], false, |_| panic!(
            "invalid panel must not switch profiles"
        ))
        .is_err()
    );
    assert!(
        round_baseline(&targets, false, |again| {
            assert!(!again);
            Ok((up.clone(), true))
        })
        .is_ok()
    );
    assert!(
        round_baseline(&targets, false, |_| anyhow::bail!("cancelled"))
            .err()
            .unwrap()
            .to_string()
            .contains("cancelled")
    );
}

#[test]
fn retries_keep_one_real_peer_and_clock_instead_of_component_minima() {
    let mut first = row("OK");
    first.conn_ms = 5.;
    first.tls_ms = 750.;
    first.total_ms = 800.;
    first.raw = json!({"remote_address":"192.0.2.1:443"});
    let mut next = first.clone();
    next.conn_ms = 30.;
    next.tls_ms = 70.;
    next.total_ms = 96.;
    next.raw = json!({"remote_address":"192.0.2.2:443"});
    let mut rows = [first.clone()];
    merge_retry(&mut rows, std::slice::from_ref(&next));
    assert_eq!(
        (rows[0].conn_ms, rows[0].tls_ms, rows[0].total_ms),
        (30., 70., 96.)
    );
    assert_eq!(rows[0].raw, next.raw);
    assert_eq!(rows[0].tries, 2);
    let mut initial = [next.clone()];
    merge_retry(&mut initial, &[first]);
    assert_eq!(initial[0].raw, next.raw);
    merge_retry(&mut initial, &[row("FAIL")]);
    assert!(initial[0].flaky && initial[0].failed_retry.is_some());

    let mut healthy = next.clone();
    healthy.group = "Clean".into();
    let mut busy = healthy.clone();
    busy.code = "503".into();
    busy.conn_ms = 1.;
    busy.tls_ms = 2.;
    let mut intermittent = [busy.clone()];
    merge_retry(&mut intermittent, std::slice::from_ref(&healthy));
    assert_eq!(intermittent[0].code, "200");
    assert!(intermittent[0].flaky);
    let mut intermittent = [healthy];
    merge_retry(&mut intermittent, &[busy]);
    assert_eq!(intermittent[0].code, "200");
    assert!(intermittent[0].flaky && intermittent[0].failed_retry.is_some());
}

fn exited_child() -> OwnedChild {
    let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let args = ["-NoProfile", "-NonInteractive", "-Command", "exit 19"].map(OsString::from);
    let child = OwnedChild::spawn(&shell, &args, &RunOptions::default()).unwrap();
    child.wait_for_exit(Duration::from_secs(5)).unwrap();
    child
}

#[test]
fn only_an_exited_alternative_can_be_skipped_and_no_partial_result_survives() {
    let mut issues = Vec::new();
    let failed = finish_trial(Some(exited_child()), Ok(vec!["partial"]));
    assert_eq!(
        failed
            .as_ref()
            .unwrap_err()
            .downcast_ref::<TrialExit>()
            .unwrap()
            .code,
        19
    );
    assert!(
        optional_candidate("2", "1", failed, |r| {
            issues.push(r);
            Ok(())
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(issues.len(), 1);
    assert_eq!(
        optional_candidate("3", "1", Ok(7), |_| panic!()).unwrap(),
        Some(7)
    );
    let exit = || -> Result<()> {
        Err(TrialExit {
            phase: "во время измерения",
            code: 19,
        }
        .into())
    };
    assert!(optional_candidate("1", "1", exit(), |_| panic!()).is_err());
    assert!(
        optional_candidate("2", "1", exit(), |_| anyhow::bail!("network changed"))
            .unwrap_err()
            .to_string()
            .contains("network changed")
    );
    let simultaneous: Result<()> =
        finish_trial(Some(exited_child()), Err(anyhow::anyhow!("cancelled")));
    assert!(!simultaneous.as_ref().unwrap_err().is::<TrialExit>());
    assert!(
        format!(
            "{:#}",
            optional_candidate("2", "1", simultaneous, |_| panic!()).unwrap_err()
        )
        .contains("cancelled")
    );
}

#[test]
fn a_failed_later_round_cannot_leave_the_current_profile_to_win_by_default() {
    let pool = ["1", "2", "3"].map(|id| Strategy {
        id: id.into(),
        ..Default::default()
    });
    let scores = pool.each_ref().map(|strategy| RankRow {
        id: strategy.id.clone(),
        ..Default::default()
    });
    let mut quality = BTreeMap::from([("1".into(), true), ("2".into(), true), ("3".into(), false)]);
    let first_round = qualified_scores(&scores, &quality);
    assert!(!missing_comparison("1", &pool, &first_round));

    quality.insert("2".into(), false);
    let final_round = qualified_scores(&scores, &quality);
    assert!(missing_comparison("1", &pool, &final_round));
    assert!(!missing_comparison("1", &pool[..1], &final_round));
    quality.insert("3".into(), true);
    assert!(!missing_comparison(
        "1",
        &pool,
        &qualified_scores(&scores, &quality)
    ));
}

#[test]
fn connection_change_during_publication_restores_the_rank_and_primary_together() {
    let temp = tempfile::tempdir().unwrap();
    let app = App {
        root: temp.path().into(),
        yes: false,
        json: true,
    };
    let runtime = app.root.join("runtime");
    fs::create_dir(&runtime).unwrap();
    let previous = Settings::default();
    save_settings(&app.root, &previous).unwrap();
    let mut candidate = previous.clone();
    candidate
        .set(
            "alt",
            if previous.get("alt") == "32" {
                "41"
            } else {
                "32"
            },
        )
        .unwrap();
    let rank = TestRank {
        date: None,
        version: VERSION.into(),
        base_ok: 1.,
        base_total: 1,
        base_groups: BTreeMap::new(),
        base_group_totals: BTreeMap::new(),
        rows: vec![],
        context: Some(zapret_core::TestResultContext {
            schema: 2,
            network_key: "A".repeat(64),
            inputs_hash: "B".repeat(64),
            run_id: "1".repeat(32),
        }),
    };
    zapret_core::save_rank(&app.root, &rank).unwrap();
    let old_rank = fs::read(runtime.join("test-rank.txt")).unwrap();
    let old_settings = fs::read(runtime.join("settings.ini")).unwrap();
    fs::write(runtime.join("test-scores.txt"), b"old history").unwrap();
    let mut changed_rank = rank.clone();
    changed_rank.base_ok = 0.;
    let mut calls = 0;
    let err = publish(
        &app,
        &previous,
        &candidate,
        &changed_rank,
        &Coverage::new(),
        b"new history",
        &[],
        || {
            calls += 1;
            if calls == 2 {
                assert_eq!(
                    read_settings(&app.root).unwrap().get("alt"),
                    candidate.get("alt")
                );
                assert_ne!(fs::read(runtime.join("test-rank.txt")).unwrap(), old_rank);
                anyhow::bail!("gateway changed");
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("gateway changed"));
    assert_eq!(calls, 2);
    assert_eq!(fs::read(runtime.join("test-rank.txt")).unwrap(), old_rank);
    assert_eq!(
        fs::read(runtime.join("settings.ini")).unwrap(),
        old_settings
    );
    assert_eq!(
        fs::read(runtime.join("test-scores.txt")).unwrap(),
        b"old history"
    );
    assert!(
        !runtime.join("test-cover.txt").exists() && !runtime.join("tested-strategies.txt").exists()
    );
}
