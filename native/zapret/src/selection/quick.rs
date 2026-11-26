use super::*;

pub(super) fn panel(
    targets: &[Target],
    baseline: &[Row],
    active: &[Row],
    controls: &[Target],
) -> Vec<Target> {
    let mut selected = BTreeSet::new();
    let mut groups = BTreeMap::<&str, Vec<&Target>>::new();
    for target in targets {
        groups.entry(&target.group).or_default().push(target);
    }
    for (group, members) in groups {
        match group {
            "Clean" => {
                selected.extend(controls.iter().map(Target::key));
                selected.extend(
                    baseline
                        .iter()
                        .chain(active)
                        .filter(|r| {
                            r.group == "Clean"
                                && crate::selection_latency::steam_target(&r.name)
                                && (r.state != "OK" || r.flaky)
                        })
                        .map(Row::key),
                );
            }
            "DPI" => {
                for ok in [false, true] {
                    if let Some(row) = baseline
                        .iter()
                        .find(|r| r.group == group && (r.state == "OK") == ok)
                    {
                        selected.insert(row.key());
                    }
                }
            }
            _ => {
                // Prefer actions users can notice (image, validated download, API) over a home page.
                let representative = members
                    .iter()
                    .find(|t| {
                        matches!(
                            t.name.as_str(),
                            "media_file" | "game_icon" | "thumbnail" | "store_image" | "oembed"
                        )
                    })
                    .or_else(|| members.iter().find(|t| t.expected.is_some()))
                    .unwrap_or(&members[0]);
                selected.insert(representative.key());
                selected.extend(
                    baseline
                        .iter()
                        .chain(active)
                        .filter(|r| r.group == group && (r.state != "OK" || r.flaky))
                        .map(Row::key),
                );
            }
        }
    }
    targets
        .iter()
        .filter(|t| selected.contains(&t.key()))
        .cloned()
        .collect()
}

fn control_ok(t: &Target, rows: &[Value], clean: &BTreeMap<String, f64>) -> bool {
    let field = if t.url.starts_with("http://") {
        "tcp_ms"
    } else {
        "tls_ms"
    };
    rows.iter()
        .find(|r| r["group"] == t.group && r["name"] == t.name && r["url"] == t.url)
        .is_some_and(|r| {
            crate::selection_latency::stable(r)
                && r["code"].as_str().is_some_and(|code| code.starts_with('2'))
                && r[field]
                    .as_f64()
                    .zip(clean.get(&t.name))
                    .is_some_and(|(ms, base)| ms > 0. && ms <= base + 500.)
        })
}

fn reliable_controls(
    candidates: &[Target],
    primary: &str,
    results: &BTreeMap<String, Vec<Value>>,
    clean: &BTreeMap<String, f64>,
) -> Vec<Target> {
    let Some(active) = results.get(primary) else {
        return Vec::new();
    };
    let mut controls: Vec<_> = candidates
        .iter()
        .filter(|t| control_ok(t, active, clean))
        .collect();
    controls.sort_by_cached_key(|t| {
        std::cmp::Reverse(
            results
                .values()
                .filter(|rows| control_ok(t, rows, clean))
                .count(),
        )
    });
    controls.into_iter().take(4).cloned().collect()
}

pub(super) fn finalists(
    pool: &[Strategy],
    primary: &str,
    results: &BTreeMap<String, Vec<Value>>,
    clean: &BTreeMap<String, f64>,
    controls: &[Target],
) -> Vec<Strategy> {
    let Some(active) = results.get(primary) else {
        return pool.to_vec();
    };
    if pool.iter().any(|s| !results.contains_key(&s.id)) {
        return pool.to_vec();
    }
    let healthy = |rows: &[Value]| controls.iter().all(|t| control_ok(t, rows, clean));
    if controls.len() < 2 || !healthy(active) {
        return pool.to_vec();
    }
    struct Evidence<'a> {
        strategy: &'a Strategy,
        healthy: bool,
        coverage: (usize, u64, u64),
        points: Option<f64>,
        gains: BTreeSet<String>,
    }
    let mut ranked: Vec<_> = pool
        .iter()
        .map(|strategy| {
            let rows = &results[&strategy.id];
            let points = crate::selection_latency::compare_panel(active, rows, Panel::Services)
                .and_then(|pair| pair.service_score)
                .map(|score| score.points);
            Evidence {
                strategy,
                healthy: healthy(rows),
                coverage: crate::selection_latency::availability_rank(rows),
                points,
                gains: gains::improvements(active, rows, clean, Panel::Services),
            }
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.healthy
            .cmp(&a.healthy)
            .then_with(|| b.coverage.cmp(&a.coverage))
            .then_with(|| {
                b.points
                    .unwrap_or(f64::NEG_INFINITY)
                    .total_cmp(&a.points.unwrap_or(f64::NEG_INFINITY))
            })
            .then_with(|| a.strategy.id.cmp(&b.strategy.id))
    });
    if ranked.iter().filter(|r| r.healthy).count() < 2 {
        return pool.to_vec();
    }
    let mut chosen = BTreeSet::from([primary.to_owned()]);
    chosen.extend(
        ranked
            .iter()
            .filter(|r| r.healthy && r.strategy.id != primary)
            .take(3)
            .map(|r| r.strategy.id.clone()),
    );
    let mut uncovered: BTreeSet<_> = ranked
        .iter()
        .flat_map(|r| r.gains.iter().cloned())
        .collect();
    for r in ranked.iter().filter(|r| chosen.contains(&r.strategy.id)) {
        uncovered.retain(|key| !r.gains.contains(key));
    }
    // Prefer healthy representatives covering the most outstanding gains.
    // max_by_key takes the last tie, so iterate in reverse ranking order.
    while !uncovered.is_empty() {
        let best = ranked
            .iter()
            .rev()
            .map(|r| (r, r.gains.intersection(&uncovered).count()))
            .filter(|(_, count)| *count > 0)
            .max_by_key(|(r, count)| (r.healthy, *count));
        let Some((candidate, _)) = best else { break };
        chosen.insert(candidate.strategy.id.clone());
        uncovered.retain(|key| !candidate.gains.contains(key));
    }
    pool.iter()
        .filter(|s| chosen.contains(&s.id))
        .cloned()
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn screen(
    context: &RunContext<'_>,
    settings: &Settings,
    pool: &[Strategy],
    targets: &[Target],
    controls: &[Target],
    primary_rows: &[Row],
    controls_stable: bool,
    arguments: &TestArgs,
    metadata: &Value,
    clean: &BTreeMap<String, f64>,
) -> Result<(Vec<Strategy>, Vec<Target>, Value)> {
    let keys: BTreeSet<_> = targets.iter().map(Target::key).collect();
    let active: Vec<_> = primary_rows
        .iter()
        .filter(|r| keys.contains(&r.key()))
        .cloned()
        .collect();
    let mut results = BTreeMap::from([(settings.get("alt").to_owned(), probe_details(&active))]);
    let mut schedule: Vec<_> = pool
        .iter()
        .filter(|s| s.id != settings.get("alt"))
        .cloned()
        .collect();
    let mut seed = arguments
        .seed
        .unwrap_or_else(|| Utc::now().timestamp_micros() as u64)
        .max(1);
    shuffle(&mut schedule, &mut seed);
    let start = Instant::now();
    crate::selection_ui::progress(
        context.app,
        &format!(
            "Короткий отбор: {} профилей, {} общих адресов.",
            pool.len(),
            targets.len()
        ),
    )?;
    for (index, s) in schedule.iter().enumerate() {
        context.assert_current()?;
        crate::selection_ui::heading(
            context.app,
            &format!(
                "[{}/{}] Короткая проверка {}",
                index + 1,
                pool.len(),
                s.display_name()
            ),
        )?;
        let mut info = metadata.clone();
        info["Stage"] = json!("quick-screen");
        info["StrategyId"] = json!(s.id);
        let child = launch(
            context,
            settings,
            &s.id,
            false,
            engine_budget(targets.len(), arguments, false)?,
        );
        let result = run_trial(child, |engine| {
            measured(
                context,
                targets,
                arguments,
                engine,
                &info,
                clean,
                &BTreeSet::new(),
            )
        });
        if let Some((rows, _)) = context.candidate(&s.id, settings.get("alt"), result)? {
            results.insert(s.id.clone(), probe_details(&rows));
        }
    }
    let after = super::controls(context, controls, arguments, metadata, "quick-end")?;
    // A standby is eligible only when both fresh no-engine probes succeeded.
    let available: Vec<_> = controls
        .iter()
        .filter(|t| {
            let tested: Vec<_> = after.iter().filter(|r| r.key() == t.key()).collect();
            tested.len() == 2
                && tested
                    .iter()
                    .all(|r| r.healthy_control(clean.get(&t.name).copied()))
        })
        .cloned()
        .collect();
    let reliable = reliable_controls(&available, settings.get("alt"), &results, clean);
    let stable = controls_stable && reliable.len() >= 2;
    let completed: Vec<_> = pool
        .iter()
        .filter(|s| results.contains_key(&s.id))
        .cloned()
        .collect();
    let chosen = if stable {
        finalists(
            &completed,
            settings.get("alt"),
            &results,
            clean,
            &reliable[..2],
        )
    } else {
        completed
    };
    let report = json!({"targets":targets.iter().map(Target::key).collect::<Vec<_>>(),"screened":pool.len(),
        "elapsed_ms":start.elapsed().as_secs_f64()*1000.,"controls_stable":stable,"controls":reliable.iter().map(Target::key).collect::<Vec<_>>(),"finalists":chosen.iter().map(|s|&s.id).collect::<Vec<_>>(),"details":results});
    Ok((chosen, reliable, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(group: &str, name: &str, ok: bool) -> Value {
        json!({"group":group,"name":name,"url":format!("https://{name}.example/"),"state":if ok{"OK"}else{"FAIL"},
            "tries":1,"code":"200","certificate_validated":true,"tls_ms":40.})
    }
    fn controls_panel() -> Vec<Target> {
        ["a", "b"]
            .iter()
            .map(|name| Target {
                group: "Clean".into(),
                name: (*name).into(),
                url: format!("https://{name}.example/"),
                post: false,
                expected: None,
                peer: None,
            })
            .collect()
    }

    #[test]
    fn standby_controls_must_work_on_the_primary_and_survive_the_screen() {
        let controls: Vec<_> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|n| Target {
                group: "Clean".into(),
                name: n.into(),
                url: format!("https://{n}.example/"),
                post: false,
                expected: None,
                peer: None,
            })
            .collect();
        let clean = controls.iter().map(|t| (t.name.clone(), 40.)).collect();
        let mut results = BTreeMap::new();
        for profile in ["primary", "1", "2"] {
            let rows = controls
                .iter()
                .map(|t| {
                    let ok = match t.name.as_str() {
                        "a" => profile == "primary",
                        "d" => profile != "primary",
                        _ => true,
                    };
                    row("Clean", &t.name, ok)
                })
                .collect();
            results.insert(profile.to_owned(), rows);
        }
        let selected = reliable_controls(&controls, "primary", &results, &clean);
        assert_eq!(
            selected.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["b", "c", "a"]
        );
    }

    #[test]
    fn retains_current_and_unique_repair_outside_three_leaders() {
        let pool: Vec<_> = (1..=6)
            .map(|i| Strategy {
                id: i.to_string(),
                ..Default::default()
            })
            .collect();
        let mut results: BTreeMap<_, _> = pool
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    vec![
                        row("Clean", "a", true),
                        row("Clean", "b", true),
                        row("Discord", "file", s.id == "6"),
                        row("YouTube", "web", s.id != "6"),
                        row("Roblox", "icon", s.id != "6"),
                        row("CDN", "file", s.id != "6"),
                    ],
                )
            })
            .collect();
        let clean = BTreeMap::from([("a".into(), 40.), ("b".into(), 40.)]);
        let chosen = finalists(&pool, "5", &results, &clean, &controls_panel());
        assert_eq!(chosen.len(), 5);
        assert!(chosen.iter().any(|s| s.id == "5") && chosen.iter().any(|s| s.id == "6"));
        // Two lower-ranked candidates repair the same address. Keep the better one.
        results.insert("4".into(), results["6"].clone());
        let chosen = finalists(&pool, "5", &results, &clean, &controls_panel());
        assert_eq!(
            chosen.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["1", "2", "3", "4", "5"]
        );
        let mut missing = results.clone();
        let removed = missing.remove("2").unwrap();
        missing.insert("unknown".into(), removed);
        assert_eq!(
            finalists(&pool, "5", &missing, &clean, &controls_panel()),
            pool
        );
        results.get_mut("5").unwrap()[0]["state"] = json!("FAIL");
        assert_eq!(
            finalists(&pool, "5", &results, &clean, &controls_panel()),
            pool
        );
    }

    #[test]
    #[ignore = "developer replay with ZAPRET_REPLAY_REPORT, ZAPRET_REPLAY_ROOT and ZAPRET_REPLAY_PRIMARY"]
    fn replay_recorded_selection() {
        let root = PathBuf::from(std::env::var_os("ZAPRET_REPLAY_ROOT").unwrap());
        let primary = std::env::var("ZAPRET_REPLAY_PRIMARY").unwrap();
        let report: Value = serde_json::from_slice(
            &std::fs::read(std::env::var_os("ZAPRET_REPLAY_REPORT").unwrap()).unwrap(),
        )
        .unwrap();
        let full: BTreeMap<String, Vec<Value>> =
            serde_json::from_value(report["details"].clone()).unwrap();
        let base: Vec<Row> = serde_json::from_value(report["base"].clone()).unwrap();
        let live: BTreeSet<_> = base.iter().map(Row::key).collect();
        let targets: Vec<_> = read_targets_with_suite(&root, &root.join("tools/dpi-suite.json"))
            .unwrap()
            .into_iter()
            .filter(|t| live.contains(&t.key()))
            .collect();
        assert_eq!(targets.len(), base.len());
        let pool: Vec<_> = list_strategies(&root)
            .unwrap()
            .into_iter()
            .filter(|s| full.contains_key(&s.id))
            .collect();
        let clean = baseline(&base);
        let active: Vec<_> = base
            .iter()
            .map(|r| {
                let d = full[&primary]
                    .iter()
                    .find(|d| d["group"] == r.group && d["name"] == r.name && d["url"] == r.url)
                    .unwrap();
                Row {
                    state: d["state"].as_str().unwrap().into(),
                    flaky: d["flaky"] == true,
                    ..r.clone()
                }
            })
            .collect();
        let controls = select_controls(&targets, &base);
        let short = panel(&targets, &base, &active, &controls);
        let masked = pool
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    full[&s.id]
                        .iter()
                        .filter(|d| {
                            short.iter().any(|t| {
                                d["group"] == t.group && d["name"] == t.name && d["url"] == t.url
                            })
                        })
                        .cloned()
                        .collect(),
                )
            })
            .collect();
        let full_controls = reliable_controls(&controls, &primary, &masked, &clean);
        let picked = finalists(
            &pool,
            &primary,
            &masked,
            &clean,
            &full_controls[..full_controls.len().min(2)],
        );
        let repairs_for = |strategies: &[Strategy]| -> BTreeSet<_> {
            strategies
                .iter()
                .flat_map(|s| {
                    gains::improvements(&full[&primary], &full[&s.id], &clean, Panel::Services)
                })
                .collect()
        };
        let repairs = repairs_for(&pool);
        let retained = repairs_for(&picked);
        let cold = crate::selection_learning::Cache::new("replay")
            .plan(&pool, &primary, false, &BTreeMap::new(), 0, &[])
            .strategies;
        let cold_rows = cold
            .iter()
            .map(|s| (s.id.clone(), masked[&s.id].clone()))
            .collect();
        let cold_controls = reliable_controls(&controls, &primary, &cold_rows, &clean);
        let cold_finalists = finalists(
            &cold,
            &primary,
            &cold_rows,
            &clean,
            &cold_controls[..cold_controls.len().min(2)],
        );
        let cold_repairs = repairs_for(&cold_finalists);
        let best = report["best"]["id"].as_str().unwrap();
        let screening = gains::improvements(&full[&primary], &full[best], &clean, Panel::Services);
        let working = gains::improvements(
            report["working_reference"].as_array().unwrap(),
            report["final_details"].as_array().unwrap(),
            &clean,
            Panel::Services,
        );
        println!(
            "{}",
            json!({"profiles":pool.len(),"full_targets":targets.len(),"short_targets":short.len(),
            "full_finalists":picked.iter().map(|s|&s.id).collect::<Vec<_>>(),"historical_winner":best,
            "possible_repairs":repairs.len(),"missed_repairs":repairs.difference(&retained).collect::<Vec<_>>(),
            "cold_profiles":cold.len(),"cold_finalists":cold_finalists.iter().map(|s|&s.id).collect::<Vec<_>>(),
            "cold_missed_repairs":repairs.difference(&cold_repairs).collect::<Vec<_>>(),
            "screening_advantages":screening,"forward_advantages":working})
        );
    }
}
