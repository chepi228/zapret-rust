use super::*;
use std::net::TcpListener;
use zapret_platform::{OwnedChild, ProcessMetrics};

fn job(name: &str, base: &str, path: &str) -> Value {
    json!({"version":1,"id":name,"url":format!("{base}{path}")})
}
fn payload(jobs: &[Value]) -> Vec<u8> {
    jobs.iter()
        .map(|job| format!("{job}\n"))
        .collect::<String>()
        .into_bytes()
}

fn measure(binary: &Path, args: &[OsString], input: Option<Vec<u8>>) -> Result<(RunOutput, Value)> {
    let started = Instant::now();
    let mut environment = BTreeMap::new();
    if binary
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("powershell.exe"))
    {
        environment.insert(
            "PSModulePath".into(),
            PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot")?)
                .join("System32/WindowsPowerShell/v1.0/Modules")
                .into_os_string(),
        );
    }
    let mut child = OwnedChild::spawn(
        binary,
        args,
        &RunOptions {
            stdin: input,
            env: environment,
            timeout: Duration::from_secs(30),
            max_output_bytes: 16 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    let metrics = ProcessMetrics::open(child.identity().clone()).ok();
    let mut peak = 0;
    while child.is_running()? {
        if let Some(sample) = metrics.as_ref().and_then(|metrics| metrics.sample().ok()) {
            peak = peak.max(sample["peak_working_set_bytes"].as_u64().unwrap_or(0));
        }
        child.wait_for_exit(Duration::from_millis(5))?;
    }
    let cpu = metrics.and_then(|metrics| metrics.cpu_total_ms().ok());
    let output = child.finish()?;
    ensure!(
        !output.timed_out && !output.output_truncated,
        "Probe subprocess exceeded its budget"
    );
    Ok((
        output,
        json!({"wall_ms":started.elapsed().as_secs_f64()*1000.,"root_cpu_ms":cpu,
        "root_peak_working_set_bytes":if peak>0{Some(peak)}else{None},"memory_scope":"sampled OS peak for the owned root process"}),
    ))
}

fn invoke_jobs(
    binary: &Path,
    prefix: &[OsString],
    jobs: &[Value],
    options: &[&str],
) -> Result<(BTreeMap<String, Value>, Value)> {
    let mut args = prefix.to_vec();
    args.extend(options.iter().map(OsString::from));
    let (output, metrics) = measure(binary, &args, Some(payload(jobs)))?;
    ensure!(
        output.exit_code == 0,
        "Probe exit {}: {}",
        output.exit_code,
        String::from_utf8_lossy(&output.stderr)
    );
    let mut rows = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        let id = row["id"].as_str().context("result id")?.to_owned();
        ensure!(rows.insert(id, row).is_none(), "Duplicate result id");
    }
    ensure!(
        rows.len() == jobs.len()
            && jobs
                .iter()
                .all(|job| job["id"].as_str().is_some_and(|id| rows.contains_key(id))),
        "Every job must have exactly one result"
    );
    Ok((rows, metrics))
}

pub(crate) fn run(
    root: &Path,
    binary: &Path,
    subcommand: Option<&str>,
    output: &Path,
    rounds: usize,
    compare_legacy: bool,
) -> Result<()> {
    ensure!((1..=7).contains(&rounds), "Benchmark rounds must be 1..7");
    ensure!(
        subcommand.is_none_or(|command| command == "probe"),
        "Only the probe subcommand is supported"
    );
    let binary = std::path::absolute(binary)?;
    let prefix = subcommand
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let mut evidence = Evidence::default();
    let result =
        (|| {
            let temporary = tempfile::Builder::new()
                .prefix("zapret-rust-probe-")
                .tempdir()?;
            let http = http::Fixture::new(false, None)?;
            let base = http.url();
            let mut cases = [
                "small",
                "large",
                "chunked",
                "chunked-short",
                "truncated",
                "empty",
                "denied",
                "redirect",
                "interim",
                "malformed",
                "oversized",
                "exact",
            ]
            .into_iter()
            .map(|name| job(name, &base, &format!("/{name}")))
            .collect::<Vec<_>>();
            let mut post = job("post", &base, "/small");
            post["post_bytes"] = json!(65536);
            cases.push(post);
            let mut timeout = job("timeout", &base, "/stall");
            timeout["timeout_ms"] = json!(200);
            cases.push(timeout);
            let mut timeout = job("header-timeout", &base, "/headers-stall");
            timeout["timeout_ms"] = json!(200);
            cases.push(timeout);
            let (rows, _) = invoke_jobs(&binary, &prefix, &cases, &[])?;
            evidence
                .observations
                .insert("initial_probes".into(), json!(rows));
            evidence
                .observations
                .insert("initial_fixture_errors".into(), json!(http.errors()));
            evidence.check(
                rows["small"]["body_complete"] == true && rows["small"]["body_bytes"] == 128,
                "complete short response",
            )?;
            for name in ["large", "chunked", "exact"] {
                let row = &rows[name];
                evidence.check(
                    row["termination"] == "BodyLimit"
                        && row["body_bytes"] == 65536
                        && row["target_reached"] == true
                        && row["body_complete"] == false,
                    format!("{name} stops at body budget"),
                )?;
            }
            evidence.check(
                rows["chunked-short"]["body_complete"] == true
                    && rows["chunked-short"]["body_bytes"] == 3,
                "chunked trailers complete correctly",
            )?;
            evidence.check(
                rows["truncated"]["termination"] == "TransferError"
                    && rows["truncated"]["body_bytes"] == 8192,
                "premature EOF retains partial body",
            )?;
            evidence.check(
                rows["empty"]["status_code"] == 204 && rows["empty"]["body_complete"] == true,
                "empty HTTP response",
            )?;
            evidence.check(
                rows["denied"]["status_code"] == 403 && rows["denied"]["body_complete"] == true,
                "HTTP error remains explicit",
            )?;
            evidence.check(
                rows["redirect"]["status_code"] == 302,
                "redirect remains an observation",
            )?;
            evidence.check(
                rows["interim"]["status_code"] == 200 && rows["interim"]["body_bytes"] == 128,
                "interim response does not replace final status",
            )?;
            for name in ["malformed", "oversized"] {
                evidence.check(
                    rows[name]["termination"] == "HttpFailure"
                        && rows[name]["status_code"].is_null(),
                    format!("{name} headers fail"),
                )?;
            }
            evidence.check(
                rows["timeout"]["termination"] == "Timeout"
                    && rows["timeout"]["stage"] == "Body"
                    && rows["timeout"]["body_bytes"] == 8192,
                "body timeout retains stage and bytes",
            )?;
            evidence.check(
                rows["header-timeout"]["termination"] == "Timeout"
                    && rows["header-timeout"]["stage"] == "Http",
                "header timeout retains completed TCP",
            )?;
            let post = http
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|request| request["method"] == "POST")
                .cloned()
                .context("POST observed")?;
            evidence.check(
                post["post_bytes"] == 65536 && rows["post"]["body_complete"] == true,
                "fixture receives full 64 KiB POST",
            )?;
            evidence.check(
                post["headers"]["range"] == "bytes=0-65535",
                "body budget is requested as Range",
            )?;
            evidence.check(
                rows.values()
                    .all(|row| !row["tcp_ms"].is_null() && row["certificate_validated"] == false),
                "HTTP retains TCP timing without TLS claims",
            )?;
            let mut one = job("one-byte", &base, "/large");
            one["body_limit"] = json!(1);
            let mut mib = job("one-mib", &base, "/large");
            mib["body_limit"] = json!(1048576);
            let (bounded, _) = invoke_jobs(&binary, &prefix, &[one, mib], &[])?;
            evidence.check(
                bounded["one-byte"]["body_bytes"] == 1
                    && bounded["one-mib"]["body_bytes"] == 1048576
                    && bounded
                        .values()
                        .all(|row| row["termination"] == "BodyLimit"),
                "custom body budgets include supported boundaries",
            )?;
            evidence.check(
                bounded
                    .values()
                    .all(|row| row["received_body_bytes"].as_u64() >= row["body_bytes"].as_u64())
                    && bounded["one-byte"]["received_body_bytes"]
                        .as_u64()
                        .is_some_and(|n| n > 1),
                "decoded bytes expose buffering beyond accepted budget",
            )?;
            let mut pending = vec![job("active", &base, "/stall")];
            pending.extend((0..5).map(|i| job(&format!("queued-{i}"), &base, "/small")));
            let (deadline, metrics) = invoke_jobs(
                &binary,
                &prefix,
                &pending,
                &["--parallel", "1", "--deadline-ms", "100"],
            )?;
            evidence.check(
                deadline
                    .values()
                    .all(|row| row["termination"] == "Deadline")
                    && deadline["active"]["body_bytes"] == 8192
                    && deadline
                        .iter()
                        .filter(|(id, _)| *id != "active")
                        .all(|(_, row)| row["stage"] == "Queued")
                    && metrics["wall_ms"].as_f64().is_some_and(|ms| ms < 1500.),
                "batch deadline includes queued jobs and preserves active progress",
            )?;
            let before = http.requests.lock().unwrap().len();
            let duplicate = job("duplicate", &base, "/small");
            let (invalid, _) = measure(
                &binary,
                &prefix,
                Some(payload(&[duplicate.clone(), duplicate])),
            )?;
            evidence.check(
                invalid.exit_code == 2
                    && invalid.stdout.is_empty()
                    && http.requests.lock().unwrap().len() == before,
                "invalid batch is rejected before network activity",
            )?;
            for (field, value) in [
                ("version", json!(2)),
                ("body_limit", json!(0)),
                ("timeout_ms", json!(60001)),
                ("unexpected", json!(true)),
                ("url", json!("file:///C:/Windows/win.ini")),
                ("url", json!("http://user:pass@localhost/")),
            ] {
                let mut bad = job("bad", &base, "/small");
                bad[field] = value;
                let (invalid, _) = measure(&binary, &prefix, Some(payload(&[bad])))?;
                evidence.check(
                    invalid.exit_code == 2 && invalid.stdout.is_empty(),
                    format!("reject invalid {field}"),
                )?;
            }
            let reserved = TcpListener::bind("127.0.0.1:0")?;
            let port = reserved.local_addr()?.port();
            drop(reserved);
            let (refused, _) = invoke_jobs(
                &binary,
                &prefix,
                &[job("refused", &format!("http://127.0.0.1:{port}"), "/")],
                &[],
            )?;
            evidence.check(
                refused["refused"]["termination"] == "TcpFailure"
                    && refused["refused"]["stage"] == "Tcp",
                "TCP refusal is separate from TLS",
            )?;
            let (dns, _) = invoke_jobs(
                &binary,
                &prefix,
                &[job(
                    "dns",
                    &base.replace("127.0.0.1", "localhost"),
                    "/small",
                )],
                &[],
            )?;
            evidence.check(
                dns["dns"]["body_complete"] == true
                    && dns["dns"]["dns_source"] == "system"
                    && dns["dns"]["resolved_addresses"]
                        .as_array()
                        .is_some_and(|a| !a.is_empty()),
                "system DNS and address fallback reach localhost",
            )?;
            let (dns, _) = invoke_jobs(
                &binary,
                &prefix,
                &[job(
                    "dns-failure",
                    &format!("http://{}.invalid", "a".repeat(64)),
                    "/",
                )],
                &[],
            )?;
            evidence.check(
                dns["dns-failure"]["termination"] == "DnsFailure"
                    && dns["dns-failure"]["stage"] == "Dns"
                    && dns["dns-failure"]["tcp_attempts"]
                        .as_array()
                        .is_some_and(Vec::is_empty),
                "DNS failure remains separate from TCP",
            )?;
            match http::Fixture::new(true, None) {
                Ok(six) => {
                    let (rows, _) =
                        invoke_jobs(&binary, &prefix, &[job("ipv6", &six.url(), "/small")], &[])?;
                    evidence.check(
                        rows["ipv6"]["body_complete"] == true
                            && rows["ipv6"]["remote_address"]
                                .as_str()
                                .is_some_and(|s| s.starts_with("[::1]")),
                        "IPv6 loopback",
                    )?;
                }
                Err(error) => {
                    evidence
                        .observations
                        .insert("ipv6_skipped".into(), json!(error.to_string()));
                }
            }
            let (tls, pem) = http::tls()?;
            let ca = temporary.path().join("cert.pem");
            fs::write(&ca, pem)?;
            let https = http::Fixture::new(false, Some(tls.clone()))?;
            let base_tls = format!("https://localhost:{}", https.address.port());
            let mut tls_job = job("tls", &base_tls, "/small");
            tls_job["connect_ip"] = json!("127.0.0.1");
            let (untrusted, _) = invoke_jobs(&binary, &prefix, &[tls_job.clone()], &[])?;
            evidence.check(
                untrusted["tls"]["termination"] == "TlsFailure"
                    && !untrusted["tls"]["tcp_ms"].is_null()
                    && untrusted["tls"]["certificate_validated"] == false,
                "default trust rejects self-signed TLS",
            )?;
            let ca = ca.to_str().context("CA path")?;
            let local = zapret_core::connection_addresses(
                std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 0))?,
                2,
            );
            if let [first, second] = local.as_slice()
                && first.is_ipv6() != second.is_ipv6()
            {
                let rejected = http::Fixture::at(*first, Some(http::tls()?.0))?;
                let mut alt = *second;
                alt.set_port(rejected.address.port());
                let alternate = http::Fixture::at(alt, Some(tls))?;
                let url = format!("https://localhost:{}", alt.port());
                let (recovered, _) = invoke_jobs(
                    &binary,
                    &prefix,
                    &[job("alternate", &url, "/small")],
                    &["--ca-file", ca],
                )?;
                let row = &recovered["alternate"];
                evidence.check(
                row["body_complete"] == true
                    && row["certificate_validated"] == true
                    && row["remote_address"] == alt.to_string()
                    && row["tcp_attempts"].as_array().is_some_and(|attempts| {
                        attempts.iter().filter(|a| a["error"].is_null()).count() == 2
                            && attempts.iter().filter(|a| a["tls_error"].is_string()).count() == 1
                    })
                    && rejected.requests.lock().unwrap().is_empty()
                    && alternate.requests.lock().unwrap().len() == 1,
                "dual-stack HTTPS retries TLS on the other address and sends one verified request",
            )?;
            }
            let (trusted, _) = invoke_jobs(&binary, &prefix, &[tls_job], &["--ca-file", ca])?;
            evidence
                .observations
                .insert("local_tls".into(), trusted["tls"].clone());
            evidence.check(
                trusted["tls"]["body_complete"] == true
                    && trusted["tls"]["certificate_validated"] == true
                    && !trusted["tls"]["tls_ms"].is_null()
                    && trusted["tls"]["trust_source"] == "SystemPlusExtraCa",
                "process-local CA permits validated TLS",
            )?;
            evidence.check(
                https
                    .names
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|name| name == "localhost")
                    && https.requests.lock().unwrap().last().is_some_and(|row| {
                        row["headers"]["host"] == format!("localhost:{}", https.address.port())
                    }),
                "selected IP preserves original SNI and Host",
            )?;
            let mut mismatch = job(
                "mismatch",
                &base_tls.replace("localhost", "wrong.invalid"),
                "/small",
            );
            mismatch["connect_ip"] = json!("127.0.0.1");
            let (wrong, _) = invoke_jobs(&binary, &prefix, &[mismatch], &["--ca-file", ca])?;
            evidence.check(
                wrong["mismatch"]["termination"] == "TlsFailure"
                    && wrong["mismatch"]["certificate_validated"] == false,
                "extra CA preserves hostname verification",
            )?;
            let mut stalled = job("tls-stall", &http.url().replace("http:", "https:"), "/");
            stalled["timeout_ms"] = json!(150);
            let (stalled, metrics) = invoke_jobs(&binary, &prefix, &[stalled], &[])?;
            evidence.check(
                stalled["tls-stall"]["stage"] == "Tls"
                    && stalled["tls-stall"]["termination"] == "Timeout"
                    && metrics["wall_ms"].as_f64().is_some_and(|n| n < 1500.),
                "TLS timeout retains completed TCP",
            )?;
            // Preserve a captured 64 KiB payload byte for byte rather than silently
            // substituting zeros. Check both the file and the default request body.
            let captured = (0..65536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let post_file = temporary.path().join("post64k.bin");
            fs::write(&post_file, &captured)?;
            let mut post_job = job("captured", &base, "/small");
            post_job["post_bytes"] = json!(65536);
            invoke_jobs(
                &binary,
                &prefix,
                &[post_job.clone()],
                &["--post-file", post_file.to_str().unwrap()],
            )?;
            evidence.check(
                http.requests
                    .lock()
                    .unwrap()
                    .last()
                    .is_some_and(|row| row["post_sha256"] == zapret_core::sha256(&captured))
                    && post["post_sha256"] == zapret_core::sha256(&vec![0; 65536]),
                "captured POST bytes and default zero body are preserved",
            )?;
            fs::write(&post_file, [1, 2, 3])?;
            let mut args = prefix.clone();
            args.extend(["--post-file".into(), post_file.into_os_string()]);
            let (bad, _) = measure(&binary, &args, Some(payload(&[post_job])))?;
            evidence.check(
                bad.exit_code == 2 && bad.stdout.is_empty(),
                "invalid POST file is rejected before requests",
            )?;
            let benchmark = benchmark(
                root,
                &binary,
                &prefix,
                &http,
                temporary.path(),
                rounds,
                compare_legacy,
            )?;
            evidence.observations.insert("benchmark".into(), benchmark);
            let until = Instant::now() + Duration::from_secs(3);
            while !http.idle() && Instant::now() < until {
                thread::sleep(Duration::from_millis(10));
            }
            evidence.check(http.idle(), "all HTTP fixture connections close")?;
            evidence.check(
                http.errors().is_empty() && https.errors().is_empty(),
                format!(
                    "fixture handlers have no unexpected errors: {:?}",
                    http.errors()
                ),
            )?;
            evidence
                .observations
                .insert("binary_sha256".into(), json!(sha256_file(&binary)?));
            evidence.observations.insert(
                "cargo_lock_sha256".into(),
                json!(sha256_file(&root.join("native/Cargo.lock"))?),
            );
            evidence.observations.insert(
                "source_sha256".into(),
                json!(hashes(&root.join("native/zapret-net/src"))?),
            );
            Ok(())
        })();
    evidence.save(output, None, &result)?;
    result
}

fn benchmark(
    root: &Path,
    binary: &Path,
    prefix: &[OsString],
    http: &http::Fixture,
    temporary: &Path,
    rounds: usize,
    compare: bool,
) -> Result<Value> {
    let jobs = (0..64)
        .map(|i| job(&format!("bench-{i}"), &http.url(), "/large"))
        .collect::<Vec<_>>();
    let input = temporary.join("bench.jsonl");
    fs::write(&input, payload(&jobs))?;
    let mut samples: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for iteration in 0..rounds {
        let arms = if compare {
            if iteration % 2 == 0 {
                vec!["rust", "powershell_curl"]
            } else {
                vec!["powershell_curl", "rust"]
            }
        } else {
            vec!["rust"]
        };
        for arm in arms {
            let mut metrics = if arm == "rust" {
                let (rows, mut metrics) =
                    invoke_jobs(binary, prefix, &jobs, &["--parallel", "16"])?;
                ensure!(
                    rows.values()
                        .all(|row| row["target_reached"] == true && row["body_bytes"] == 65536),
                    "Benchmark result mismatch"
                );
                metrics["network_ms"] = json!(
                    rows.values()
                        .map(|row| row["started_ms"].as_f64().unwrap()
                            + row["total_ms"].as_f64().unwrap())
                        .fold(0., f64::max)
                );
                let median = |field: &str| {
                    let mut samples = rows
                        .values()
                        .map(|row| row[field].as_f64().unwrap())
                        .collect::<Vec<_>>();
                    samples.sort_by(f64::total_cmp);
                    let middle = samples.len() / 2;
                    (samples[middle - 1] + samples[middle]) / 2.
                };
                metrics["request_start_offset_p50_ms"] = json!(median("started_ms"));
                metrics["request_elapsed_p50_ms"] = json!(median("total_ms"));
                metrics["process_overhead_ms"] = json!(
                    metrics["wall_ms"].as_f64().unwrap() - metrics["network_ms"].as_f64().unwrap()
                );
                metrics["body_bytes"] = json!(
                    rows.values()
                        .map(|row| row["body_bytes"].as_u64().unwrap())
                        .sum::<u64>()
                );
                metrics["decoded_body_bytes"] = json!(
                    rows.values()
                        .map(|row| row["received_body_bytes"].as_u64().unwrap())
                        .sum::<u64>()
                );
                metrics["request_child_launches"] = json!(0);
                metrics
            } else {
                // Explicit historical comparison arm. No production command
                // depends on PowerShell/curl and these numbers are root-only.
                let powershell =
                    PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot")?)
                        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
                let baseline = root.join("dev/rust-probe/curl-baseline.ps1");
                let args = vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    baseline.into_os_string(),
                    "-InputFile".into(),
                    input.as_os_str().into(),
                    "-Parallel".into(),
                    "16".into(),
                ];
                // Windows PowerShell must discover its own modules when the
                // developer runner itself was launched from PowerShell 7.
                let (out, mut metrics) = measure(&powershell, &args, None)?;
                ensure!(
                    out.exit_code == 0,
                    "Legacy comparison failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let value: Value = serde_json::from_str(
                    std::str::from_utf8(&out.stdout)?.trim_start_matches('\u{feff}'),
                )?;
                let rows = value["Rows"].as_array().context("legacy rows")?;
                ensure!(
                    rows.len() == 64
                        && rows
                            .iter()
                            .all(|row| row["TargetReached"] == true && row["BodyBytes"] == 65536),
                    "Legacy benchmark result mismatch"
                );
                metrics["network_ms"] = value["NetworkMs"].clone();
                metrics["body_bytes"] = json!(
                    rows.iter()
                        .map(|row| row["BodyBytes"].as_u64().unwrap())
                        .sum::<u64>()
                );
                metrics["decoded_body_bytes"] = json!(
                    rows.iter()
                        .map(|row| row["Down"].as_u64().unwrap())
                        .sum::<u64>()
                );
                metrics["request_child_launches"] = json!(64);
                metrics["source_sha256"] = value["SourceHash"].clone();
                metrics
            };
            metrics["scope"] = json!("Owned root process only; excludes child CPU/memory");
            samples.entry(arm).or_default().push(metrics);
        }
    }
    let mut medians = BTreeMap::new();
    for (arm, values) in &samples {
        let mut row = serde_json::Map::new();
        for field in [
            "wall_ms",
            "network_ms",
            "request_start_offset_p50_ms",
            "request_elapsed_p50_ms",
            "process_overhead_ms",
            "root_cpu_ms",
            "root_peak_working_set_bytes",
            "body_bytes",
            "decoded_body_bytes",
        ] {
            let mut numbers = values
                .iter()
                .filter_map(|value| value[field].as_f64())
                .collect::<Vec<_>>();
            numbers.sort_by(f64::total_cmp);
            row.insert(
                field.into(),
                if numbers.len() != values.len() {
                    Value::Null
                } else {
                    let mid = numbers.len() / 2;
                    json!(if numbers.len() % 2 == 0 {
                        (numbers[mid - 1] + numbers[mid]) / 2.
                    } else {
                        numbers[mid]
                    })
                },
            );
        }
        medians.insert(*arm, Value::Object(row));
    }
    Ok(
        json!({"rounds":rounds,"jobs_per_round":64,"parallel":16,"comparison":if compare{"HistoricalPowerShellCurl"}else{"NotMeasured"},"scope":"loopback HTTP/1.1; cold root processes; root CPU/memory excludes children; not game latency or strategy selection runtime","samples":samples,"medians":medians}),
    )
}
