//! Revalidate game pins through a bounded, owned read-only worker before touching hosts.
use crate::{
    RunOptions,
    process::wide,
    storage::{atomic_write, read_limited},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    net::Ipv4Addr,
    path::Path,
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::NetworkManagement::Dns::*;
use zapret_core::{EPIC_API_HOST, EPIC_JWKS_URL, JWKS_MAX_BYTES, NBA_CDN_HOST, NBA_STORE_IMAGE};

const BEGIN: &str = "# zapret: серверы игр - начало (меню: Проверка обходов)";
const END: &str = "# zapret: серверы игр - конец";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    host: String,
    pinned: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    address: String,
    peer_address: Option<String>,
    validation_host: String,
    certificate_validated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_verified: Option<bool>,
    supported: bool,
    reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    host: String,
    dns_known: bool,
    dns: Vec<String>,
    checks: Vec<Check>,
    error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: u32,
    rows: Vec<Row>,
}
fn public_v4(text: &str) -> bool {
    text.parse::<Ipv4Addr>().is_ok() && zapret_core::is_public_ip(text)
}
fn hosts(root: &Path) -> Result<Vec<String>> {
    let mut names = BTreeSet::from(["api.quago.io".to_owned()]);
    let settings = zapret_core::read_settings(root)?;
    if settings.get("game").eq_ignore_ascii_case("selected")
        && zapret_core::selected_game_names(settings.get("gameapps"))?
            .iter()
            .any(|name| name == "nba2k27")
    {
        names.insert(NBA_CDN_HOST.to_owned());
        names.insert(EPIC_API_HOST.to_owned());
    }
    let path = root.join("runtime/gamepins-user.txt");
    if path.exists() {
        let bytes = read_limited(&path, 32768)?;
        for line in std::str::from_utf8(&bytes)?
            .trim_start_matches('\u{feff}')
            .lines()
        {
            let text = line.split(['#', ';']).next().unwrap_or("").trim();
            if !text.is_empty() {
                names.insert(zapret_core::normalize_domain(text)?);
            }
        }
    }
    ensure!(names.len() <= 32, "Game pin host limit exceeded");
    Ok(names.into_iter().collect())
}
fn targets(root: &Path, old: &[u8]) -> Result<Vec<Target>> {
    let text = std::str::from_utf8(old)?.trim_start_matches('\u{feff}');
    let entries = crate::hosts::entries(text);
    // Epic is shared with other games. Leave external hosts overrides under their owner's control.
    let mut inside = false;
    let manual_epic = text.lines().any(|line| {
        match line {
            BEGIN => inside = true,
            END => inside = false,
            _ if !inside => {
                let mut parts = line.split('#').next().unwrap_or("").split_whitespace();
                return parts
                    .next()
                    .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                    && parts.any(|alias| alias.eq_ignore_ascii_case(EPIC_API_HOST));
            }
            _ => {}
        }
        false
    });
    hosts(root)?
        .into_iter()
        .filter(|host| host != EPIC_API_HOST || !manual_epic)
        .map(|host| {
            let pinned = entries
                .iter()
                .filter(|(ip, name)| name == &host && public_v4(ip))
                .map(|(ip, _)| ip.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            ensure!(
                pinned.len() <= 16,
                "Too many existing game pin addresses for {host}"
            );
            Ok(Target { host, pinned })
        })
        .collect()
}
fn validate_targets(targets: &[Target]) -> Result<()> {
    ensure!(
        !targets.is_empty() && targets.len() <= 32,
        "Game pin targets must contain 1..32 hosts"
    );
    let mut seen = BTreeSet::new();
    for target in targets {
        ensure!(
            zapret_core::normalize_domain(&target.host)? == target.host
                && seen.insert(&target.host)
                && target.pinned.len() <= 16
                && target.pinned.iter().all(|ip| public_v4(ip)),
            "Invalid game pin target"
        );
    }
    Ok(())
}
fn dns(host: &str) -> Result<Vec<String>> {
    let name = wide(host)?;
    let mut records = null_mut();
    let result = unsafe {
        DnsQuery_W(
            name.as_ptr(),
            1,
            DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT,
            null_mut(),
            &mut records,
            null_mut(),
        )
    };
    struct Records(*mut DNS_RECORDA);
    impl Drop for Records {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DnsFree(self.0.cast(), DnsFreeRecordList);
                }
            }
        }
    }
    let _owner = Records(records);
    ensure!(
        result == 0,
        "DNS without hosts failed: Windows status {result}"
    );
    let mut addresses = BTreeSet::new();
    let mut count = 0;
    while !records.is_null() {
        count += 1;
        ensure!(count <= 256, "Game pin DNS record limit exceeded");
        let record = unsafe { &*records };
        if record.wType == 1 {
            let address =
                unsafe { Ipv4Addr::from(record.Data.A.IpAddress.to_ne_bytes()) }.to_string();
            if public_v4(&address) {
                addresses.insert(address);
            }
        }
        records = record.pNext;
    }
    ensure!(addresses.len() <= 16, "Game pin DNS address limit exceeded");
    Ok(addresses.into_iter().collect())
}
fn request(host: &str) -> (String, &'static str, usize) {
    match host {
        NBA_CDN_HOST => (
            NBA_STORE_IMAGE.url.to_owned(),
            "full_get",
            NBA_STORE_IMAGE.bytes + 1,
        ),
        EPIC_API_HOST => (EPIC_JWKS_URL.to_owned(), "jwks", JWKS_MAX_BYTES + 1),
        _ => (format!("https://{host}/"), "range", 1),
    }
}
fn checks_from_json(bytes: &[u8], host: &str, addresses: &BTreeSet<String>) -> Result<Vec<Check>> {
    let expected = addresses.iter().collect::<Vec<_>>();
    let (url, mode, limit) = request(host);
    let mut seen = BTreeSet::new();
    let mut checks = Vec::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let row: Value = serde_json::from_str(line)?;
        let id = row["id"]
            .as_str()
            .context("Game pin probe id missing")?
            .parse::<usize>()?;
        ensure!(
            id < expected.len() && seen.insert(id),
            "Duplicate or unexpected game pin TLS observation"
        );
        let address = expected[id];
        ensure!(
            row["version"] == 1
                && row["url"] == url
                && row["trust_source"] == "System"
                && row["tls_backend"] == "Schannel"
                && row["dns_source"] == "connect_ip override",
            "Game pin worker did not confirm exact-address system-trust TLS"
        );
        let validated = row["certificate_validated"]
            .as_bool()
            .context("Missing TLS validation result")?;
        let peer = row["remote_address"]
            .as_str()
            .map(str::parse::<std::net::SocketAddr>)
            .transpose()?;
        if let Some(peer) = peer {
            ensure!(
                peer.port() == 443 && peer.ip().to_string() == *address,
                "Game pin worker connected to a different peer"
            );
        }
        if validated {
            ensure!(
                peer.is_some()
                    && row["tls_ms"]
                        .as_f64()
                        .is_some_and(|ms| ms.is_finite() && ms >= 0.0),
                "Game pin worker did not prove a completed TLS handshake"
            );
        }
        let file_verified = if mode != "range" {
            ensure!(
                row["mode"] == mode && row["body_limit"] == limit,
                "Missing game service download observation"
            );
            let content_matches = if host == NBA_CDN_HOST {
                NBA_STORE_IMAGE.matches(
                    row["status_code"].as_u64(),
                    row["body_bytes"].as_u64(),
                    row["body_sha256"].as_str(),
                )
            } else {
                // A completed jwks observation proves that the worker parsed a usable key set.
                row["status_code"] == 200
                    && row["body_bytes"]
                        .as_u64()
                        .is_some_and(|n| (1..=JWKS_MAX_BYTES as u64).contains(&n))
            };
            Some(
                validated
                    && row["termination"] == "Complete"
                    && row["body_complete"] == true
                    && row["target_reached"] == false
                    && content_matches,
            )
        } else {
            None
        };
        checks.push(Check {
            address: address.clone(),
            peer_address: peer.map(|peer| peer.ip().to_string()),
            validation_host: host.into(),
            certificate_validated: validated,
            file_verified,
            supported: true,
            reason: row["termination"]
                .as_str()
                .context("Missing TLS termination")?
                .into(),
        });
    }
    ensure!(
        checks.len() == expected.len(),
        "Incomplete game pin TLS observations"
    );
    Ok(checks)
}
fn probe_addresses(root: &Path, host: &str, addresses: &BTreeSet<String>) -> Result<Vec<Check>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    let (url, mode, limit) = request(host);
    let method = if mode == "range" { "HEAD" } else { "GET" };
    for (id, address) in addresses.iter().enumerate() {
        serde_json::to_writer(
            &mut input,
            &json!({"version":1,"id":id.to_string(),
            "url":url,"connect_ip":address,"timeout_ms":4000,"mode":mode,
            "body_limit":limit,"method":method,"post_bytes":0}),
        )?;
        input.push(b'\n');
    }
    // The common native probe owns the existing Schannel policy and exact-IP connector.
    let executable = std::env::current_exe()?;
    let arguments = ["probe", "--parallel", "16", "--deadline-ms", "4500"].map(OsString::from);
    let result = crate::run_owned(
        &executable,
        &arguments,
        &RunOptions {
            cwd: Some(root.into()),
            stdin: Some(input),
            timeout: Duration::from_secs(6),
            max_output_bytes: 512 * 1024,
            ..Default::default()
        },
    )?;
    ensure!(
        !result.timed_out && !result.output_truncated && result.exit_code == 0,
        "Game pin TLS worker did not finish; existing pins retained: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    checks_from_json(&result.stdout, host, addresses)
}
pub(crate) fn probe(root: &Path, args: &Value) -> Result<Value> {
    let targets: Vec<Target> = serde_json::from_value(args["targets"].clone())?;
    validate_targets(&targets)?;
    let end = Instant::now() + Duration::from_secs(18);
    let mut rows = Vec::new();
    for target in targets {
        ensure!(Instant::now() < end, "Game pin probe deadline reached");
        let result = dns(&target.host);
        let error = result.as_ref().err().map(ToString::to_string);
        let dns_known = result.is_ok();
        let dns = result.unwrap_or_default();
        let addresses = dns
            .iter()
            .chain(&target.pinned)
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(addresses.len() <= 16, "Game pin candidate limit exceeded");
        let mut checks = probe_addresses(root, &target.host, &addresses)?;
        if target.host == EPIC_API_HOST {
            let failed = checks
                .iter()
                .filter(|check| check.file_verified == Some(false))
                .map(|check| check.address.clone())
                .collect();
            let retries = probe_addresses(root, &target.host, &failed)?;
            for check in &mut checks {
                if let Some(retry) = retries.iter().find(|r| r.address == check.address) {
                    *check = retry.clone();
                }
            }
        }
        rows.push(Row {
            host: target.host,
            dns_known,
            dns,
            checks,
            error,
        });
    }
    Ok(serde_json::to_value(Evidence { schema: 1, rows })?)
}
fn plan(targets: &[Target], evidence: &Evidence) -> Result<BTreeMap<String, Vec<String>>> {
    validate_targets(targets)?;
    ensure!(
        evidence.schema == 1 && evidence.rows.len() == targets.len(),
        "Incomplete game pin evidence"
    );
    let mut pins = BTreeMap::new();
    for target in targets {
        let rows = evidence
            .rows
            .iter()
            .filter(|row| row.host == target.host)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1,
            "Duplicate or missing game pin host evidence"
        );
        let row = rows[0];
        ensure!(
            row.dns_known && row.dns.len() <= 16 && row.dns.iter().all(|ip| public_v4(ip)),
            "Game pin DNS observation is unavailable: {}",
            target.host
        );
        let candidates = row
            .dns
            .iter()
            .chain(&target.pinned)
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            candidates.len() <= 16 && row.checks.len() == candidates.len(),
            "Incomplete game pin address coverage"
        );
        let mut checked = BTreeSet::new();
        let mut good = BTreeSet::new();
        let require_file = matches!(target.host.as_str(), NBA_CDN_HOST | EPIC_API_HOST);
        for check in &row.checks {
            ensure!(
                check.supported
                    && check.file_verified.is_some() == require_file
                    && candidates.contains(&check.address)
                    && checked.insert(check.address.clone())
                    && check.validation_host == target.host,
                "Unsupported or inconsistent exact-address TLS observation"
            );
            if check.certificate_validated {
                ensure!(
                    check.peer_address.as_deref() == Some(&check.address)
                        && public_v4(&check.address),
                    "Game pin TLS peer did not match the proposed address"
                );
                if check.file_verified != Some(false) {
                    good.insert(check.address.clone());
                }
            }
        }
        if target.host == EPIC_API_HOST
            && ((!row.dns.is_empty() && row.dns.iter().all(|ip| good.contains(ip)))
                || (good.is_empty() && target.pinned.is_empty()))
        {
            // Healthy DNS needs no pin. With no verified alternative, leave unpinned DNS alone.
            continue;
        }
        // A retired test file or a temporary service outage cannot validate a replacement.
        ensure!(
            !require_file || !good.is_empty(),
            "Ни один адрес {} не прошёл проверку содержимого. Записи hosts сохранены.",
            target.host
        );
        if !good.is_empty() {
            let mut addresses: Vec<_> = good.into_iter().collect();
            if require_file && addresses.len() > 6 {
                // Make room for verified addresses from the current DNS rotation.
                addresses.sort_by_key(|ip| !row.dns.contains(ip));
            }
            addresses.truncate(6);
            pins.insert(target.host.clone(), addresses);
        }
    }
    Ok(pins)
}
fn render(
    old: &[u8],
    names: &BTreeSet<String>,
    pins: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(old)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines = Vec::new();
    let mut inside = false;
    for line in text.trim_start_matches('\u{feff}').lines() {
        if line == BEGIN {
            ensure!(!inside, "Nested game pin hosts block");
            inside = true;
            continue;
        }
        if line == END {
            ensure!(inside, "Unmatched game pin hosts block end");
            inside = false;
            continue;
        }
        if inside {
            continue;
        }
        let (body, comment) = line
            .split_once('#')
            .map_or((line, None), |(body, comment)| (body, Some(comment)));
        let parts = body.split_whitespace().collect::<Vec<_>>();
        if parts.len() >= 2
            && parts[0].parse::<std::net::IpAddr>().is_ok()
            && parts[1..]
                .iter()
                .any(|name| names.contains(&name.to_ascii_lowercase()))
        {
            let remain = parts[1..]
                .iter()
                .filter(|name| !names.contains(&name.to_ascii_lowercase()))
                .copied()
                .collect::<Vec<_>>();
            if remain.is_empty() {
                continue;
            }
            let mut updated = format!("{} {}", parts[0], remain.join(" "));
            if let Some(comment) = comment {
                updated.push_str(" #");
                updated.push_str(comment);
            }
            lines.push(updated);
        } else {
            lines.push(line.to_owned());
        }
    }
    ensure!(!inside, "Unclosed game pin hosts block");
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    if !pins.is_empty() {
        lines.push(String::new());
        lines.push(BEGIN.into());
        for (host, addresses) in pins {
            for address in addresses {
                lines.push(format!("{address} {host}"));
            }
        }
        lines.push(END.into());
    }
    let mut output = if text.starts_with('\u{feff}') {
        "\u{feff}".to_owned()
    } else {
        String::new()
    };
    output.push_str(&lines.join(newline));
    output.push_str(newline);
    Ok(output.into_bytes())
}
fn commit(
    root: &Path,
    path: &Path,
    old: &[u8],
    targets: &[Target],
    evidence: &Evidence,
) -> Result<Value> {
    let pins = plan(targets, evidence)?;
    let names = targets.iter().map(|target| target.host.clone()).collect();
    let output = render(old, &names, &pins)?;
    if output == old {
        return Ok(json!({"updated":false,"known":true,"pins":pins,"evidence":evidence}));
    }
    ensure!(
        read_limited(path, 8 * 1024 * 1024)? == old,
        "Hosts changed during game pin validation; update deferred"
    );
    let backup = root.join(format!(
        "runtime/hosts-gamepins-{}-{}.bak",
        crate::time_filetime(),
        std::process::id()
    ));
    atomic_write(&backup, old)?;
    ensure!(
        read_limited(path, 8 * 1024 * 1024)? == old,
        "Hosts changed during game pin staging"
    );
    atomic_write(path, &output)?;
    Ok(
        json!({"updated":true,"known":true,"pins":pins,"evidence":evidence,"backup":backup,"path":path}),
    )
}
fn has_tunnel() -> Result<bool> {
    let adapters = crate::system::adapters()?;
    Ok(adapters
        .as_array()
        .context("Adapter list unavailable")?
        .iter()
        .any(|adapter| adapter["up"] == true && adapter["tun"] == true))
}
pub(crate) fn status(root: &Path, args: &Value) -> Result<Value> {
    let path = crate::hosts::path(root, args)?;
    let old = read_limited(&path, 8 * 1024 * 1024)?;
    Ok(json!({"path":path,"targets":targets(root, &old)?}))
}
pub(crate) fn update(root: &Path, args: &Value) -> Result<Value> {
    let _guard = crate::ControlGuard::acquire(root, "gamepins-update")?;
    crate::launch::allowed(root, args)?;
    if has_tunnel()? {
        return Ok(json!({"updated":false,"skipped":true,"reason":"TunnelActive","known":false}));
    }
    let path = crate::hosts::path(root, args)?;
    let old = read_limited(&path, 8 * 1024 * 1024)?;
    let requested = targets(root, &old)?;
    let executable = crate::tasks::executable(root, args)?;
    let arguments: Vec<OsString> = [
        OsString::from("--root"),
        root.as_os_str().into(),
        "platform-worker".into(),
        "gamepins-probe".into(),
        "--arguments-json".into(),
        serde_json::to_string(&json!({"targets":requested}))?.into(),
    ]
    .into();
    let result = crate::run_owned(
        &executable,
        &arguments,
        &RunOptions {
            cwd: Some(root.into()),
            timeout: Duration::from_secs(20),
            max_output_bytes: 512 * 1024,
            ..Default::default()
        },
    )?;
    ensure!(
        !result.timed_out && !result.output_truncated && result.exit_code == 0,
        "Game pin revalidation did not complete; existing pins retained: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let evidence: Evidence = serde_json::from_slice(&result.stdout)?;
    ensure!(
        targets(root, &old)? == requested,
        "Game pin host selection changed during validation"
    );
    crate::launch::allowed(root, args)?;
    if let Some(expected) = args.get("expected_engine") {
        let expected: crate::ProcessIdentity = serde_json::from_value(expected.clone())?;
        ensure!(
            crate::process_identity(expected.pid)? == expected,
            "Engine changed during game pin revalidation"
        );
    }
    if has_tunnel()? {
        return Ok(json!({"updated":false,"skipped":true,"reason":"TunnelChanged","known":false}));
    }
    let mut output = commit(root, &path, &old, &requested, &evidence)?;
    if output["updated"] == true && !args["path"].is_string() {
        output["flush_dns"] = crate::dns_cache::flush();
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_probe_evidence_requires_system_schannel_exact_peer_and_complete_coverage() {
        let addresses = BTreeSet::from(["8.8.8.8".into()]);
        let row = json!({"id":"0","version":1,"url":"https://api.quago.io/",
            "trust_source":"System","tls_backend":"Schannel","dns_source":"connect_ip override",
            "certificate_validated":true,"remote_address":"8.8.8.8:443","tls_ms":12.0,"termination":"Complete"});
        assert!(
            checks_from_json(
                &serde_json::to_vec(&row).unwrap(),
                "api.quago.io",
                &addresses
            )
            .unwrap()[0]
                .certificate_validated
        );
        for (key, value) in [
            ("trust_source", json!("FixtureCA")),
            ("remote_address", json!("1.1.1.1:443")),
            ("tls_backend", json!("unknown")),
            ("tls_ms", Value::Null),
        ] {
            let mut bad = row.clone();
            bad[key] = value;
            assert!(
                checks_from_json(
                    &serde_json::to_vec(&bad).unwrap(),
                    "api.quago.io",
                    &addresses
                )
                .is_err()
            );
        }
        assert!(checks_from_json(b"", "api.quago.io", &addresses).is_err());
    }
    fn evidence(host: &str, addresses: &[&str]) -> Evidence {
        Evidence {
            schema: 1,
            rows: vec![Row {
                host: host.into(),
                dns_known: true,
                dns: addresses.iter().map(|address| (*address).into()).collect(),
                error: None,
                checks: addresses
                    .iter()
                    .map(|address| Check {
                        address: (*address).into(),
                        peer_address: Some((*address).into()),
                        validation_host: host.into(),
                        certificate_validated: true,
                        file_verified: None,
                        supported: true,
                        reason: "fixture".into(),
                    })
                    .collect(),
            }],
        }
    }
    #[test]
    fn nba_pin_requires_the_full_store_file_from_the_selected_address() {
        let addresses = BTreeSet::from(["8.8.8.8".to_owned()]);
        let valid = json!({"id":"0","version":1,"url":NBA_STORE_IMAGE.url,
            "mode":"full_get","body_limit":NBA_STORE_IMAGE.bytes+1,
            "trust_source":"System","tls_backend":"Schannel","dns_source":"connect_ip override",
            "certificate_validated":true,"remote_address":"8.8.8.8:443","tls_ms":12.0,
            "termination":"Complete","status_code":200,"body_bytes":NBA_STORE_IMAGE.bytes,
            "body_sha256":NBA_STORE_IMAGE.sha256,"body_complete":true,"target_reached":false});
        let check = |row: &Value| {
            checks_from_json(&serde_json::to_vec(row).unwrap(), NBA_CDN_HOST, &addresses)
                .map(|checks| checks[0].file_verified)
        };
        assert_eq!(check(&valid).unwrap(), Some(true));
        for (key, value) in [
            ("status_code", json!(403)),
            ("body_bytes", json!(16384)),
            ("body_sha256", json!("0".repeat(64))),
            ("body_complete", json!(false)),
            ("target_reached", json!(true)),
            ("termination", json!("Timeout")),
            ("certificate_validated", json!(false)),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert_eq!(check(&bad).unwrap(), Some(false), "{key}");
        }
        for (key, value) in [
            ("url", json!(format!("https://{NBA_CDN_HOST}/"))),
            ("mode", json!("range")),
            ("remote_address", json!("1.1.1.1:443")),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(check(&bad).is_err(), "{key}");
        }
    }

    #[test]
    fn nba_rotation_keeps_verified_dns_and_defers_writes_when_the_file_is_unavailable() {
        let old_ips = [
            "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "1.1.1.6",
        ];
        let targets = [Target {
            host: NBA_CDN_HOST.into(),
            pinned: old_ips.iter().map(|s| (*s).to_owned()).collect(),
        }];
        let mut all_ips = old_ips.to_vec();
        all_ips.push("8.8.8.8");
        let mut report = evidence(NBA_CDN_HOST, &all_ips);
        report.rows[0].dns = vec!["8.8.8.8".into()];
        for check in &mut report.rows[0].checks {
            check.file_verified = Some(true);
        }
        let pins = &plan(&targets, &report).unwrap()[NBA_CDN_HOST];
        assert_eq!(pins.len(), 6);
        assert!(pins.iter().any(|s| s == "8.8.8.8"));
        report.rows[0].checks[0].file_verified = Some(false);
        assert!(
            !plan(&targets, &report).unwrap()[NBA_CDN_HOST]
                .iter()
                .any(|s| s == old_ips[0])
        );
        report.rows[0].checks[0].file_verified = None;
        assert!(plan(&targets, &report).is_err());
        for check in &mut report.rows[0].checks {
            check.file_verified = Some(false);
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hosts");
        let old = format!("127.0.0.1 localhost\r\n{BEGIN}\r\n1.1.1.1 {NBA_CDN_HOST}\r\n{END}\r\n");
        std::fs::write(&path, &old).unwrap();
        assert!(commit(root.path(), &path, old.as_bytes(), &targets, &report).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), old);
    }

    #[test]
    fn epic_uses_normal_dns_until_a_verified_alternative_is_needed() {
        let ips = ["1.1.1.1", "8.8.8.8"];
        let mut requested = [Target {
            host: EPIC_API_HOST.into(),
            pinned: vec![],
        }];
        let mut report = evidence(EPIC_API_HOST, &ips);
        assert!(plan(&requested, &report).is_err()); // An older TLS-only worker.
        for check in &mut report.rows[0].checks {
            check.file_verified = Some(true);
        }
        assert!(plan(&requested, &report).unwrap().is_empty());
        report.rows[0].checks[0].file_verified = Some(false);
        assert_eq!(
            plan(&requested, &report).unwrap()[EPIC_API_HOST],
            vec![ips[1]]
        );
        requested[0].pinned.push(ips[1].into());
        report.rows[0].dns = vec![ips[0].into()];
        assert_eq!(
            plan(&requested, &report).unwrap()[EPIC_API_HOST],
            vec![ips[1]]
        );
        report.rows[0].checks[1].file_verified = Some(false);
        assert!(plan(&requested, &report).is_err());
        report.rows[0].checks[0].file_verified = Some(true);
        assert!(plan(&requested, &report).unwrap().is_empty());
    }

    #[test]
    fn pins_require_full_dns_tls_hostname_and_exact_public_peer_evidence() {
        let targets = vec![Target {
            host: "api.quago.io".into(),
            pinned: Vec::new(),
        }];
        let valid = evidence("api.quago.io", &["8.8.8.8"]);
        assert_eq!(
            plan(&targets, &valid).unwrap()["api.quago.io"],
            vec!["8.8.8.8"]
        );
        let mut wrong = valid.clone();
        wrong.rows[0].checks[0].peer_address = Some("1.1.1.1".into());
        assert!(plan(&targets, &wrong).is_err());
        let mut unknown = valid.clone();
        unknown.rows[0].dns_known = false;
        assert!(plan(&targets, &unknown).is_err());
        let mut unsupported = valid.clone();
        unsupported.rows[0].checks[0].supported = false;
        assert!(plan(&targets, &unsupported).is_err());
        assert!(plan(&targets, &evidence("api.quago.io", &["127.0.0.1"])).is_err());
        let mut failed = valid;
        failed.rows[0].checks[0].certificate_validated = false;
        assert!(plan(&targets, &failed).unwrap().is_empty());
    }
    #[test]
    fn fixture_commit_preserves_flowseal_bom_crlf_mixed_aliases_and_original_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hosts");
        let old = format!(
            "\u{feff}# keep\r\n127.0.0.1 localhost\r\n9.9.9.9 api.quago.io keep.example # mixed\r\n# zapret: hosts Flowseal - начало (меню: Проверка обходов)\r\n140.82.112.3 github.com\r\n# zapret: hosts Flowseal - конец\r\n{BEGIN}\r\n1.1.1.1 api.quago.io\r\n{END}\r\n"
        );
        std::fs::write(&path, &old).unwrap();
        let targets = vec![Target {
            host: "api.quago.io".into(),
            pinned: Vec::new(),
        }];
        let report = evidence("api.quago.io", &["8.8.8.8"]);
        let result = commit(root.path(), &path, old.as_bytes(), &targets, &report).unwrap();
        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.starts_with('\u{feff}'));
        assert!(updated.contains("9.9.9.9 keep.example # mixed\r\n"));
        assert!(updated.contains("140.82.112.3 github.com\r\n"));
        assert!(updated.contains("8.8.8.8 api.quago.io\r\n"));
        assert!(!updated.contains("1.1.1.1 api.quago.io"));
        assert_eq!(
            std::fs::read_to_string(result["backup"].as_str().unwrap()).unwrap(),
            old
        );
        std::fs::write(&path, b"external edit").unwrap();
        assert!(commit(root.path(), &path, old.as_bytes(), &targets, &report).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"external edit");
    }
    #[test]
    fn game_pin_names_include_user_file_and_malformed_blocks_never_write() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime")).unwrap();
        std::fs::write(
            root.path().join("runtime/gamepins-user.txt"),
            "Game.Example\n# comment\n",
        )
        .unwrap();
        assert_eq!(
            hosts(root.path()).unwrap(),
            vec!["api.quago.io", "game.example"]
        );
        let mut settings = zapret_core::Settings::default();
        settings.set("game", "selected").unwrap();
        settings.set("gameapps", "NBA2K27.exe|Game.exe").unwrap();
        zapret_core::save_settings(root.path(), &settings).unwrap();
        assert_eq!(
            hosts(root.path()).unwrap(),
            vec![EPIC_API_HOST, "api.quago.io", "game.example", NBA_CDN_HOST]
        );
        let external = format!("127.0.0.1 local {EPIC_API_HOST} # manual\n");
        assert!(
            targets(root.path(), external.as_bytes())
                .unwrap()
                .iter()
                .all(|t| t.host != EPIC_API_HOST)
        );
        let managed = format!("{BEGIN}\n8.8.8.8 {EPIC_API_HOST}\n{END}\n");
        let epic = targets(root.path(), managed.as_bytes())
            .unwrap()
            .into_iter()
            .find(|t| t.host == EPIC_API_HOST)
            .unwrap();
        assert_eq!(epic.pinned, vec!["8.8.8.8"]);
        assert!(
            render(
                format!("{BEGIN}\n127.0.0.1 keep\n").as_bytes(),
                &BTreeSet::new(),
                &BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            probe(
                root.path(),
                &json!({"targets":[{"host":"bad/path","pinned":[]}]})
            )
            .is_err()
        );
    }
}
