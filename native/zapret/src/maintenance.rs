pub(crate) mod first_run;
mod list_sources;

use crate::{App, VERSION, cli::TestArgs, runtime_file, snapshot::check_plain};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Local, NaiveDateTime};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime},
};
use zapret_core::{
    ComposeOptions, GameProtocols, IpNetwork, Settings, atomic_write, checked_command_line,
    compose, find_strategy, list_lines, normalize_domain, normalize_ip_network, normalize_list,
    port_in_list, prepare_runtime, read_bounded, read_settings, read_text,
    ring_composition_key_with_identity, sha256, verify_package,
};
use zapret_platform::{ControlGuard, OwnedChild, RunOptions, RunOutput};

const LISTS: [(&str, &str); 6] = [
    ("ipset-all.txt", ".service/ipset-service.txt"),
    ("ipset-exclude.txt", "lists/ipset-exclude.txt"),
    ("list-general.txt", "lists/list-general.txt"),
    ("list-google.txt", "lists/list-google.txt"),
    ("list-exclude.txt", "lists/list-exclude.txt"),
    ("hosts-flowseal.txt", ".service/hosts"),
];

const DIRECT_DOMAINS: [(&str, &[&str]); 3] = [
    (
        "Steam и Dota 2",
        &[
            "steampowered.com",
            "steamserver.net",
            "steamstatic.com",
            "steamcontent.com",
            "steam-chat.com",
            "valvesoftware.com",
            "dota2.com",
        ],
    ),
    (
        "Discord",
        &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "discordcdn.com",
        ],
    ),
    (
        "NBA 2K и EAC",
        &["2k.com", "take2games.com", "easyanticheat.net"],
    ),
];

const VALVE_NETWORKS: [&str; 32] = [
    "45.121.184.0/24",
    "103.10.124.0/23",
    "103.28.54.0/24",
    "146.66.152.0/24",
    "146.66.155.0/24",
    "155.133.224.0/21",
    "155.133.236.0/22",
    "155.133.240.0/23",
    "155.133.244.0/24",
    "155.133.246.0/24",
    "155.133.248.0/22",
    "155.133.252.0/24",
    "155.133.254.0/23",
    "162.254.192.0/21",
    "185.25.180.0/24",
    "185.25.182.0/23",
    "192.69.96.0/22",
    "205.196.6.0/24",
    "208.64.200.0/22",
    "208.78.164.0/22",
    "2404:3fc0::/46",
    "2404:3fc0:8::/47",
    "2404:3fc0:a::/48",
    "2602:801:f000::/46",
    "2602:801:f005::/48",
    "2602:801:f006::/47",
    "2602:801:f008::/46",
    "2602:801:f00d::/48",
    "2602:801:f00e::/48",
    "2a01:bc80::/45",
    "2a01:bc80:8::/46",
    "2a01:bc80:c::/48",
];

const DISCORD_MEDIA_URL: &str = "https://media.discordapp.net/stickers/781291442961383434.png";
const DISCORD_MEDIA_BYTES: usize = 229034;
const DISCORD_MEDIA_SHA256: &str =
    "8dbecf7b6d7da8a9c761ad89a73066838d89f3cda4a1313976c9533ac88a3fb3";
const SERVICE_PROBES: [(&str, &str); 8] = [
    ("YouTube", "https://www.youtube.com/generate_204"),
    (
        "видео YouTube",
        "https://redirector.googlevideo.com/report_mapping",
    ),
    ("Discord", "https://discord.com/api/v9/gateway"),
    (zapret_platform::DISCORD_MEDIA_GROUP, DISCORD_MEDIA_URL),
    ("Steam", "https://store.steampowered.com/"),
    ("GitHub", "https://github.com/"),
    ("NBA 2K27: вход (Epic)", "https://api.epicgames.dev/"),
    ("NBA 2K27: запись матча", "https://api.quago.io/"),
];

const HOSTS_PROBES: [(&str, &str, &str); 4] = [
    (
        "GitHub",
        "raw.githubusercontent.com",
        "/Flowseal/zapret-discord-youtube/refs/heads/main/.service/version.txt",
    ),
    ("Telegram", "telegram.org", "/"),
    ("Discord", "discord.com", "/api/v9/gateway"),
    (
        zapret_platform::DISCORD_MEDIA_GROUP,
        zapret_platform::DISCORD_MEDIA_HOST,
        "/stickers/781291442961383434.png",
    ),
];

pub fn integrity(root: &Path) -> Result<Value> {
    let mut bad = verify_package(root)?;
    if let Err(error) = zapret_core::verify_telegram(root) {
        bad.push(format!("{error:#}"));
    }
    Ok(json!({"ok":bad.is_empty(),"changed":bad}))
}

pub fn clear_restart_intent(app: &App) -> Result<()> {
    let path = runtime_file(&app.root, "update-restart.txt")?;
    if path.exists() {
        ensure!(
            zapret_platform::trusted_path(&path)?,
            "Недоверенный файл восстановления запуска"
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn recover_start(app: &App) -> Result<()> {
    let recovery = crate::updates::recover(&app.root)?;
    if recovery["restart_required"] == true {
        return app.print(&recovery);
    }
    let path = runtime_file(&app.root, "update-restart.txt")?;
    if path.is_file() {
        ensure!(
            zapret_platform::trusted_path(&path)?,
            "Недоверенный файл восстановления запуска"
        );
        let intent = read_text(&path, 64)?;
        if intent.trim() == "start" {
            app.game_check("Восстановление после обновления запустит обход")?;
            let result = app.platform("start", json!({"game_approved":true}))?;
            ensure!(
                result["running"] == true,
                "Восстановление запуска не подтверждено"
            );
        }
        clear_restart_intent(app)?;
    }
    Ok(())
}

pub fn check_engine_args(root: &Path, arguments: &[String]) -> Result<Value> {
    zapret_platform::validate_engine_args(root, arguments)
}

fn engine_arguments(root: &Path, arguments: &[String], dry_run: bool) -> Result<Vec<OsString>> {
    let mut arguments = arguments.to_vec();
    if dry_run && !arguments.iter().any(|value| value == "--dry-run") {
        arguments.insert(0, "--dry-run".into());
    }
    Ok(checked_command_line(root, &arguments)?
        .into_iter()
        .map(OsString::from)
        .collect())
}

fn run_engine(root: &Path, arguments: &[OsString], options: &RunOptions) -> Result<RunOutput> {
    crate::interrupt::install()?;
    crate::interrupt::check()?;
    let mut child = OwnedChild::spawn(&root.join("bin/winws2.exe"), arguments, options)?;
    loop {
        crate::interrupt::check()?;
        if !child.is_running()? {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.finish()
}

pub fn pc_check(app: &App) -> Result<Value> {
    crate::interrupt::install()?;
    crate::interrupt::check()?;
    let network = observation_result(app.platform("network", json!({})));
    let conflicts = observation_result(app.platform("conflicts", json!({})));
    let vpn = conflicts["tun_adapters"]
        .as_array()
        .is_some_and(|items| !items.is_empty());
    let has_ipv6 = network["adapters"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|adapter| {
            adapter["up"] == true
                && adapter["addresses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|address| {
                        address["address"]
                            .as_str()
                            .and_then(|text| text.parse::<IpAddr>().ok())
                            .is_some_and(|ip| {
                                ip.is_ipv6() && zapret_core::is_public_ip(&ip.to_string())
                            })
                    })
        });
    let (provider, services, dns, ipv6, pins) = thread::scope(|scope| {
        let provider = scope
            .spawn(|| zapret_net::diagnostics(&app.root, "provider", &json!({"timeout_ms":5000})));
        let services = scope.spawn(service_observations);
        let dns = scope.spawn(|| {
            if vpn {
                Ok(json!({"status":"Skipped","reason":"TunnelActive"}))
            } else {
                zapret_net::diagnostics(&app.root, "dns", &json!({"timeout_ms":1000}))
            }
        });
        let ipv6=scope.spawn(||if has_ipv6 {zapret_net::diagnostics(&app.root,"ipv6",&json!({"timeout_ms":6000}))}
            else {Ok(json!({"status":"Skipped","reason":"NoPublicIpv6Address","rows":[],"broken":[],"slow":[]}))});
        let pins = scope.spawn(|| {
            if vpn {
                Ok(json!({"status":"Skipped","reason":"TunnelActive","rows":[]}))
            } else {
                hosts_pin_observations(&app.root)
            }
        });
        (
            joined_observation(provider.join()),
            joined_observation(services.join()),
            joined_observation(dns.join()),
            joined_observation(ipv6.join()),
            joined_observation(pins.join()),
        )
    });
    crate::interrupt::check()?;
    let mut result = json!({"integrity":observation_result(integrity(&app.root)),"bypass":observation_result(app.platform("status",json!({}))),
        "conflicts":conflicts,"network":network,"hosts":observation_result(app.platform("hosts-status",json!({}))),
        "priority":observation_result(app.platform("priority",json!({}))),"ipv4_preference":observation_result(app.platform("prefer-ipv4",json!({}))),
        "provider":provider,"services":services,"dns":dns,"ipv6":ipv6,"hosts_pins":pins,
        "proxy_apps":observation_result(proxy_app_observations(app)),
        "boosters":observation_result(booster_observations(app)),
        "certificates":observation_result(app.platform("certificates",json!({}))),
        "telegram":observation_result(app.platform("telegram-status",json!({}))),
        "autolist_ips":list_lines(&list_path(&app.root,"autohostlist.txt")?)?.into_iter().filter(|line|line.parse::<IpAddr>().is_ok()).collect::<Vec<_>>(),
        "evidence":"HTTPS reachability and local configuration; game latency not measured"});
    let fixes = pc_fixes(&result);
    result["fixes"] = json!(fixes);
    result["text"] = json!(pc_check_text(&result));
    atomic_write(
        &runtime_file(&app.root, "pc-check-last.json")?,
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

fn observation_result(result: Result<Value>) -> Value {
    result.unwrap_or_else(
        |error| json!({"status":"Unavailable","known":false,"error":format!("{error:#}")}),
    )
}

fn joined_observation(result: thread::Result<Result<Value>>) -> Value {
    observation_result(
        result
            .map_err(|_| anyhow::anyhow!("Поток диагностики завершился с ошибкой"))
            .and_then(|result| result),
    )
}

fn service_job(id: String, url: String, connect_ip: Option<IpAddr>) -> zapret_net::Job {
    let media = url == DISCORD_MEDIA_URL;
    zapret_net::Job {
        version: 1,
        id,
        url,
        timeout_ms: 6000,
        body_limit: if media {
            DISCORD_MEDIA_BYTES + 1
        } else {
            65536
        },
        post_bytes: 0,
        method: Some(if media { "GET" } else { "HEAD" }.into()),
        mode: if media {
            zapret_net::ProbeMode::FullGet
        } else {
            zapret_net::ProbeMode::Range
        },
        connect_ip,
    }
}

fn probe_reached(row: &zapret_net::Observation) -> bool {
    row.body_complete
        && row.certificate_validated
        && row
            .status_code
            .is_some_and(|code| (200..=599).contains(&code))
        && row.termination == zapret_net::Termination::Complete
        && (row.url != DISCORD_MEDIA_URL
            || (row.status_code == Some(200)
                && row.body_bytes == DISCORD_MEDIA_BYTES
                && row.body_sha256.as_deref() == Some(DISCORD_MEDIA_SHA256)))
}

fn service_observations() -> Result<Value> {
    let jobs = SERVICE_PROBES
        .iter()
        .enumerate()
        .map(|(index, (_, url))| service_job(index.to_string(), (*url).into(), None))
        .collect::<Vec<_>>();
    let rows = zapret_net::probe(
        &jobs,
        &zapret_net::BatchOptions {
            parallel: 16,
            deadline_ms: 8000,
            ..Default::default()
        },
    )?;
    let mut output = Vec::new();
    for (index, (name, url)) in SERVICE_PROBES.iter().enumerate() {
        let row = rows
            .iter()
            .find(|row| row.id == index.to_string())
            .context("Отсутствует результат HTTPS-пробы")?;
        output.push(json!({"name":name,"url":url,"ok":probe_reached(row),"observation":row}));
    }
    Ok(
        json!({"rows":output,"evidence":"Validated TLS and HTTP responses, including a complete Discord media file with SHA-256"}),
    )
}

fn hosts_pin_observations(root: &Path) -> Result<Value> {
    let dns = zapret_net::diagnostics(
        root,
        "dns",
        &json!({"hosts":HOSTS_PROBES.map(|(_,host,_)|host),"no_hosts":true,"compare":false,"timeout_ms":1500}),
    )?;
    let reference = read_text(&list_path(root, "hosts-flowseal.txt")?, 8 * 1024 * 1024)?;
    let reference = zapret_platform::hosts_reference_entries(&reference);
    let mut jobs = Vec::new();
    let mut endpoints = BTreeMap::new();
    for (index, (_, host, path)) in HOSTS_PROBES.iter().enumerate() {
        let system = dns["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|row| row["host"] == *host)
            .and_then(|row| row["system_dns"]["addresses"].as_array())
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .find_map(|ip| ip.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4));
        let pin = reference
            .iter()
            .filter(|(_, name)| name.eq_ignore_ascii_case(host))
            .find_map(|(ip, _)| ip.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4));
        for (kind, address) in [("dns", system), ("pin", pin)] {
            endpoints.insert(format!("{index}-{kind}"), address);
            if let Some(address) = address {
                for attempt in 0..2 {
                    jobs.push(service_job(
                        format!("{index}-{kind}-{attempt}"),
                        format!("https://{host}{path}"),
                        Some(address),
                    ));
                }
            }
        }
    }
    let observations = zapret_net::probe(
        &jobs,
        &zapret_net::BatchOptions {
            parallel: 16,
            deadline_ms: 8000,
            ..Default::default()
        },
    )?;
    let mut rows = Vec::new();
    for (index, (group, host, _)) in HOSTS_PROBES.iter().enumerate() {
        let side = |kind: &str| {
            let prefix = format!("{index}-{kind}-");
            let attempts = observations
                .iter()
                .filter(|row| row.id.starts_with(&prefix))
                .collect::<Vec<_>>();
            let best = attempts
                .iter()
                .filter(|row| probe_reached(row))
                .filter_map(|row| row.tcp_ms.zip(row.tls_ms).map(|(tcp, tls)| tcp + tls))
                .min_by(f64::total_cmp);
            json!({"ip":endpoints[&format!("{index}-{kind}")],"ok":best.is_some(),"ms":best,"attempts":attempts})
        };
        let system = side("dns");
        let pin = side("pin");
        let verdict = hosts_pin_verdict(&system, &pin);
        rows.push(json!({"group":group,"host":host,"dns":system,"pin":pin,"verdict":verdict}));
    }
    Ok(
        json!({"rows":rows,"evidence":"DNS-only resolution and validated HTTP responses at explicit IPv4 addresses, including Discord media file integrity"}),
    )
}

fn hosts_pin_verdict(system: &Value, pin: &Value) -> &'static str {
    if pin["ip"].is_null() {
        "none"
    } else if system["ok"] != true && pin["ok"] == true {
        "helps"
    } else if system["ok"] != true {
        "down"
    } else if pin["ok"] != true
        || pin["ms"]
            .as_f64()
            .zip(system["ms"].as_f64())
            .is_some_and(|(pin, dns)| pin > dns + 300.)
    {
        "worse"
    } else {
        "same"
    }
}

fn pc_fixes(result: &Value) -> Vec<Value> {
    let mut fixes = Vec::new();
    if result["ipv4_preference"]["known"] == true
        && result["ipv4_preference"]["enabled"] != true
        && result["ipv6"]["broken"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        fixes.push(json!({"id":"prefer-ipv4","text":"Предпочитать IPv4: часть проверенных путей IPv6 не отвечает","action":"prefer-ipv4","arguments":{"enabled":true}}));
    }
    if let (Some(rows), Some(current)) = (
        result["hosts_pins"]["rows"].as_array(),
        result["hosts"]["groups"].as_array(),
    ) {
        if rows.len() == HOSTS_PROBES.len() {
            let mut groups = Vec::new();
            let mut changed = false;
            for row in rows {
                let status = current.iter().find(|group| group["group"] == row["group"]);
                let present =
                    status.is_some_and(|group| group["entries"].as_u64().unwrap_or(0) > 0);
                let wanted = row["verdict"] == "helps" || (row["verdict"] != "worse" && present);
                if wanted {
                    groups.push(row["group"].clone());
                }
                changed |= wanted != present
                    || (wanted
                        && status.is_some_and(|group| {
                            group["stale"].as_u64().unwrap_or(0) > 0
                                || group["duplicates"].as_u64().unwrap_or(0) > 0
                        }));
            }
            if changed {
                fixes.push(json!({"id":"hosts-flowseal","text":"Применить проверенные группы hosts Flowseal","action":"hosts-set","arguments":{"groups":groups}}));
            }
        }
    }
    fixes
}

fn pc_check_text(result: &Value) -> String {
    let mut lines = vec![
        format!(
            "Обход: {}",
            if result["bypass"]["known"] != true || result["bypass"]["ownership_known"] != true {
                "состояние не подтверждено"
            } else if result["bypass"]["running"] == true {
                "работает"
            } else if result["bypass"]["known"] == false {
                "состояние неизвестно"
            } else {
                "остановлен"
            }
        ),
        format!(
            "Целостность: {}",
            if result["integrity"]["ok"] == true {
                "проверена"
            } else {
                "требует внимания"
            }
        ),
    ];
    if let Some(provider) = result["provider"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|row| row["provider"].as_object())
    {
        lines.push(format!(
            "Внешнее подключение: {} · {} · {}",
            provider
                .get("masked_ip")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            provider
                .get("country_code")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            provider.get("isp").and_then(Value::as_str).unwrap_or("?")
        ));
    } else {
        lines.push("Внешнее подключение: провайдер не определён".into());
    }
    if let Some(items) = result["conflicts"]["foreign_bypass"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        lines.push(format!("Другой обход: {} процессов", items.len()));
    }
    if result["conflicts"]["tun_adapters"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        lines.push("Включён туннель VPN: сравнение DNS и hosts отложено".into());
    }
    if let Some(boosters) = result["boosters"]["items"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        lines.push(format!(
            "Игровые ускорители: {}",
            boosters
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for row in result["proxy_apps"]["stuck"]
        .as_array()
        .into_iter()
        .flatten()
    {
        lines.push(format!("{}: процесс использовал локальный прокси, который сейчас не слушает порт; проверьте приложение",row["app"].as_str().unwrap_or("Приложение")));
    }
    if result["certificates"]["suspicious"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        lines.push("В доверенных хранилищах найдены сертификаты российских удостоверяющих центров; проверьте, устанавливали ли вы их сами.".into());
    }
    lines.push("HTTPS сейчас:".into());
    if let Some(rows) = result["services"]["rows"].as_array() {
        for row in rows {
            lines.push(format!(
                "  {}: {}",
                row["name"].as_str().unwrap_or("?"),
                if row["ok"] == true {
                    "HTTP-ответ получен"
                } else {
                    "доступность не подтверждена"
                }
            ));
        }
    } else {
        lines.push("  Проверка недоступна".into());
    }
    lines.push(format!(
        "DNS: {}",
        if result["dns"]["status"] == "Skipped" {
            "отложена из-за туннеля".into()
        } else if result["dns"]["status"] == "Unavailable" {
            "проверка недоступна".into()
        } else if let Some(suspect) = result["dns"]["suspect"]
            .as_array()
            .filter(|_| result["dns"]["checked"].is_number())
        {
            format!(
                "проверено {}, подозрительных доменов {}",
                result["dns"]["checked"],
                suspect.len()
            )
        } else {
            "проверка недоступна".into()
        }
    ));
    for row in result["dns"]["rows"].as_array().into_iter().flatten() {
        if row["conclusion"] == "SuspiciousMissingAddress" {
            lines.push(format!(
                "  {} — Windows не вернула IP, адрес из защищённого DNS прошёл проверку TLS.",
                row["host"].as_str().unwrap_or("?")
            ));
        }
    }
    lines.push(format!(
        "IPv6: {}",
        if result["ipv6"]["status"] == "Unavailable" {
            "проверка недоступна".into()
        } else if result["ipv6"]["reason"] == "NoPublicIpv6Address" {
            "у активных адаптеров нет внешнего IPv6-адреса".into()
        } else if let Some(rows) = result["ipv6"]["rows"].as_array() {
            format!(
                "проверено {}, проблемных путей {}",
                rows.len(),
                result["ipv6"]["broken"].as_array().map_or(0, Vec::len)
            )
        } else {
            "проверка недоступна".into()
        }
    ));
    for row in result["hosts_pins"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let verdict = match row["verdict"].as_str() {
            Some("helps") => "адрес Flowseal помогает",
            Some("worse") => "адрес DNS лучше",
            Some("same") => "оба адреса отвечают",
            Some("none") => "нет эталонного адреса",
            _ => "доступность не подтверждена",
        };
        lines.push(format!(
            "hosts {}: {verdict}",
            row["group"].as_str().unwrap_or("?")
        ));
    }
    lines.push(format!(
        "В автосписке IP вместо доменов: {}",
        result["autolist_ips"].as_array().map_or(0, Vec::len)
    ));
    for fix in result["fixes"].as_array().into_iter().flatten() {
        lines.push(format!(
            "Можно исправить: {}",
            fix["text"].as_str().unwrap_or("?")
        ));
    }
    lines
        .push("Эта проверка измеряет доступность HTTPS. Задержка игры здесь не измеряется.".into());
    lines.join("\n")
}

fn proxy_ports(proxy: &str) -> BTreeSet<u16> {
    proxy
        .split([';', ' ', '\t'])
        .filter_map(|part| {
            let endpoint = part.rsplit_once('=').map_or(part, |(_, value)| value);
            let endpoint = endpoint
                .split_once("://")
                .map_or(endpoint, |(_, value)| value)
                .trim_end_matches('/');
            let (host, port) = endpoint.rsplit_once(':')?;
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_loopback());
            let port = port.parse::<u16>().ok()?;
            (loopback && port > 0).then_some(port)
        })
        .collect()
}

fn proxy_app(identity: &Value) -> Option<&'static str> {
    let executable = identity["executable"].as_str()?;
    let name = Path::new(executable)
        .file_stem()?
        .to_string_lossy()
        .to_ascii_lowercase();
    match name.as_str() {
        "steam" | "steamwebhelper" => Some("Steam"),
        "discord" | "discordcanary" | "discordptb" | "discorddevelopment" => Some("Discord"),
        _ => None,
    }
}

fn filetime_local(filetime: u64) -> Option<DateTime<Local>> {
    const WINDOWS_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    let seconds = i64::try_from(filetime.checked_sub(WINDOWS_UNIX_EPOCH)? / 10_000_000).ok()?;
    DateTime::from_timestamp(seconds, 0).map(|time| time.with_timezone(&Local))
}

fn steam_log_port(
    log: &str,
    since: DateTime<Local>,
    observed: DateTime<Local>,
    ports: &BTreeSet<u16>,
) -> Option<u16> {
    log.lines().rev().find_map(|line| {
        let (timestamp, message) = line.strip_prefix('[')?.split_once(']')?;
        let time = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S")
            .ok()?
            .and_local_timezone(Local)
            .single()?;
        if !(since..=observed).contains(&time) {
            return None;
        }
        message
            .split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | ':'))
            .filter(|word| word.starts_with("127."))
            .filter_map(|word| word.trim_end_matches('.').parse::<SocketAddr>().ok())
            .find_map(|endpoint| {
                let port = endpoint.port();
                (matches!(endpoint.ip(), IpAddr::V4(ip) if ip.is_loopback())
                    && ports.contains(&port))
                .then_some(port)
            })
    })
}

fn steam_proxy_observation(
    processes: &[Value],
    ports: &BTreeSet<u16>,
    observed_filetime: u64,
) -> Option<Value> {
    let observed = filetime_local(observed_filetime)?;
    processes
        .iter()
        .filter(|row| row["name"].as_str().is_some_and(|name| name.eq_ignore_ascii_case("steam")))
        .find_map(|row| {
            let identity = &row["identity"];
            let executable = Path::new(identity["executable"].as_str()?);
            if !executable.file_name()?.eq_ignore_ascii_case("steam.exe") {
                return None;
            }
            let created = identity["created_filetime"].as_u64()?;
            if created > observed_filetime {
                return None;
            }
            let since = filetime_local(created)? - chrono::Duration::seconds(5);
            let log = executable.parent()?.join("logs/connection_log.txt");
            let text = read_tail_text(&log, 256 * 1024, 400).ok()?;
            let port = steam_log_port(&text, since, observed, ports)?;
            Some(json!({"app":"Steam","identity":identity,"port":port,"source":"steam_connection_log"}))
        })
}

fn proxy_app_state(
    configured: &BTreeSet<u16>,
    connections: &Value,
    processes: &Value,
    previous: &[Value],
) -> Value {
    if connections["known"] != true || connections["states_known"] != true {
        return json!({"known":false,"scope":"IPv4 loopback only","active":[],"stuck":[],"remembered":previous,"reason":"TcpStatesUnknown"});
    }
    let rows = connections["connections"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let live = processes.as_array().map_or(&[][..], Vec::as_slice);
    let mut remembered = previous
        .iter()
        .filter(|old| {
            live.iter().any(|process| {
                process["identity"].is_object() && process["identity"] == old["identity"]
            }) && proxy_app(&old["identity"]).is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let listeners = rows
        .iter()
        .filter(|row| {
            row["state"] == 2
                && row["local_address"]
                    .as_str()
                    .and_then(|text| text.parse::<std::net::Ipv4Addr>().ok())
                    .is_some_and(|ip| ip.is_loopback() || ip.is_unspecified())
        })
        .filter_map(|row| {
            row["local_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
        })
        .collect::<BTreeSet<_>>();
    for row in rows {
        let port = row["remote_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok());
        let loopback = row["remote_address"]
            .as_str()
            .and_then(|text| text.parse::<std::net::Ipv4Addr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if row["state"] != 5 || !loopback || !port.is_some_and(|port| configured.contains(&port)) {
            continue;
        }
        if let Some(app) = proxy_app(&row["identity"]) {
            let item = json!({"app":app,"identity":row["identity"],"port":port});
            if !remembered.contains(&item) {
                remembered.push(item);
            }
        }
    }
    remembered.truncate(128);
    let mut active = Vec::new();
    let mut stuck = Vec::new();
    for item in &remembered {
        let port = item["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok());
        if port.is_some_and(|port| listeners.contains(&port)) {
            active.push(item.clone());
        } else {
            stuck.push(item.clone());
        }
    }
    let log_fallback = !configured.is_empty()
        && configured.is_disjoint(&listeners)
        && !active
            .iter()
            .chain(&stuck)
            .any(|item| item["app"] == "Steam");
    if let Some(item) = connections["observed_filetime"]
        .as_u64()
        .filter(|_| log_fallback)
        .and_then(|observed| steam_proxy_observation(live, configured, observed))
    {
        stuck.push(item);
    }
    json!({"known":connections["known"]==true,"scope":"IPv4 loopback only","active":active,"stuck":stuck,
        "remembered":remembered,"basis":"TCP evidence or Steam connection log for the running process; closed listener is advisory"})
}

fn proxy_app_observations(app: &App) -> Result<Value> {
    let path = runtime_file(&app.root, "proxy-apps-native.json")?;
    let previous = if path.is_file() {
        serde_json::from_slice::<Vec<Value>>(&read_bounded(&path, 128 * 1024)?)?
    } else {
        Vec::new()
    };
    let connections = app.platform("tcp-connections", json!({}))?;
    ensure!(
        connections["known"] == true && connections["states_known"] == true,
        "Недоступны подтверждённые состояния TCP-соединений"
    );
    let proxy = app.platform("proxy", json!({}))?;
    let mut configured = proxy["proxy"].as_str().map(proxy_ports).unwrap_or_default();
    if configured.is_empty() {
        if let Ok(Some(saved)) = zapret_platform::configured_proxy_server() {
            configured = proxy_ports(&saved);
        }
    }
    let processes = app.platform("processes", json!({}))?;
    let result = proxy_app_state(&configured, &connections, &processes, &previous);
    atomic_write(&path, &serde_json::to_vec(&result["remembered"])?)?;
    Ok(result)
}

fn booster_observations(app: &App) -> Result<Value> {
    let processes = app.platform("processes", json!({}))?;
    let services = app.platform("services", json!({}))?;
    let mut items = BTreeSet::new();
    for (name, prefixes) in [
        ("ExitLag", &["exitlag"][..]),
        ("NoPing", &["noping"][..]),
        ("WTFast", &["wtfast"][..]),
        ("Mudfish", &["mudfish", "mudrun"][..]),
        ("GearUP Booster", &["gearup"][..]),
        ("LagoFast", &["lagofast"][..]),
        ("Haste", &["haste"][..]),
        ("Outfox", &["outfox"][..]),
        ("Speedify", &["speedify"][..]),
        ("Xunyou", &["xunyou"][..]),
    ] {
        let matched = |text: &str| {
            prefixes
                .iter()
                .any(|prefix| text.to_ascii_lowercase().starts_with(prefix))
        };
        if processes
            .as_array()
            .into_iter()
            .flatten()
            .any(|row| row["name"].as_str().is_some_and(matched))
        {
            items.insert(name.to_owned());
            continue;
        }
        for row in services
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["state"] == 4)
        {
            if row["name"].as_str().is_some_and(matched)
                || row["display_name"].as_str().is_some_and(matched)
            {
                items.insert(format!(
                    "{name} (служба {})",
                    row["name"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    Ok(json!({"known":true,"items":items}))
}

pub fn track(app: &App, process: &str, seconds: u64, voice: bool) -> Result<Value> {
    track_game_connections(app, process, seconds, voice, true)
}

pub fn track_city(app: &App) -> Result<String> {
    crate::ensure_controller_current()?;
    let before = city_engine_state(app);
    let mut capture = track_game_connections(app, "NBA2K*", 120, false, false)?;
    let path = runtime_file(&app.root, "track-last.json")?;
    capture["city"] = json!({"before":before,"after":city_engine_state(app)});
    atomic_write(&path, &serde_json::to_vec_pretty(&capture)?)?;
    Ok(format!(
        "{}\nФайл для передачи — {}",
        city_summary(&capture),
        path.display()
    ))
}

fn city_engine_state(app: &App) -> Value {
    let state = observation_result(app.platform("status", json!({})));
    let conflicts = observation_result(app.platform("conflicts", json!({})));
    json!({"running":state["running"],"ownership_known":state["ownership_known"],
        "processes":state["processes"],"foreign_bypass_count":conflicts["foreign_bypass"].as_array().map(Vec::len),
        "foreign_service":conflicts["foreign_service"]})
}

fn city_summary(capture: &Value) -> String {
    let mut lines = vec![
        match capture["status"].as_str() {
            Some("Captured") => "Запись NBA City завершена.",
            Some("Partial") => "Запись NBA City неполная.",
            _ => "Не удалось записать соединения NBA City.",
        }
        .to_owned(),
    ];
    let flows = capture["flows"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if flows.is_empty() {
        lines.push(
            "Соединений NBA 2K в записи нет. Откройте игру и нажмите T перед входом в City.".into(),
        );
    } else {
        for protocol in ["tcp", "udp"] {
            let mut sent = 0;
            let mut received = 0;
            let mut ports = BTreeSet::new();
            for flow in flows.iter().filter(|row| row["protocol"] == protocol) {
                sent += flow["out"].as_u64().unwrap_or(0);
                received += flow["in"].as_u64().unwrap_or(0);
                if let Some(port) = flow["port"].as_u64() {
                    ports.insert(port);
                }
            }
            let label = protocol.to_uppercase();
            if ports.is_empty() {
                lines.push(format!("{label} — событий в записи нет."));
            } else {
                let shown = ports
                    .iter()
                    .take(8)
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let more = if ports.len() > 8 {
                    " и другие"
                } else {
                    ""
                };
                lines.push(format!(
                    "{label} — исходящих событий {sent}, входящих {received}. Порты {shown}{more}."
                ));
            }
        }
    }
    let after = &capture["city"]["after"];
    if after["foreign_bypass_count"]
        .as_u64()
        .is_some_and(|n| n > 0)
        || after["foreign_service"] == true
    {
        lines.push("В конце записи обнаружен другой обход или его служба.".into());
    }
    if after["running"] == false && after["ownership_known"] == true {
        lines.push("В конце записи обход этой установки остановлен.".into());
    }
    lines.join("\n")
}

fn track_game_connections(
    app: &App,
    process: &str,
    seconds: u64,
    voice: bool,
    diagnostics: bool,
) -> Result<Value> {
    ensure!(
        (1..=120).contains(&seconds),
        "Время наблюдения вне диапазона 1–120 секунд"
    );
    let settings = read_settings(&app.root)?;
    let owners = OwnerSets::load(&app.root, &settings)?;
    let selected_only = settings.get("game").eq_ignore_ascii_case("selected")
        && selected_process(
            &zapret_core::selected_game_names(settings.get("gameapps"))?,
            process,
        )
        .is_some();
    let mut result = app.platform(
        if voice { "voice-capture" } else { "track" },
        json!({"process_name":process,"duration_sec":seconds,"seconds":seconds,"selected_only":selected_only}),
    )?;
    let name = if voice {
        "voice-track-last.json"
    } else {
        "track-last.json"
    };
    let path = runtime_file(&app.root, name)?;
    // Preserve the completed ETW capture even if a later configuration read or
    // post-capture probe cannot finish. An unannotated record cannot authorize exclusions.
    atomic_write(&path, &serde_json::to_vec_pretty(&result)?)?;
    let stable = read_settings(&app.root).is_ok_and(|current| settings == current)
        && OwnerSets::load(&app.root, &settings).is_ok_and(|current| owners == current);
    annotate_capture(&mut result, &settings, &owners, stable);
    if diagnostics {
        let mut result_diagnostics = observation_result(zapret_net::enrich_tracker(
            &app.root,
            &result,
            &json!({"geo":true}),
        ));
        result_diagnostics["phase"] = json!("PostCapture");
        result["diagnostics"] = result_diagnostics;
    }
    result["text"] = json!(capture_text(&result, voice));
    atomic_write(&path, &serde_json::to_vec_pretty(&result)?)?;
    Ok(result)
}

fn capture_text(capture: &Value, voice: bool) -> String {
    let mut lines = vec![format!(
        "{}: {}",
        if voice {
            "Голос Discord"
        } else {
            "Трекер"
        },
        match capture["status"].as_str() {
            Some("Captured") => "запись завершена",
            Some("Partial") => "частичная запись",
            Some("Unavailable") => "запись недоступна",
            _ => "состояние записи не подтверждено",
        }
    )];
    for flow in capture["flows"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {} {}:{} · {} · пакеты {}/{} · по настройкам: {} ({})",
            flow["protocol"]
                .as_str()
                .unwrap_or("?")
                .to_ascii_uppercase(),
            flow["address"].as_str().unwrap_or("?"),
            flow["port"],
            flow["process_name"].as_str().unwrap_or("?"),
            flow["out"],
            flow["in"],
            if flow["configured_bypass"] == true {
                "обход"
            } else {
                "без обхода"
            },
            match flow["bypass_reason"].as_str() {
                Some("Lists") => "адрес не включён в списки",
                Some("Excluded" | "UserExcluded" | "TakeTwo") => "адрес в исключениях",
                Some("SelectedGame") => "адрес выбранной игры",
                Some("NotSelected") => "адрес вне списков выбранных игр",
                Some("Game") => "игровой фильтр",
                Some("Protocol") => "выбранный протокол",
                Some("Port") => "порт вне правил профиля",
                Some("MissingEngine") => "процесс обхода не найден",
                _ => "правило не подтверждено",
            }
        ));
    }
    if capture["truncated"] == true {
        lines.push("Запись неполная: часть событий не попала в отчёт.".into());
    }
    if capture["configuration_stable"] == false {
        lines.push(
            "Настройки или списки менялись во время записи; сети нельзя исключать по этой записи."
                .into(),
        );
    }
    lines.extend(
        capture["diagnostics"]["summary_lines"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    if capture["diagnostics"]["status"] == "Unavailable" {
        lines.push(format!(
            "Диагностика после записи недоступна: {}",
            capture["diagnostics"]["error"]
                .as_str()
                .unwrap_or("причина неизвестна")
        ));
    }
    if capture.get("diagnostics").is_some() {
        lines.push("Метки обхода получены из настроек. Период активных проб — после записи; RTT в моменты пауз и FPS здесь не измеряются.".into());
    } else {
        lines.push("Метки обхода получены из настроек и списков адресов.".into());
    }
    lines.join("\n")
}

#[derive(PartialEq, Eq)]
struct OwnerSets {
    lists: Vec<(&'static str, Vec<IpNetwork>)>,
    game: GameProtocols,
}

impl OwnerSets {
    fn load(root: &Path, settings: &Settings) -> Result<Self> {
        let mut owners = Vec::new();
        let mut files = vec![
            ("исключено", "ipset-exclude.txt".to_owned()),
            ("исключено", "ipset-exclude-user.txt".to_owned()),
            ("Take-Two", "ipset-taketwo.txt".to_owned()),
        ];
        if settings.get("game").eq_ignore_ascii_case("selected") {
            for game in zapret_core::selected_game_names(settings.get("gameapps"))? {
                files.push(("выбранная игра", zapret_core::game_server_list(&game)));
            }
        }
        files.extend(
            [
                ("ipset-all", "ipset-all.txt"),
                ("найден ранее", "ipset-user.txt"),
                ("AWS", "ipset-aws.txt"),
            ]
            .map(|(owner, file)| (owner, file.to_owned())),
        );
        for (name, file) in files {
            let path = list_path(root, &file)?;
            let networks = list_lines(&path)?
                .iter()
                .filter(|line| line.as_str() != "203.0.113.113/32")
                .map(|line| IpNetwork::parse(line))
                .collect::<Result<Vec<_>>>()?;
            owners.push((name, networks));
        }
        let game = find_strategy(root, settings.get("alt"))?
            .filter(|strategy| strategy.is_valid())
            .map(|strategy| strategy.game_protocols(settings.get("game")))
            .unwrap_or_default();
        Ok(Self {
            lists: owners,
            game,
        })
    }

    fn owner(&self, address: IpAddr) -> &str {
        // Explicit engine exclusions still apply when upstream include ranges grow.
        self.lists
            .iter()
            .filter(|(name, _)| ["исключено", "Take-Two"].contains(name))
            .chain(
                self.lists
                    .iter()
                    .filter(|(name, _)| !["исключено", "Take-Two"].contains(name)),
            )
            .find(|(_, networks)| networks.iter().any(|network| network.contains(address)))
            .map_or("", |(name, _)| *name)
    }
}

fn configured_bypass(
    owner: &str,
    protocol: &str,
    port: u16,
    settings: &Settings,
    game_protocols: GameProtocols,
) -> (bool, &'static str) {
    if owner == "Take-Two" {
        return (false, "TakeTwo");
    }
    if owner == "исключено" {
        return (false, "UserExcluded");
    }
    if protocol == "udp" && ((19294..=19344).contains(&port) || (50000..=50100).contains(&port)) {
        return (true, "Voice");
    }
    let mode = settings.get("game").to_ascii_lowercase();
    let game = (protocol == "tcp"
        && game_protocols.tcp
        && port_in_list(port, settings.get("gametcp")))
        || (protocol == "udp" && game_protocols.udp && port_in_list(port, settings.get("gameudp")));
    let web = (protocol == "tcp" && [80, 443, 8443].contains(&port))
        || (protocol == "udp" && port == 443);
    if !web && !game {
        return (false, "Port");
    }
    if mode == "selected" {
        if owner == "выбранная игра" {
            return (true, "SelectedGame");
        }
        if !web {
            return (false, "NotSelected");
        }
    }
    if settings.get("ipset") == "any" {
        return (true, "Any");
    }
    if owner == "найден ранее" {
        return (true, "User");
    }
    if owner == "ipset-all" && settings.get("ipset") == "loaded" {
        return (true, "Loaded");
    }
    (false, "Lists")
}

fn annotate_capture(capture: &mut Value, settings: &Settings, owners: &OwnerSets, stable: bool) {
    capture["configuration_stable"] = json!(stable);
    capture["configuration"] = json!(settings.values);
    if let Some(flows) = capture["flows"].as_array_mut() {
        for flow in flows {
            let address = flow["address"]
                .as_str()
                .and_then(|text| text.parse::<IpAddr>().ok());
            let owner = address.map_or("", |ip| owners.owner(ip));
            let protocol = flow["protocol"].as_str().unwrap_or("").to_ascii_lowercase();
            let port = flow["port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(0);
            let (bypassed, reason) =
                configured_bypass(owner, &protocol, port, settings, owners.game);
            flow["owner"] = json!(owner);
            flow["configured_bypass"] = json!(bypassed);
            flow["bypass_reason"] = json!(reason);
            flow["bypass_basis"] = json!("ConfigurationOnly");
            flow["exclusion_eligible"] =
                json!(stable && bypassed && reason != "Voice" && address.is_some());
        }
    }
}

fn remote_addresses(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                remote_addresses(value, output);
            }
        }
        Value::Object(values) => {
            for key in [
                "remote_address",
                "remote_ip",
                "RemoteAddress",
                "address",
                "ip",
            ] {
                if let Some(text) = values.get(key).and_then(Value::as_str) {
                    let ip = text
                        .parse::<IpAddr>()
                        .ok()
                        .or_else(|| text.parse::<SocketAddr>().ok().map(|address| address.ip()));
                    if let Some(ip) = ip.filter(|ip| zapret_core::is_public_ip(&ip.to_string())) {
                        output.insert(ip.to_string());
                    }
                }
            }
            for value in values
                .values()
                .filter(|value| value.is_array() || value.is_object())
            {
                remote_addresses(value, output);
            }
        }
        _ => {}
    }
}

fn list_path(root: &Path, name: &str) -> Result<PathBuf> {
    let directory = root.join("lists");
    check_existing_plain(&directory)?;
    let path = directory.join(name);
    check_existing_plain(&path)?;
    Ok(path)
}

fn check_existing_plain(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_plain(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Недоступен {}", path.display())),
    }
}

fn appended_addresses(
    text: &str,
    addresses: &BTreeSet<String>,
    comment: &str,
) -> Result<Option<String>> {
    let existing = normalize_list(text, true)?
        .into_iter()
        .map(|line| IpNetwork::parse(&line))
        .collect::<Result<Vec<_>>>()?;
    let additions = normalize_list(
        &addresses.iter().cloned().collect::<Vec<_>>().join("\n"),
        true,
    )?
    .into_iter()
    .filter(|line| {
        let network = IpNetwork::parse(line).expect("normalized IP network");
        !existing
            .iter()
            .any(|old| old.prefix <= network.prefix && old.contains(network.address))
    })
    .collect::<Vec<_>>();
    if additions.is_empty() {
        return Ok(None);
    }
    let newline = if text.contains("\r\n") || !text.contains('\n') {
        "\r\n"
    } else {
        "\n"
    };
    let mut output = text.to_owned();
    if !output.is_empty() && !output.ends_with('\n') {
        output.push_str(newline);
    }
    output.push_str("# ");
    output.push_str(comment);
    output.push_str(newline);
    output.push_str(&additions.join(newline));
    output.push_str(newline);
    Ok(Some(output))
}

fn text_with_original_encoding(text: &str, original: &[u8]) -> Vec<u8> {
    if original.starts_with(&[0xff, 0xfe]) {
        [
            vec![0xff, 0xfe],
            text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ]
        .concat()
    } else if original.starts_with(&[0xfe, 0xff]) {
        [
            vec![0xfe, 0xff],
            text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        ]
        .concat()
    } else if original.starts_with(&[0xef, 0xbb, 0xbf]) {
        [vec![0xef, 0xbb, 0xbf], text.as_bytes().to_vec()].concat()
    } else {
        text.as_bytes().to_vec()
    }
}

fn append_addresses(
    root: &Path,
    name: &str,
    addresses: &BTreeSet<String>,
    comment: &str,
) -> Result<bool> {
    let _guard = ControlGuard::acquire(root, "scan-lists")?;
    let path = list_path(root, name)?;
    let original = if path.is_file() {
        read_bounded(&path, 32 * 1024 * 1024)?
    } else {
        Vec::new()
    };
    let text = if path.is_file() {
        read_text(&path, 32 * 1024 * 1024)?
    } else {
        String::new()
    };
    if let Some(output) = appended_addresses(&text, addresses, comment)? {
        atomic_write(&path, &text_with_original_encoding(&output, &original))?;
        return Ok(true);
    }
    Ok(false)
}

fn address_network(text: &str) -> Option<String> {
    let ip = text.parse::<IpAddr>().ok()?;
    if !zapret_core::is_public_ip(text) {
        return None;
    }
    normalize_ip_network(&format!("{ip}/{}", if ip.is_ipv4() { 24 } else { 64 })).ok()
}

fn scan_is_eligible(capture: &Value) -> bool {
    matches!(capture["status"].as_str(), Some("Captured" | "Completed"))
        && capture["configuration_stable"] == true
        && capture["cleanup_confirmed"] == true
        && capture["truncated"] == false
        && capture["events_lost"].as_u64() == Some(0)
        && capture["decode_errors"].as_u64() == Some(0)
}

fn selected_process<'a>(names: &'a [String], input: &str) -> Option<&'a str> {
    let lower = input.trim().to_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    names
        .iter()
        .find(|name| name.as_str() == stem)
        .map(String::as_str)
}

fn selected_addresses(capture: &Value, game: &str) -> BTreeSet<String> {
    capture["flows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|flow| {
            flow["process_name"]
                .as_str()
                .is_some_and(|name| name.to_lowercase() == game)
                && matches!(flow["protocol"].as_str(), Some("tcp" | "udp"))
                && flow["port"]
                    .as_u64()
                    .is_some_and(|p| (1..=65535).contains(&p))
        })
        .filter_map(|flow| flow["address"].as_str()?.parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical().to_string())
        .filter(|ip| zapret_core::is_public_ip(ip))
        .collect()
}

pub fn scan(app: &App, process: &str, seconds: u64, apply: bool) -> Result<Value> {
    let settings = read_settings(&app.root)?;
    let selected = settings.get("game").eq_ignore_ascii_case("selected");
    let names = if selected {
        zapret_core::selected_game_names(settings.get("gameapps"))?
    } else {
        Vec::new()
    };
    let process = if selected {
        if process.is_empty() && names.len() == 1 {
            names[0].as_str()
        } else {
            selected_process(&names, process)
                .context("Укажите одну из выбранных игр по имени EXE")?
        }
    } else if process.is_empty() {
        "NBA2K*"
    } else {
        process
    };
    let capture = track_game_connections(app, process, seconds, false, !selected)?;
    let _write_guard = apply
        .then(|| ControlGuard::acquire(&app.root, "scan-apply"))
        .transpose()?;
    let eligible = scan_is_eligible(&capture)
        && read_settings(&app.root)? == settings
        && capture["configuration"] == json!(settings.values);
    ensure!(
        !apply || eligible,
        "Запись неполная или настройки менялись; добавление сетей отменено. Повторите запись."
    );
    let addresses = if selected {
        selected_addresses(&capture, process)
    } else {
        let mut addresses = BTreeSet::new();
        remote_addresses(&capture["flows"], &mut addresses);
        addresses
    };
    let owners = OwnerSets::load(&app.root, &settings)?;
    let networks: BTreeSet<_> = addresses
        .iter()
        .filter(|_| eligible)
        .filter(|address| {
            address.parse::<IpAddr>().is_ok_and(|ip| {
                if selected {
                    !["исключено", "Take-Two"].contains(&owners.owner(ip))
                } else {
                    ["", "AWS"].contains(&owners.owner(ip))
                }
            })
        })
        .filter_map(|address| {
            if selected {
                address
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
            } else {
                address_network(address)
            }
        })
        .collect();
    let list = if selected {
        zapret_core::game_server_list(process)
    } else {
        "ipset-user.txt".into()
    };
    let applied = apply
        && !networks.is_empty()
        && append_addresses(
            &app.root,
            &list,
            &networks,
            "добавлено сканером zapret-rust",
        )?;
    let text = format!(
        "Сканер: {} удалённых адресов. {}\n{}",
        addresses.len(),
        if !eligible {
            "Запись неполная или настройки менялись; сети для добавления не определены."
        } else if networks.is_empty() || (apply && !applied) {
            "Новых сетей для добавления не найдено."
        } else if applied {
            "Адреса сохранены."
        } else {
            "Адреса для добавления:"
        },
        networks.iter().cloned().collect::<Vec<_>>().join("\n")
    );
    let result = json!({"capture":capture,"addresses":addresses,"networks":networks,"list":list,"applied":applied,"text":text});
    atomic_write(
        &runtime_file(&app.root, "scan-last.json")?,
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

pub fn exclude(app: &App, apply: bool) -> Result<Value> {
    let native = runtime_file(&app.root, "track-last.json")?;
    let legacy = runtime_file(&app.root, "track-last.txt")?;
    let legacy_newer = legacy.is_file()
        && (!native.is_file() || legacy.metadata()?.modified()? > native.metadata()?.modified()?);
    let (path, networks) = if legacy_newer {
        let networks = legacy_exclusion_networks(&read_text(&legacy, 16 * 1024 * 1024)?)?;
        (legacy, networks)
    } else {
        let capture: Value = serde_json::from_slice(&read_bounded(&native, 16 * 1024 * 1024)?)?;
        (native, exclusion_networks(&capture))
    };
    ensure!(
        !networks.is_empty(),
        "В последнем трекере нет сетей настроенного обхода для исключения"
    );
    if apply {
        append_addresses(
            &app.root,
            "ipset-exclude-user.txt",
            &networks,
            "исключено по трекеру zapret-rust",
        )?;
    }
    let text = format!(
        "{}\n{}\nИсточник: {}. Метки обхода основаны на настройках трекера.",
        if apply {
            "Сети добавлены в ipset-exclude-user.txt:"
        } else {
            "Сети настроенного обхода для исключения:"
        },
        networks.iter().cloned().collect::<Vec<_>>().join("\n"),
        path.display()
    );
    Ok(
        json!({"addresses":networks,"networks":networks,"source":path,"basis":"ConfigurationOnly","applied":apply,"text":text}),
    )
}

fn exclusion_networks(capture: &Value) -> BTreeSet<String> {
    if capture["configuration_stable"] != true {
        return BTreeSet::new();
    }
    capture["flows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|flow| flow["exclusion_eligible"] == true && flow["bypass_reason"] != "Voice")
        .filter_map(|flow| flow["address"].as_str().and_then(address_network))
        .collect()
}

fn legacy_exclusion_networks(text: &str) -> Result<BTreeSet<String>> {
    let row = regex::Regex::new(
        r"^\s+(?:TCP|UDP) \[?([0-9a-fA-F:.]+?)\]?:(\d+)\s.*\| обход: да(?: \((?:any|user)\))?\s*$",
    )?;
    let mut all_addresses = false;
    let mut networks = BTreeSet::new();
    for line in text.lines() {
        if line.starts_with("Все адреса") {
            all_addresses = true;
            continue;
        }
        if !all_addresses {
            continue;
        }
        if let Some(captures) = row.captures(line) {
            if captures[2].parse::<u16>().is_ok_and(|port| port > 0) {
                if let Some(network) = address_network(&captures[1]) {
                    networks.insert(network);
                }
            }
        }
    }
    Ok(networks)
}

pub fn report(app: &App, output: Option<&Path>) -> Result<Value> {
    let path = output.map(Path::to_owned).unwrap_or(runtime_file(
        &app.root,
        &format!(
            "report-{}.txt",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ),
    )?);
    let mut sections = vec![
        format!(
            "zapret-rust {VERSION} · Rust\n{}",
            chrono::Local::now().to_rfc3339()
        ),
        format!(
            "Настройки\n{}",
            serde_json::to_string_pretty(&read_settings(&app.root)?.values)?
        ),
        format!(
            "Состояние\n{}",
            serde_json::to_string_pretty(&observation_result(app.platform("status", json!({}))))?
        ),
    ];
    let network = observation_result(app.platform("network", json!({})));
    sections.push(format!(
        "Контекст подключения\n{}",
        json!({"known":network["known"],"key":network["key"]})
    ));
    if let Ok(Some((_, reason))) = crate::selection::last_interruption(&app.root) {
        sections.push(format!(
            "Последняя остановка автоподбора из-за сети\n{reason}"
        ));
    }
    for (label, command) in [
        ("Конфликты", "conflicts"),
        ("hosts", "hosts-status"),
        ("Порядок IPv4/IPv6", "prefer-ipv4"),
        ("Мост Telegram", "telegram-status"),
    ] {
        let mut value = observation_result(app.platform(command, json!({})));
        redact_report_value(&mut value);
        sections.push(format!(
            "{label}\n{}",
            serde_json::to_string_pretty(&value)?
        ));
    }
    sections.push(format!(
        "Списки\n{}",
        serde_json::to_string_pretty(&lists(app, false)?)?
    ));
    let mut own_addresses = BTreeSet::new();
    for (name, pc) in [
        ("pc-check-last.json", true),
        ("provider-check-last.json", false),
    ] {
        let cached = runtime_file(&app.root, name)?;
        if cached.is_file() {
            if let Ok(bytes) = read_bounded(&cached, 16 * 1024 * 1024) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    let provider = if pc { &value["provider"] } else { &value };
                    for row in provider["rows"].as_array().into_iter().flatten() {
                        if let Some(ip) = row["provider"]["ip"]
                            .as_str()
                            .and_then(|ip| ip.parse::<IpAddr>().ok())
                        {
                            own_addresses.insert(ip);
                        }
                    }
                }
            }
        }
    }
    for name in [
        "control-actions.log",
        "start-error.txt",
        "test-last.txt",
        "test-best.txt",
        "autotune.log",
        "args-active.txt",
        "test-native-last.json",
        "comparison-native-last.json",
        "test-rank.txt",
        "track-last.json",
        "track-last.txt",
        "scan-last.json",
        "voice-track-last.json",
        "pc-check-last.json",
        "update-check-native.json",
        "test-restore-pending.txt",
        "network-watch-native-events.log",
        "connection-check-last.json",
        "web-check-last.json",
        "voice-check-last.json",
        "provider-check-last.json",
        "latency-check-last.json",
    ] {
        let file = runtime_file(&app.root, name)?;
        if file.is_file() {
            let text = (|| -> Result<String> {
                if name.ends_with(".json") {
                    let mut value: Value =
                        serde_json::from_slice(&read_bounded(&file, 16 * 1024 * 1024)?)?;
                    redact_report_value(&mut value);
                    Ok(serde_json::to_string_pretty(&value)?)
                } else {
                    read_tail_text(&file, 2 * 1024 * 1024, 250)
                }
            })()
            .unwrap_or_else(|error| format!("(файл не включён: {error:#})"));
            sections.push(format!("{name}\n{text}"));
        }
    }
    let mut report = redact(&sections.join("\n\n"), &app.root);
    for address in own_addresses {
        report = report.replace(&address.to_string(), &masked_ip(address));
    }
    atomic_write(&path, report.as_bytes())?;
    Ok(
        json!({"path":path,"bytes":report.len(),"text":format!("Отчёт готов: {}\nИмя пользователя и известный внешний IP скрыты. Подробный пакетный лог сохранён отдельно.",path.display())}),
    )
}

fn masked_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let bytes = ip.octets();
            format!("{}.{}.{}.x", bytes[0], bytes[1], bytes[2])
        }
        IpAddr::V6(ip) => {
            let words = ip.segments();
            format!("{:x}:{:x}:{:x}:...", words[0], words[1], words[2])
        }
    }
}

fn redact_report_value(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                redact_report_value(item);
            }
        }
        Value::Object(items) => {
            for (key, value) in items {
                if key.eq_ignore_ascii_case("local_address") {
                    if let Some(ip) = value.as_str().and_then(|text| text.parse::<IpAddr>().ok()) {
                        *value = json!(masked_ip(ip));
                    }
                } else if [
                    "adapters", "routes", "profiles", "secret", "password", "token", "link", "lat",
                    "lon",
                ]
                .contains(&key.to_ascii_lowercase().as_str())
                {
                    *value = json!("<скрыто>");
                } else {
                    redact_report_value(value);
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn read_tail_text(path: &Path, max_bytes: u64, max_lines: usize) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let length = file.metadata()?.len();
    let text = if length <= max_bytes {
        read_text(path, max_bytes)?
    } else {
        let mut header = [0; 3];
        let _ = file.read(&mut header)?;
        let start = length - max_bytes;
        file.seek(SeekFrom::Start(start - start % 2))?;
        let mut bytes = Vec::new();
        file.take(max_bytes + 2).read_to_end(&mut bytes)?;
        let text = if header[..2] == [0xff, 0xfe] || header[..2] == [0xfe, 0xff] {
            let units = bytes
                .chunks_exact(2)
                .map(|bytes| {
                    if header[0] == 0xff {
                        u16::from_le_bytes([bytes[0], bytes[1]])
                    } else {
                        u16::from_be_bytes([bytes[0], bytes[1]])
                    }
                })
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        text.split_once('\n')
            .map_or(String::new(), |(_, rest)| rest.to_owned())
    };
    Ok(text
        .lines()
        .rev()
        .take(max_lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n"))
}

fn redact(text: &str, root: &Path) -> String {
    let replace_path = |text: String, path: &str, replacement: &str| {
        let mut text = text;
        for spelling in [
            path.to_owned(),
            path.replace('\\', "\\\\"),
            path.replace('\\', "/"),
        ] {
            if let Ok(pattern) = regex::RegexBuilder::new(&regex::escape(&spelling))
                .case_insensitive(true)
                .build()
            {
                text = pattern.replace_all(&text, replacement).into_owned();
            }
        }
        text
    };
    let mut text = replace_path(
        text.to_owned(),
        root.to_string_lossy().as_ref(),
        "<zapret-rust>",
    );
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        text = replace_path(text, profile.to_string_lossy().as_ref(), "<user>");
    }
    text.lines()
        .filter(|line| {
            !line.to_ascii_lowercase().contains("secret")
                && !line.to_ascii_lowercase().contains("password")
                && !line.to_ascii_lowercase().contains("tg://proxy")
                && !(line.to_ascii_lowercase().contains("config:") && line.contains('{'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn direct_rules(app: &App, output: Option<&Path>) -> Result<Value> {
    let mut lines = vec![format!("# zapret-rust {VERSION}: что пускать мимо прокси (правила \"напрямую\" / direct). Обход обрабатывает это сам."),
        "# Happ и другие клиенты на xray: вставьте строки из блока \"domain:\" в прямые домены, сети - в прямые IP.".into(),
        String::new(),"# --- домены, для xray / Happ ---".into()];
    for (group, domains) in DIRECT_DOMAINS {
        lines.push(format!("# {group}"));
        lines.extend(domains.iter().map(|domain| format!("domain:{domain}")));
    }
    lines.push(String::new());
    lines
        .push("# --- те же домены без приставки (для клиентов, которые её не понимают) ---".into());
    for (_, domains) in DIRECT_DOMAINS {
        lines.extend(domains.iter().map(|domain| domain.to_string()));
    }
    lines.push(String::new());
    lines.push(
        "# --- сети серверов игр: Valve и Take-Two (нужны, если прокси в режиме TUN) ---".into(),
    );
    lines.extend(list_lines(&app.root.join("lists/ipset-taketwo.txt"))?);
    lines.extend(VALVE_NETWORKS.map(String::from));
    let text = format!("{}\r\n", lines.join("\r\n"));
    let path = output
        .map(Path::to_owned)
        .unwrap_or(runtime_file(&app.root, "direct-rules.txt")?);
    atomic_write(&path, text.as_bytes())?;
    Ok(json!({"path":path,"text":text}))
}

pub fn lists(app: &App, update: bool) -> Result<Value> {
    if !update {
        let status: Vec<_> = LISTS.iter().map(|(name,_)| {
            let path=app.root.join("lists").join(name);
            json!({"name":name,"exists":path.is_file(),"bytes":path.metadata().ok().map(|m|m.len())})
        }).collect();
        return Ok(json!(status));
    }
    update_lists(app, 30000, || Ok(()))
}

fn update_lists(
    app: &App,
    timeout_ms: u64,
    before_write: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let _lease = worker_lease(&app.root, "lists-update-native.lock")?
        .context("Другое окно уже обновляет списки в этой папке")?;
    crate::ensure_controller_current()?;
    crate::interrupt::install()?;
    crate::interrupt::check()?;
    let downloads = thread::scope(|scope| {
        let pending = LISTS.map(|(name, source)| {
            scope.spawn(move || {
                let path = list_path(&app.root, name)?;
                let previous = existing_list(&path)?;
                let old_lines = previous
                    .as_ref()
                    .and_then(|bytes| zapret_core::decode_text(bytes.clone()).ok())
                    .map_or(0, |text| {
                        text.lines()
                            .map(list_content)
                            .filter(|line| !line.is_empty())
                            .filter_map(|line| download_entry(name, line).ok())
                            .collect::<BTreeSet<_>>()
                            .len()
                    });
                let (bytes, route) = list_sources::download(name, source, old_lines, timeout_ms)?;
                let details = json!({"name":name,"bytes":bytes.len(),"route":route});
                Ok((
                    ListReplacement {
                        path,
                        previous,
                        bytes,
                    },
                    details,
                ))
            })
        });
        pending
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("Поток загрузки списка завершился с ошибкой"))?
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let (staged, details): (Vec<_>, Vec<_>) = downloads.into_iter().unzip();
    // A slow download must not hold up Start/Stop in another menu. Only
    // publication needs exclusive control, including checking the previous bytes.
    let _guard = ControlGuard::acquire(&app.root, "lists-update")?;
    crate::ensure_controller_current()?;
    before_write()?;
    for item in &staged {
        crate::interrupt::check()?;
        check_existing_plain(&item.path)?;
        ensure!(
            existing_list(&item.path)? == item.previous,
            "Список изменился во время загрузки. Повторите обновление."
        );
    }
    crate::interrupt::check()?;
    apply_list_replacements(&staged, atomic_write)?;
    let routes = details
        .iter()
        .filter_map(|item| item["route"].as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    let mut report = json!({"updated":true,"updated_at":chrono::Utc::now().to_rfc3339(),"lists":details,
        "text":format!("Обновлены все {} списков Flowseal. Источник загрузки — {routes}.",staged.len())});
    let saved = runtime_file(&app.root, "list-update-last.json")
        .and_then(|path| atomic_write(&path, &serde_json::to_vec(&report)?));
    report["report_saved"] = json!(saved.is_ok());
    Ok(report)
}

fn existing_list(path: &Path) -> Result<Option<Vec<u8>>> {
    if path.try_exists()? {
        Ok(Some(read_bounded(path, 32 * 1024 * 1024)?))
    } else {
        Ok(None)
    }
}

fn list_content(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or("").trim()
}

fn download_entry(name: &str, content: &str) -> Result<String> {
    Ok(if name == "hosts-flowseal.txt" {
        let mut fields = content.split_whitespace();
        let ip: IpAddr = fields.next().context("Отсутствует адрес hosts")?.parse()?;
        let domains = fields.map(normalize_domain).collect::<Result<Vec<_>>>()?;
        ensure!(!domains.is_empty(), "В записи hosts отсутствует имя");
        format!("{ip} {}", domains.join(" "))
    } else if name.starts_with("ipset-") {
        normalize_ip_network(content)?
    } else {
        let (prefix, domain) = content
            .strip_prefix('^')
            .map_or(("", content), |domain| ("^", domain));
        format!("{prefix}{}", normalize_domain(domain)?)
    })
}

fn validate_download(name: &str, bytes: &[u8], old_lines: usize) -> Result<()> {
    let text = std::str::from_utf8(bytes)?.trim_start_matches('\u{feff}');
    ensure!(
        !text.contains('\0'),
        "Список {name} содержит нулевой символ"
    );
    let entries = text
        .lines()
        .map(list_content)
        .filter(|content| !content.is_empty())
        .map(|content| download_entry(name, content))
        .collect::<Result<BTreeSet<_>>>()?;
    let minimum = old_lines
        .div_ceil(2)
        .max(if name == "ipset-all.txt" { 1000 } else { 1 });
    ensure!(
        entries.len() >= minimum,
        "Список {name} выглядит обрезанным: {} записей, требуется {minimum}",
        entries.len()
    );
    Ok(())
}

struct ListReplacement {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    bytes: Vec<u8>,
}

fn apply_list_replacements(
    staged: &[ListReplacement],
    mut write: impl FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    // Prepare every backup before replacing the first live list. An empty old
    // file has a real backup, while an absent old file remains absent on rollback.
    for item in staged {
        if let Some(previous) = &item.previous {
            let backup = item.path.with_extension("txt.bak");
            check_existing_plain(&backup)?;
            write(&backup, previous)?;
        }
    }
    for (index, item) in staged.iter().enumerate() {
        if let Err(error) = write(&item.path, &item.bytes) {
            let mut failures = Vec::new();
            for previous in staged[..index].iter().rev() {
                let restored = match &previous.previous {
                    Some(bytes) => write(&previous.path, bytes),
                    None => fs::remove_file(&previous.path).map_err(Into::into),
                };
                if let Err(restore) = restored {
                    failures.push(format!("{}: {restore:#}", previous.path.display()));
                }
            }
            return if failures.is_empty() {
                Err(error)
            } else {
                Err(error.context(format!(
                    "Ошибки восстановления списков: {}",
                    failures.join("; ")
                )))
            };
        }
    }
    Ok(())
}

pub fn diagnostic_engine(app: &App, run: bool, seconds: u64) -> Result<Value> {
    let _guard = if run {
        Some(ControlGuard::acquire(&app.root, "diagnostic")?)
    } else {
        None
    };
    let settings = read_settings(&app.root)?;
    let log = runtime_file(&app.root, "diagnostic-native.log")?;
    let arguments = compose(
        &app.root,
        &settings,
        &ComposeOptions {
            no_auto: true,
            persistence: false,
            debug_file: Some(log.clone()),
            ..Default::default()
        },
    )?;
    if !run {
        return Ok(json!({"arguments":arguments,"log":log}));
    }
    ensure!(
        (1..=3600).contains(&seconds),
        "Время диагностики вне диапазона"
    );
    crate::interrupt::install()?;
    crate::interrupt::check()?;
    let approved_games = crate::selection::game_snapshot(app)?;
    app.game_check("Диагностика временно остановит рабочий обход")?;
    diagnostic_control(app, &approved_games)?;
    prepare_runtime(&app.root, &settings)?;
    check_engine_args(&app.root, &arguments)?;
    let launch = engine_arguments(&app.root, &arguments, false)?;
    let status = app.platform("status", json!({}))?;
    ensure!(
        status["known"] == true && status["ownership_known"] == true,
        "Не удалось подтвердить принадлежность рабочего обхода"
    );
    let was_running = status["running"] == true;
    with_running_restore(
        was_running,
        || {
            diagnostic_control(app, &approved_games)?;
            if was_running {
                app.platform("stop", json!({"game_approved":true}))?;
            }
            diagnostic_control(app, &approved_games)?;
            let result = run_engine(
                &app.root,
                &launch,
                &RunOptions {
                    cwd: Some(app.root.join("bin")),
                    timeout: Duration::from_secs(seconds),
                    ..Default::default()
                },
            )?;
            Ok(
                json!({"log":log,"timed_out":result.timed_out,"exit_code":result.exit_code,"stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr),"output_truncated":result.output_truncated}),
            )
        },
        || {
            diagnostic_control(app, &approved_games)?;
            if app.platform("status", json!({}))?["running"] != true {
                app.platform("start", json!({"game_approved":true}))?;
            }
            Ok(())
        },
    )
}

fn diagnostic_control(app: &App, approved: &BTreeSet<String>) -> Result<()> {
    let current = crate::selection::game_snapshot(app)?;
    if !current.is_subset(approved) {
        let message = "Во время диагностики запущена новая игра. Запустите обход пунктом 1 после закрытия игры.";
        atomic_write(
            &runtime_file(&app.root, "test-restore-pending.txt")?,
            message.as_bytes(),
        )?;
        anyhow::bail!("{message}");
    }
    app.platform("control-check", json!({"game_approved":true}))?;
    Ok(())
}

fn with_running_restore<T>(
    was_running: bool,
    operation: impl FnOnce() -> Result<T>,
    restore: impl FnOnce() -> Result<()>,
) -> Result<T> {
    let result = operation();
    let restored = if was_running { restore() } else { Ok(()) };
    match (result, restored) {
        (result, Ok(())) => result,
        (Ok(_), Err(restore)) => {
            Err(restore.context("Не удалось восстановить обход после диагностики"))
        }
        (Err(error), Err(restore)) => Err(error.context(format!(
            "Не удалось восстановить обход после диагностики: {restore:#}"
        ))),
    }
}

fn older_than(path: &Path, days: u64) -> bool {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_none_or(|age| age > Duration::from_secs(days * 86400))
}

fn log(root: &Path, name: &str, text: &str) -> Result<()> {
    let path = runtime_file(root, name)?;
    let mut old = if path.exists() {
        read_text(&path, 8 * 1024 * 1024)?
    } else {
        String::new()
    };
    if old.len() > 4 * 1024 * 1024 {
        old = old
            .lines()
            .rev()
            .take(1000)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
    }
    old.push_str(&format!(
        "\n{} {text}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    atomic_write(&path, old.as_bytes())
}

pub fn autotune(app: &App, force: bool) -> Result<Value> {
    let _guard = ControlGuard::acquire(&app.root, "autotune")?;
    let conflicts = app.platform("conflicts", json!({}))?;
    let games = app.platform("games", json!({}))?;
    let foreign = conflicts["foreign_bypass"]
        .as_array()
        .is_some_and(|values| !values.is_empty());
    let tun = conflicts["tun_adapters"]
        .as_array()
        .is_some_and(|values| !values.is_empty());
    let proxy = conflicts["proxy"]["proxy"]
        .as_str()
        .is_some_and(|value| !value.is_empty());
    if games.as_array().is_some_and(|values| !values.is_empty()) || foreign || tun || proxy {
        log(
            &app.root,
            "autotune.log",
            "Автоподбор отложен из-за игры, прокси или другого обхода",
        )?;
        return Ok(json!({"deferred":true,"games":games,"conflicts":conflicts}));
    }
    if force || older_than(&app.root.join("lists/ipset-all.txt"), 7) {
        refresh_for_autotune(&app.root, || lists(app, true))?;
    }
    if !force && !older_than(&app.root.join("runtime/test-rank.txt"), 7) {
        return Ok(json!({"due":false}));
    }
    let arguments = TestArgs {
        full: false,
        keep_primary: true,
        ..Default::default()
    };
    let automatic = App {
        root: app.root.clone(),
        yes: true,
        json: app.json,
    };
    let result = crate::selection::run(&automatic, &arguments);
    log(
        &app.root,
        "autotune.log",
        &match &result {
            Ok(_) => "Автоподбор завершён".into(),
            Err(error) => format!("Автоподбор завершился ошибкой {error:#}"),
        },
    )?;
    result
}

fn refresh_for_autotune(root: &Path, update: impl FnOnce() -> Result<Value>) -> Result<()> {
    if let Err(error) = update() {
        crate::interrupt::check()?;
        crate::ensure_controller_current()?;
        if !first_run::local_lists_ready(root) {
            return Err(error);
        }
        log(
            root,
            "autotune.log",
            &format!(
                "Обновление списков недоступно. Автоподбор использует локальные списки ({error:#})."
            ),
        )?;
    }
    Ok(())
}

/// Preserve the menu's passive startup maintenance without blocking menu input.
/// No strategy test, engine restart or system-setting change runs in this thread.
pub fn start_background_maintenance(app: &App, refresh_lists: bool) {
    let updates_due = older_than(&app.root.join("runtime/update-check-native.json"), 3);
    let lists_due = refresh_lists
        && LISTS
            .iter()
            .any(|(name, _)| older_than(&app.root.join("lists").join(name), 7));
    if !updates_due && !lists_due {
        return;
    }
    let root = app.root.clone();
    thread::spawn(move || {
        let background = App {
            root,
            yes: false,
            json: true,
        };
        let result = (|| -> Result<()> {
            let Some(_lease) = worker_lease(&background.root, "startup-maintenance-native.lock")?
            else {
                return Ok(());
            };
            crate::ensure_controller_current()?;
            if updates_due {
                update_observation(&background)?;
            }
            if lists_due {
                crate::ensure_controller_current()?;
                if background.platform("control-check", json!({})).is_err() {
                    return Ok(());
                }
                let status = background.platform("status", json!({}))?;
                if status["known"] != true || status["ownership_known"] != true {
                    return Ok(());
                }
                update_lists(&background, 30000, || {
                    background.platform("control-check", json!({})).map(|_| ())
                })?;
                log(
                    &background.root,
                    "startup-native.log",
                    "Списки Flowseal обновлены в фоне",
                )?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = log(
                &background.root,
                "startup-native.log",
                &format!("Фоновая проверка отложена: {error:#}"),
            );
        }
    });
}

pub fn notices(app: &App) -> Result<Value> {
    let mut notices = Vec::new();
    let state = observation_result(app.platform("status", json!({})));
    if state["known"] == true
        && state["running"] != true
        && state["service"]["owned"] == true
        && state["service"]["state"] == 1
        && !runtime_file(&app.root, "manual-stop.txt")?.exists()
    {
        notices.push(json!({"id":"stopped","text":"Служба обхода остановлена. Запустите обход из меню, чтобы увидеть причину."}));
    }
    for (name, id) in [
        ("start-error.txt", "start"),
        ("autotune.log", "autotune"),
        ("test-restore-pending.txt", "test-restore-pending"),
    ] {
        let path = runtime_file(&app.root, name)?;
        if path.is_file() {
            let text = read_text(&path, 8 * 1024 * 1024)?;
            if let Some(last) = text.lines().rfind(|line| !line.trim().is_empty()) {
                notices.push(json!({"id":id,"text":last}));
            }
        }
    }
    let proxy = observation_result(proxy_app_observations(app));
    if let Some(stuck) = proxy["stuck"].as_array().filter(|items| !items.is_empty()) {
        let names = stuck
            .iter()
            .filter_map(|item| item["app"].as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        notices.push(json!({"id":"proxy-stuck","text":format!("{names}: процесс использовал локальный прокси, который сейчас не слушает порт. Проверьте приложение; может понадобиться перезапуск.")}));
    }
    let updates = update_observation(app)?;
    if updates["available"] == true {
        let tag = updates["release"]["tag"].as_str().unwrap_or("?");
        notices.push(json!({"id":"version","text":format!("Доступна версия zapret-rust {tag}. Обновление — Настройки → Обновить zapret-rust.")}));
    }
    let settings = read_settings(&app.root)?;
    if settings.get("telegram") == "on" {
        if let Ok(telegram) = app.platform("telegram-status", json!({})) {
            if telegram["running"] != true {
                notices.push(json!({"id":"telegram","text":"Мост Telegram включён в настройках, но не запущен."}));
            }
        }
    }
    let text = if notices.is_empty() {
        "Новых уведомлений нет.".into()
    } else {
        notices
            .iter()
            .filter_map(|item| item["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(json!({"notices":notices,"proxy_apps":proxy,"update_check":updates,"text":text}))
}

fn update_observation(app: &App) -> Result<Value> {
    let path = runtime_file(&app.root, "update-check-native.json")?;
    if !older_than(&path, 3) {
        if let Ok(value) = serde_json::from_slice::<Value>(&read_bounded(&path, 2 * 1024 * 1024)?) {
            return Ok(value);
        }
    }
    crate::interrupt::check()?;
    let result = observation_result(crate::updates::update(app, false, None, None));
    atomic_write(&path, &serde_json::to_vec_pretty(&result)?)?;
    crate::interrupt::check()?;
    Ok(result)
}

fn worker_lease(root: &Path, name: &str) -> Result<Option<std::fs::File>> {
    let path = runtime_file(root, name)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => Ok(None),
        Err(error) => Err(error).context("Не удалось открыть блокировку фонового наблюдателя"),
    }
}

pub fn notify(app: &App, watch: bool) -> Result<Value> {
    crate::interrupt::install()?;
    let Some(_lease) = worker_lease(&app.root, "notify-native.lock")? else {
        return Ok(json!({"already_running":true}));
    };
    let state_path = runtime_file(&app.root, "notify-state-native.json")?;
    let mut seen: BTreeSet<String> = if state_path.is_file() {
        serde_json::from_slice(&read_bounded(&state_path, 65536)?).unwrap_or_default()
    } else {
        BTreeSet::new()
    };
    loop {
        crate::interrupt::check()?;
        crate::ensure_controller_current()?;
        if read_settings(&app.root)?.get("notify") == "off" {
            return Ok(json!({"enabled":false}));
        }
        let current = notices(app)?;
        let mut live = BTreeSet::new();
        for item in current["notices"].as_array().context("Invalid notices")? {
            let key = sha256(item.to_string().as_bytes());
            live.insert(key.clone());
            if !seen.contains(&key) {
                app.platform("notify", json!({"title":"zapret-rust","text":item["text"]}))?;
            }
        }
        seen = live;
        atomic_write(&state_path, &serde_json::to_vec(&seen)?)?;
        if !watch {
            return Ok(current);
        }
        interruptible_wait(Duration::from_secs(60), crate::interrupt::check)?;
    }
}

fn interruptible_wait(duration: Duration, mut check: impl FnMut() -> Result<()>) -> Result<()> {
    let end = Instant::now() + duration;
    loop {
        check()?;
        let Some(remaining) = end.checked_duration_since(Instant::now()) else {
            return Ok(());
        };
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

#[derive(Default)]
struct WifiGuard {
    links: BTreeMap<String, bool>,
    observed: i64,
    last_event: i64,
    pause_until: i64,
}

fn wifi_id(adapter: &Value) -> Option<&str> {
    adapter["id"].as_str().filter(|id| {
        id.len() == 32
            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && id.bytes().any(|byte| byte != b'0')
    })
}

impl WifiGuard {
    fn scope(&self, observation: &Value) -> BTreeSet<String> {
        let mut scope = self.links.keys().cloned().collect::<BTreeSet<_>>();
        if let Some(adapters) = observation["adapters"].as_array() {
            for adapter in adapters.iter().filter(|a| {
                a["if_type"] == 71
                    && a["up"] == true
                    && a["gateways"].as_array().is_some_and(|gateways| {
                        gateways.iter().any(|gateway| {
                            gateway
                                .as_str()
                                .and_then(|text| text.parse::<IpAddr>().ok())
                                .is_some_and(|ip| !ip.is_unspecified())
                        })
                    })
            }) {
                if let Some(id) = wifi_id(adapter) {
                    scope.insert(id.to_ascii_lowercase());
                }
            }
        }
        scope.into_iter().take(16).collect()
    }

    fn update(&mut self, observation: &Value, event: &Value, now: i64) {
        if now < self.observed {
            self.last_event = 0;
            self.pause_until = 0;
        }
        self.observed = now;
        if let Some(adapters) = observation["adapters"].as_array() {
            let scope = self.scope(observation);
            let current = adapters
                .iter()
                .filter(|adapter| adapter["if_type"] == 71)
                .filter_map(|adapter| {
                    wifi_id(adapter).map(|id| (id.to_ascii_lowercase(), adapter["up"] == true))
                })
                .collect::<BTreeMap<_, _>>();
            self.links.retain(|id, _| scope.contains(id));
            let mut changed = false;
            for (id, up) in &mut self.links {
                let current_up = current.get(id).copied().unwrap_or(false);
                changed |= *up != current_up;
                *up = current_up;
            }
            for id in scope {
                self.links
                    .entry(id.clone())
                    .or_insert_with(|| current.get(&id).copied().unwrap_or(false));
            }
            if changed {
                self.last_event = now;
                self.pause_until = now + 20;
            }
        }
        if event["known"] == true {
            if let Some(epoch) = event["last_disconnect_unix"]
                .as_i64()
                .filter(|epoch| *epoch <= now && *epoch >= now - 30 && *epoch > self.last_event)
            {
                self.last_event = epoch;
                self.pause_until = self.pause_until.max(epoch + 20);
            }
        }
    }

    fn record(&self, now: i64) -> String {
        if now < 0
            || self.last_event < 0
            || self.last_event > now
            || self.pause_until < 0
            || ((self.last_event == 0) != (self.pause_until == 0))
            || self.pause_until > now + 20
            || (self.pause_until != 0 && self.pause_until < self.last_event)
        {
            return "1 0 0 0\n".into();
        }
        format!("1 {now} {} {}\n", self.last_event, self.pause_until)
    }
}

const WATCH_INTERVAL: Duration = Duration::from_secs(5);
const WATCH_LOCK: &str = "network-watch-native.lock";

fn network_watch_lease(root: &Path, timeout: Duration) -> Result<Option<fs::File>> {
    // A previous controller may still hold this lock until its next network poll.
    // Wait in the new watcher, so handing over does not delay the engine start.
    let deadline = Instant::now() + timeout;
    loop {
        let lease = worker_lease(root, WATCH_LOCK)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if lease.is_some() || remaining.is_zero() {
            return Ok(lease);
        }
        interruptible_wait(
            remaining.min(Duration::from_millis(250)),
            crate::interrupt::check,
        )?;
    }
}

pub fn watch(app: &App) -> Result<Value> {
    crate::interrupt::install()?;
    let Some(_lease) = network_watch_lease(&app.root, WATCH_INTERVAL * 3)? else {
        return Ok(json!({"already_running":true,"text":"Фоновый контроль сети уже запущен."}));
    };
    let initial = crate::controller_hash()?;
    let mut previous: Option<(String, String)> = None;
    let mut wifi = WifiGuard::default();
    let mut events_known = None;
    let context_path = runtime_file(&app.root, "ring/network-context.txt")?;
    let link_path = runtime_file(&app.root, "ring/link-guard.txt")?;
    atomic_write(&context_path, b"3 0 - -\n")?;
    atomic_write(&link_path, b"1 0 0 0\n")?;
    loop {
        crate::interrupt::check()?;
        let state = app.platform("status", json!({}))?;
        if state["running"] != true {
            break;
        }
        if state["processes"]
            .as_array()
            .is_none_or(|processes| processes.is_empty())
        {
            atomic_write(&context_path, b"3 0 - -\n")?;
            atomic_write(&link_path, b"1 0 0 0\n")?;
            previous = None;
            wifi = WifiGuard::default();
            interruptible_wait(WATCH_INTERVAL, crate::interrupt::check)?;
            continue;
        }
        if crate::ensure_controller_current().is_err() {
            atomic_write(&context_path, b"3 0 - -\n")?;
            atomic_write(&link_path, b"1 0 0 0\n")?;
            break;
        }
        let observation = app.platform("network", json!({}))?;
        let key = observation["key"]
            .as_str()
            .filter(|_| observation["known"] == true)
            .unwrap_or("");
        let composition =
            ring_composition_key_with_identity(&app.root, &read_settings(&app.root)?, initial)
                .unwrap_or_default();
        let now = chrono::Utc::now().timestamp();
        let current = (key.to_owned(), composition.clone());
        let record =
            if key.len() == 64 && composition.len() == 64 && previous.as_ref() == Some(&current) {
                format!("3 {now} {key} {}\n", &composition[..24])
            } else {
                "3 0 - -\n".into()
            };
        let events = app.platform(
            "wifi-events",
            json!({"interface_ids":wifi.scope(&observation)}),
        )?;
        let known = events["known"] == true && events["truncated"] != true;
        if events_known != Some(known) {
            if !known {
                log(
                    &app.root,
                    "network-watch-native-events.log",
                    "Журнал отключений Wi-Fi недоступен; короткий переподъём между опросами может остаться незамеченным",
                )?;
            }
            events_known = Some(known);
        }
        wifi.update(&observation, &events, now);
        atomic_write(&context_path, record.as_bytes())?;
        atomic_write(&link_path, wifi.record(now).as_bytes())?;
        previous = Some(current);
        interruptible_wait(WATCH_INTERVAL, crate::interrupt::check)?;
    }
    Ok(
        json!({"stopped":true,"wifi_events_known":events_known,"text":"Фоновый контроль сети завершён."}),
    )
}

pub fn uninstall(app: &App) -> Result<Value> {
    app.game_check("Удаление остановит обход")?;
    ensure!(
        app.confirm("Удалить службу и задачи zapret-rust из Windows?")?,
        "Удаление отменено"
    );
    let _guard = ControlGuard::acquire(&app.root, "uninstall")?;
    let ipv4 = app.platform("prefer-ipv4", json!({}))?;
    let restore_ipv4 = ipv4["enabled"] == true
        && app.confirm("Включено предпочтение IPv4. Вернуть стандартный порядок Windows?")?;
    let result = app.platform(
        "uninstall",
        json!({"game_approved":true,"restore_ipv4":restore_ipv4}),
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn city_summary_counts_observed_directions_and_does_not_guess_a_disconnect() {
        let capture = json!({"status":"Partial","flows":[
            {"protocol":"tcp","port":20895,"out":6,"in":1},{"protocol":"tcp","port":443,"out":2,"in":3}],
            "city":{"after":{"foreign_bypass_count":1,"ownership_known":true,"running":false}}});
        let text = city_summary(&capture);
        for expected in [
            "неполная",
            "исходящих событий 8, входящих 4",
            "443, 20895",
            "UDP — событий в записи нет",
            "другой обход",
            "установки остановлен",
        ] {
            assert!(text.contains(expected), "{text}");
        }
    }

    #[test]
    fn scanner_never_applies_partial_or_changed_observations() {
        let complete = json!({"status":"Captured","configuration_stable":true,"cleanup_confirmed":true,"truncated":false,"events_lost":0,"decode_errors":0});
        assert!(scan_is_eligible(&complete));
        for (field, value) in [
            ("status", json!("Partial")),
            ("configuration_stable", json!(false)),
            ("cleanup_confirmed", json!(false)),
            ("truncated", json!(true)),
            ("events_lost", json!(1)),
            ("decode_errors", json!(1)),
        ] {
            let mut partial = complete.clone();
            partial[field] = value;
            assert!(!scan_is_eligible(&partial), "{field}");
        }
        assert!(!scan_is_eligible(&json!({})));
    }

    #[test]
    fn pc_summary_requires_known_ownership_and_does_not_invent_zero_ipv6_failures() {
        let rendered = pc_check_text(&json!({
            "bypass":{"known":false,"ownership_known":false,"running":true},
            "integrity":{"status":"Unavailable"},
            "ipv6":{"status":"Unavailable","rows":[],"broken":[]},
            "dns":{"status":"Unavailable","suspect":[]}
        }));
        assert!(rendered.contains("Обход: состояние не подтверждено"));
        assert!(!rendered.contains("Обход: работает"));
        assert!(rendered.contains("IPv6: проверка недоступна"));
        assert!(!rendered.contains("проблемных путей 0"));
        assert!(!rendered.contains("проверено null"));
    }

    #[test]
    fn tracker_translates_partial_capture_and_configuration_reasons() {
        let rendered = capture_text(
            &json!({"status":"Partial","truncated":true,"configuration_stable":true,
            "flows":[{"protocol":"tcp","address":"8.8.8.8","port":443,"process_name":"fixture",
                "out":1,"in":2,"configured_bypass":false,"bypass_reason":"Lists"}]}),
            false,
        );
        assert!(rendered.contains("частичная запись"));
        assert!(rendered.contains("адрес не включён в списки"));
        assert!(!rendered.contains("Partial") && !rendered.contains("(Lists)"));
    }

    #[test]
    fn remote_extraction_skips_local_addresses_and_redacts_secrets() {
        let mut output = BTreeSet::new();
        remote_addresses(
            &json!({"connections":[{"remote_address":"8.8.8.8"},{"remote_address":"192.168.1.1"},
            {"remote_address":"[2606:4700:4700::1111]:443"}],"flows":[{"address":"9.9.9.9","local_address":"1.1.1.1"}]}),
            &mut output,
        );
        assert_eq!(
            output,
            BTreeSet::from([
                "8.8.8.8".into(),
                "9.9.9.9".into(),
                "2606:4700:4700::1111".into()
            ])
        );
        let text = redact(
            "ok\nsecret=example\ntg://proxy?secret=example\nlast",
            Path::new("C:/zapret"),
        );
        assert_eq!(text, "ok\nlast");
    }

    #[test]
    fn appending_networks_keeps_comments_order_encoding_and_existing_coverage() {
        let original = "# мой порядок\n9.9.9.0/24 # игра\n\n8.8.8.8/32";
        let add = BTreeSet::from(["9.9.9.9".into(), "8.8.8.8".into(), "1.1.1.1/24".into()]);
        let text = appended_addresses(original, &add, "сканер")
            .unwrap()
            .unwrap();
        assert_eq!(text, format!("{original}\n# сканер\n1.1.1.0/24\n"));
        assert!(appended_addresses(&text, &add, "сканер").unwrap().is_none());
        let temporary = tempfile::tempdir().unwrap();
        for header in [
            vec![],
            vec![0xef, 0xbb, 0xbf],
            vec![0xff, 0xfe],
            vec![0xfe, 0xff],
        ] {
            let path = temporary.path().join(format!(
                "encoding-{}.txt",
                header.len() + header.first().copied().unwrap_or(0) as usize
            ));
            let bytes = text_with_original_encoding(&text, &header);
            fs::write(&path, &bytes).unwrap();
            assert_eq!(read_text(&path, 65536).unwrap(), text);
            assert!(bytes.starts_with(&text_with_original_encoding(original, &header)));
        }
    }

    #[test]
    fn downloaded_lists_validate_real_content_without_rewriting_source_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let bytes = "\u{feff}# Flowseal\n^DNS.Google # exact hostname\nexample.org\n".as_bytes();
        validate_download("list-general.txt", bytes, 3).unwrap();
        let path = temporary.path().join("list-general.txt");
        apply_list_replacements(
            &[ListReplacement {
                path: path.clone(),
                previous: None,
                bytes: bytes.to_vec(),
            }],
            atomic_write,
        )
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(validate_download("list-general.txt", b"example.org\n", 3).is_err());
        for invalid in [
            "<html>unavailable</html>",
            "example.org/path",
            "good.example\0bad.example",
        ] {
            assert!(validate_download("list-general.txt", invalid.as_bytes(), 0).is_err());
        }
        assert!(validate_download("hosts-flowseal.txt", b"8.8.8.8\n", 0).is_err());
        assert!(validate_download("hosts-flowseal.txt", b"8.8.8.8 bad/name\n", 0).is_err());
        validate_download(
            "hosts-flowseal.txt",
            b"# mapping\n8.8.8.8 good.example alias.example # aliases\n",
            0,
        )
        .unwrap();
        let ipset = (0..1000)
            .map(|n| format!("{}/32", std::net::Ipv4Addr::from(0x0800_0000 + n)))
            .collect::<Vec<_>>()
            .join("\n");
        validate_download("ipset-all.txt", ipset.as_bytes(), 0).unwrap();
        assert!(validate_download("ipset-all.txt", b"8.8.8.8\n", 0).is_err());
        assert!(
            validate_download("ipset-all.txt", "8.8.8.8\n".repeat(1000).as_bytes(), 0).is_err()
        );
    }

    #[test]
    fn a_failed_list_transaction_restores_empty_files_and_removes_new_files() {
        let temporary = tempfile::tempdir().unwrap();
        let new = temporary.path().join("absent.txt");
        let empty = temporary.path().join("empty.txt");
        let last = temporary.path().join("last.txt");
        fs::write(&empty, b"").unwrap();
        fs::write(&last, b"last old").unwrap();
        let staged = [
            ListReplacement {
                path: new.clone(),
                previous: None,
                bytes: b"new".to_vec(),
            },
            ListReplacement {
                path: empty.clone(),
                previous: Some(Vec::new()),
                bytes: b"filled".to_vec(),
            },
            ListReplacement {
                path: last.clone(),
                previous: Some(b"last old".to_vec()),
                bytes: b"last new".to_vec(),
            },
        ];
        let result = apply_list_replacements(&staged, |path, bytes| {
            if path == last {
                anyhow::bail!("injected replacement failure");
            }
            atomic_write(path, bytes)
        });
        assert!(result.is_err());
        assert!(!new.exists());
        assert!(empty.is_file());
        assert_eq!(fs::read(&empty).unwrap(), b"");
        assert_eq!(fs::read(empty.with_extension("txt.bak")).unwrap(), b"");
        assert_eq!(fs::read(last).unwrap(), b"last old");
    }

    #[test]
    fn list_rollback_attempts_every_previous_file_after_one_restore_fails() {
        let temporary = tempfile::tempdir().unwrap();
        let staged = ["first", "second", "third"].map(|name| ListReplacement {
            path: temporary.path().join(format!("{name}.txt")),
            previous: Some(b"old".to_vec()),
            bytes: b"new".to_vec(),
        });
        for item in &staged {
            fs::write(&item.path, b"old").unwrap();
        }
        let failed = Cell::new(false);
        let result = apply_list_replacements(&staged, |path, bytes| {
            if path == staged[2].path {
                failed.set(true);
                anyhow::bail!("replacement failed");
            }
            if failed.get() && path == staged[1].path {
                anyhow::bail!("restore failed");
            }
            atomic_write(path, bytes)
        });
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("replacement failed") && error.contains("restore failed"));
        assert_eq!(fs::read(&staged[0].path).unwrap(), b"old");
        assert_eq!(fs::read(&staged[1].path).unwrap(), b"new");
        assert_eq!(
            fs::read(staged[1].path.with_extension("txt.bak")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn engine_checks_compact_long_paths_before_spawn_and_reject_oversized_commands() {
        let root = PathBuf::from(format!("C:\\{}", "длинная папка ".repeat(70)));
        let arguments = (0..50)
            .map(|index| {
                format!(
                    "--hostlist={}{}lists/list-{index}.txt",
                    root.display(),
                    std::path::MAIN_SEPARATOR
                )
            })
            .collect::<Vec<_>>();
        assert!(
            zapret_core::windows_command_line(&arguments)
                .encode_utf16()
                .count()
                > 30000
        );
        let compact = engine_arguments(&root, &arguments, true).unwrap();
        assert!(
            compact
                .iter()
                .any(|arg| arg.to_string_lossy().starts_with("--chdir="))
        );
        assert!(
            compact
                .iter()
                .any(|arg| arg == "--hostlist=lists/list-0.txt")
        );
        assert_eq!(
            compact
                .iter()
                .filter(|arg| arg == &&OsString::from("--dry-run"))
                .count(),
            1
        );
        assert!(
            engine_arguments(
                &root,
                &[format!("--filter-tcp={}", "1".repeat(33000))],
                true
            )
            .is_err()
        );
    }

    #[test]
    fn diagnostics_restore_only_the_previous_running_state_and_keep_both_errors() {
        let calls = RefCell::new(Vec::new());
        let result = with_running_restore(
            true,
            || -> Result<()> {
                calls.borrow_mut().push("operation");
                anyhow::bail!("diagnostic failed");
            },
            || {
                calls.borrow_mut().push("restore");
                Ok(())
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("diagnostic failed")
        );
        assert_eq!(*calls.borrow(), ["operation", "restore"]);
        calls.borrow_mut().clear();
        let result = with_running_restore(
            false,
            || Ok(7),
            || {
                calls.borrow_mut().push("restore");
                Ok(())
            },
        );
        assert_eq!(result.unwrap(), 7);
        assert!(calls.borrow().is_empty());
        let result = with_running_restore(
            true,
            || -> Result<()> {
                anyhow::bail!("diagnostic failed");
            },
            || {
                anyhow::bail!("restore failed");
            },
        );
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("diagnostic failed") && error.contains("restore failed"));
    }

    #[test]
    fn interruptible_workers_observe_cancellation_before_the_long_sleep_ends() {
        let calls = Cell::new(0);
        let start = Instant::now();
        let result = interruptible_wait(Duration::from_secs(60), || {
            calls.set(calls.get() + 1);
            ensure!(calls.get() < 2, "cancelled");
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 2);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn selected_game_scan_admits_only_exact_public_peers_of_that_executable() {
        let capture = json!({"flows":[
            {"process_name":"Игра Test","address":"9.9.9.9","port":443,"protocol":"tcp"},
            {"process_name":"Игра Test","address":"2606:4700:4700::1111","port":27015,"protocol":"udp"},
            {"process_name":"Игра Test","address":"::ffff:127.0.0.1","port":443,"protocol":"tcp"},
            {"process_name":"Игра Test","address":"1.1.1.1","port":0,"protocol":"udp"},
            {"process_name":"Игра Test","address":"1.1.1.1","port":80,"protocol":"icmp"},
            {"process_name":"Игра Test Launcher","address":"8.8.8.8","port":443,"protocol":"tcp"}],
            "diagnostics":{"peers":[{"address":"8.8.4.4"}]}});
        let configured = zapret_core::selected_game_names("Игра Test.exe").unwrap();
        let game = selected_process(&configured, "ИГРА Test.EXE").unwrap();
        assert!(selected_process(&configured, "Игра*").is_none());
        assert_eq!(
            selected_addresses(&capture, game),
            BTreeSet::from(["9.9.9.9".into(), "2606:4700:4700::1111".into()])
        );
        let mut settings = Settings::default();
        settings.set("game", "selected").unwrap();
        settings.set("ipset", "any").unwrap();
        let game = zapret_core::Strategy::default().game_protocols("selected");
        for proto in ["tcp", "udp"] {
            assert_eq!(
                configured_bypass("выбранная игра", proto, 27015, &settings, game),
                (true, "SelectedGame")
            );
            assert_eq!(
                configured_bypass("ipset-all", proto, 27015, &settings, game),
                (false, "NotSelected")
            );
            assert!(!configured_bypass("исключено", proto, 27015, &settings, game).0);
        }
        let tcp_only = GameProtocols {
            tcp: true,
            udp: false,
        };
        assert_eq!(
            configured_bypass("выбранная игра", "udp", 27015, &settings, tcp_only),
            (false, "Port")
        );
        assert_eq!(
            configured_bypass("выбранная игра", "udp", 443, &settings, tcp_only),
            (true, "SelectedGame")
        );
    }

    #[test]
    fn exclusion_uses_only_configured_game_paths_and_keeps_voice_out() {
        let game = zapret_core::Strategy::default().game_protocols("all");
        let overlap = OwnerSets {
            lists: vec![
                ("ipset-all", vec![IpNetwork::parse("2.2.0.0/16").unwrap()]),
                ("Take-Two", vec![IpNetwork::parse("2.2.2.0/24").unwrap()]),
            ],
            game,
        };
        assert_eq!(overlap.owner("2.2.2.2".parse().unwrap()), "Take-Two");
        let owners = OwnerSets {
            lists: vec![
                ("ipset-all", vec![IpNetwork::parse("8.8.8.0/24").unwrap()]),
                ("Take-Two", vec![IpNetwork::parse("2.2.2.0/24").unwrap()]),
            ],
            game,
        };
        let mut capture = json!({"flows":[
            {"address":"8.8.8.8","protocol":"tcp","port":443},
            {"address":"8.8.8.9","protocol":"udp","port":50000},
            {"address":"2.2.2.2","protocol":"tcp","port":443},
            {"address":"7.7.7.7","protocol":"tcp","port":443},
            {"address":"8.8.8.10","protocol":"tcp","port":22},
        ]});
        annotate_capture(&mut capture, &Settings::default(), &owners, true);
        assert_eq!(
            exclusion_networks(&capture),
            BTreeSet::from(["8.8.8.0/24".into()])
        );
        assert_eq!(capture["flows"][1]["bypass_reason"], "Voice");
        assert_eq!(capture["flows"][2]["configured_bypass"], false);
        annotate_capture(&mut capture, &Settings::default(), &owners, false);
        assert!(exclusion_networks(&capture).is_empty());
        assert!(exclusion_networks(&json!({"flows":[{"address":"8.8.8.8"}]})).is_empty());
    }

    #[test]
    fn legacy_tracker_exclusion_reads_the_final_summary_and_exact_eligible_labels() {
        let text = "новый UDP 7.7.7.7:443 | обход: да\nВсе адреса\n  TCP 8.8.8.8:443 proc | обход: да\n  UDP 9.9.9.9:27015 proc | обход: да (any)\n  TCP [2606:4700:1234:5678::1]:443 proc | обход: да (user)\n  UDP 1.1.1.1:50000 proc | обход: да (голос)\n  TCP 2.2.2.2:443 proc | обход: нет (2K)\n  TCP 192.168.1.1:443 proc | обход: да\n";
        assert_eq!(
            legacy_exclusion_networks(text).unwrap(),
            BTreeSet::from([
                "8.8.8.0/24".into(),
                "9.9.9.0/24".into(),
                "2606:4700:1234:5678::/64".into()
            ])
        );
    }

    #[test]
    fn wifi_reconnect_between_polls_pauses_without_extending_the_same_event() {
        let id = "1234567890abcdef1234567890abcdef";
        let observation = |up: bool| json!({"adapters":[{"id":id,"index":4,"if_type":71,"up":up,"gateways":["192.168.1.1"]}]});
        let mut guard = WifiGuard::default();
        guard.update(&observation(true), &json!({"known":true}), 100);
        assert_eq!(guard.record(100), "1 100 0 0\n");
        let event = json!({"known":true,"last_disconnect_unix":101,"sequence":42});
        guard.update(&observation(true), &event, 105);
        assert_eq!(guard.record(105), "1 105 101 121\n");
        guard.update(&observation(true), &event, 110);
        assert_eq!(guard.record(110), "1 110 101 121\n");
        guard.update(&observation(false), &event, 111);
        assert_eq!(guard.record(111), "1 111 111 131\n");
        assert!(guard.scope(&observation(false)).contains(id));
        guard.update(
            &json!({}),
            &json!({"known":false,"last_disconnect_unix":112}),
            112,
        );
        assert_eq!(guard.record(112), "1 112 111 131\n");
        guard.update(
            &observation(false),
            &json!({"known":true,"last_disconnect_unix":300}),
            50,
        );
        assert_eq!(guard.record(50), "1 50 0 0\n");
    }

    #[test]
    fn proxy_stuck_advice_requires_exact_process_identity_and_known_tcp_states() {
        let identity = json!({"pid":123,"created_filetime":10,"executable":"C:\\Apps\\Steam.exe"});
        let live = json!([{"identity":identity}]);
        let old = json!({"app":"Steam","identity":identity,"port":7890});
        let connections = json!({"known":true,"states_known":true,"connections":[]});
        let configured = BTreeSet::new();
        let state = proxy_app_state(&configured, &connections, &live, std::slice::from_ref(&old));
        assert_eq!(state["stuck"].as_array().unwrap().len(), 1);
        let reused = json!([{"identity":{"pid":123,"created_filetime":11,"executable":"C:\\Apps\\Steam.exe"}}]);
        assert!(
            proxy_app_state(
                &configured,
                &connections,
                &reused,
                std::slice::from_ref(&old)
            )["stuck"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let unknown = json!({"known":true,"states_known":false,"connections":[]});
        assert_eq!(
            proxy_app_state(&configured, &unknown, &live, &[old])["known"],
            false
        );
        assert_eq!(
            proxy_ports("http=127.0.0.1:7890;https=localhost:7891"),
            BTreeSet::from([7890, 7891])
        );
        assert_eq!(
            proxy_ports("127.0.0.1:7890;127.0.0.2:7891;192.168.1.1:7892;[::1]:7893"),
            BTreeSet::from([7890, 7891])
        );
    }

    #[test]
    fn steam_proxy_log_fallback_checks_current_process_and_closed_port() {
        let root = tempfile::tempdir().unwrap();
        let steam = root.path().join("steam.exe");
        fs::create_dir(root.path().join("logs")).unwrap();
        let log = root.path().join("logs/connection_log.txt");
        let created = DateTime::from_timestamp(1_789_000_000, 0)
            .unwrap()
            .with_timezone(&Local);
        let stamp =
            |delta| (created + chrono::Duration::seconds(delta)).format("%Y-%m-%d %H:%M:%S");
        let older = format!("[{}] (127.0.0.1:7890, WebSocket)\n", stamp(-6));
        let unrelated = format!(
            "[{}] (127.0.0.1:78901, WebSocket)\n[{}] (127.0.0.1:7890, WebSocket)\n",
            stamp(8),
            stamp(60)
        );
        let created = 116_444_736_000_000_000u64 + 1_789_000_000 * 10_000_000;
        let processes = json!([{"name":"steam","identity":{"pid":42,"created_filetime":created,"executable":steam}}]);
        let connections = json!({"known":true,"states_known":true,
            "observed_filetime":created + 20 * 10_000_000,"connections":[]});
        let ports = BTreeSet::from([7890]);
        let live = |connections: &Value| proxy_app_state(&ports, connections, &processes, &[]);

        fs::write(&log, format!("{older}{unrelated}")).unwrap();
        assert_eq!(live(&connections)["stuck"], json!([]));

        let current = filetime_local(created + 5 * 10_000_000).unwrap();
        fs::write(
            &log,
            format!(
                "{}[{current}] ConnectionDisconnected (127.0.0.1:7890, WebSocket)\n{unrelated}",
                "old line\n".repeat(32_768),
                current = current.format("%Y-%m-%d %H:%M:%S"),
            ),
        )
        .unwrap();
        let result = live(&connections);
        assert_eq!(result["stuck"][0]["port"], 7890);
        assert_eq!(result["stuck"][0]["source"], "steam_connection_log");
        assert_eq!(result["remembered"], json!([]));

        let mut listening = connections.clone();
        listening["connections"] = json!([{"state":2,"local_address":"0.0.0.0","local_port":7890}]);
        assert_eq!(live(&listening)["stuck"], json!([]));
        let mut unknown = connections;
        unknown["states_known"] = json!(false);
        assert_eq!(live(&unknown)["stuck"], json!([]));
    }

    #[test]
    fn pc_repairs_remain_explicit_and_hosts_preserves_uncertain_groups() {
        let result = json!({"ipv4_preference":{"known":true,"enabled":false},"ipv6":{"broken":["test"]},
            "hosts":{"groups":[{"group":"GitHub","entries":0},{"group":"Telegram","entries":1},{"group":"Discord","entries":1},{"group":zapret_platform::DISCORD_MEDIA_GROUP,"entries":0}]},
            "hosts_pins":{"rows":[{"group":"GitHub","verdict":"helps"},{"group":"Telegram","verdict":"down"},{"group":"Discord","verdict":"worse"},{"group":zapret_platform::DISCORD_MEDIA_GROUP,"verdict":"helps"}]}});
        let fixes = pc_fixes(&result);
        assert_eq!(fixes.len(), 2);
        let hosts = fixes
            .iter()
            .find(|fix| fix["action"] == "hosts-set")
            .unwrap();
        assert_eq!(
            hosts["arguments"]["groups"],
            json!(["GitHub", "Telegram", zapret_platform::DISCORD_MEDIA_GROUP])
        );
        assert_eq!(
            hosts_pin_verdict(
                &json!({"ok":true,"ms":10}),
                &json!({"ip":"8.8.8.8","ok":true,"ms":500})
            ),
            "worse"
        );
    }

    #[test]
    fn reports_redact_json_paths_network_identity_and_secrets_and_bound_log_tails() {
        let mut value = json!({"context_before":{"adapters":[{"id":"private"}],"profiles":["home"]},"link":"tg://proxy?secret=test","secret":"test","lat":1});
        value["local_address"] = json!("2606:4700:abcd:1234::1");
        redact_report_value(&mut value);
        assert_eq!(value["context_before"]["adapters"], "<скрыто>");
        assert_eq!(value["link"], "<скрыто>");
        assert_eq!(value["local_address"], "2606:4700:abcd:...");
        let text = redact(
            r#"{"path":"c:\\ZAPRET\\bin\\winws2.exe"}"#,
            Path::new("C:\\zapret"),
        );
        assert!(!text.to_ascii_lowercase().contains("zapret\\\\bin"));
        assert!(text.contains("<zapret-rust>"));
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("long.log");
        fs::write(&path, format!("{}\nlast-a\nlast-b\n", "old\n".repeat(1000))).unwrap();
        assert_eq!(read_tail_text(&path, 64, 2).unwrap(), "last-a\nlast-b");
    }

    #[test]
    fn tracker_summary_keeps_post_capture_probe_timing_and_original_capture_failures() {
        let capture = json!({"status":"Partial","truncated":true,"configuration_stable":true,"flows":[],
            "diagnostics":{"phase":"PostCapture","summary_lines":["ICMP после записи: 12 мс","Пауза в ETW: причина не установлена"]}});
        let text = capture_text(&capture, false);
        assert!(text.contains("ICMP после записи: 12 мс"));
        assert!(text.contains("Запись неполная"));
        assert!(text.contains("RTT в моменты пауз и FPS здесь не измеряются"));
        let failed = json!({"status":"Captured","flows":[],"diagnostics":{"status":"Unavailable","error":"injected post-capture failure"}});
        assert!(capture_text(&failed, false).contains("injected post-capture failure"));
    }

    #[test]
    fn direct_rules_preserve_the_legacy_domain_and_valve_network_contract() {
        let source = include_str!("../../../tools/lib.ps1");
        let quoted = regex::Regex::new("'([^']*)'").unwrap();
        let valve = source
            .lines()
            .find(|line| line.starts_with("$Script:ValveNets ="))
            .unwrap();
        assert_eq!(
            quoted
                .captures_iter(valve)
                .map(|capture| capture[1].to_owned())
                .collect::<Vec<_>>(),
            VALVE_NETWORKS
        );
        for (group, domains) in DIRECT_DOMAINS {
            let line = source
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("'{group}'")))
                .unwrap();
            assert_eq!(
                quoted
                    .captures_iter(line)
                    .skip(1)
                    .map(|capture| capture[1].to_owned())
                    .collect::<Vec<_>>(),
                domains
            );
        }
        assert!(
            !DIRECT_DOMAINS
                .iter()
                .flat_map(|(_, domains)| domains.iter())
                .any(|domain| *domain == "steamcommunity.com")
        );
    }

    #[test]
    fn watcher_waits_for_its_predecessor_before_monitoring_the_new_engine() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let previous = worker_lease(root, WATCH_LOCK).unwrap().unwrap();
        assert!(network_watch_lease(root, Duration::ZERO).unwrap().is_none());
        let exiting = thread::spawn(move || {
            thread::sleep(Duration::from_millis(35));
            drop(previous);
        });
        let next = network_watch_lease(root, Duration::from_secs(2)).unwrap();
        exiting.join().unwrap();
        assert!(next.is_some());
        assert!(worker_lease(root, WATCH_LOCK).unwrap().is_none());
    }

    #[test]
    fn a_worker_lease_distinguishes_an_existing_worker_from_other_file_errors() {
        let temporary = tempfile::tempdir().unwrap();
        let lease = worker_lease(temporary.path(), "worker.lock")
            .unwrap()
            .unwrap();
        assert!(
            worker_lease(temporary.path(), "worker.lock")
                .unwrap()
                .is_none()
        );
        drop(lease);
        assert!(
            worker_lease(temporary.path(), "worker.lock")
                .unwrap()
                .is_some()
        );
        fs::create_dir(temporary.path().join("runtime/directory.lock")).unwrap();
        assert!(worker_lease(temporary.path(), "directory.lock").is_err());
    }
}
