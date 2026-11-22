use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use std::collections::HashSet;

pub(super) type Profile = Vec<(String, String)>;

pub(super) fn value<'a>(profile: &'a Profile, key: &str) -> Option<&'a str> {
    profile
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

pub(super) fn profiles(text: &str) -> Result<Vec<Profile>> {
    let text = text.replace("^\r\n", "").replace("^\n", "");
    let commands: Vec<_> = text
        .lines()
        .filter(|line| {
            line.trim_start().to_ascii_lowercase().starts_with("start ")
                && line.contains("winws.exe\"")
        })
        .collect();
    ensure!(commands.len() == 1, "Expected one winws.exe start command");
    let line = commands[0]
        .split_once("winws.exe\"")
        .context("Missing winws.exe command")?
        .1
        .replace("^!", "!");
    let pattern = Regex::new(r#"(--[a-z0-9-]+)(?:=("[^"]*"|[^\s"]+))?(?:\s|$)"#)?;
    let mut end = 0;
    let mut profiles = Vec::new();
    let mut current = Vec::new();
    let mut filters = HashSet::new();
    for capture in pattern.captures_iter(&line) {
        let token = capture.get(0).context("Missing option")?;
        ensure!(
            line[end..token.start()].trim().is_empty(),
            "Unconsumed option text"
        );
        end = token.end();
        let key = &capture[1];
        let argument = capture
            .get(2)
            .map_or("", |value| value.as_str())
            .trim_matches('"');
        match key {
            "--new" => {
                ensure!(
                    argument.is_empty() && !current.is_empty(),
                    "Invalid or empty --new profile"
                );
                profiles.push(std::mem::take(&mut current));
            }
            key if key.starts_with("--wf-") => {
                ensure!(
                    profiles.is_empty() && filters.insert(key.to_owned()),
                    "Duplicate or misplaced global filter"
                );
                let expected = match key {
                    "--wf-tcp" => "80,443,2053,2083,2087,2096,8443,%GameFilterTCP%",
                    "--wf-udp" => "443,19294-19344,50000-50100,%GameFilterUDP%",
                    _ => bail!("Unsupported global filter {key}"),
                };
                ensure!(
                    argument == expected,
                    "Unsupported global capture ports {key}={argument}"
                );
            }
            _ => current.push((key.to_owned(), argument.to_owned())),
        }
    }
    ensure!(
        line[end..].trim().is_empty() && !current.is_empty(),
        "Unconsumed text or empty final profile"
    );
    ensure!(
        filters.len() == 2,
        "Both canonical global capture filters are required"
    );
    profiles.push(current);
    Ok(profiles)
}

pub(super) fn classify(profile: &Profile, warnings: &mut Vec<String>) -> Result<&'static str> {
    for key in [
        "--filter-tcp",
        "--filter-udp",
        "--filter-l7",
        "--hostlist-domains",
    ] {
        ensure!(
            profile.iter().filter(|(name, _)| name == key).count() <= 1,
            "Duplicate selector {key}"
        );
    }
    let tcp = value(profile, "--filter-tcp");
    let udp = value(profile, "--filter-udp");
    ensure!(
        tcp.is_none() || udp.is_none(),
        "Combined TCP/UDP profile is not representable"
    );
    let has = |text: &str| profile.iter().any(|(_, value)| value.contains(text));
    match (tcp, udp) {
        (_, Some("%GameFilterUDP%")) => return Ok("game_udp"),
        (Some("%GameFilterTCP%"), _) => return Ok("game_tcp"),
        (_, Some("19294-19344,50000-50100")) => return Ok("discord_udp"),
        (_, Some("443")) => {
            return Ok(if has("ipset-all") {
                "quic_ipset"
            } else {
                "quic"
            });
        }
        (None, None) if value(profile, "--filter-l7") == Some("quic") => {
            warnings.push(
                "EXP: L7-only QUIC перенесён в профиль UDP443; исходная область портов шире".into(),
            );
            return Ok(if has("ipset-all") {
                "quic_ipset"
            } else {
                "quic"
            });
        }
        (Some("2053,2083,2087,2096,8443"), _) => return Ok("discord_media"),
        (Some("443"), _) if has("list-google") => return Ok("google"),
        (Some("80,443"), _) if has("list-general") => return Ok("general"),
        (Some("80,443,8443"), _) if has("ipset-all") => return Ok("ipset_tcp"),
        (Some("80,443,2053,2083,2087,2096,8443"), _) if value(profile, "--hostlist").is_none() => {
            return Ok("all_tcp");
        }
        _ => {}
    }
    bail!("Unrepresentable profile port selectors")
}

pub(super) fn blob(value: &str) -> Result<String> {
    if value == "!" {
        return Ok("fake_default_tls".into());
    }
    if let Some(hex) = value.strip_prefix("0x") {
        ensure!(
            !hex.is_empty()
                && hex.len() % 2 == 0
                && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid inline blob"
        );
        return Ok(value.into());
    }
    let name = value
        .strip_prefix("%BIN%")
        .context("Blob must use its declared %BIN% path")?;
    let blob = match name {
        "quic_initial_www_google_com.bin" => "quic_google",
        "quic_initial_4pda_to.bin" => "quic_4pda",
        "stun.bin" => "stun_fs",
        "stun2.bin" => "stun2",
        "tls_clienthello_www_google_com.bin" => "tls_google",
        "tls_clienthello_4pda_to.bin" => "tls_4pda",
        "tls_clienthello_www_sferum_ru.bin" => "tls_sferum",
        "tls_clienthello_sochi_park.bin" => "tls_sochi",
        "ACTIVE_DISCORD_UDP.bin" => "discord_udp",
        "ACTIVE_GAME_UDP.bin" => "game_udp",
        _ => bail!("Unknown package blob {name}"),
    };
    Ok(blob.into())
}

#[derive(Default)]
pub(super) struct Options {
    pub modes: Vec<String>,
    pub repeats: String,
    pub fooling: Vec<String>,
    pub badseq: String,
    pub tls: Vec<(String, String)>,
    pub http: Vec<String>,
    pub unknown: Vec<String>,
    pub quic: Vec<String>,
    pub discord: Vec<String>,
    pub stun: Vec<String>,
    pub unknown_udp: Vec<String>,
    pub pos: String,
    pub seqovl: String,
    pub seqovl_pattern: String,
    pub fakedsplit_pattern: String,
    pub host: String,
    pub cutoff: String,
    pub any: bool,
    pub ip_id_zero: bool,
    pub default_tls_mod: String,
    pub l3: String,
    pub host_alt_order: bool,
}

pub(super) fn options(profile: &Profile, warnings: &mut Vec<String>) -> Result<Options> {
    let mut options = Options {
        badseq: "-10000".into(),
        ..Default::default()
    };
    let mut seen = HashSet::new();
    let mut tls_mod_seen = HashSet::new();
    for (key, argument) in profile {
        let key = key.as_str();
        let text = argument.as_str();
        let is_blob = matches!(
            key,
            "--dpi-desync-fake-tls"
                | "--dpi-desync-fake-http"
                | "--dpi-desync-fake-unknown"
                | "--dpi-desync-fake-quic"
                | "--dpi-desync-fake-discord"
                | "--dpi-desync-fake-stun"
                | "--dpi-desync-fake-unknown-udp"
        );
        if key.starts_with("--dpi-desync") && !is_blob && key != "--dpi-desync-fake-tls-mod" {
            ensure!(seen.insert(key), "Duplicate action option {key}");
        }
        ensure!(
            !(key.starts_with("--dpi-desync-fake-")
                && text == "!"
                && key != "--dpi-desync-fake-tls"),
            "Builtin ! blob is only supported for TLS"
        );
        match key {
            "--dpi-desync" => {
                ensure!(
                    matches!(
                        text,
                        "fake"
                            | "multisplit"
                            | "hostfakesplit"
                            | "syndata"
                            | "fake,fakedsplit"
                            | "fake,hostfakesplit"
                            | "fake,multidisorder"
                            | "fake,multisplit"
                            | "syndata,multidisorder"
                    ),
                    "Unsupported action sequence {text}"
                );
                options.modes = text.split(',').map(str::to_owned).collect();
            }
            "--dpi-desync-repeats" => options.repeats.clone_from(argument),
            "--dpi-desync-fooling" => {
                options.fooling = text.split(',').map(str::to_owned).collect()
            }
            "--dpi-desync-badseq-increment" => options.badseq.clone_from(argument),
            "--dpi-desync-fake-tls" => options.tls.push((blob(text)?, String::new())),
            "--dpi-desync-fake-tls-mod" => {
                ensure!(
                    tls_mod_seen.insert(options.tls.len()),
                    "Duplicate TLS modifier for the same fake"
                );
                validate_tls_mod(text)?;
                match options.tls.last_mut() {
                    Some((_, modifier)) if text != "none" => modifier.clone_from(argument),
                    Some(_) => {}
                    None => options.default_tls_mod.clone_from(argument),
                }
            }
            "--dpi-desync-fake-http" => options.http.push(blob(text)?),
            "--dpi-desync-fake-unknown" => options.unknown.push(blob(text)?),
            "--dpi-desync-fake-quic" => options.quic.push(blob(text)?),
            "--dpi-desync-fake-discord" => options.discord.push(blob(text)?),
            "--dpi-desync-fake-stun" => options.stun.push(blob(text)?),
            "--dpi-desync-fake-unknown-udp" => options.unknown_udp.push(blob(text)?),
            "--dpi-desync-split-pos" => options.pos.clone_from(argument),
            "--dpi-desync-split-seqovl" => options.seqovl.clone_from(argument),
            "--dpi-desync-split-seqovl-pattern" => options.seqovl_pattern = blob(text)?,
            "--dpi-desync-fakedsplit-pattern" => options.fakedsplit_pattern = blob(text)?,
            "--dpi-desync-hostfakesplit-mod" => {
                for part in text.split(',') {
                    match part {
                        "altorder=1" => options.host_alt_order = true,
                        "altorder=0" => options.host_alt_order = false,
                        _ => {
                            options.host = part
                                .strip_prefix("host=")
                                .context("Unsupported hostfakesplit modifier")?
                                .into()
                        }
                    }
                }
            }
            "--dpi-desync-cutoff" => options.cutoff.clone_from(argument),
            "--dpi-desync-any-protocol" => {
                ensure!(matches!(text, "0" | "1"), "Unsupported any-protocol value");
                options.any = text == "1";
            }
            "--ip-id" => {
                ensure!(text == "zero", "Unsupported --ip-id value");
                options.ip_id_zero = true;
            }
            "--filter-l3" => {
                ensure!(
                    matches!(text, "ipv4" | "ipv6")
                        && (options.l3.is_empty() || options.l3 == text),
                    "Unsupported or conflicting L3 filter"
                );
                options.l3.clone_from(argument);
            }
            "--filter-l7" => ensure!(
                matches!(text, "quic" | "discord,stun" | "discord,stun,unknown"),
                "Unsupported L7 filter"
            ),
            "--hostlist-domains" => ensure!(text == "discord.media", "Unsupported domain selector"),
            "--hostlist-exclude-domains" => {
                ensure!(
                    text == "fonts.googleapis.com",
                    "Unsupported domain exclusion"
                );
                warnings.push("EXP: исключение fonts.googleapis.com в IPSet-профиле не перенесено; область списков задаётся сборкой".into());
            }
            "--hostlist" | "--hostlist-exclude" | "--ipset" | "--ipset-exclude" => {
                validate_list(key, text)?
            }
            "--filter-udp" | "--filter-tcp" => {}
            _ => bail!("Unsupported option {key}={text}"),
        }
    }
    Ok(options)
}

fn validate_tls_mod(text: &str) -> Result<()> {
    if text == "none" {
        return Ok(());
    }
    for modifier in text.split(',') {
        if matches!(modifier, "rnd" | "rndsni" | "dupsid") {
            continue;
        }
        let sni = modifier
            .strip_prefix("sni=")
            .context("Unsupported TLS modifier")?;
        ensure!(
            !sni.is_empty()
                && sni
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "Invalid TLS SNI modifier"
        );
    }
    Ok(())
}

fn validate_list(key: &str, text: &str) -> Result<()> {
    let file = text
        .strip_prefix("%LISTS%")
        .context("List must use its declared %LISTS% path")?;
    let allowed = match key {
        "--hostlist" => matches!(
            file,
            "list-general.txt" | "list-general-user.txt" | "list-google.txt"
        ),
        "--hostlist-exclude" => matches!(file, "list-exclude.txt" | "list-exclude-user.txt"),
        "--ipset" => file == "ipset-all.txt",
        "--ipset-exclude" => matches!(file, "ipset-exclude.txt" | "ipset-exclude-user.txt"),
        _ => false,
    };
    ensure!(allowed, "Unsupported list condition {key}={text}");
    Ok(())
}
