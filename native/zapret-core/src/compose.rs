use crate::{
    Coverage, Settings, Strategy, TestRank, capture_exclusion,
    context::{InputHashes, rank_context, ring_key},
    find_strategy, list_strategies,
    ranking::{read_rank_cover, read_rank_for_network, rotation_order_refs},
    read_text, sha256, valid_port_list,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const DISCORD_TCP: &str = "2053,2083,2087,2096,8443";
const DISCORD_UDP: &str = "19294-19344,50000-50100";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ComposeOptions {
    pub alt: Option<String>,
    pub no_auto: bool,
    pub ipset_mode: Option<String>,
    pub dry_run: bool,
    pub debug_file: Option<PathBuf>,
    pub persistence: bool,
    pub network_key: Option<String>,
    pub native_identity: Option<String>,
}
impl Default for ComposeOptions {
    fn default() -> Self {
        Self {
            alt: None,
            no_auto: false,
            ipset_mode: None,
            dry_run: false,
            debug_file: None,
            persistence: true,
            network_key: None,
            native_identity: None,
        }
    }
}

pub fn ring_state_name<'a>(
    section: &str,
    ring: impl IntoIterator<Item = &'a Strategy>,
    composition_key: &str,
) -> Result<String> {
    state_name(section, ring, composition_key, &mut InputHashes::live())
}
fn state_name<'a>(
    section: &str,
    ring: impl IntoIterator<Item = &'a Strategy>,
    composition_key: &str,
    hashes: &mut InputHashes<'_>,
) -> Result<String> {
    ensure!(
        crate::io::hex(composition_key, 64),
        "Unconfirmed rotation composition"
    );
    ensure!(
        !section.is_empty()
            && section
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "Invalid ring section"
    );
    let mut parts = Vec::new();
    for s in ring {
        parts.push(format!("{}:{}:{}", s.id, s.name, hashes.get(&s.file)?));
    }
    let hash = sha256(format!("{composition_key}|{}", parts.join(",")).as_bytes());
    Ok(format!(
        "ring-{section}-{}-{}.txt",
        composition_key[..24].to_ascii_lowercase(),
        hash[..24].to_ascii_lowercase()
    ))
}

struct Composer<'a> {
    root: &'a Path,
    options: &'a ComposeOptions,
    strategies: &'a [Strategy],
    primary: &'a Strategy,
    auto: bool,
    builtin: bool,
    rank: Option<TestRank>,
    cover: Option<Coverage>,
    composition_key: String,
    hashes: InputHashes<'a>,
    args: Vec<String>,
    first: bool,
    templates: BTreeMap<String, String>,
}
impl<'a> Composer<'a> {
    fn path(&self, rel: &str) -> String {
        self.root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))
            .to_string_lossy()
            .into_owned()
    }
    fn paths(&self, option: &str, paths: &[&str]) -> Vec<String> {
        paths
            .iter()
            .map(|p| format!("{option}{}", self.path(p)))
            .collect()
    }
    fn ring(&self, section: &str, circular: bool) -> Vec<&'a Strategy> {
        if circular && self.auto {
            let mut order = rotation_order_refs(
                self.strategies,
                &self.primary.id,
                section,
                self.rank.as_ref(),
                self.cover.as_ref(),
            );
            if section == "game_tcp" {
                order.retain(|s| !s.skips_game_section(section));
            }
            order
        } else {
            vec![self.primary]
        }
    }
    fn profile_raw(&mut self, name: &str, filters: &[String]) {
        self.args.push(format!(
            "--{}={name}",
            if self.first { "name" } else { "new" }
        ));
        self.first = false;
        self.args.extend_from_slice(filters);
    }
    /// A family restriction is materialized on each profile; incompatible actions never share a template.
    fn profile(
        &mut self,
        name: &str,
        filters: Vec<String>,
        section: Option<(&str, bool, bool, &str)>,
    ) -> Result<()> {
        if !self.templates.is_empty() && filters.iter().any(|f| f == "--import=tpl_general") {
            for family in ["ipv4", "ipv6"] {
                if let Some(template) = self.templates.get(family) {
                    let mut f: Vec<_> = filters
                        .iter()
                        .filter(|f| f.as_str() != "--import=tpl_general")
                        .cloned()
                        .collect();
                    f.push(format!("--filter-l3={family}"));
                    f.push(format!("--import={template}"));
                    self.profile_raw(&format!("{name}_{family}"), &f);
                }
            }
            return Ok(());
        }
        if let Some((section, circular, learn, fallback)) = section {
            let ring = self.ring(section, circular);
            if ring
                .iter()
                .any(|s| s.section_family(section, fallback) != "any")
            {
                for family in ["ipv4", "ipv6"] {
                    if ring
                        .iter()
                        .any(|s| ["any", family].contains(&s.section_family(section, fallback)))
                    {
                        let mut f = filters.clone();
                        f.push(format!("--filter-l3={family}"));
                        self.profile_raw(&format!("{name}_{family}"), &f);
                        self.section(section, &ring, learn, fallback, family)?;
                    }
                }
            } else {
                self.profile_raw(name, &filters);
                self.section(section, &ring, learn, fallback, "")?;
            }
        } else {
            self.profile_raw(name, &filters);
        }
        Ok(())
    }
    fn section(
        &mut self,
        name: &str,
        order: &[&Strategy],
        learn: bool,
        fallback: &str,
        family: &str,
    ) -> Result<()> {
        let mut ring: Vec<_> = order
            .iter()
            .copied()
            .filter(|s| {
                family.is_empty() || ["any", family].contains(&s.section_family(name, fallback))
            })
            .collect();
        if self.builtin
            && ring.len() > 1
            && ring
                .iter()
                .all(|s| repeatable_builtin_section(s.section(name, fallback)))
        {
            let mut seen = BTreeSet::new();
            ring.retain(|s| seen.insert(s.section(name, fallback)));
        }
        if ring.is_empty() {
            return Ok(());
        }
        if learn {
            self.args.extend(
                [
                    "--payload=all",
                    "--out-range=x",
                    "--in-range=a",
                    "--lua-desync=rst_guard",
                    "--in-range=x",
                    "--out-range=a",
                ]
                .map(str::to_owned),
            );
        }
        if ring.len() >= 2 {
            self.args.extend(
                ["--payload=all", "--out-range=-s34228", "--in-range=-s5556"].map(str::to_owned),
            );
            let reset = if name == "game_tcp" { "" } else { ":reset" };
            let memory_name = if family.is_empty() {
                name.to_owned()
            } else {
                format!("{name}_{family}")
            };
            let state = if learn && self.options.persistence {
                format!(
                    ":context=network-context.txt:state={}",
                    state_name(
                        &memory_name,
                        ring.iter().copied(),
                        &self.composition_key,
                        &mut self.hashes
                    )?
                )
            } else {
                String::new()
            };
            let memory = if learn {
                format!(
                    ":key={memory_name}{state}:hostcache=bounded:link_guard=link-guard.txt:success_detector=ring_success:failure_detector=ring_failure"
                )
            } else {
                String::new()
            };
            self.args.push(format!(
                "--lua-desync=circular:fails=3:time=60:nld=2{reset}{memory}"
            ));
            self.args.push("--in-range=x".into());
            for (index, strategy) in ring.iter().enumerate() {
                for line in strategy.section(name, fallback) {
                    self.args.push(if line.starts_with("--lua-desync=") {
                        format!("{line}:strategy={}", index + 1)
                    } else {
                        line.clone()
                    });
                }
                if learn {
                    self.args.extend([
                        "--payload=all".into(),
                        "--out-range=-d10".into(),
                        format!("--lua-desync=rst_mark:strategy={}", index + 1),
                    ]);
                }
            }
        } else {
            self.args.extend_from_slice(ring[0].section(name, fallback));
            if learn {
                self.args.extend(
                    ["--payload=all", "--out-range=-d10", "--lua-desync=rst_mark"]
                        .map(str::to_owned),
                );
            }
        }
        Ok(())
    }
}

// Custom Lua, hooks and options with per-slot state must retain their original slots.
fn repeatable_builtin_section(lines: &[String]) -> bool {
    lines.iter().all(|line| {
        let Some((option, value)) = line.split_once('=') else {
            return false;
        };
        match option {
            "--payload" | "--in-range" | "--out-range" => true,
            "--lua-desync" => {
                let mut fields = value.split(':');
                matches!(
                    fields.next(),
                    Some(
                        "fake"
                            | "multisplit"
                            | "multidisorder"
                            | "hostfakesplit"
                            | "hostfakesplit_alt"
                            | "fakedsplit"
                            | "fakeddisorder"
                            | "syndata"
                    )
                ) && fields.all(|field| {
                    matches!(
                        field.split('=').next(),
                        Some(
                            "blob"
                                | "fool"
                                | "host"
                                | "ip_id"
                                | "ip_autottl"
                                | "ip6_autottl"
                                | "payload"
                                | "pos"
                                | "repeats"
                                | "seqovl"
                                | "seqovl_pattern"
                                | "tcp_md5"
                                | "tcp_ts"
                                | "tcp_ts_up"
                                | "tls_mod"
                        )
                    )
                })
            }
            _ => false,
        }
    })
}

/// Compose engine arguments without writing runtime state or starting any process.
pub fn compose(root: &Path, settings: &Settings, options: &ComposeOptions) -> Result<Vec<String>> {
    compose_from_inputs(root, settings, options, InputHashes::live())
}

/// Use SHA-256 values from the launcher's open, write-denying file handles.
/// Keys are full package paths. The caller keeps those handles until launch completes.
pub fn compose_with_pinned_hashes(
    root: &Path,
    settings: &Settings,
    options: &ComposeOptions,
    pinned: &BTreeMap<PathBuf, &str>,
) -> Result<Vec<String>> {
    compose_from_inputs(root, settings, options, InputHashes::Pinned(pinned))
}

fn compose_from_inputs(
    root: &Path,
    settings: &Settings,
    options: &ComposeOptions,
    mut hashes: InputHashes<'_>,
) -> Result<Vec<String>> {
    let auto = settings.get("auto").eq_ignore_ascii_case("on") && !options.no_auto;
    let alt = options
        .alt
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(settings.get("alt"));
    let strategies = if auto {
        list_strategies(root)?
    } else {
        find_strategy(root, alt)?.into_iter().collect()
    };
    let primary = strategies
        .iter()
        .find(|s| s.id == alt)
        .with_context(|| format!("Стратегия ALT{alt} не найдена"))?;
    ensure!(
        primary.is_valid(),
        "В {} нет секций: {}",
        primary.file.display(),
        primary.missing.join(", ")
    );
    let mode_raw = options
        .ipset_mode
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(settings.get("ipset"));
    let mode_owned = mode_raw.to_ascii_lowercase();
    let mode = mode_owned.as_str();
    ensure!(
        ["loaded", "any", "none"].contains(&mode),
        "Unknown IPSet mode"
    );
    ensure!(
        valid_port_list(settings.get("gametcp")) && valid_port_list(settings.get("gameudp")),
        "Invalid game port list"
    );
    let composition_key = if auto && options.persistence {
        let mut composition_settings = settings.clone();
        composition_settings.values.insert("alt".into(), alt.into());
        composition_settings
            .values
            .insert("ipset".into(), mode_raw.into());
        ring_key(
            root,
            &composition_settings,
            options.native_identity.as_deref(),
            &mut hashes,
        )?
    } else {
        String::new()
    };
    let rank = if let Some(key) = options.network_key.as_deref().filter(|_| auto) {
        read_rank_for_network(root, key, &strategies, || {
            rank_context(
                root,
                settings,
                key,
                options.native_identity.as_deref(),
                &mut hashes,
            )
            .ok()
        })?
    } else {
        None
    };
    let cover = match rank.as_ref().and_then(|r| r.context.as_ref()) {
        Some(context) => read_rank_cover(root, context)?,
        None => None,
    };
    let builtin = crate::uses_builtin_rules(root);
    let mut c = Composer {
        root,
        options,
        strategies: &strategies,
        primary,
        auto,
        builtin,
        rank,
        cover,
        composition_key,
        hashes,
        args: Vec::new(),
        first: true,
        templates: BTreeMap::new(),
    };
    if options.dry_run {
        c.args.push("--dry-run".into());
    }
    if let Some(file) = &options.debug_file {
        c.args.push(format!("--debug=@{}", file.display()));
    }
    let autolist = settings.get("autolist").eq_ignore_ascii_case("on");
    let game = settings.get("game").to_ascii_lowercase();
    let selected = game == "selected";
    let game_protocols = c.primary.game_protocols(&game);
    if autolist {
        c.args.push(format!(
            "--hostlist-auto-debug={}",
            c.path("runtime/autohostlist-debug.log")
        ));
    }
    let web_tcp = format!("80,443,{DISCORD_TCP}");
    for (protocol, ports, extra) in [
        (
            "tcp",
            web_tcp.as_str(),
            game_protocols.tcp.then(|| settings.get("gametcp")),
        ),
        (
            "udp",
            DISCORD_UDP,
            game_protocols.udp.then(|| settings.get("gameudp")),
        ),
    ] {
        let ports = match extra {
            Some(extra) if builtin => crate::capture::merged_ports(ports, extra)?,
            Some(extra) => format!("{ports},{extra}"),
            None => ports.to_owned(),
        };
        c.args.push(format!("--wf-{protocol}-out={ports}"));
    }
    let quic = "windivert/quic_initial_ietf.txt";
    if builtin {
        // Both QUIC profiles match UDP/443. Voice and game ports have independent selectors.
        let predicate = read_text(&root.join(quic), 65535)?;
        let predicate = predicate
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        c.args
            .push(format!("--wf-raw-part=udp.DstPort==443 and ({predicate})"));
    } else {
        c.args.push(format!("--wf-raw-part=@{}", c.path(quic)));
    }
    let capture = read_text(&root.join("lists/ipset-taketwo.txt"), 8192)
        .ok()
        .and_then(|text| capture_exclusion(&text.lines().map(str::to_owned).collect::<Vec<_>>()));
    if let Some(capture) = &capture {
        c.args.push(format!("--wf-raw-filter={}", capture.filter));
    }
    if builtin {
        c.args.push("--builtin-rules".into());
    } else {
        c.args
            .extend(c.paths("--lua-init=@", &crate::BUNDLED_LUA_FILES));
    }
    if auto {
        c.args
            .push(format!("--writable={}", c.path("runtime/ring")));
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
        c.args.push(format!(
            "--blob={name}:@{}",
            c.path(&format!("fake/{file}"))
        ));
    }
    let hostlists = c.paths(
        "--hostlist=",
        &["lists/list-general.txt", "lists/list-general-user.txt"],
    );
    let host_ex = c.paths(
        "--hostlist-exclude=",
        &["lists/list-exclude.txt", "lists/list-exclude-user.txt"],
    );
    let ip_games = vec![
        capture
            .map(|capture| capture.ip_argument)
            .unwrap_or_else(|| format!("--ipset-exclude={}", c.path("lists/ipset-taketwo.txt"))),
    ];
    let mut ip_ex = c.paths(
        "--ipset-exclude=",
        &["lists/ipset-exclude.txt", "lists/ipset-exclude-user.txt"],
    );
    ip_ex.extend(ip_games.clone());
    let mut ips = Vec::new();
    match mode {
        "loaded" => ips.push(format!("--ipset={}", c.path("lists/ipset-all.txt"))),
        "any" => ips.push(format!("--ipset={}", c.path("runtime/ipset-any.txt"))),
        _ => {}
    }
    ips.push(format!("--ipset={}", c.path("lists/ipset-user.txt")));
    let game_ips = if selected {
        // An empty file means "any address" to the engine. Keep a fixed,
        // non-routable include even before the first observed game connection.
        let mut selected_ips = vec!["--ipset-ip=203.0.113.113/32".to_owned()];
        for name in crate::selected_game_names(settings.get("gameapps"))? {
            let path = format!("lists/{}", crate::game_server_list(&name));
            if root.join(&path).is_file() {
                selected_ips.push(format!("--ipset={}", c.path(&path)));
            }
        }
        // The web and QUIC profiles also service game logins and content on 443.
        ips.extend(selected_ips.iter().skip(1).cloned());
        selected_ips
    } else {
        ips.clone()
    };
    let general_ring = c.ring("general", true);
    if general_ring
        .iter()
        .any(|s| s.section_family("general", "") != "any")
    {
        for family in ["ipv4", "ipv6"] {
            if general_ring
                .iter()
                .any(|s| ["any", family].contains(&s.section_family("general", "")))
            {
                let template = format!("tpl_general_{family}");
                c.templates.insert(family.into(), template.clone());
                c.args.push(format!("--template={template}"));
                c.section("general", &general_ring, true, "", family)?;
                c.args.push("--new".into());
            }
        }
    } else {
        c.args.push("--template=tpl_general".into());
        c.section("general", &general_ring, true, "", "")?;
        c.args.push("--new".into());
    }
    let filters = |initial: Vec<String>, sets: &[&Vec<String>]| -> Vec<String> {
        let mut all = initial;
        for set in sets {
            all.extend((*set).clone());
        }
        all
    };
    c.profile(
        "quic_list",
        filters(
            vec!["--filter-udp=443".into(), "--filter-l7=quic".into()],
            &[&hostlists, &host_ex, &ip_ex],
        ),
        Some(("quic", false, false, "")),
    )?;
    c.profile(
        "discord_voice",
        filters(
            vec![
                format!("--filter-udp={DISCORD_UDP}"),
                "--filter-l7=discord,stun".into(),
            ],
            &[&ip_games],
        ),
        Some(("discord_udp", false, false, "")),
    )?;
    c.profile(
        "discord_media",
        filters(
            vec![
                format!("--filter-tcp={DISCORD_TCP}"),
                "--hostlist-domains=discord.media".into(),
            ],
            &[&ip_games],
        ),
        Some(("discord_media", true, true, "")),
    )?;
    c.profile(
        "google",
        filters(
            vec![
                "--filter-tcp=443".into(),
                format!("--hostlist={}", c.path("lists/list-google.txt")),
            ],
            &[&ip_games],
        ),
        Some(("google", true, true, "")),
    )?;
    let mut f = filters(
        vec!["--filter-tcp=80,443".into()],
        &[&hostlists, &host_ex, &ip_ex],
    );
    f.push("--import=tpl_general".into());
    c.profile("general", f, None)?;
    c.profile(
        "quic_ipset",
        filters(
            vec!["--filter-udp=443".into(), "--filter-l7=quic".into()],
            &[&ips, &host_ex, &ip_ex],
        ),
        Some(("quic", false, false, "")),
    )?;
    let mut f = filters(
        vec!["--filter-tcp=80,443,8443".into()],
        &[&ips, &host_ex, &ip_ex],
    );
    if c.ring("ipset_tcp", true)
        .iter()
        .any(|s| s.sections.contains_key("ipset_tcp"))
    {
        c.profile("tcp_ipset", f, Some(("ipset_tcp", true, true, "general")))?;
    } else {
        f.push("--import=tpl_general".into());
        c.profile("tcp_ipset", f, None)?;
    }
    if autolist {
        let mut f = filters(
            vec![
                "--filter-tcp=80,443".into(),
                "--filter-l7=tls,http".into(),
                format!("--hostlist-auto={}", c.path("lists/autohostlist.txt")),
            ],
            &[&host_ex, &ip_ex],
        );
        f.push("--import=tpl_general".into());
        c.profile("autolist", f, None)?;
    }
    if game_protocols.tcp {
        c.profile(
            "game_tcp",
            filters(
                vec![format!("--filter-tcp={}", settings.get("gametcp"))],
                &[&game_ips, &ip_ex],
            ),
            Some(("game_tcp", true, false, "")),
        )?;
    }
    if game_protocols.udp {
        c.profile(
            "game_udp",
            filters(
                vec![format!("--filter-udp={}", settings.get("gameudp"))],
                &[&game_ips, &ip_ex],
            ),
            Some(("game_udp", false, false, "")),
        )?;
    }
    if options.dry_run {
        c.args.push("--wf-dup-check=0".into());
    }
    Ok(c.args)
}

pub fn windows_argument(arg: &str) -> String {
    let mut quoted = String::from("\"");
    let mut slashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.push_str(&"\\".repeat(2 * slashes + 1));
            quoted.push('"');
        } else {
            quoted.push_str(&"\\".repeat(slashes));
            quoted.push(ch);
        }
        slashes = 0;
    }
    quoted.push_str(&"\\".repeat(2 * slashes));
    quoted.push('"');
    quoted
}
pub fn windows_command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| windows_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn compact_arguments(root: &Path, args: &[String]) -> Vec<String> {
    let prefix = format!("{}{}", root.display(), std::path::MAIN_SEPARATOR);
    let pattern=regex::Regex::new(r"^(--(?:lua-init=@|blob=[A-Za-z_][A-Za-z_0-9]*:@|hostlist(?:-exclude|-auto|-auto-debug)?=|ipset(?:-exclude)?=|debug=@))(.+)$").expect("constant regex");
    let mut result = vec![format!("--chdir={}", root.display())];
    for arg in args {
        if let Some(c) = pattern.captures(arg) {
            let path = &c[2];
            if path
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
            {
                result.push(format!(
                    "{}{}",
                    &c[1],
                    path[prefix.len()..].replace('\\', "/")
                ));
                continue;
            }
        }
        result.push(arg.clone());
    }
    result
}
pub fn checked_command_line(root: &Path, args: &[String]) -> Result<Vec<String>> {
    let mut args = args.to_vec();
    if windows_command_line(&args).encode_utf16().count() > 30000 {
        args = compact_arguments(root, &args);
    }
    ensure!(
        windows_command_line(&args).encode_utf16().count() <= 32000,
        "Командная строка winws2 слишком длинная; перенесите папку в короткий путь"
    );
    Ok(args)
}
