use crate::{
    Coverage, Settings, Strategy, TestRank, capture_exclusion, find_strategy, list_strategies,
    read_cover, read_rank, read_text, ring_composition_key, rotation_order, sha256,
    test_result_context, valid_port_list,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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

pub fn ring_state_name(section: &str, ring: &[Strategy], composition_key: &str) -> Result<String> {
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
        parts.push(format!("{}:{}:{}", s.id, s.name, s.fingerprint()?));
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
    strategies: Vec<Strategy>,
    primary: Strategy,
    auto: bool,
    rank: Option<TestRank>,
    cover: Option<Coverage>,
    composition_key: String,
    args: Vec<String>,
    first: bool,
    templates: BTreeMap<String, String>,
}
impl Composer<'_> {
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
    fn ring(&self, section: &str, circular: bool) -> Vec<Strategy> {
        if circular && self.auto {
            rotation_order(
                &self.strategies,
                &self.primary.id,
                section,
                self.rank.as_ref(),
                self.cover.as_ref(),
            )
        } else {
            vec![self.primary.clone()]
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
                        self.section(section, circular, learn, fallback, family)?;
                    }
                }
            } else {
                self.profile_raw(name, &filters);
                self.section(section, circular, learn, fallback, "")?;
            }
        } else {
            self.profile_raw(name, &filters);
        }
        Ok(())
    }
    fn section(
        &mut self,
        name: &str,
        circular: bool,
        learn: bool,
        fallback: &str,
        family: &str,
    ) -> Result<()> {
        let ring: Vec<_> = self
            .ring(name, circular)
            .into_iter()
            .filter(|s| {
                family.is_empty() || ["any", family].contains(&s.section_family(name, fallback))
            })
            .collect();
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
                    ring_state_name(&memory_name, &ring, &self.composition_key)?
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

/// Compose engine arguments without writing runtime state or starting any process.
pub fn compose(root: &Path, settings: &Settings, options: &ComposeOptions) -> Result<Vec<String>> {
    let auto = settings.get("auto").eq_ignore_ascii_case("on") && !options.no_auto;
    let alt = options
        .alt
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(settings.get("alt"));
    let (strategies, primary) = if auto {
        let strategies = list_strategies(root)?;
        let primary = strategies.iter().find(|s| s.id == alt).cloned();
        (strategies, primary)
    } else {
        (Vec::new(), find_strategy(root, alt)?)
    };
    let primary = primary.with_context(|| format!("Стратегия ALT{alt} не найдена"))?;
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
        if let Some(identity) = options.native_identity.as_deref() {
            crate::ring_composition_key_with_identity(root, &composition_settings, identity)?
        } else {
            ring_composition_key(root, &composition_settings)?
        }
    } else {
        String::new()
    };
    let context = if auto && root.join("runtime/test-rank.txt").exists() {
        options.network_key.as_deref().and_then(|key| {
            if let Some(identity) = options.native_identity.as_deref() {
                crate::test_result_context_with_identity(root, settings, key, identity).ok()
            } else {
                test_result_context(root, settings, key).ok()
            }
        })
    } else {
        None
    };
    let rank = if auto {
        read_rank(root, context.as_ref(), &strategies)?
    } else {
        None
    };
    let cover = match (&rank, &context) {
        (Some(rank), Some(context)) => read_cover(root, rank, context)?,
        _ => None,
    };
    let mut c = Composer {
        root,
        options,
        strategies,
        primary,
        auto,
        rank,
        cover,
        composition_key,
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
    let game_tcp = selected || ["all", "tcp"].contains(&game.as_str());
    let game_udp = selected || ["all", "udp"].contains(&game.as_str());
    if autolist {
        c.args.push(format!(
            "--hostlist-auto-debug={}",
            c.path("runtime/autohostlist-debug.log")
        ));
    }
    c.args.push(format!(
        "--wf-tcp-out=80,443,{DISCORD_TCP}{}",
        if game_tcp {
            format!(",{}", settings.get("gametcp"))
        } else {
            String::new()
        }
    ));
    c.args.push(format!(
        "--wf-udp-out={DISCORD_UDP}{}",
        if game_udp {
            format!(",{}", settings.get("gameudp"))
        } else {
            String::new()
        }
    ));
    c.args.push(format!(
        "--wf-raw-part=@{}",
        c.path("windivert/quic_initial_ietf.txt")
    ));
    let capture = read_text(&root.join("lists/ipset-taketwo.txt"), 8192)
        .ok()
        .and_then(|text| capture_exclusion(&text.lines().map(str::to_owned).collect::<Vec<_>>()));
    if let Some(capture) = &capture {
        c.args.push(format!("--wf-raw-filter={}", capture.filter));
    }
    if crate::uses_builtin_rules(root) {
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
                c.section("general", true, true, "", family)?;
                c.args.push("--new".into());
            }
        }
    } else {
        c.args.push("--template=tpl_general".into());
        c.section("general", true, true, "", "")?;
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
    if game_tcp {
        c.profile(
            "game_tcp",
            filters(
                vec![format!("--filter-tcp={}", settings.get("gametcp"))],
                &[&game_ips, &ip_ex],
            ),
            Some(("game_tcp", true, false, "")),
        )?;
    }
    if game_udp {
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
