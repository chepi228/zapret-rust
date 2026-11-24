use crate::storage::{atomic_write, hash, no_reparse, read_limited};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
};
const BEGIN: &str = "# zapret: hosts Flowseal - начало (меню: Проверка обходов)";
const END: &str = "# zapret: hosts Flowseal - конец";
pub const DISCORD_MEDIA_HOST: &str = "media.discordapp.net";
pub const DISCORD_MEDIA_GROUP: &str = "Медиа Discord";
const GROUPS: [&str; 4] = ["GitHub", "Telegram", "Discord", DISCORD_MEDIA_GROUP];
fn group(host: &str) -> Option<&'static str> {
    let h = host.to_lowercase();
    if h == DISCORD_MEDIA_HOST {
        return Some(DISCORD_MEDIA_GROUP);
    }
    for (kind, domains) in [
        ("GitHub", &["github.com", "githubusercontent.com"][..]),
        (
            "Telegram",
            &[
                "telegram.org",
                "telegram.me",
                "telegram.dog",
                "telegram.space",
                "t.me",
                "telesco.pe",
                "tg.dev",
            ][..],
        ),
        ("Discord", &["discord.com"][..]),
    ] {
        if domains
            .iter()
            .any(|d| h == *d || h.ends_with(&format!(".{d}")))
        {
            return Some(kind);
        }
    }
    None
}
pub(crate) fn entries(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let fields = line
            .split('#')
            .next()
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.len() < 2 || fields[0].parse::<IpAddr>().is_err() {
            continue;
        }
        for h in &fields[1..] {
            if h.len() <= 253
                && h.is_ascii()
                && h.chars()
                    .all(|x| x.is_ascii_alphanumeric() || x == '.' || x == '-')
            {
                out.push((fields[0].into(), h.to_lowercase()));
            }
        }
    }
    out
}

pub fn reference_entries(text: &str) -> Vec<(String, String)> {
    let mut rows = entries(text);
    // Use just the IPv4 peer the diagnostic will check with the media hostname,
    // SNI and a complete file. Prefer a dedicated entry in a refreshed list.
    let media_ip = [DISCORD_MEDIA_HOST, "discord.com"].iter().find_map(|host| {
        rows.iter()
            .find(|(ip, name)| name == host && ip.parse::<std::net::Ipv4Addr>().is_ok())
            .map(|(ip, _)| ip.clone())
    });
    rows.retain(|(_, host)| host != DISCORD_MEDIA_HOST);
    if let Some(ip) = media_ip {
        rows.push((ip, DISCORD_MEDIA_HOST.into()));
    }
    rows
}
fn system_hosts() -> Result<PathBuf> {
    Ok(crate::system::system_directory()?.join("drivers/etc/hosts"))
}
pub(crate) fn path(root: &Path, args: &Value) -> Result<PathBuf> {
    let default = system_hosts()?;
    let p = args["path"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or(default.clone());
    ensure!(
        !p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "Hosts fixture cannot traverse parent directories"
    );
    ensure!(
        p == default || p.starts_with(root),
        "Hosts fixture must remain within the selected package"
    );
    no_reparse(&p)?;
    Ok(p)
}
pub(crate) fn status(root: &Path, args: &Value) -> Result<Value> {
    let p = path(root, args)?;
    let b = read_limited(&p, 8 * 1024 * 1024)?;
    let text = std::str::from_utf8(&b)?;
    let current = entries(text);
    let expected =
        std::fs::read_to_string(root.join("lists/hosts-flowseal.txt")).unwrap_or_default();
    let expected = reference_entries(&expected);
    let mut rows = Vec::new();
    for g in GROUPS {
        let active = current
            .iter()
            .filter(|(_, h)| group(h) == Some(g))
            .collect::<Vec<_>>();
        let stale = active
            .iter()
            .filter(|(ip, h)| !expected.iter().any(|(i, n)| i == ip && n == h))
            .count();
        let unique = active.iter().map(|(_, h)| h).collect::<BTreeSet<_>>();
        rows.push(json!({"group":g,"entries":active.len(),"stale":stale,"duplicates":active.len()-unique.len(),"available":expected.iter().filter(|(_,h)|group(h)==Some(g)).count()}));
    }
    Ok(json!({"path":p,"hash":hash(&b),"groups":rows}))
}
pub(crate) fn set(root: &Path, args: &Value) -> Result<Value> {
    let groups = args["groups"]
        .as_array()
        .context("groups must be an array")?
        .iter()
        .map(|g| {
            let s = g.as_str().context("Hosts group must be a string")?;
            ensure!(GROUPS.contains(&s), "Unknown hosts group: {s}");
            Ok(s.to_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let p = path(root, args)?;
    let old = read_limited(&p, 8 * 1024 * 1024)?;
    let text = std::str::from_utf8(&old)?;
    let bom = text.starts_with('\u{feff}');
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines = Vec::new();
    let mut in_block = false;
    let mut user_media = false;
    for line in text.trim_start_matches('\u{feff}').lines() {
        if [
            BEGIN,
            "# NBA2K27-zapret2: hosts Flowseal - начало (пункт H меню)",
            "# zapret: hosts Flowseal - начало (меню, пункт 4)",
        ]
        .contains(&line)
        {
            ensure!(!in_block, "Nested hosts block");
            in_block = true;
            continue;
        }
        if [END, "# NBA2K27-zapret2: hosts Flowseal - конец"].contains(&line) {
            ensure!(in_block, "Unmatched hosts block end");
            in_block = false;
            continue;
        }
        if in_block {
            continue;
        }
        let names = entries(line);
        if names.iter().any(|(_, h)| h == DISCORD_MEDIA_HOST) {
            user_media = true;
        } else if !names.is_empty() && names.iter().all(|(_, h)| group(h).is_some()) {
            continue;
        }
        lines.push(line.to_owned());
    }
    ensure!(
        !in_block,
        "Unclosed hosts block; refusing to discard unrelated lines"
    );
    while lines.last().is_some_and(|s| s.trim().is_empty()) {
        lines.pop();
    }
    let reference = read_limited(&root.join("lists/hosts-flowseal.txt"), 8 * 1024 * 1024)?;
    let reference = reference_entries(std::str::from_utf8(&reference)?);
    for name in &groups {
        ensure!(
            reference
                .iter()
                .any(|(_, h)| group(h) == Some(name.as_str())),
            "Hosts reference has no validated entries for {name}"
        );
    }
    let add = reference
        .into_iter()
        .filter(|(_, h)| h != DISCORD_MEDIA_HOST || !user_media)
        .filter(|(_, h)| group(h).is_some_and(|g| groups.contains(g)))
        .collect::<Vec<_>>();
    if !add.is_empty() {
        lines.push(String::new());
        lines.push(BEGIN.into());
        for (ip, h) in add {
            lines.push(format!("{ip} {h}"));
        }
        lines.push(END.into());
    }
    let mut output = if bom {
        "\u{feff}".into()
    } else {
        String::new()
    };
    output.push_str(&lines.join(nl));
    output.push_str(nl);
    let backup = root.join(format!(
        "runtime/hosts-{}-{}.bak",
        crate::time_filetime(),
        std::process::id()
    ));
    atomic_write(&backup, &old)?;
    ensure!(
        read_limited(&p, 8 * 1024 * 1024)? == old,
        "Hosts changed during staging; replacement cancelled"
    );
    atomic_write(&p, output.as_bytes())?;
    let flush = args["flush_dns"]
        .as_bool()
        .unwrap_or(p == system_hosts()?)
        .then(crate::dns_cache::flush);
    Ok(json!({"updated":true,"path":p,"backup":backup,"groups":groups,"flush_dns":flush}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applying_and_removing_the_media_pin_preserves_an_external_override() {
        let root = tempfile::tempdir().unwrap();
        let hosts = root.path().join("hosts");
        std::fs::create_dir_all(root.path().join("lists")).unwrap();
        std::fs::create_dir_all(root.path().join("runtime")).unwrap();
        std::fs::write(
            root.path().join("lists/hosts-flowseal.txt"),
            "192.0.2.1 discord.com\n",
        )
        .unwrap();
        let manual = "192.0.2.44 media.discordapp.net\n127.0.0.1 localhost\n";
        std::fs::write(&hosts, manual).unwrap();
        for groups in [json!([DISCORD_MEDIA_GROUP]), json!([])] {
            set(
                root.path(),
                &json!({"path":hosts,"groups":groups,"flush_dns":false}),
            )
            .unwrap();
            assert_eq!(std::fs::read_to_string(&hosts).unwrap(), manual);
        }
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        set(
            root.path(),
            &json!({"path":hosts,"groups":[DISCORD_MEDIA_GROUP],"flush_dns":false}),
        )
        .unwrap();
        let installed = std::fs::read_to_string(&hosts).unwrap();
        assert!(installed.contains(&format!("{BEGIN}\n192.0.2.1 {DISCORD_MEDIA_HOST}\n{END}")));
    }

    #[test]
    fn media_candidates_follow_the_reference_and_never_expand_to_other_hosts() {
        let base = "192.0.2.1 discord.com\n192.0.2.2 updates.discord.com\n";
        let media = |text: &str| {
            reference_entries(text)
                .into_iter()
                .filter(|(_, h)| group(h) == Some(DISCORD_MEDIA_GROUP))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            media(base),
            vec![("192.0.2.1".into(), DISCORD_MEDIA_HOST.into())]
        );
        let dedicated =
            format!("{base}192.0.2.3 {DISCORD_MEDIA_HOST}\n192.0.2.4 {DISCORD_MEDIA_HOST}");
        assert_eq!(
            media(&dedicated),
            vec![("192.0.2.3".into(), DISCORD_MEDIA_HOST.into())]
        );
        assert!(media("192.0.2.1 other.example").is_empty());
    }
}
