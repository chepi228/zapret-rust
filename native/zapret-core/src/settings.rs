use crate::{atomic_write, read_text};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const DEFAULT_STRATEGY_ID: &str = "31";

const DEFAULTS: [(&str, &str); 10] = [
    ("alt", DEFAULT_STRATEGY_ID),
    ("auto", "on"),
    ("game", "all"),
    ("ipset", "loaded"),
    ("gametcp", "1024-65535"),
    ("gameudp", "1024-65535"),
    ("autolist", "on"),
    ("telegram", ""),
    ("notify", ""),
    ("gamepins", ""),
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub values: BTreeMap<String, String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            values: DEFAULTS
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        }
    }
}
impl Settings {
    pub fn get(&self, key: &str) -> &str {
        self.values
            .get(&key.to_ascii_lowercase())
            .or_else(|| {
                self.values
                    .iter()
                    .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
                    .map(|(_, value)| value)
            })
            .map(String::as_str)
            .unwrap_or("")
    }
    /// Check a user edit before changing any value. Unknown single-line INI keys survive.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let spelling = key;
        let key = key.to_ascii_lowercase();
        validate_record(&key, value)?;
        match key.as_str() {
            "alt" => ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "Strategy ID must be numeric"
            ),
            "auto" | "autolist" => ensure!(["on", "off"].contains(&value), "Expected on/off"),
            "telegram" | "notify" | "gamepins" => {
                ensure!(["on", "off", ""].contains(&value), "Expected on/off/empty")
            }
            "game" => ensure!(
                ["all", "tcp", "udp", "off", "selected"].contains(&value),
                "Unknown game mode"
            ),
            "gameapps" => {
                let apps = selected_game_names(value)?;
                self.insert_legacy("gameapps", &apps.join("|"));
                return Ok(());
            }
            "ipset" => ensure!(
                ["loaded", "any", "none"].contains(&value),
                "Unknown IPSet mode"
            ),
            "gametcp" | "gameudp" => ensure!(valid_port_list(value), "Invalid port list"),
            _ => {}
        }
        self.insert_legacy(spelling, value);
        Ok(())
    }
    fn insert_legacy(&mut self, key: &str, value: &str) {
        let spelling = self
            .values
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(key))
            .cloned()
            .unwrap_or_else(|| key.to_owned());
        self.values.insert(spelling, value.to_owned());
    }
    pub fn normalized(mut self) -> Self {
        for (key, default) in DEFAULTS {
            self.values
                .entry(key.to_owned())
                .or_insert_with(|| default.to_owned());
        }
        for (key, allowed, default) in [
            ("game", &["all", "tcp", "udp", "off", "selected"][..], "all"),
            ("ipset", &["loaded", "any", "none"][..], "loaded"),
            ("autolist", &["on", "off"][..], "on"),
            ("telegram", &["on", "off", ""][..], ""),
            ("notify", &["on", "off", ""][..], ""),
            ("gamepins", &["on", "off", ""][..], ""),
        ] {
            if !allowed
                .iter()
                .any(|v| v.eq_ignore_ascii_case(self.get(key)))
            {
                self.values.insert(key.to_owned(), default.to_owned());
            }
        }
        for key in ["gametcp", "gameudp"] {
            if !valid_port_list(self.get(key)) {
                self.values.insert(key.to_owned(), "1024-65535".to_owned());
            }
        }
        self
    }
}

/// Canonical executable stems. A vertical bar is not valid in a Windows filename.
pub fn selected_game_names(value: &str) -> Result<Vec<String>> {
    let mut names = std::collections::BTreeSet::new();
    if !value.trim().is_empty() {
        for item in value.split('|') {
            let lower = item.trim().to_lowercase();
            let name = lower.strip_suffix(".exe").unwrap_or(&lower);
            ensure!(
                !name.is_empty()
                    && name.encode_utf16().count() <= 251
                    && !name.ends_with(".exe")
                    && !name.ends_with([' ', '.'])
                    && !name.contains(['/', '\\', ':', '*', '?', '"', '<', '>'])
                    && !name.chars().any(char::is_control),
                "Укажите имя EXE игры без пути и маски"
            );
            names.insert(name.to_owned());
        }
    }
    ensure!(names.len() <= 32, "Можно выбрать до 32 игр");
    Ok(names.into_iter().collect())
}

pub fn game_server_list(name: &str) -> String {
    format!(
        "ipset-game-{}-user.txt",
        &crate::sha256(name.as_bytes())[..24]
    )
}
fn validate_record(key: &str, value: &str) -> Result<()> {
    ensure!(
        !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && key.as_bytes()[0].is_ascii_alphabetic(),
        "Invalid INI key"
    );
    ensure!(
        !value.contains(['\r', '\n', '\0']),
        "INI value must be a single line"
    );
    Ok(())
}
fn settings_path(root: &Path) -> PathBuf {
    if root
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("settings.ini"))
    {
        root.to_owned()
    } else {
        root.join("runtime/settings.ini")
    }
}
pub fn read_settings(root: &Path) -> Result<Settings> {
    let path = settings_path(root);
    let mut result = Settings::default();
    if !path.exists() {
        return Ok(result);
    }
    for raw in read_text(&path, 16 * 1024 * 1024)?.lines() {
        if let Some((key, value)) = raw.trim().split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if validate_record(key, value).is_ok() {
                result.insert_legacy(key, value);
            }
        }
    }
    Ok(result.normalized())
}
pub fn save_settings(root: &Path, settings: &Settings) -> Result<()> {
    let mut text = String::new();
    let mut entries: Vec<_> = settings.values.iter().collect();
    entries.sort_by(|(a, _), (b, _)| crate::io::legacy_compare(a, b));
    for (key, value) in entries {
        validate_record(key, value)?;
        text.push_str(&format!("{key}={value}\r\n"));
    }
    atomic_write(&settings_path(root), text.as_bytes())
}
pub fn valid_port_list(text: &str) -> bool {
    parse_port_list(text).is_some()
}
pub fn parse_port_list(text: &str) -> Option<Vec<(u16, u16)>> {
    text.split(',')
        .map(|part| {
            let (a, b) = part.split_once('-').unwrap_or((part, part));
            if a.is_empty()
                || b.is_empty()
                || a.len() > 5
                || b.len() > 5
                || !a.bytes().all(|v| v.is_ascii_digit())
                || !b.bytes().all(|v| v.is_ascii_digit())
            {
                return None;
            }
            let a = a.parse::<u16>().ok()?;
            let b = b.parse::<u16>().ok()?;
            (a >= 1 && a <= b).then_some((a, b))
        })
        .collect()
}
pub fn port_in_list(port: u16, text: &str) -> bool {
    parse_port_list(text)
        .is_some_and(|ranges| ranges.into_iter().any(|(a, b)| port >= a && port <= b))
}
