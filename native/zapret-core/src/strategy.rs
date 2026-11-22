use crate::{read_text, sha256_file};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const SECTIONS: [&str; 7] = [
    "quic",
    "discord_udp",
    "discord_media",
    "google",
    "general",
    "game_tcp",
    "game_udp",
];
pub const ROTATION_PREFERENCE: [&str; 9] = ["12", "11", "32", "31", "13", "10", "21", "22", "23"];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Strategy {
    pub id: String,
    pub name: String,
    pub desc: String,
    pub since: String,
    pub file: PathBuf,
    pub sections: BTreeMap<String, Vec<String>>,
    pub match_l3: BTreeMap<String, String>,
    pub missing: Vec<String>,
}
impl Strategy {
    /// Built-in display codes are keyed by both ID and the profile's recorded name.
    /// A custom profile with a different name keeps that name.
    pub fn display_name(&self) -> &str {
        match (self.id.as_str(), self.name.as_str()) {
            ("1", "ALT") => "MIX-SPLIT",
            ("2", "ALT2") => "SPLIT-B2",
            ("3", "ALT3") => "HOST-MIX",
            ("4", "ALT4") => "SEQ-SPLIT",
            ("5", "ALT5") => "SYN-DATA",
            ("6", "ALT6") => "SPLIT-B1",
            ("7", "ALT7") => "SPLIT-DUAL",
            ("8", "ALT8") => "FAKE-SEQ",
            ("9", "ALT9") => "HOST-ONLY",
            ("10", "ALT10") => "TIME-ONLY",
            ("11", "ALT11") => "CORE-STUN2",
            ("12", "ALT12") => "CORE-STUN",
            ("13", "ALT13") => "HOST-STUN2",
            ("21", "BV1") => "Z2-BASE",
            ("22", "BV2") => "Z2-GENERAL",
            ("23", "BV3") => "Z2-YT",
            ("31", "ALT11 мягкая") => "SOFT-STUN2",
            ("32", "ALT12 мягкая") => "SOFT-STUN",
            ("40", "GENERAL") => "FS-BASE",
            ("41", "EXP") => "FS-EXP",
            ("42", "SIMPLE FAKE") => "TLS-ONLY",
            ("43", "SIMPLE FAKE ALT") => "TLS-S2-SEQ",
            ("44", "SIMPLE FAKE ALT2") => "TLS-S2-TIME",
            ("45", "FAKE TLS AUTO") => "TLS-REV",
            ("46", "FAKE TLS AUTO ALT") => "TLS-MIX",
            ("47", "FAKE TLS AUTO ALT2") => "TLS-SEQ",
            ("48", "FAKE TLS AUTO ALT3") => "TLS-TIME",
            ("50", "ALT11 белый 1") => "WHITE-01",
            ("51", "ALT11 белый 2") => "WHITE-02",
            ("52", "ALT11 белый 3") => "WHITE-03",
            ("53", "IPFRAG") => "IP-FRAG",
            ("54", "DISORDER") => "SPLIT-REV",
            ("55", "AUTOTTL") => "AUTO-TTL",
            ("56", "BADSUM") => "TCP-SUM",
            ("57", "ALT11 белый 1+3") => "WHITE-01-03",
            ("58", "ALT11 белый 4 лёгкая") => "WHITE-04-LITE",
            ("59", "ALT11 белый 5") => "WHITE-05",
            ("60", "ALT11 белый 6") => "WHITE-06",
            ("61", "ALT11 белый 1 везде") => "WHITE-01-PLUS",
            ("70", "ALT11 без STUN") => "SOFT-NO-STUN",
            ("71", "ALT11 STUN вторым") => "SOFT-STUN-2ND",
            _ => &self.name,
        }
    }

    pub fn section(&self, name: &str, fallback: &str) -> &[String] {
        self.sections
            .get(name)
            .or_else(|| self.sections.get(fallback))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
    pub fn section_family(&self, name: &str, fallback: &str) -> &str {
        let actual = if self.sections.contains_key(name) {
            name
        } else {
            fallback
        };
        self.match_l3
            .get(actual)
            .map(String::as_str)
            .unwrap_or("any")
    }
    pub fn fingerprint(&self) -> Result<String> {
        sha256_file(&self.file)
    }
    pub fn is_valid(&self) -> bool {
        self.missing.is_empty()
    }
}
pub fn parse_strategy(path: &Path) -> Result<Strategy> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid strategy filename")?;
    let folded_stem = stem.to_ascii_lowercase();
    let id = folded_stem
        .strip_prefix("alt")
        .context("Strategy filename must start with alt")?;
    ensure!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "Invalid strategy ID"
    );
    let mut result = Strategy {
        id: id.to_owned(),
        name: format!("ALT{id}"),
        file: path.to_owned(),
        ..Default::default()
    };
    let mut current = String::new();
    let mut invalid = Vec::new();
    for raw in read_text(path, 1024 * 1024)?.lines() {
        let t = raw.trim();
        if let Some(comment) = t.strip_prefix('#') {
            if let Some((key, value)) = comment.trim_start().split_once(':') {
                let value = value.trim();
                match key.to_ascii_lowercase().as_str() {
                    "name" if !value.is_empty() => result.name = value.to_owned(),
                    "desc" if !value.is_empty() => result.desc = value.to_owned(),
                    "since" if !value.is_empty() => result.since = value.to_owned(),
                    "match-l3" => {
                        let family = value.to_ascii_lowercase();
                        if current.is_empty()
                            || !["ipv4", "ipv6"].contains(&family.as_str())
                            || result.match_l3.contains_key(&current)
                        {
                            invalid.push("некорректный match-l3".to_owned());
                        } else {
                            result.match_l3.insert(current.clone(), family);
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if let Some(section) = t
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_'))
        {
            current = section.to_ascii_lowercase();
            result.sections.insert(current.clone(), Vec::new());
            continue;
        }
        if let Some(lines) = result.sections.get_mut(&current) {
            lines.push(t.to_owned());
        }
    }
    result.missing = SECTIONS
        .iter()
        .filter(|s| !result.sections.contains_key(**s))
        .map(|s| s.to_string())
        .chain(invalid)
        .collect();
    Ok(result)
}
pub fn list_strategies(root: &Path) -> Result<Vec<Strategy>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root.join("strategies"))? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let folded_name = name.to_ascii_lowercase();
        let Some(id) = folded_name
            .strip_prefix("alt")
            .and_then(|v| v.strip_suffix(".txt"))
        else {
            continue;
        };
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        result.push(parse_strategy(&path)?);
    }
    result.sort_by(|a, b| {
        a.id.parse::<u64>()
            .unwrap_or(u64::MAX)
            .cmp(&b.id.parse::<u64>().unwrap_or(u64::MAX))
            .then(a.id.cmp(&b.id))
    });
    Ok(result)
}

/// Read the selected profile without opening unrelated strategy files.
pub fn find_strategy(root: &Path, id: &str) -> Result<Option<Strategy>> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let name = format!("alt{id}.txt");
    for entry in fs::read_dir(root.join("strategies"))? {
        let entry = entry?;
        if entry.file_name().eq_ignore_ascii_case(&name) {
            return parse_strategy(&entry.path()).map(Some);
        }
    }
    Ok(None)
}

/// Resolve a display code or the name recorded in the profile.
pub fn strategy_index_by_name(strategies: &[Strategy], name: &str) -> Result<Option<usize>> {
    let name = name.trim().to_lowercase();
    let mut matches = strategies.iter().enumerate().filter(|(_, strategy)| {
        strategy.is_valid()
            && (strategy.name.to_lowercase() == name
                || strategy.display_name().to_lowercase() == name)
    });
    let first = matches.next();
    ensure!(
        matches.next().is_none(),
        "Имя стратегии неоднозначно. Укажите номер."
    );
    Ok(first.map(|(index, _)| index))
}

pub fn ordered_strategies(strategies: &[Strategy]) -> Vec<Strategy> {
    let mut all: Vec<_> = strategies
        .iter()
        .filter(|s| s.is_valid())
        .cloned()
        .collect();
    all.sort_by_key(|s| {
        ROTATION_PREFERENCE
            .iter()
            .position(|id| *id == s.id)
            .unwrap_or(usize::MAX)
    });
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn bundled_codes_are_unique_and_resolve_with_the_recorded_names() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let strategies = list_strategies(&root)?;
        let retired = crate::list_lines(&root.join("strategies/retired.txt"))?;
        let mut codes = BTreeSet::new();
        assert_eq!(strategies.len(), 36);
        for (index, strategy) in strategies.iter().enumerate() {
            assert!(!retired.contains(&format!("alt{}.txt", strategy.id)));
            let code = strategy.display_name();
            assert_ne!(code, strategy.name);
            assert!(code.len() <= 16);
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            );
            assert!(!code.contains("MAX") && !code.contains("GOSUSLUGI"));
            assert!(codes.insert(code));
            assert_eq!(
                strategy_index_by_name(&strategies, &code.to_lowercase())?,
                Some(index)
            );
            assert_eq!(
                strategy_index_by_name(&strategies, &strategy.name.to_lowercase())?,
                Some(index)
            );
        }
        Ok(())
    }

    #[test]
    fn custom_labels_are_preserved_and_ambiguous_names_are_rejected() {
        let bundled = Strategy {
            id: "12".into(),
            name: "ALT12".into(),
            ..Strategy::default()
        };
        let renamed = Strategy {
            name: "My profile".into(),
            ..bundled.clone()
        };
        assert_eq!(renamed.display_name(), "My profile");
        let duplicate = Strategy {
            id: "99".into(),
            name: "CORE-STUN".into(),
            ..Strategy::default()
        };
        assert!(strategy_index_by_name(&[bundled, duplicate], "core-stun").is_err());
    }
}
