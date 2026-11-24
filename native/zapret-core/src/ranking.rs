use crate::{
    ROTATION_PREFERENCE, Settings, Strategy, TestResultContext, atomic_write, ordered_strategies,
    read_text, result_header,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::Path,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RankRow {
    pub id: String,
    pub score: f64,
    pub ok: f64,
    pub total: usize,
    pub harm: usize,
    pub freeze: usize,
    pub groups: BTreeMap<String, f64>,
    #[serde(default)]
    pub group_totals: BTreeMap<String, usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TestRank {
    pub date: Option<String>,
    pub version: String,
    pub base_ok: f64,
    pub base_total: usize,
    pub base_groups: BTreeMap<String, f64>,
    pub base_group_totals: BTreeMap<String, usize>,
    pub rows: Vec<RankRow>,
    pub context: Option<TestResultContext>,
}
pub type Coverage = BTreeMap<String, Vec<String>>;
pub const NEAR_BEST_SCORE_MARGIN: f64 = 1.;
fn groups(parts: &[&str]) -> (BTreeMap<String, f64>, BTreeMap<String, usize>) {
    let mut scores = BTreeMap::new();
    let mut totals = BTreeMap::new();
    for part in parts {
        if let Some((name, counts)) = part.split_once('=') {
            if let Some((ok, total)) = counts.split_once('/') {
                if let (Ok(ok), Ok(total)) = (ok.parse::<f64>(), total.parse::<usize>()) {
                    if ok.is_finite() && ok >= 0.0 {
                        scores.insert(name.to_owned(), ok);
                        totals.insert(name.to_owned(), total);
                    }
                }
            }
        }
    }
    (scores, totals)
}
/// Parse historical v1 and v2 data. Parsing alone does not make a rank trusted.
pub fn parse_rank(text: &str, exists: &[String]) -> Result<Option<TestRank>> {
    parse_rank_rows(text, exists, result_header(text))
}
fn parse_rank_rows(
    text: &str,
    exists: &[String],
    context: Option<TestResultContext>,
) -> Result<Option<TestRank>> {
    let mut rank = TestRank {
        date: None,
        version: "1.5".into(),
        base_ok: 0.,
        base_total: 0,
        base_groups: BTreeMap::new(),
        base_group_totals: BTreeMap::new(),
        rows: Vec::new(),
        context,
    };
    let mut base = false;
    for line in text.trim_start_matches('\u{feff}').lines() {
        if let Some(value) = line.strip_prefix("# date:") {
            rank.date = Some(value.trim().into());
            continue;
        }
        if let Some(value) = line.strip_prefix("# version:") {
            rank.version = value.trim().into();
            continue;
        }
        let p: Vec<_> = line.split_whitespace().collect();
        if p.len() >= 3 && p[0] == "base" {
            if let (Ok(ok), Ok(total)) = (p[1].parse::<f64>(), p[2].parse::<usize>()) {
                if ok.is_finite() {
                    rank.base_ok = ok;
                    rank.base_total = total;
                    (rank.base_groups, rank.base_group_totals) = groups(&p[3..]);
                    base = true;
                }
            }
        } else if p.len() >= 6
            && p[0].bytes().all(|b| b.is_ascii_digit())
            && exists.iter().any(|id| id == p[0])
        {
            if let (Ok(score), Ok(ok), Ok(total), Ok(harm), Ok(freeze)) = (
                p[1].parse::<f64>(),
                p[2].parse::<f64>(),
                p[3].parse::<usize>(),
                p[4].parse::<usize>(),
                p[5].parse::<usize>(),
            ) {
                if score.is_finite() && ok.is_finite() {
                    let (groups, group_totals) = groups(&p[6..]);
                    rank.rows.push(RankRow {
                        id: p[0].into(),
                        score,
                        ok,
                        total,
                        harm,
                        freeze,
                        groups,
                        group_totals,
                    });
                }
            }
        }
    }
    Ok((base && !rank.rows.is_empty()).then_some(rank))
}
pub fn read_rank(
    root: &Path,
    context: Option<&TestResultContext>,
    strategies: &[Strategy],
) -> Result<Option<TestRank>> {
    let Some(context) = context else {
        return Ok(None);
    };
    read_rank_for_network(root, &context.network_key, strategies, || {
        Some(context.clone())
    })
}

pub(crate) fn read_rank_for_network(
    root: &Path,
    network_key: &str,
    strategies: &[Strategy],
    current: impl FnOnce() -> Option<TestResultContext>,
) -> Result<Option<TestRank>> {
    let path = root.join("runtime/test-rank.txt");
    if !path.exists() {
        return Ok(None);
    }
    let text = match read_text(&path, 16 * 1024 * 1024) {
        Ok(text) => text,
        // Without a verifiable current context even an unreadable rank is unused.
        Err(error) => {
            return if current().is_some() {
                Err(error)
            } else {
                Ok(None)
            };
        }
    };
    let Some(saved) = result_header(&text) else {
        return Ok(None);
    };
    if saved.network_key != network_key || !current().is_some_and(|ctx| saved.compatible(&ctx)) {
        return Ok(None);
    }
    let ids = strategies.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
    parse_rank_rows(&text, &ids, Some(saved))
}
pub fn parse_cover(text: &str) -> Coverage {
    text.trim_start_matches('\u{feff}')
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut p = line.split('\t');
            let id = p.next().unwrap_or("").to_owned();
            (
                id,
                p.filter(|v| !v.starts_with('?'))
                    .map(str::to_owned)
                    .collect(),
            )
        })
        .collect()
}
pub fn read_cover(
    root: &Path,
    rank: &TestRank,
    context: &TestResultContext,
) -> Result<Option<Coverage>> {
    let Some(rank_context) = &rank.context else {
        return Ok(None);
    };
    if !rank_context.compatible(context) {
        return Ok(None);
    }
    read_rank_cover(root, rank_context)
}
pub(crate) fn read_rank_cover(
    root: &Path,
    rank_context: &TestResultContext,
) -> Result<Option<Coverage>> {
    let path = root.join("runtime/test-cover.txt");
    if !path.exists() {
        return Ok(None);
    }
    let text = read_text(&path, 16 * 1024 * 1024)?;
    let Some(saved) = result_header(&text) else {
        return Ok(None);
    };
    if !saved.compatible(rank_context) || saved.run_id != rank_context.run_id {
        return Ok(None);
    }
    Ok(Some(parse_cover(&text)))
}
fn publish(root: &Path, file: &str, lines: &[String], context: &TestResultContext) -> Result<()> {
    ensure!(context.valid(), "Unknown network/configuration context");
    let path = root.join("runtime").join(file);
    let backup = path.with_file_name(format!("{file}.v1.bak"));
    if path.exists()
        && !backup.exists()
        && result_header(&read_text(&path, 16 * 1024 * 1024)?).is_none()
    {
        fs::copy(&path, &backup)?;
    }
    let text = format!(
        "# context: {}\r\n{}\r\n",
        serde_json::to_string(context)?,
        lines.join("\r\n")
    );
    atomic_write(&path, text.as_bytes())
}
fn format_groups(groups: &BTreeMap<String, f64>, totals: &BTreeMap<String, usize>) -> String {
    groups
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}/{total}",
                format_points(*value),
                total = totals.get(key).copied().unwrap_or(0)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn format_points(x: f64) -> String {
    let value = format!("{x:.1}");
    value.strip_suffix(".0").unwrap_or(&value).to_owned()
}
pub fn save_rank(root: &Path, rank: &TestRank) -> Result<()> {
    let context = rank
        .context
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Cannot publish unscoped historical rank"))?;
    ensure!(
        rank.base_ok.is_finite()
            && rank.rows.iter().all(|r| r.score.is_finite()
                && r.ok.is_finite()
                && r.groups.values().all(|v| v.is_finite())),
        "Invalid rank points"
    );
    let mut lines = vec![
        "# Рейтинг стратегий по автоподбору".into(),
        format!("# date: {}", rank.date.as_deref().unwrap_or("")),
        format!("# version: {}", rank.version),
        format!(
            "base {} {} {}",
            format_points(rank.base_ok),
            rank.base_total,
            format_groups(&rank.base_groups, &rank.base_group_totals)
        ),
    ];
    for r in &rank.rows {
        lines.push(format!(
            "{} {} {} {} {} {} {}",
            r.id,
            format_points(r.score),
            format_points(r.ok),
            r.total,
            r.harm,
            r.freeze,
            format_groups(&r.groups, &r.group_totals)
        ));
    }
    publish(root, "test-rank.txt", &lines, context)
}
pub fn save_cover(root: &Path, cover: &Coverage, context: &TestResultContext) -> Result<()> {
    let mut lines = vec!["# Какие адреса открыла каждая стратегия в последнем автоподборе".into()];
    for (id, values) in cover {
        ensure!(
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
            "Invalid coverage strategy ID"
        );
        let values: BTreeSet<_> = values.iter().collect();
        ensure!(
            values.iter().all(|v| !v.contains(['\r', '\n', '\t'])),
            "Invalid coverage key"
        );
        lines.push(
            std::iter::once(id.as_str())
                .chain(values.into_iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("\t"),
        );
    }
    publish(root, "test-cover.txt", &lines, context)
}
#[cfg(test)]
#[test]
fn foreign_rank_skips_input_hashing_and_local_rank_requires_the_exact_inputs() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("runtime")).unwrap();
    let context = TestResultContext {
        schema: 2,
        network_key: "A".repeat(64),
        inputs_hash: "B".repeat(64),
        run_id: "1".repeat(32),
    };
    fs::write(
        temp.path().join("runtime/test-rank.txt"),
        format!(
            "# context: {}\nbase 1 2\n31 2 2 2 0 0\n",
            serde_json::to_string(&context).unwrap()
        ),
    )
    .unwrap();
    let strategies = [Strategy {
        id: "31".into(),
        ..Default::default()
    }];
    assert!(
        read_rank_for_network(temp.path(), &"C".repeat(64), &strategies, || {
            panic!("a different network must not hash package inputs")
        })
        .unwrap()
        .is_none()
    );
    let mut changed = context.clone();
    changed.inputs_hash = "D".repeat(64);
    assert!(
        read_rank(temp.path(), Some(&changed), &strategies)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        read_rank(temp.path(), Some(&context), &strategies)
            .unwrap()
            .unwrap()
            .rows[0]
            .id,
        "31"
    );
}

fn group_for_section(section: &str) -> Option<&'static str> {
    match section {
        "google" => Some("YouTube"),
        "discord_media" => Some("Discord"),
        _ => None,
    }
}
pub fn ring_by_cover(
    ids: &[String],
    section: &str,
    primary_id: &str,
    rank: &TestRank,
    cover: Option<&Coverage>,
) -> Vec<String> {
    let Some(cover) = cover.filter(|c| c.contains_key("0")) else {
        return ids.to_vec();
    };
    let Some(first) = ids
        .iter()
        .find(|id| id.as_str() == primary_id)
        .or(ids.first())
    else {
        return Vec::new();
    };
    let mut done: HashSet<_> = cover
        .get("0")
        .into_iter()
        .flatten()
        .chain(cover.get(first).into_iter().flatten())
        .cloned()
        .collect();
    let mut ring = vec![first.clone()];
    let mut candidates: Vec<_> = rank.rows.iter().collect();
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.freeze.cmp(&b.freeze)));
    let mine = |id: &String| -> Vec<String> {
        cover
            .get(id)
            .into_iter()
            .flatten()
            .filter(|key| {
                let group = key.split_once('|').map_or("", |(g, _)| g);
                group_for_section(section)
                    .map_or(!["YouTube", "Discord"].contains(&group), |want| {
                        group.eq_ignore_ascii_case(want)
                    })
            })
            .cloned()
            .collect()
    };
    while ring.len() < 5 {
        let mut best = None;
        let mut gain = 0;
        for row in &candidates {
            if ring.contains(&row.id) {
                continue;
            }
            let n = mine(&row.id)
                .iter()
                .filter(|key| !done.contains(*key))
                .count();
            if n > gain {
                best = Some(row.id.clone());
                gain = n;
            }
        }
        let Some(best) = best else {
            break;
        };
        done.extend(mine(&best));
        ring.push(best);
    }
    for id in ids {
        if ring.len() >= 5 {
            break;
        }
        if !ring.contains(id) {
            ring.push(id.clone());
        }
    }
    ring
}
pub fn section_rank(
    rank: &TestRank,
    section: &str,
    primary_id: &str,
    cover: Option<&Coverage>,
) -> Option<Vec<String>> {
    let group = group_for_section(section);
    if group.is_some_and(|g| !rank.base_groups.contains_key(g)) {
        return None;
    }
    let score = |r: &RankRow| -> f64 {
        group.map_or(r.score - rank.base_ok, |g| {
            r.groups.get(g).copied().unwrap_or(0.) - rank.base_groups[g]
        })
    };
    let best = rank
        .rows
        .iter()
        .map(score)
        .fold(f64::NEG_INFINITY, f64::max);
    if best <= 0. {
        return None;
    }
    let mut rows: Vec<_> = rank
        .rows
        .iter()
        .filter(|r| score(r) >= 0.6 * best)
        .collect();
    rows.sort_by(|a, b| {
        score(b)
            .total_cmp(&score(a))
            .then(b.score.total_cmp(&a.score))
            .then(a.freeze.cmp(&b.freeze))
    });
    let ids: Vec<_> = rows.into_iter().take(5).map(|r| r.id.clone()).collect();
    Some(ring_by_cover(&ids, section, primary_id, rank, cover))
}
pub fn rotation_order(
    strategies: &[Strategy],
    primary_id: &str,
    section: &str,
    rank: Option<&TestRank>,
    cover: Option<&Coverage>,
) -> Vec<Strategy> {
    rotation_order_refs(strategies, primary_id, section, rank, cover)
        .into_iter()
        .cloned()
        .collect()
}
pub(crate) fn rotation_order_refs<'a>(
    strategies: &'a [Strategy],
    primary_id: &str,
    section: &str,
    rank: Option<&TestRank>,
    cover: Option<&Coverage>,
) -> Vec<&'a Strategy> {
    let all: Vec<_> = strategies.iter().filter(|s| s.is_valid()).collect();
    if section != "game_tcp" {
        if let Some(rank) = rank {
            if let Some(ids) = section_rank(rank, section, primary_id, cover)
                .or_else(|| section_rank(rank, "general", primary_id, cover))
            {
                let mut order = Vec::new();
                let near_leader = rank
                    .rows
                    .iter()
                    .find(|row| row.id == primary_id)
                    .is_some_and(|selected| {
                        selected.score
                            >= rank
                                .rows
                                .iter()
                                .map(|row| row.score)
                                .fold(f64::NEG_INFINITY, f64::max)
                                - NEAR_BEST_SCORE_MARGIN
                            && selected.harm == 0
                            && selected.freeze == 0
                            && group_for_section(section).is_none_or(|group| {
                                selected.groups.get(group).copied().unwrap_or(0.)
                                    >= rank
                                        .rows
                                        .iter()
                                        .map(|row| row.groups.get(group).copied().unwrap_or(0.))
                                        .fold(0., f64::max)
                            })
                    });
                if ids.iter().any(|id| id == primary_id) || near_leader {
                    order.extend(all.iter().filter(|s| s.id == primary_id).copied());
                }
                for id in ids {
                    if order.len() >= 5 {
                        break;
                    }
                    order.extend(
                        all.iter()
                            .filter(|s| s.id == id && id != primary_id)
                            .copied(),
                    );
                }
                if !order.is_empty() {
                    return order;
                }
            }
        }
    }
    let mut order: Vec<_> = all.iter().filter(|s| s.id == primary_id).copied().collect();
    for id in ROTATION_PREFERENCE {
        if id != primary_id {
            order.extend(all.iter().filter(|s| s.id == id).copied());
        }
    }
    order
}
pub fn test_strategy_ids(
    root: &Path,
    settings: &Settings,
    strategies: &[Strategy],
    rank: Option<&TestRank>,
    cover: Option<&Coverage>,
    full: bool,
) -> Result<Vec<Strategy>> {
    let all = ordered_strategies(strategies);
    if full {
        return Ok(all);
    }
    let tested = crate::list_lines(&root.join("runtime/tested-strategies.txt"))?;
    let mut ids: HashSet<String> = ROTATION_PREFERENCE
        .into_iter()
        .chain(["41", "42"])
        .map(str::to_owned)
        .collect();
    ids.insert(settings.get("alt").to_owned());
    for s in &all {
        let is_tested = if tested.is_empty() {
            rank.is_some_and(|r| r.rows.iter().any(|r| r.id == s.id))
        } else {
            tested
                .iter()
                .any(|line| *line == format!("{}|{}", s.id, s.name))
        };
        if !s.since.is_empty() && (rank.is_none() || !is_tested) {
            ids.insert(s.id.clone());
        }
    }
    for section in ["general", "google", "discord_media", "game_tcp"] {
        for s in rotation_order_refs(&all, settings.get("alt"), section, rank, cover) {
            ids.insert(s.id.clone());
        }
    }
    let (mut preferred, others): (Vec<_>, Vec<_>) =
        all.into_iter().partition(|s| ids.contains(&s.id));
    preferred.extend(others);
    Ok(preferred)
}
