mod definitions;
mod parse;
mod render;
mod validate;

use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fmt::Write, fs, path::Path};

type Sections = BTreeMap<String, Vec<String>>;
const ORDER: [&str; 8] = [
    "quic",
    "discord_udp",
    "discord_media",
    "google",
    "general",
    "ipset_tcp",
    "game_tcp",
    "game_udp",
];

struct Definition {
    id: &'static str,
    name: &'static str,
    source: &'static str,
    description: &'static str,
    managed: bool,
}

struct Converted {
    sections: Sections,
    warnings: Vec<String>,
}

fn convert(text: &str) -> Result<Converted> {
    let mut sections = BTreeMap::new();
    let mut warnings = Vec::new();
    for (index, profile) in parse::profiles(text)?.iter().enumerate() {
        convert_profile(profile, &mut sections, &mut warnings)
            .with_context(|| format!("Profile {}", index + 1))?;
    }
    if sections.get("ipset_tcp") == sections.get("general") {
        sections.remove("ipset_tcp");
    }
    Ok(Converted { sections, warnings })
}

fn convert_profile(
    profile: &parse::Profile,
    sections: &mut Sections,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let kind = parse::classify(profile, warnings)?;
    let options = parse::options(profile, warnings)?;
    validate::selectors(profile, kind)?;
    validate::actions(profile, &options, kind)?;
    if let Some(l7) = parse::value(profile, "--filter-l7") {
        let allowed: &[&str] = match kind {
            "discord_udp" => &["discord,stun", "discord,stun,unknown"],
            "quic" | "quic_ipset" => &["quic"],
            _ => &[],
        };
        ensure!(
            allowed.contains(&l7),
            "L7 condition is incompatible with {kind}"
        );
    }
    if kind == "all_tcp" {
        for section in ["discord_media", "google", "general", "ipset_tcp"] {
            ensure!(
                !sections.contains_key(section),
                "Duplicate section {section}"
            );
            let lines = with_family(render::tcp(&options, section, warnings)?, &options.l3);
            sections.insert(section.into(), lines);
        }
        return Ok(());
    }
    let lines = if matches!(kind, "quic" | "quic_ipset" | "discord_udp" | "game_udp") {
        ensure!(
            options.l3.is_empty(),
            "L3 condition for UDP is not representable by the current section format"
        );
        render::udp(&options, kind, warnings)?
    } else {
        render::tcp(&options, kind, warnings)?
    };
    let lines = with_family(lines, &options.l3);
    if kind == "quic_ipset" {
        ensure!(
            sections.get("quic").is_none_or(|current| *current == lines),
            "QUIC ipset and hostlist actions differ"
        );
        sections.entry("quic".into()).or_insert(lines);
    } else {
        ensure!(!sections.contains_key(kind), "Duplicate section {kind}");
        sections.insert(kind.into(), lines);
    }
    Ok(())
}

fn with_family(mut lines: Vec<String>, family: &str) -> Vec<String> {
    if !family.is_empty() {
        lines.insert(0, format!("# match-l3: {family}"));
    }
    lines
}

fn render_strategy(converted: &Converted, definition: &Definition) -> Result<String> {
    let mut text = format!(
        "# name: {}\n# desc: {}\n# flowseal: {} (перенесено конвертером из 1.10.4)\n",
        definition.name, definition.description, definition.source
    );
    for warning in &converted.warnings {
        writeln!(text, "# compatibility: {warning}")?;
    }
    for section in ORDER {
        match converted.sections.get(section) {
            Some(lines) => {
                writeln!(text, "[{section}]")?;
                for line in lines {
                    writeln!(text, "{line}")?;
                }
            }
            None => ensure!(
                section == "ipset_tcp",
                "{}: missing section {section}",
                definition.name
            ),
        }
    }
    Ok(text)
}

fn read_sections(text: &str) -> Result<Sections> {
    let mut sections = Sections::new();
    let mut current = String::new();
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let line = raw.trim();
        if line.starts_with("# match-l3:") && !current.is_empty() {
            sections
                .get_mut(&current)
                .context("Missing section")?
                .push(line.into());
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            ensure!(
                ORDER.contains(&section) && !sections.contains_key(section),
                "Unknown or duplicate section {section}"
            );
            current = section.into();
            sections.insert(current.clone(), Vec::new());
        } else {
            sections
                .get_mut(&current)
                .context("Action outside a section")?
                .push(line.into());
        }
    }
    Ok(sections)
}

pub(super) fn run(
    source: &Path,
    output: &Path,
    check: bool,
    allow_differences: bool,
) -> Result<()> {
    // Parse every declared source before writing any strategy.
    let prepared: Vec<_> = definitions::DEFINITIONS
        .iter()
        .map(|definition| {
            let path = source.join(definition.source);
            let bytes = zapret_core::read_bounded(&path, 1024 * 1024)?;
            let text = std::str::from_utf8(&bytes).context("Flowseal source must be UTF-8")?;
            let converted = convert(text).with_context(|| format!("Convert {}", path.display()))?;
            ensure!(
                allow_differences || converted.warnings.is_empty(),
                "{}: known differences require --allow-known-differences: {}",
                definition.source,
                converted.warnings.join("; ")
            );
            let rendered = render_strategy(&converted, definition)?;
            Ok((definition, converted, rendered))
        })
        .collect::<Result<_>>()?;
    // Empty export directories still support every upstream profile.
    let retired = zapret_core::list_lines(&output.join("retired.txt"))?;
    let prepared = prepared.into_iter().filter(|(definition, _, _)| {
        let name = format!("alt{}.txt", definition.id);
        !retired
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&name))
    });
    if check {
        let mut different = false;
        for (definition, converted, _) in prepared {
            let path = output.join(format!("alt{}.txt", definition.id));
            let bytes = zapret_core::read_bounded(&path, 1024 * 1024)?;
            let current = read_sections(std::str::from_utf8(&bytes)?)?;
            let changed: Vec<_> = ORDER
                .iter()
                .copied()
                .filter(|section| converted.sections.get(*section) != current.get(*section))
                .collect();
            different |= !changed.is_empty();
            let result = if changed.is_empty() {
                "ok".into()
            } else {
                format!("DIFF {}", changed.join(","))
            };
            println!("{}: {result}", definition.name);
        }
        ensure!(
            !different,
            "Converted profiles differ from the current strategy files"
        );
    } else {
        fs::create_dir_all(output)?;
        for (definition, _, text) in prepared.filter(|(definition, _, _)| definition.managed) {
            let path = output.join(format!("alt{}.txt", definition.id));
            zapret_core::atomic_write(&path, text.as_bytes())?;
            println!("alt{}.txt {}: ok", definition.id, definition.name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
