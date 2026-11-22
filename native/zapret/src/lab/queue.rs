use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Block {
    Trial { name: String, lines: Vec<String> },
    Sleep { seconds: u64 },
}

pub(super) fn parse(path: &Path) -> Result<Vec<Block>> {
    let text = zapret_core::read_text(path, 1024 * 1024)?;
    parse_text(&text).with_context(|| format!("Очередь {}", path.display()))
}

fn parse_text(text: &str) -> Result<Vec<Block>> {
    let allowed = Regex::new(concat!(
        r"^(--payload=[a-z0-9_,]+|--out-range=[-A-Za-z0-9<>+.]+|--lua-desync=(",
        "fake|multisplit|multidisorder|fakedsplit|fakeddisorder|hostfakesplit|hostfakesplit_alt|",
        "tls_client_hello_clone|syndata|tcpseg|send|drop|oob|wsize|wssize|http_hostcase|",
        r"http_domcase|http_methodeol|http_unixeol|pktmod)(:[A-Za-z0-9_=,.+%-]*)*)$"
    ))?;
    let mut blocks = Vec::new();
    let mut current = None;
    for (index, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(seconds) = line
            .strip_prefix("@sleep")
            .filter(|tail| tail.starts_with(char::is_whitespace))
        {
            if let Some(block) = current.take() {
                blocks.push(block)
            }
            let seconds = seconds
                .trim()
                .parse::<u64>()
                .context("Неверная пауза @sleep")?;
            ensure!(seconds <= 86400, "Пауза @sleep превышает сутки");
            blocks.push(Block::Sleep { seconds });
        } else if let Some(name) = line.strip_prefix('@') {
            if let Some(block) = current.take() {
                blocks.push(block)
            }
            let name = name.trim();
            ensure!(
                !name.is_empty() && name.len() <= 1024 && !name.chars().any(char::is_control),
                "Некорректное имя варианта"
            );
            current = Some(Block::Trial {
                name: name.into(),
                lines: Vec::new(),
            });
        } else {
            ensure!(
                allowed.is_match(line),
                "Недопустимая строка {}: {}",
                index + 1,
                line
            );
            let Some(Block::Trial { lines, .. }) = current.as_mut() else {
                anyhow::bail!("Строка варианта вне блока @ на строке {}", index + 1)
            };
            ensure!(lines.len() < 512, "Слишком много строк варианта");
            lines.push(line.into());
        }
        ensure!(blocks.len() < 1024, "Слишком много блоков очереди");
    }
    if let Some(block) = current {
        blocks.push(block)
    }
    ensure!(!blocks.is_empty(), "Пустая очередь");
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_preserves_trials_and_interruptible_delays_and_rejects_incomplete_variants() {
        let blocks=parse_text("@ first\n--payload=tls_client_hello\n--lua-desync=fake:blob=tls_google\n@sleep 2\n@ baseline\n").unwrap();
        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0],Block::Trial{name,lines} if name=="first" && lines.len()==2));
        for text in [
            "@ unsafe\n--lua-init=@evil.lua",
            "@ partial\n--lua-desync=fake\ninvalid",
            "--payload=all",
            "@sleep -1",
            "@sleep 18446744073709551615",
            "@ bad\u{1b}name",
        ] {
            assert!(parse_text(text).is_err(), "{text}");
        }
    }
}
