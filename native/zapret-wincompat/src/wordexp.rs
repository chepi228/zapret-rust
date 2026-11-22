//! Bounded argument expansion for the engine's configuration files.
mod arithmetic;
#[cfg(windows)]
mod native;

use glob::{MatchOptions, Pattern};
use std::{
    collections::BTreeMap,
    ffi::c_int,
    path::{Path, PathBuf},
};

const NOSPACE: c_int = 1;
const SYNTAX: c_int = 5;
const MAX_INPUT: usize = 65536;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORDS: usize = 16384;
const MAX_DEPTH: usize = 32;
type Result<T> = std::result::Result<T, c_int>;

#[derive(Clone)]
struct Atom {
    character: Option<char>,
    quoted: bool,
    split: bool,
}
type Word = Vec<Atom>;

fn append(word: &mut Word, text: &str, quoted: bool, split: bool) -> Result<()> {
    if word.len().saturating_add(text.len()) > MAX_BYTES {
        return Err(NOSPACE);
    }
    word.extend(text.chars().map(|character| Atom {
        character: Some(character),
        quoted,
        split,
    }));
    Ok(())
}
fn anchor(word: &mut Word) {
    word.push(Atom {
        character: None,
        quoted: true,
        split: false,
    });
}
fn text(word: &[Atom]) -> String {
    word.iter().filter_map(|atom| atom.character).collect()
}
fn pattern(word: &[Atom]) -> String {
    let mut result = String::new();
    let mut star = false;
    for atom in word {
        let Some(character) = atom.character else {
            continue;
        };
        if atom.quoted {
            result.push_str(&Pattern::escape(&character.to_string()));
        } else if character != '*' || !star {
            result.push(character);
        }
        star = !atom.quoted && character == '*';
    }
    result
}
fn blank(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}
fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn ansi_end(input: &[char], start: usize) -> Result<usize> {
    let mut position = start + 1;
    while position < input.len() {
        if input[position] == '\'' {
            return Ok(position + 1);
        }
        position += if input[position] == '\\' { 2 } else { 1 };
    }
    Err(SYNTAX)
}
fn ansi_string(input: &[char]) -> Result<String> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < input.len() {
        let mut character = input[position];
        position += 1;
        if character == '\\' && position < input.len() {
            character = input[position];
            position += 1;
            character = match character {
                'a' => '\u{0007}',
                'b' => '\u{0008}',
                'e' | 'E' => '\u{001b}',
                'f' => '\u{000c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\u{000b}',
                '\\' | '\'' | '"' | '?' => character,
                'c' if position < input.len() => {
                    let value = input[position] as u32;
                    position += 1;
                    char::from_u32(value & 31).ok_or(SYNTAX)?
                }
                'x' | 'u' | 'U' | '0'..='7' => {
                    let octal = character.is_digit(8);
                    let radix = if octal { 8 } else { 16 };
                    let maximum = match character {
                        'u' => 4,
                        'U' => 8,
                        'x' => 2,
                        _ => 3,
                    };
                    let mut digits = usize::from(octal);
                    let mut value = character.to_digit(8).filter(|_| octal).unwrap_or(0);
                    while digits < maximum {
                        let Some(digit) = input.get(position).and_then(|c| c.to_digit(radix))
                        else {
                            break;
                        };
                        value = value * radix + digit;
                        position += 1;
                        digits += 1;
                    }
                    if digits == 0 {
                        output.push(b'\\');
                        character
                    } else if octal || character == 'x' {
                        let value = value as u8;
                        if value == 0 {
                            break;
                        }
                        output.push(value);
                        continue;
                    } else {
                        char::from_u32(value).ok_or(SYNTAX)?
                    }
                }
                _ => {
                    output.push(b'\\');
                    character
                }
            };
        }
        if character == '\0' {
            break;
        }
        let mut buffer = [0u8; 4];
        output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
    }
    String::from_utf8(output).map_err(|_| SYNTAX)
}

// Locate shell syntax without evaluating its contents. Protected command and
// process substitutions retain their literal bytes, as in Cygwin's Bash mode.
fn group_end(input: &[char], start: usize, depth: usize) -> Result<usize> {
    if depth > MAX_DEPTH {
        return Err(NOSPACE);
    }
    let first = input[start];
    let close = match first {
        '(' => ')',
        '{' => '}',
        '[' => ']',
        '\'' | '"' | '\u{0060}' => first,
        _ => return Err(SYNTAX),
    };
    let mut position = start + 1;
    while position < input.len() {
        let character = input[position];
        if character == close {
            return Ok(position + 1);
        }
        if first != '\'' && character == '\\' {
            position += 2;
        } else if first != '\''
            && first != '"'
            && character == '$'
            && input.get(position + 1) == Some(&'\'')
        {
            position = ansi_end(input, position + 1)?;
        } else if first != '\''
            && (character == '$'
                && input
                    .get(position + 1)
                    .is_some_and(|c| matches!(c, '(' | '{' | '[')))
        {
            position = group_end(input, position + 1, depth + 1)?;
        } else if first != '\''
            && matches!(character, '\'' | '"' | '\u{0060}')
            && first != '\u{0060}'
        {
            // A single quote inside double quotes has no shell significance.
            if first == '"' && character == '\'' {
                position += 1
            } else {
                position = group_end(input, position, depth + 1)?
            }
        } else if first != '\'' && first != '"' && first != '\u{0060}' && character == first {
            position = group_end(input, position, depth + 1)?;
        } else {
            position += 1;
        }
    }
    Err(SYNTAX)
}
fn syntax_end(input: &[char], position: usize) -> Result<Option<usize>> {
    match input[position] {
        '$' if input.get(position + 1) == Some(&'\'') => ansi_end(input, position + 1).map(Some),
        '\'' | '"' | '\u{0060}' => group_end(input, position, 0).map(Some),
        '$' if input
            .get(position + 1)
            .is_some_and(|c| matches!(c, '(' | '{' | '[')) =>
        {
            group_end(input, position + 1, 0).map(Some)
        }
        '<' | '>' if input.get(position + 1) == Some(&'(') => {
            group_end(input, position + 1, 0).map(Some)
        }
        '\\' => Ok(Some((position + 2).min(input.len()))),
        _ => Ok(None),
    }
}
fn lexical_words(input: &str) -> Result<Vec<String>> {
    let input: Vec<char> = input.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();
    let mut redirect = false;
    let mut position = 0;
    while position < input.len() {
        let character = input[position];
        if let Some(end) = syntax_end(&input, position)? {
            current.extend(&input[position..end]);
            position = end;
            continue;
        }
        if blank(character) || matches!(character, '<' | '>') {
            let io_number = !current.is_empty()
                && current.bytes().all(|b| b.is_ascii_digit())
                && matches!(character, '<' | '>');
            if !current.is_empty() {
                if !redirect && !io_number {
                    words.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                redirect = false;
            }
            if matches!(character, '<' | '>') {
                redirect = true;
                position += 1;
                if input
                    .get(position)
                    .is_some_and(|c| *c == character || *c == '&' || *c == '|')
                {
                    position += 1;
                }
                continue;
            }
        } else if character == '#' && current.is_empty() {
            break;
        } else if matches!(character, ';' | '|' | '&') {
            return Err(NOSPACE);
        } else if matches!(character, '(' | ')') {
            return Err(SYNTAX);
        } else {
            current.push(character);
        }
        if words.len() > MAX_WORDS {
            return Err(NOSPACE);
        }
        position += 1;
    }
    if !current.is_empty() {
        if !redirect {
            words.push(current)
        }
        redirect = false;
    }
    if redirect {
        return Err(SYNTAX);
    }
    Ok(words)
}

fn brace_range(body: &str) -> Result<Option<Vec<String>>> {
    let pieces: Vec<_> = body.split("..").collect();
    if !(2..=3).contains(&pieces.len()) {
        return Ok(None);
    }
    let step = if pieces.len() == 3 {
        let Ok(step) = pieces[2].parse::<i64>() else {
            return Ok(None);
        };
        step.unsigned_abs().max(1)
    } else {
        1
    };
    let numeric = pieces[0]
        .parse::<i64>()
        .ok()
        .zip(pieces[1].parse::<i64>().ok());
    let (start, end, width, letters) = if let Some((start, end)) = numeric {
        let width = pieces[..2]
            .iter()
            .filter(|piece| piece.trim_start_matches('-').starts_with('0') && piece.len() > 1)
            .map(|piece| piece.len())
            .max()
            .unwrap_or(0);
        (start, end, width, false)
    } else if pieces[0].len() == 1
        && pieces[1].len() == 1
        && pieces[0].as_bytes()[0].is_ascii_alphabetic()
        && pieces[1].as_bytes()[0].is_ascii_alphabetic()
    {
        (
            pieces[0].as_bytes()[0] as i64,
            pieces[1].as_bytes()[0] as i64,
            0,
            true,
        )
    } else {
        return Ok(None);
    };
    let count = (start.abs_diff(end) / step).checked_add(1).ok_or(NOSPACE)?;
    if count > MAX_WORDS as u64 {
        return Err(NOSPACE);
    }
    let mut result = Vec::new();
    for offset in 0..count {
        let distance = offset.checked_mul(step).ok_or(NOSPACE)?;
        let value = if start <= end {
            (start as i128) + distance as i128
        } else {
            (start as i128) - distance as i128
        };
        let value = i64::try_from(value).map_err(|_| NOSPACE)?;
        result.push(if letters {
            (value as u8 as char).to_string()
        } else {
            format!("{value:0width$}")
        });
    }
    Ok(Some(result))
}
fn brace_words(word: &str, depth: usize) -> Result<Vec<String>> {
    if depth > MAX_DEPTH {
        return Err(NOSPACE);
    }
    let input: Vec<char> = word.chars().collect();
    let mut position = 0;
    while position < input.len() {
        if let Some(end) = syntax_end(&input, position)? {
            position = end;
            continue;
        }
        if input[position] != '{' {
            position += 1;
            continue;
        }
        let Ok(end) = group_end(&input, position, 0) else {
            return Ok(vec![word.into()]);
        };
        let body: String = input[position + 1..end - 1].iter().collect();
        let mut alternatives = Vec::new();
        let body_chars: Vec<char> = body.chars().collect();
        let mut begin = 0;
        let mut at = 0;
        while at < body_chars.len() {
            if let Some(after) = syntax_end(&body_chars, at)? {
                at = after;
                continue;
            }
            if body_chars[at] == '{' {
                at = group_end(&body_chars, at, 0)?;
                continue;
            }
            if body_chars[at] == ',' {
                alternatives.push(body_chars[begin..at].iter().collect::<String>());
                begin = at + 1;
            }
            at += 1;
        }
        if !alternatives.is_empty() {
            alternatives.push(body_chars[begin..].iter().collect());
        } else if let Some(range) = brace_range(&body)? {
            alternatives = range;
        }
        if alternatives.is_empty() {
            position = end;
            continue;
        }
        let prefix: String = input[..position].iter().collect();
        let suffix: String = input[end..].iter().collect();
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for alternative in alternatives {
            let candidate = format!("{prefix}{alternative}{suffix}");
            if candidate.len() > MAX_BYTES {
                return Err(NOSPACE);
            }
            let expanded = brace_words(&candidate, depth + 1)?;
            bytes = bytes.saturating_add(expanded.iter().map(|word| word.len() + 1).sum::<usize>());
            if result.len().saturating_add(expanded.len()) > MAX_WORDS || bytes > MAX_BYTES {
                return Err(NOSPACE);
            }
            result.extend(expanded);
        }
        return Ok(result);
    }
    Ok(vec![word.into()])
}

struct Expansion {
    variables: BTreeMap<String, String>,
    directory: PathBuf,
}
impl Expansion {
    fn value(&self, name: &str) -> Option<String> {
        match name {
            "@" | "*" | "!" | "-" => None,
            "#" | "?" => Some("0".into()),
            "$" => Some(std::process::id().to_string()),
            "0" => Some("bash".into()),
            name if name.bytes().all(|b| b.is_ascii_digit()) => None,
            _ => self.variables.get(name).cloned(),
        }
    }
    fn fragment(&mut self, raw: &[char], quoted: bool, depth: usize) -> Result<Word> {
        if depth > MAX_DEPTH {
            return Err(NOSPACE);
        }
        let mut result = Word::new();
        let mut position = 0;
        while position < raw.len() {
            let character = raw[position];
            match character {
                '\'' if !quoted => {
                    let end = group_end(raw, position, depth)?;
                    anchor(&mut result);
                    append(
                        &mut result,
                        &raw[position + 1..end - 1].iter().collect::<String>(),
                        true,
                        false,
                    )?;
                    position = end;
                }
                '"' if !quoted => {
                    let end = group_end(raw, position, depth)?;
                    anchor(&mut result);
                    result.extend(self.fragment(&raw[position + 1..end - 1], true, depth + 1)?);
                    position = end;
                }
                '\\' => {
                    let next = raw.get(position + 1).copied();
                    if next == Some('\n') {
                        position += 2;
                        continue;
                    }
                    let escaped = next
                        .filter(|next| !quoted || matches!(next, '$' | '\u{0060}' | '"' | '\\'));
                    let chosen = escaped.unwrap_or('\\');
                    append(&mut result, &chosen.to_string(), true, false)?;
                    position += if escaped.is_some() { 2 } else { 1 };
                }
                '$' => {
                    position = self.dollar(raw, position, quoted, depth, &mut result)?;
                }
                '\u{0060}' => {
                    let end = group_end(raw, position, depth)?;
                    append(
                        &mut result,
                        &raw[position..end].iter().collect::<String>(),
                        quoted,
                        !quoted,
                    )?;
                    position = end;
                }
                '<' | '>' if !quoted && raw.get(position + 1) == Some(&'(') => {
                    let end = group_end(raw, position + 1, depth)?;
                    append(
                        &mut result,
                        &raw[position..end].iter().collect::<String>(),
                        true,
                        false,
                    )?;
                    position = end;
                }
                '~' if !quoted
                    && (position == 0
                        || raw[position - 1] == '='
                            && identifier(&raw[..position - 1].iter().collect::<String>())) =>
                {
                    let end = raw[position..]
                        .iter()
                        .position(|c| matches!(c, '/' | ':'))
                        .map_or(raw.len(), |n| position + n);
                    let user: String = raw[position + 1..end].iter().collect();
                    let home = match user.as_str() {
                        "" => self
                            .variables
                            .get("HOME")
                            .or_else(|| self.variables.get("USERPROFILE"))
                            .cloned(),
                        "+" => Some(self.directory.to_string_lossy().replace('\\', "/")),
                        "-" => self
                            .variables
                            .get("OLDPWD")
                            .filter(|path| Path::new(path).is_dir())
                            .cloned(),
                        _ => None,
                    };
                    if let Some(home) = home {
                        append(&mut result, &home, true, false)?;
                        position = end;
                    } else {
                        append(&mut result, "~", false, false)?;
                        position += 1;
                    }
                }
                _ => {
                    append(&mut result, &character.to_string(), quoted, false)?;
                    position += 1;
                }
            }
            if result.len() > MAX_BYTES {
                return Err(NOSPACE);
            }
        }
        if result.len() > MAX_BYTES {
            return Err(NOSPACE);
        }
        Ok(result)
    }
    fn dollar(
        &mut self,
        raw: &[char],
        position: usize,
        quoted: bool,
        depth: usize,
        out: &mut Word,
    ) -> Result<usize> {
        let begin = position + 1;
        match raw.get(begin) {
            Some('\'') if !quoted => {
                let end = ansi_end(raw, begin)?;
                anchor(out);
                append(out, &ansi_string(&raw[begin + 1..end - 1])?, true, false)?;
                Ok(end)
            }
            Some('{') => {
                let end = group_end(raw, begin, depth)?;
                out.extend(self.parameter(&raw[begin + 1..end - 1], quoted, depth + 1)?);
                Ok(end)
            }
            Some('(') if raw.get(begin + 1) == Some(&'(') => {
                let end = group_end(raw, begin, depth)?;
                if raw.get(end - 2) != Some(&')') {
                    return Err(SYNTAX);
                }
                let expression: String = raw[begin + 2..end - 2].iter().collect();
                let value = arithmetic::evaluate(&expression, &mut self.variables, depth)?;
                append(out, &value.to_string(), quoted, !quoted)?;
                Ok(end)
            }
            Some('[') => {
                let end = group_end(raw, begin, depth)?;
                let expression: String = raw[begin + 1..end - 1].iter().collect();
                let value = arithmetic::evaluate(&expression, &mut self.variables, depth)?;
                append(out, &value.to_string(), quoted, !quoted)?;
                Ok(end)
            }
            Some('(') => {
                let end = group_end(raw, begin, depth)?;
                append(
                    out,
                    &raw[position..end].iter().collect::<String>(),
                    quoted,
                    !quoted,
                )?;
                Ok(end)
            }
            Some('"') if !quoted => {
                let end = group_end(raw, begin, depth)?;
                anchor(out);
                out.extend(self.fragment(&raw[begin + 1..end - 1], true, depth + 1)?);
                Ok(end)
            }
            Some(character) if character.is_ascii_alphabetic() || *character == '_' => {
                let mut end = begin + 1;
                while raw
                    .get(end)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    end += 1
                }
                let name: String = raw[begin..end].iter().collect();
                append(out, &self.value(&name).unwrap_or_default(), quoted, !quoted)?;
                Ok(end)
            }
            Some(character) if character.is_ascii_digit() || "@*?!#$-".contains(*character) => {
                append(
                    out,
                    &self.value(&character.to_string()).unwrap_or_default(),
                    quoted,
                    !quoted,
                )?;
                Ok(begin + 1)
            }
            _ => {
                append(out, "$", quoted, false)?;
                Ok(begin)
            }
        }
    }
    fn parameter(&mut self, raw: &[char], quoted: bool, depth: usize) -> Result<Word> {
        if depth > MAX_DEPTH || raw.is_empty() {
            return Err(SYNTAX);
        }
        let mut position = 0;
        let length = raw[0] == '#' && raw.len() > 1;
        let indirect = raw[0] == '!' && raw.len() > 1;
        if length || indirect {
            position += 1
        }
        let begin = position;
        if raw[position].is_ascii_alphabetic() || raw[position] == '_' {
            position += 1;
            while raw
                .get(position)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                position += 1
            }
        } else if raw[position].is_ascii_digit() || "@*?!#$-".contains(raw[position]) {
            position += 1;
        } else {
            return Err(SYNTAX);
        }
        let mut name: String = raw[begin..position].iter().collect();
        if indirect {
            name = self.value(&name).ok_or(SYNTAX)?;
        }
        let value = self.value(&name);
        let rest: String = raw[position..].iter().collect();
        let mut result = Word::new();
        if length {
            if !rest.is_empty() {
                return Err(SYNTAX);
            }
            append(
                &mut result,
                &value.unwrap_or_default().chars().count().to_string(),
                quoted,
                !quoted,
            )?;
        } else if rest.is_empty() {
            append(&mut result, &value.unwrap_or_default(), quoted, !quoted)?;
        } else if let Some((operator, operand, colon)) = parameter_operator(&rest) {
            let absent = value.is_none() || colon && value.as_ref().is_some_and(String::is_empty);
            if operator == '+' && !absent || operator != '+' && absent {
                if operator == '?' {
                    return Err(SYNTAX);
                }
                result = self.fragment(&operand.chars().collect::<Vec<_>>(), quoted, depth + 1)?;
                if operator == '=' {
                    self.variables.insert(name, text(&result));
                }
            } else if operator != '+' {
                append(&mut result, &value.unwrap_or_default(), quoted, !quoted)?;
            }
        } else if rest.starts_with('%') || rest.starts_with('#') {
            let marker = rest.as_bytes()[0] as char;
            let longest = rest.chars().nth(1) == Some(marker);
            let offset = if longest { 2 } else { 1 };
            let operand = self.fragment(
                &rest[offset..].chars().collect::<Vec<_>>(),
                false,
                depth + 1,
            )?;
            let value = trim_pattern(
                &value.unwrap_or_default(),
                &pattern(&operand),
                marker == '#',
                longest,
            )?;
            append(&mut result, &value, quoted, !quoted)?;
        } else if let Some(replacement) = rest.strip_prefix('/') {
            let (replacement, all) = replacement
                .strip_prefix('/')
                .map_or((replacement, false), |rest| (rest, true));
            let raw: Vec<char> = replacement.chars().collect();
            let mut position = 0;
            while position < raw.len() && raw[position] != '/' {
                position = syntax_end(&raw, position)?.unwrap_or(position + 1);
            }
            let find = self.fragment(&raw[..position], false, depth + 1)?;
            let replacement = if position < raw.len() {
                self.fragment(&raw[position + 1..], quoted, depth + 1)?
            } else {
                Word::new()
            };
            let value = replace_pattern(
                &value.unwrap_or_default(),
                &pattern(&find),
                &text(&replacement),
                all,
            )?;
            append(&mut result, &value, quoted, !quoted)?;
        } else if let Some(offset) = rest.strip_prefix(':') {
            let (offset, count) = offset
                .split_once(':')
                .map_or((offset, None), |(a, b)| (a, Some(b)));
            let offset = arithmetic::evaluate(offset, &mut self.variables, depth)?;
            let value: Vec<char> = value.unwrap_or_default().chars().collect();
            let begin = if offset < 0 {
                (value.len() as i128 + offset as i128).max(0) as usize
            } else {
                offset as usize
            }
            .min(value.len());
            let end = if let Some(count) = count {
                let count = arithmetic::evaluate(count, &mut self.variables, depth)?;
                if count < 0 {
                    (value.len() as i128 + count as i128).max(begin as i128) as usize
                } else {
                    begin.saturating_add(count as usize).min(value.len())
                }
            } else {
                value.len()
            };
            append(
                &mut result,
                &value[begin..end].iter().collect::<String>(),
                quoted,
                !quoted,
            )?;
        } else if rest.starts_with('^') || rest.starts_with(',') {
            let upper = rest.starts_with('^');
            let all = rest.as_bytes().get(1) == rest.as_bytes().first();
            let offset = if all { 2 } else { 1 };
            let wanted = if rest.len() == offset {
                "?".into()
            } else {
                pattern(&self.fragment(
                    &rest[offset..].chars().collect::<Vec<_>>(),
                    false,
                    depth + 1,
                )?)
            };
            let matcher = Pattern::new(&wanted).map_err(|_| SYNTAX)?;
            let value: String = value
                .unwrap_or_default()
                .chars()
                .enumerate()
                .map(|(index, character)| {
                    if (all || index == 0) && matcher.matches(&character.to_string()) {
                        if upper {
                            character.to_uppercase().to_string()
                        } else {
                            character.to_lowercase().to_string()
                        }
                    } else {
                        character.to_string()
                    }
                })
                .collect();
            append(&mut result, &value, quoted, !quoted)?;
        } else if rest == "@Q" {
            if let Some(value) = value {
                append(
                    &mut result,
                    &format!("'{}'", value.replace('\'', "'\\''")),
                    quoted,
                    !quoted,
                )?;
            }
        } else {
            return Err(SYNTAX);
        }
        Ok(result)
    }
}
fn parameter_operator(rest: &str) -> Option<(char, &str, bool)> {
    let (rest, colon) = rest
        .strip_prefix(':')
        .map_or((rest, false), |rest| (rest, true));
    let operator = rest.chars().next()?;
    "-+=?"
        .contains(operator)
        .then_some((operator, &rest[1..], colon))
}
fn trim_pattern(value: &str, pattern: &str, prefix: bool, longest: bool) -> Result<String> {
    let Ok(pattern) = Pattern::new(pattern) else {
        return Ok(value.into());
    };
    let mut boundaries: Vec<usize> = value
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(value.len()))
        .collect();
    if longest != !prefix {
        boundaries.reverse()
    }
    let mut work = 0usize;
    for boundary in boundaries {
        let (head, tail) = value.split_at(boundary);
        let candidate = if prefix { head } else { tail };
        work = work.saturating_add(candidate.len() + 1);
        if work > 16 * MAX_BYTES {
            return Err(NOSPACE);
        }
        if pattern.matches(candidate) {
            return Ok(if prefix { tail } else { head }.into());
        }
    }
    Ok(value.into())
}
fn replace_pattern(value: &str, wanted: &str, replacement: &str, all: bool) -> Result<String> {
    if wanted.is_empty() {
        return Ok(value.into());
    }
    let (wanted, prefix, suffix) = if let Some(wanted) = wanted.strip_prefix('#') {
        (wanted, true, false)
    } else if let Some(wanted) = wanted.strip_prefix('%') {
        (wanted, false, true)
    } else {
        (wanted, false, false)
    };
    let Ok(pattern) = Pattern::new(wanted) else {
        return Ok(value.into());
    };
    let boundaries: Vec<usize> = value
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(value.len()))
        .collect();
    let mut output = String::new();
    let mut copied = 0;
    let mut work = 0usize;
    for (index, begin) in boundaries.iter().copied().enumerate() {
        if begin < copied || prefix && begin != 0 {
            continue;
        }
        let mut found = None;
        for end in boundaries[index..].iter().rev().copied() {
            if suffix && end != value.len() {
                continue;
            }
            work = work.saturating_add(end - begin + 1);
            if work > 16 * MAX_BYTES {
                return Err(NOSPACE);
            }
            if pattern.matches(&value[begin..end]) {
                found = Some(end);
                break;
            }
        }
        if let Some(end) = found {
            output.push_str(&value[copied..begin]);
            output.push_str(replacement);
            copied = end;
            if output.len() > MAX_BYTES {
                return Err(NOSPACE);
            }
            if !all || end == begin {
                break;
            }
        }
    }
    output.push_str(&value[copied..]);
    Ok(output)
}
fn split_fields(word: Word) -> Result<Vec<Word>> {
    let mut fields = Vec::new();
    let mut current = Word::new();
    for atom in word {
        if atom.split
            && atom
                .character
                .is_some_and(|c| matches!(c, ' ' | '\t' | '\n'))
        {
            if !current.is_empty() {
                fields.push(std::mem::take(&mut current));
                if fields.len() > MAX_WORDS {
                    return Err(NOSPACE);
                }
            }
        } else {
            current.push(atom);
        }
    }
    if !current.is_empty() {
        fields.push(current)
    }
    if fields.len() > MAX_WORDS {
        return Err(NOSPACE);
    }
    Ok(fields)
}
fn filenames(word: &Word, directory: &Path) -> Result<Vec<String>> {
    let original = text(word);
    if !word
        .iter()
        .any(|atom| !atom.quoted && atom.character.is_some_and(|c| matches!(c, '*' | '?' | '[')))
    {
        return Ok(vec![original]);
    }
    let pattern = pattern(word);
    let relative = Path::new(&original).is_relative();
    let full = if relative {
        format!(
            "{}/{}",
            Pattern::escape(&directory.to_string_lossy().replace('\\', "/")),
            pattern
        )
    } else {
        pattern
    };
    let options = MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: true,
    };
    let Ok(paths) = glob::glob_with(&full, options) else {
        return Ok(vec![original]);
    };
    let mut result = Vec::new();
    let mut bytes = 0usize;
    for path in paths.flatten() {
        let path = if relative {
            path.strip_prefix(directory).map_err(|_| SYNTAX)?
        } else {
            &path
        };
        let mut value = path.to_str().ok_or(SYNTAX)?.replace('\\', "/");
        if original.starts_with("./") && relative {
            value = format!("./{value}");
        }
        bytes = bytes.saturating_add(value.len() + 1);
        result.push(value);
        if result.len() > MAX_WORDS || bytes > MAX_BYTES {
            return Err(NOSPACE);
        }
    }
    if result.is_empty() {
        result.push(original)
    }
    result.sort();
    Ok(result)
}

fn expand(
    input: &str,
    variables: BTreeMap<String, String>,
    directory: PathBuf,
) -> Result<Vec<String>> {
    if input.len() > MAX_INPUT {
        return Err(NOSPACE);
    }
    if input.contains('\0') {
        return Err(SYNTAX);
    }
    let mut context = Expansion {
        variables,
        directory,
    };
    let mut output = Vec::new();
    let mut bytes = 0usize;
    for raw in lexical_words(input)? {
        for raw in brace_words(&raw, 0)? {
            let word = context.fragment(&raw.chars().collect::<Vec<_>>(), false, 0)?;
            for field in split_fields(word)? {
                for word in filenames(&field, &context.directory)? {
                    bytes = bytes.saturating_add(word.len() + 1);
                    output.push(word);
                    if bytes > MAX_BYTES || output.len() > MAX_WORDS {
                        return Err(NOSPACE);
                    }
                }
            }
        }
    }
    if output.is_empty() {
        return Err(NOSPACE);
    }
    // Cygwin's Bash wordexp protocol reads exactly word_count newline-delimited
    // records, including when an expansion itself produces a newline.
    let count = output.len();
    Ok(output
        .iter()
        .flat_map(|word| word.split('\n'))
        .take(count)
        .map(str::to_owned)
        .collect())
}

/// Expand an engine configuration into caller-owned NUL-separated UTF-8 bytes.
///
/// # Safety
/// Input must reference length readable bytes. The length outputs must be valid,
/// writable and disjoint from input and output. A non-null output must reference
/// capacity writable bytes. No Rust allocation crosses this interface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_wordexp(
    input: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
    required: *mut usize,
    word_count: *mut usize,
) -> c_int {
    if required.is_null() || word_count.is_null() {
        return SYNTAX;
    }
    unsafe {
        required.write(0);
        word_count.write(0);
    }
    let result = std::panic::catch_unwind(|| -> Result<(Vec<u8>, usize)> {
        if input.is_null()
            || length > MAX_INPUT
            || capacity > MAX_BYTES
            || output.is_null() && capacity != 0
        {
            return Err(NOSPACE);
        }
        let input = unsafe { std::slice::from_raw_parts(input, length) };
        let input = std::str::from_utf8(input).map_err(|_| SYNTAX)?;
        let variables = std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        let directory = std::env::current_dir().map_err(|_| SYNTAX)?;
        let words = expand(input, variables, directory)?;
        let count = words.len();
        let mut bytes = Vec::new();
        for word in words {
            bytes.extend_from_slice(word.as_bytes());
            bytes.push(0);
        }
        Ok((bytes, count))
    });
    match result {
        Ok(Ok((bytes, count))) => {
            unsafe {
                required.write(bytes.len());
                word_count.write(count);
            }
            if capacity < bytes.len() {
                return NOSPACE;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            }
            0
        }
        Ok(Err(error)) => error,
        Err(_) => NOSPACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        variables: BTreeMap<String, String>,
        files: Vec<String>,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        input: String,
        status: c_int,
        words: Vec<String>,
    }

    #[test]
    fn configuration_words_match_the_pinned_cygwin_protected_shell() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/wordexp-cygwin.json")).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        for name in fixture.files {
            let path = temporary.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"fixture").unwrap();
        }
        for case in fixture.cases {
            let result = expand(
                &case.input,
                fixture.variables.clone(),
                temporary.path().to_path_buf(),
            );
            match result {
                Ok(words) => {
                    assert_eq!(case.status, 0, "{}", case.name);
                    assert_eq!(words, case.words, "{}", case.name);
                }
                Err(status) => assert_eq!(status, case.status, "{}: {:?}", case.name, case.words),
            }
        }
    }

    #[test]
    fn ffi_sizes_and_publishes_one_complete_result() {
        let input = "x 'directory with spaces' \"Привет\"".as_bytes();
        let mut required = usize::MAX;
        let mut count = usize::MAX;
        let mut small = [0xa5u8; 3];
        let status = unsafe {
            zapret_wordexp(
                input.as_ptr(),
                input.len(),
                small.as_mut_ptr(),
                small.len(),
                &mut required,
                &mut count,
            )
        };
        assert_eq!(status, NOSPACE);
        assert_eq!(small, [0xa5; 3]);
        assert_eq!(count, 3);
        let mut output = vec![0xa5; required];
        let status = unsafe {
            zapret_wordexp(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut required,
                &mut count,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(output, "x\0directory with spaces\0Привет\0".as_bytes());
    }

    #[test]
    fn ffi_clears_lengths_and_keeps_output_atomic_on_invalid_input() {
        for input in [b"x 'broken".as_slice(), b"x a\0b", b"x \xff"] {
            let mut required = 999usize;
            let mut count = 999usize;
            let mut output = [0xa5u8; 128];
            let status = unsafe {
                zapret_wordexp(
                    input.as_ptr(),
                    input.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &mut required,
                    &mut count,
                )
            };
            assert_eq!(status, SYNTAX);
            assert_eq!(required, 0);
            assert_eq!(count, 0);
            assert_eq!(output, [0xa5; 128]);
        }
    }

    #[test]
    fn recursive_and_multiplicative_expansion_has_finite_budgets() {
        let directory = tempfile::tempdir().unwrap();
        for source in [
            format!("x {}", "a".repeat(MAX_INPUT)),
            "x {1..1000000000}".to_owned(),
            "x {-9223372036854775808..9223372036854775807}".to_owned(),
            "x {1..128}{1..129}".to_owned(),
            format!("x {}1{}", "$((".repeat(128), "))".repeat(128)),
        ] {
            assert_eq!(
                expand(&source, BTreeMap::new(), directory.path().to_owned()),
                Err(NOSPACE)
            );
        }
    }

    #[test]
    fn exact_word_budget_is_accepted_before_the_first_excess_word() {
        let temporary = tempfile::tempdir().unwrap();
        let variables = BTreeMap::from([("WORDS".to_owned(), "w ".repeat(MAX_WORDS - 1))]);
        let words = expand("x $WORDS", variables, temporary.path().to_owned()).unwrap();
        assert_eq!(words.len(), MAX_WORDS);
        let variables = BTreeMap::from([("WORDS".to_owned(), "w ".repeat(MAX_WORDS))]);
        assert_eq!(
            expand("x $WORDS", variables, temporary.path().to_owned()),
            Err(NOSPACE)
        );
    }
}
