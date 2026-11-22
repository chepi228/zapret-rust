use super::{MAX_DEPTH, MAX_INPUT, MAX_WORDS, NOSPACE, Result, SYNTAX};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
enum Token {
    Number(i64),
    Name(String),
    Operator(&'static str),
}
#[derive(Default)]
struct Value {
    number: i64,
    name: Option<String>,
}
struct Parser<'a> {
    tokens: Vec<Token>,
    position: usize,
    variables: &'a mut BTreeMap<String, String>,
    depth: usize,
}

fn number(text: &str) -> Result<i64> {
    let (base, digits) = if let Some((base, digits)) = text.split_once('#') {
        (base.parse::<u32>().map_err(|_| SYNTAX)?, digits)
    } else if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (16, digits)
    } else if text.len() > 1 && text.starts_with('0') {
        (8, &text[1..])
    } else {
        (10, text)
    };
    if !(2..=64).contains(&base) || digits.is_empty() {
        return Err(SYNTAX);
    }
    let mut value = 0i64;
    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' if base <= 36 => u32::from(byte - b'A') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 36,
            b'@' => 62,
            b'_' => 63,
            _ => return Err(SYNTAX),
        };
        if digit >= base {
            return Err(SYNTAX);
        }
        value = value
            .wrapping_mul(i64::from(base))
            .wrapping_add(i64::from(digit));
    }
    Ok(value)
}
fn tokens(source: &str) -> Result<Vec<Token>> {
    const OPERATORS: &[&str] = &[
        "<<=", ">>=", "**", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "&&", "||",
        "==", "!=", "<=", ">=", "<<", ">>", "+", "-", "*", "/", "%", "!", "~", "&", "|", "^", "<",
        ">", "=", "?", ":", "(", ")", ",",
    ];
    let mut output = Vec::new();
    let mut position = 0;
    while position < source.len() {
        if output.len() >= MAX_WORDS {
            return Err(NOSPACE);
        }
        let byte = source.as_bytes()[position];
        if byte.is_ascii_whitespace() {
            position += 1;
            continue;
        }
        if byte.is_ascii_digit() {
            let begin = position;
            while source
                .as_bytes()
                .get(position)
                .is_some_and(|b| b.is_ascii_alphanumeric() || b"#@_".contains(b))
            {
                position += 1
            }
            output.push(Token::Number(number(&source[begin..position])?));
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            let begin = position;
            while source
                .as_bytes()
                .get(position)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                position += 1
            }
            output.push(Token::Name(source[begin..position].into()));
        } else if let Some(operator) = OPERATORS
            .iter()
            .find(|operator| source[position..].starts_with(**operator))
        {
            output.push(Token::Operator(operator));
            position += operator.len();
        } else {
            return Err(SYNTAX);
        }
    }
    Ok(output)
}

fn binding(operator: &str) -> Option<(u8, u8)> {
    Some(match operator {
        "," => (1, 2),
        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" => (2, 2),
        "?" => (3, 3),
        "||" => (4, 5),
        "&&" => (5, 6),
        "|" => (6, 7),
        "^" => (7, 8),
        "&" => (8, 9),
        "==" | "!=" => (9, 10),
        "<" | ">" | "<=" | ">=" => (10, 11),
        "<<" | ">>" => (11, 12),
        "+" | "-" => (12, 13),
        "*" | "/" | "%" => (13, 14),
        "**" => (15, 15),
        _ => return None,
    })
}
fn operation(operator: &str, left: i64, right: i64) -> Result<i64> {
    Ok(match operator {
        "+" => left.wrapping_add(right),
        "-" => left.wrapping_sub(right),
        "*" => left.wrapping_mul(right),
        "/" if right != 0 => left.wrapping_div(right),
        "%" if right != 0 => left.wrapping_rem(right),
        "**" if right >= 0 => {
            let mut base = left;
            let mut power = right as u64;
            let mut result = 1i64;
            while power != 0 {
                if power & 1 != 0 {
                    result = result.wrapping_mul(base)
                }
                base = base.wrapping_mul(base);
                power >>= 1;
            }
            result
        }
        "<<" => left.wrapping_shl(right as u32),
        ">>" => left.wrapping_shr(right as u32),
        "&" => left & right,
        "|" => left | right,
        "^" => left ^ right,
        "<" => i64::from(left < right),
        ">" => i64::from(left > right),
        "<=" => i64::from(left <= right),
        ">=" => i64::from(left >= right),
        "==" => i64::from(left == right),
        "!=" => i64::from(left != right),
        "&&" => i64::from(left != 0 && right != 0),
        "||" => i64::from(left != 0 || right != 0),
        "," | "=" => right,
        _ => return Err(SYNTAX),
    })
}
impl Parser<'_> {
    fn accept(&mut self, wanted: &str) -> bool {
        if matches!(self.tokens.get(self.position), Some(Token::Operator(operator)) if *operator == wanted)
        {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn prefix(&mut self, active: bool, level: usize) -> Result<Value> {
        if level > MAX_DEPTH {
            return Err(NOSPACE);
        }
        let token = self.tokens.get(self.position).cloned().ok_or(SYNTAX)?;
        self.position += 1;
        let mut value = match token {
            Token::Number(number) => Value { number, name: None },
            Token::Name(name) => {
                let number = if active {
                    let source = self.variables.get(&name).cloned().unwrap_or_default();
                    evaluate(&source, self.variables, self.depth + 1)?
                } else {
                    0
                };
                Value {
                    number,
                    name: Some(name),
                }
            }
            Token::Operator("(") => {
                let value = self.expression(0, active, level + 1)?;
                if !self.accept(")") {
                    return Err(SYNTAX);
                }
                value
            }
            Token::Operator(operator @ ("+" | "-" | "!" | "~" | "++" | "--")) => {
                let value = self.prefix(active, level + 1)?;
                let number = match operator {
                    "+" => value.number,
                    "-" => value.number.wrapping_neg(),
                    "!" => i64::from(value.number == 0),
                    "~" => !value.number,
                    _ => {
                        let name = value.name.ok_or(SYNTAX)?;
                        let number =
                            value
                                .number
                                .wrapping_add(if operator == "++" { 1 } else { -1 });
                        if active {
                            self.variables.insert(name, number.to_string());
                        }
                        number
                    }
                };
                Value { number, name: None }
            }
            _ => return Err(SYNTAX),
        };
        if self.accept("++") {
            let name = value.name.take().ok_or(SYNTAX)?;
            if active {
                self.variables
                    .insert(name, value.number.wrapping_add(1).to_string());
            }
        } else if self.accept("--") {
            let name = value.name.take().ok_or(SYNTAX)?;
            if active {
                self.variables
                    .insert(name, value.number.wrapping_sub(1).to_string());
            }
        }
        Ok(value)
    }
    fn expression(&mut self, minimum: u8, active: bool, level: usize) -> Result<Value> {
        if level > MAX_DEPTH {
            return Err(NOSPACE);
        }
        let mut left = self.prefix(active, level + 1)?;
        while let Some(Token::Operator(operator)) = self.tokens.get(self.position).cloned() {
            let Some((left_binding, right_binding)) = binding(operator) else {
                break;
            };
            if left_binding < minimum {
                break;
            }
            self.position += 1;
            if operator == "?" {
                let yes = self.expression(0, active && left.number != 0, level + 1)?;
                if !self.accept(":") {
                    return Err(SYNTAX);
                }
                let no = self.expression(right_binding, active && left.number == 0, level + 1)?;
                left = Value {
                    number: if left.number != 0 {
                        yes.number
                    } else {
                        no.number
                    },
                    name: None,
                };
                continue;
            }
            let right_active = active
                && match operator {
                    "&&" => left.number != 0,
                    "||" => left.number == 0,
                    _ => true,
                };
            let right = self.expression(right_binding, right_active, level + 1)?;
            let assignment = left_binding == 2;
            let primitive = if assignment && operator != "=" {
                &operator[..operator.len() - 1]
            } else {
                operator
            };
            let number = if active {
                operation(primitive, left.number, right.number)?
            } else {
                0
            };
            if assignment {
                let name = left.name.take().ok_or(SYNTAX)?;
                if active {
                    self.variables.insert(name, number.to_string());
                }
            }
            left = Value { number, name: None };
        }
        Ok(left)
    }
}

pub(super) fn evaluate(
    source: &str,
    variables: &mut BTreeMap<String, String>,
    depth: usize,
) -> Result<i64> {
    if depth > MAX_DEPTH || source.len() > MAX_INPUT {
        return Err(NOSPACE);
    }
    if source.trim().is_empty() {
        return Ok(0);
    }
    let mut parser = Parser {
        tokens: tokens(source)?,
        position: 0,
        variables,
        depth,
    };
    let value = parser.expression(0, true, 0)?;
    if parser.position != parser.tokens.len() {
        return Err(SYNTAX);
    }
    Ok(value.number)
}
