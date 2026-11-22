use super::{Evidence, metric, string};
use serde_json::Value;

// .NET Framework Double.ToString("R"): try G15, then G17 if the shorter
// spelling does not round-trip. Keep the historical journal digest stable.
pub(super) fn roundtrip(number: f64) -> String {
    if number == 0. {
        return "0".into();
    }
    let short = format!("{number:.14e}");
    let precision = if short.parse::<f64>().ok() == Some(number) {
        15
    } else {
        17
    };
    general(number, precision)
}

pub(super) fn general(number: f64, precision: i32) -> String {
    if number == 0. {
        return "0".into();
    }
    let scientific = format!("{number:.digits$e}", digits = (precision - 1) as usize);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("finite scientific number");
    let exponent = exponent.parse::<i32>().expect("scientific exponent");
    let negative = mantissa.starts_with('-');
    let digits = mantissa
        .trim_start_matches('-')
        .replace('.', "")
        .trim_end_matches('0')
        .to_owned();
    let sign = if negative { "-" } else { "" };
    if exponent < -4 || exponent >= precision {
        let tail = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        format!(
            "{sign}{}{tail}E{}{:02}",
            &digits[..1],
            if exponent >= 0 { "+" } else { "-" },
            exponent.abs()
        )
    } else {
        let point = exponent + 1;
        if point <= 0 {
            format!("{sign}0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!(
                "{sign}{digits}{}",
                "0".repeat(point as usize - digits.len())
            )
        } else {
            format!(
                "{sign}{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        }
    }
}

pub(super) fn digest(rows: &[Value]) -> Evidence<String> {
    let base = [
        "Schema",
        "RunId",
        "Seed",
        "Stage",
        "ComparisonSlot",
        "ComparisonBlock",
        "ComparisonKind",
        "ComparisonArm",
        "StrategyId",
        "StrategyHash",
        "CapturedNetworkKey",
        "CapturedInputsHash",
        "TargetKey",
        "Group",
        "Name",
        "Attempt",
        "State",
        "Code",
        "Exit",
        "Up",
        "Down",
        "ConnMs",
        "TlsMs",
        "DnsMs",
        "FirstByteMs",
        "TotalMs",
        "StartedMs",
        "ObservedMs",
    ];
    let numbers = [
        "Schema",
        "Seed",
        "ComparisonSlot",
        "ComparisonBlock",
        "Attempt",
        "Exit",
        "Up",
        "Down",
        "ConnMs",
        "TlsMs",
        "DnsMs",
        "FirstByteMs",
        "TotalMs",
        "StartedMs",
        "ObservedMs",
        "ResourceSchema",
        "ProcessId",
        "ReadDurationMs",
        "CpuTotalMs",
        "PrivateBytes",
        "WorkingSetBytes",
        "OsPeakWorkingSetBytes",
    ];
    let resource = [
        "ResourceSchema",
        "ResourcePhase",
        "ResourceStatus",
        "ResourceReason",
        "ProcessId",
        "ProcessStartKey",
        "ReadDurationMs",
        "CpuTotalMs",
        "PrivateBytes",
        "WorkingSetBytes",
        "OsPeakWorkingSetBytes",
    ];
    let mut lines = Vec::with_capacity(rows.len());
    for row in rows {
        let stage = string(row, "Stage");
        if stage == "comparison-complete" {
            continue;
        }
        if !matches!(
            stage.as_str(),
            "comparison" | "comparison-warmup" | "comparison-resource"
        ) {
            return Err("invalid-evidence-stage");
        }
        let fields = base.iter().chain(if stage == "comparison-resource" {
            resource.iter()
        } else {
            [].iter()
        });
        let parts = fields
            .map(|field| {
                let value = if numbers.contains(field) {
                    metric(row, field).map(roundtrip)
                } else {
                    row.get(field)
                        .filter(|value| !value.is_null())
                        .map(|_| string(row, field))
                };
                value.map_or_else(|| "-".into(), |text| format!("{}:{text}", text.len()))
            })
            .collect::<Vec<_>>();
        lines.push(parts.join("|"));
    }
    lines.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    Ok(crate::sha256(lines.join("\n").as_bytes()))
}

pub(super) struct DotNetRandom {
    values: [i32; 56],
    next: usize,
    nextp: usize,
}
impl DotNetRandom {
    pub fn new(seed: i32) -> Self {
        let mut values = [0; 56];
        let mut mj = 161803398i32 - seed;
        values[55] = mj;
        let mut mk = 1;
        for i in 1..55 {
            let index = 21 * i % 55;
            values[index] = mk;
            mk = mj.wrapping_sub(mk);
            if mk < 0 {
                mk = mk.wrapping_add(i32::MAX)
            }
            mj = values[index];
        }
        for _ in 0..4 {
            for i in 1..56 {
                values[i] = values[i].wrapping_sub(values[1 + (i + 30) % 55]);
                if values[i] < 0 {
                    values[i] = values[i].wrapping_add(i32::MAX)
                }
            }
        }
        Self {
            values,
            next: 0,
            nextp: 21,
        }
    }
    pub fn bit(&mut self) -> bool {
        self.next = if self.next + 1 >= 56 {
            1
        } else {
            self.next + 1
        };
        self.nextp = if self.nextp + 1 >= 56 {
            1
        } else {
            self.nextp + 1
        };
        let mut result = self.values[self.next].wrapping_sub(self.values[self.nextp]);
        if result == i32::MAX {
            result -= 1
        }
        if result < 0 {
            result += i32::MAX
        }
        self.values[self.next] = result;
        result as f64 / i32::MAX as f64 * 2. >= 1.
    }
}
