//! Store decisions between Lua-owned effects. No coroutine state or Lua
//! reference is retained by this interface.
use crate::{MAX_BYTES, MAX_RECORDS, MIN_BYTES, TTL};

const LIMITS: [(&str, f64, f64); 3] = [
    ("maxrecords", 1., MAX_RECORDS as f64),
    ("maxbytes", MIN_BYTES as f64, MAX_BYTES as f64),
    ("ttl", 1., TTL as f64),
];
#[derive(Clone, Copy)]
pub enum Stat {
    Count,
    Dirty,
    Disabled,
    Serial,
}

pub const STATS: [Stat; 4] = [Stat::Count, Stat::Dirty, Stat::Disabled, Stat::Serial];

impl Stat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Dirty => "dirty",
            Self::Disabled => "disabled",
            Self::Serial => "serial",
        }
    }
}
pub const LIMIT_ERROR: &str = "invalid ring store limit";
pub const TEMP_SUFFIX: &str = ".tmp-";
pub const TIMER_NAME: &str = "ring_store_flush_v2";
pub const TIMER_INTERVAL: u32 = 1000;
pub const TIMER_ERROR: &str = "timer API unavailable";
pub const LOG_PREFIX: &str = "ring store: ";

pub fn limit_name(index: usize) -> Option<&'static str> {
    LIMITS.get(index.checked_sub(1)?).map(|limit| limit.0)
}

pub fn limit(index: usize, default: bool, value: Option<f64>) -> Option<f64> {
    let &(_, min, max) = LIMITS.get(index.checked_sub(1)?)?;
    if default {
        return Some(max);
    }
    value.filter(|number| (min..=max).contains(number) && number.fract() == 0.)
}

pub fn stat_name(index: usize) -> Option<&'static str> {
    stat(index).map(Stat::name)
}

pub fn stat(index: usize) -> Option<Stat> {
    STATS.get(index.checked_sub(1)?).copied()
}

pub fn schema_names() -> impl Iterator<Item = &'static str> {
    LIMITS
        .iter()
        .map(|limit| limit.0)
        .chain(STATS.map(Stat::name))
}

pub fn construct_next(previous: Option<&str>, file: bool) -> Option<&'static str> {
    match previous {
        None if file => Some("read"),
        None | Some("read") => Some("create"),
        Some("create") if file => Some("temporary_path"),
        _ => None,
    }
}

pub fn construction(provided_file: bool, file: bool) -> (bool, bool) {
    // An explicitly false file value creates a file-backed store without I/O during construction.
    (construct_next(None, file) == Some("read"), provided_file)
}

pub fn initial_file(ok: bool, string: bool, length: usize, limit: usize) -> Option<&'static str> {
    if !ok {
        None
    } else if string && length <= limit {
        Some("borrow")
    } else {
        Some("empty")
    }
}

pub fn key_check(put: bool, string: bool, length: usize) -> Option<&'static str> {
    match (put, string, (1..=255).contains(&length)) {
        (false, true, _) => Some("valid"),
        (true, true, true) => Some("whitespace"),
        _ => None,
    }
}

pub fn put_value(whitespace: bool, absent: bool, value: Option<f64>) -> bool {
    !whitespace && (absent || value.is_some_and(|n| (2. ..=128.).contains(&n) && n.fract() == 0.))
}

pub fn atomic_next(
    previous: Option<&str>,
    ok: bool,
    provided_error: bool,
) -> (Option<&'static str>, Option<&'static str>) {
    match previous {
        None => (Some("write"), None),
        Some("write") => (Some("verify"), None),
        Some("verify") if !ok => (
            Some("verification_error"),
            Some("incomplete temporary snapshot"),
        ),
        Some("verify" | "verification_error") => (Some("rename"), None),
        Some("rename") if !ok => (
            Some("rename_error"),
            (!provided_error).then_some("rename failed"),
        ),
        _ => (None, None),
    }
}

pub fn publish_next(previous: Option<&str>, ok: bool, valid: bool) -> Option<&'static str> {
    match previous {
        None => Some("validate"),
        Some("validate") if ok && valid => Some("snapshot"),
        Some("validate") => Some("discard"),
        Some("snapshot") => Some("atomic"),
        Some("atomic") => Some("commit"),
        Some("commit") if !ok => Some("remove"),
        Some("remove") => Some("retry_log"),
        _ => None,
    }
}

pub fn after_next(operation: &str, previous: Option<&str>, ok: bool) -> Option<&'static str> {
    match (operation, previous, ok) {
        ("legacy", None, true) => Some("legacy_commit"),
        ("legacy", None, false) => Some("legacy_discard"),
        ("legacy", Some("legacy_discard"), false) => Some("log"),
        ("flush", None, false) => Some("defer"),
        ("flush", Some("defer"), false) => Some("log"),
        ("dispatch", None, false) => Some("log"),
        ("dispatch", Some("log"), false) => Some("clear"),
        _ => None,
    }
}

pub fn after_plan(operation: &str, ok: bool) -> [Option<&'static str>; 2] {
    let first = after_next(operation, None, ok);
    [
        first,
        first.and_then(|action| after_next(operation, Some(action), ok)),
    ]
}

pub fn timer_success(protected_success: bool, explicitly_false: bool) -> bool {
    protected_success && !explicitly_false
}

pub fn timer_check(api_available: bool) -> Option<&'static str> {
    (!api_available).then_some(TIMER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_stops_after_discard_and_cleans_up_after_failed_commit() {
        assert_eq!(publish_next(None, false, false), Some("validate"));
        assert_eq!(publish_next(Some("validate"), true, false), Some("discard"));
        assert_eq!(publish_next(Some("discard"), true, false), None);
        assert_eq!(publish_next(Some("validate"), true, true), Some("snapshot"));
        assert_eq!(publish_next(Some("atomic"), false, false), Some("commit"));
        assert_eq!(publish_next(Some("commit"), true, false), None);
        assert_eq!(publish_next(Some("commit"), false, false), Some("remove"));
        assert_eq!(
            publish_next(Some("remove"), false, false),
            Some("retry_log")
        );
    }

    #[test]
    fn input_validation_differentiates_default_and_invalid_operands() {
        assert_eq!(limit(2, true, None), Some(MAX_BYTES as f64));
        assert_eq!(limit(2, false, None), None);
        assert_eq!(limit(2, false, Some(f64::NAN)), None);
        assert_eq!(
            limit(2, false, Some(MIN_BYTES as f64)),
            Some(MIN_BYTES as f64)
        );
        assert!(!put_value(false, false, Some(2.5)));
        assert!(!put_value(true, true, None));
        assert!(put_value(false, true, None));
        assert_eq!(initial_file(true, false, 0, 64), Some("empty"));
        assert_eq!(initial_file(false, false, 0, 64), None);
    }

    #[test]
    fn batched_actions_keep_effect_order_and_explicit_false_file_state() {
        assert_eq!(construction(false, false), (false, false));
        assert_eq!(construction(true, false), (false, true));
        assert_eq!(construction(true, true), (true, true));
        assert_eq!(after_plan("legacy", true), [Some("legacy_commit"), None]);
        assert_eq!(
            after_plan("legacy", false),
            [Some("legacy_discard"), Some("log")]
        );
        assert_eq!(after_plan("flush", false), [Some("defer"), Some("log")]);
        assert_eq!(after_plan("dispatch", false), [Some("log"), Some("clear")]);
        assert_eq!(after_plan("dispatch", true), [None, None]);
    }
}
