use super::{Row, hostname};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const FAILURE_LIMIT: usize = 16;

#[derive(Default)]
pub(super) struct Plan {
    pub first: BTreeSet<String>,
    pub sampled: BTreeSet<String>,
    pub reserve: BTreeSet<String>,
}

impl Plan {
    pub(super) fn new(
        rows: &[Row],
        clean: &BTreeMap<String, f64>,
        hopeless: &BTreeSet<String>,
        can_reduce_parallelism: bool,
    ) -> Self {
        let mut plan = Self::default();
        let mut failures = Vec::new();
        for row in rows {
            let failed = matches!(row.state.as_str(), "FAIL" | "FREEZE");
            if row.group == "Clean" {
                if row.dns_failure()
                    || failed
                    || clean
                        .get(&row.name)
                        .is_some_and(|base| row.state == "OK" && !row.healthy_control(Some(*base)))
                {
                    plan.first.insert(row.key());
                }
            } else if !hopeless.contains(&row.key()) {
                if row.dns_failure() {
                    plan.first.insert(row.key());
                } else if failed {
                    failures.push(row);
                }
            }
        }
        if failures.len() <= FAILURE_LIMIT {
            plan.first.extend(failures.into_iter().map(Row::key));
            return plan;
        }
        if !can_reduce_parallelism {
            return plan;
        }
        // An error page, an invalid file or a certificate rejection cannot confirm
        // congestion. Choose different services AND hosts, independent of worker order.
        failures.retain(|r| {
            r.state == "FAIL" && matches!(r.termination.as_str(), "Timeout" | "TcpFailure")
        });
        failures.sort_by_cached_key(|r| (r.group == "DPI", r.key()));
        let mut groups = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        for row in failures {
            let key = row.key();
            if plan.sampled.len() < 4
                && !groups.contains(&row.group)
                && hostname(&row.url).is_some_and(|host| hosts.insert(host))
            {
                groups.insert(row.group.clone());
                plan.sampled.insert(key.clone());
                plan.first.insert(key);
            } else {
                plan.reserve.insert(key);
            }
        }
        plan
    }

    pub(super) fn expand(&self, observations: &[Row]) -> bool {
        !self.reserve.is_empty()
            && observations
                .iter()
                .filter(|r| {
                    r.state == "OK" && r.code.starts_with('2') && self.sampled.contains(&r.key())
                })
                .map(Row::key)
                .collect::<BTreeSet<_>>()
                .len()
                >= 2
    }
}
