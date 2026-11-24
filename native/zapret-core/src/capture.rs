use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr};

/// WinDivert expands each range to a separate predicate on every captured direction.
pub(crate) fn merged_ports(base: &str, game: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    let mut ranges =
        crate::parse_port_list(&format!("{base},{game}")).context("Invalid capture ports")?;
    ranges.sort_unstable();
    let mut merged = Vec::<(u16, u16)>::new();
    for (lo, hi) in ranges {
        match merged.last_mut() {
            Some((_, end)) if lo <= end.saturating_add(1) => *end = (*end).max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    Ok(merged
        .into_iter()
        .map(|(lo, hi)| {
            if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(","))
}

#[cfg(test)]
mod port_tests {
    use super::merged_ports;

    #[test]
    fn capture_ranges_merge_duplicates_and_neighbours_without_filling_gaps() {
        assert_eq!(
            merged_ports("80,443,2053,8443", "1024-65535").unwrap(),
            "80,443,1024-65535"
        );
        assert_eq!(
            merged_ports("65535,15-20,3", "1-2,4,22,19-21,65534-65535").unwrap(),
            "1-4,15-22,65534-65535"
        );
        assert!(merged_ports("80", "65536").is_err());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureExclusion {
    pub count: usize,
    pub cidrs: Vec<String>,
    pub ip_argument: String,
    pub filter: String,
}
/// Only a small canonical aligned IPv4 set may be snapshotted into both engine and kernel filters.
pub fn capture_exclusion(lines: &[String]) -> Option<CaptureExclusion> {
    let mut cidrs = Vec::new();
    let mut tests = Vec::new();
    let mut seen = HashSet::new();
    for line in lines {
        let line = line.split('#').next()?.trim();
        if line.is_empty() {
            continue;
        }
        let (host, prefix) = line.split_once('/')?;
        let ip = host.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        if ip.to_string() != host
            || prefix == 0
            || prefix > 32
            || !line.ends_with(&format!("/{prefix}"))
        {
            return None;
        }
        let n = u32::from(ip) as u64;
        let size = 1u64 << (32 - prefix);
        if n % size != 0 {
            return None;
        }
        if !seen.insert(line.to_owned()) {
            continue;
        }
        cidrs.push(line.to_owned());
        if cidrs.len() > 32 {
            return None;
        }
        tests.push(if size == 1 {
            format!("ip.DstAddr!={ip}")
        } else {
            format!(
                "(ip.DstAddr<{ip} or ip.DstAddr>{})",
                Ipv4Addr::from((n + size - 1) as u32)
            )
        });
    }
    if cidrs.is_empty() {
        return None;
    }
    let dst = tests.join(" and ");
    let src = dst.replace("ip.DstAddr", "ip.SrcAddr");
    Some(CaptureExclusion {
        count: cidrs.len(),
        ip_argument: format!("--ipset-exclude-ip={}", cidrs.join(",")),
        cidrs,
        filter: format!(
            "(not outbound or (not tcp and not udp) or not ip or ({dst})) and (not inbound or not tcp or not ip or ({src}))"
        ),
    })
}
