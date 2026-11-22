use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr};

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
