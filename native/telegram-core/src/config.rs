use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[derive(Clone)]
pub struct Config {
    pub(crate) listen: SocketAddr,
    pub(crate) secret: [u8; 16],
    pub(crate) dc_ips: BTreeMap<u16, Ipv4Addr>,
    pub(crate) buffer_size: usize,
    pub(crate) pool_size: usize,
    pub(crate) verbose: bool,
    pub(crate) cfproxy: bool,
    pub(crate) h2: bool,
    pub(crate) no_secure: bool,
    pub(crate) force_test_dc: bool,
    pub(crate) cf_domains: Vec<String>,
    pub(crate) worker_domains: Vec<String>,
}

impl Config {
    /// Parse the stored upstream JSON. UI settings and unknown application fields
    /// remain the caller's property; recognized transport options are strict.
    pub fn from_value(value: &Value) -> Result<Self> {
        ensure!(
            value.is_object(),
            "Telegram configuration must be an object"
        );
        let host = string(value, "host", "127.0.0.1")?;
        let ip = match host {
            "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1" => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            _ => bail!("Telegram host must be a loopback address"),
        };
        let port = number(value, "port", 1443, 1, 65535)? as u16;
        let text = string(value, "secret", "")?;
        ensure!(
            text.len() == 32 && text.is_ascii(),
            "Telegram secret must contain 32 hexadecimal characters"
        );
        let mut secret = [0u8; 16];
        for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            secret[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)
                .context("Telegram secret must contain 32 hexadecimal characters")?;
        }
        let mut dc_ips = BTreeMap::new();
        if let Some(entries) = value.get("dc_ip") {
            let entries = entries
                .as_array()
                .context("dc_ip must be an array of DC:IPv4 strings")?;
            ensure!(entries.len() <= 6, "dc_ip has too many entries");
            for entry in entries {
                let entry = entry.as_str().context("dc_ip entries must be strings")?;
                let (dc, ip) = entry
                    .split_once(':')
                    .context("dc_ip must use DC:IPv4 format")?;
                let dc: u16 = dc.parse().context("dc_ip has an invalid DC number")?;
                ensure!(
                    supported_dc(dc, false),
                    "dc_ip has an unsupported DC number"
                );
                let ip = ip
                    .parse::<Ipv4Addr>()
                    .context("dc_ip has an invalid IPv4 address")?;
                ensure!(
                    !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
                    "dc_ip must identify one destination"
                );
                ensure!(
                    dc_ips.insert(dc, ip).is_none(),
                    "dc_ip contains duplicate DC numbers"
                );
            }
        } else {
            dc_ips.insert(2, Ipv4Addr::new(149, 154, 167, 220));
            dc_ips.insert(4, Ipv4Addr::new(149, 154, 167, 220));
        }
        ensure!(
            string(value, "fake_tls_domain", "")?.is_empty(),
            "fake_tls_domain is not supported by the native Telegram core"
        );
        ensure!(
            string(value, "fake_tls", "")?.is_empty(),
            "fake_tls is not supported by the native Telegram core"
        );
        ensure!(
            !boolean(value, "proxy_protocol", false)?,
            "proxy_protocol is not supported by the native Telegram core"
        );
        let cf_enabled = boolean(value, "cfproxy_user_domain_enabled", true)?;
        let worker_enabled = boolean(value, "cfproxy_worker_enabled", true)?;
        let cf_domains = domain_aliases(
            value,
            &[
                "cfproxy_domains",
                "cfproxy_user_domains",
                "cfproxy_user_domain",
            ],
        )?;
        let worker_domains =
            domain_aliases(value, &["cfproxy_worker_domains", "cfproxy_worker_domain"])?;
        Ok(Self {
            listen: SocketAddr::new(ip, port),
            secret,
            dc_ips,
            buffer_size: number(value, "buf_kb", 256, 16, 4096)? as usize * 1024,
            pool_size: number(value, "pool_size", 4, 0, 32)? as usize,
            verbose: boolean(value, "verbose", false)?,
            cfproxy: boolean(value, "cfproxy", true)?,
            h2: boolean(value, "h2", true)?,
            no_secure: boolean(value, "no_secure", false)?,
            force_test_dc: boolean(value, "force_test_dc", false)?,
            cf_domains: if cf_enabled && !cf_domains.is_empty() {
                cf_domains
            } else {
                default_domains()
            },
            worker_domains: if worker_enabled {
                worker_domains
            } else {
                Vec::new()
            },
        })
    }
    pub fn listener_addr(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn h2_enabled(&self) -> bool {
        self.h2 && self.cfproxy && !self.no_secure && !self.force_test_dc
    }
}

fn string<'a>(value: &'a Value, key: &str, default: &'a str) -> Result<&'a str> {
    value.get(key).map_or(Ok(default), |v| {
        v.as_str()
            .with_context(|| format!("{key} must be a string"))
    })
}
fn boolean(value: &Value, key: &str, default: bool) -> Result<bool> {
    value.get(key).map_or(Ok(default), |v| {
        v.as_bool()
            .with_context(|| format!("{key} must be a boolean"))
    })
}
fn number(value: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let result = value.get(key).map_or(Ok(default), |v| {
        v.as_u64()
            .with_context(|| format!("{key} must be an unsigned integer"))
    })?;
    ensure!(
        (min..=max).contains(&result),
        "{key} must be between {min} and {max}"
    );
    Ok(result)
}
fn domain_aliases(value: &Value, keys: &[&str]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for key in keys {
        let Some(value) = value.get(*key) else {
            continue;
        };
        let entries: Vec<&str> = match value {
            Value::String(s) => vec![s.as_str()],
            Value::Array(entries) => entries
                .iter()
                .map(|v| {
                    v.as_str()
                        .with_context(|| format!("{key} entries must be strings"))
                })
                .collect::<Result<_>>()?,
            _ => bail!("{key} must be a domain string or array"),
        };
        for entry in entries {
            for domain in entry
                .split(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';')
                .filter(|s| !s.is_empty())
            {
                ensure!(
                    valid_domain(domain),
                    "{key} must contain DNS names without URLs, ports or paths"
                );
                let domain = domain.to_ascii_lowercase();
                if !result.contains(&domain) {
                    result.push(domain);
                }
                ensure!(result.len() <= 64, "{key} contains too many domains");
            }
        }
    }
    Ok(result)
}
fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').count() >= 2
        && domain
            .rsplit('.')
            .next()
            .is_some_and(|s| s.len() >= 2 && s.bytes().any(|b| b.is_ascii_alphabetic()))
        && domain.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub(crate) fn supported_dc(dc: u16, test: bool) -> bool {
    if test {
        (1..=3).contains(&dc)
    } else {
        (1..=5).contains(&dc) || dc == 203
    }
}

// Bundled Flowseal 1.11.4 domain pool; no unverified remote configuration is
// executed. The user can override these DNS names in the upstream JSON.
fn default_domains() -> Vec<String> {
    [
        "virkgj.com",
        "vmmzovy.com",
        "mkuosckvso.com",
        "zaewayzmplad.com",
        "twdmbzcm.com",
        "awzwsldi.com",
        "clngqrflngqin.com",
        "tjacxbqtj.com",
        "bxaxtxmrw.com",
        "dmohrsgmohcrwb.com",
        "vwbmtmoi.com",
        "khgrre.com",
        "ulihssf.com",
        "tmhqsdqmfpmk.com",
        "xwuwoqbm.com",
        "orgcnunpj.com",
        "zhkuldz.com",
        "zypoljnslxa.com",
        "efabnxaowuzs.com",
        "zaftuzsftqdq.com",
    ]
    .into_iter()
    .map(|s| {
        let prefix = s.strip_suffix(".com").unwrap();
        let shift = prefix.len() as u8;
        let mut decoded: String = prefix
            .bytes()
            .map(|b| (b'a' + (b - b'a' + 26 - shift) % 26) as char)
            .collect();
        decoded.push_str(".co.uk");
        decoded
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn valid() -> Value {
        json!({"secret":"000102030405060708090a0b0c0d0e0f"})
    }

    #[test]
    fn default_listener_is_local_and_unknown_settings_are_preserved_by_caller() {
        let mut value = valid();
        value["custom"] = json!({"x":true});
        let config = Config::from_value(&value).unwrap();
        assert_eq!(config.listener_addr(), "127.0.0.1:1443".parse().unwrap());
        assert_eq!(value["custom"]["x"], true);
    }

    #[test]
    fn invalid_recognized_settings_are_rejected() {
        for (key, value) in [
            ("host", json!("0.0.0.0")),
            ("secret", json!("ddnothex")),
            ("dc_ip", json!(["2:not-an-ip"])),
            ("dc_ip", json!(["99:1.2.3.4"])),
            ("pool_size", json!(-1)),
            ("pool_size", json!(1000)),
            ("buf_kb", json!(0)),
            ("buf_kb", json!("256")),
            ("h2", json!("true")),
            ("cfproxy", json!(1)),
            ("no_secure", json!("false")),
            ("force_test_dc", json!(null)),
            ("cfproxy_domains", json!(["https://example.org/evil"])),
            ("cfproxy_worker_domains", json!(["user:pass@example.org"])),
            ("fake_tls_domain", json!("example.org")),
            ("proxy_protocol", json!(true)),
        ] {
            let mut config = valid();
            config[key] = value;
            assert!(
                Config::from_value(&config).is_err(),
                "accepted invalid {key}"
            );
        }
    }
}
