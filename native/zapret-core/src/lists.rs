use crate::{Settings, atomic_write, read_text};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

pub fn list_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(read_text(path, 32 * 1024 * 1024)?
        .lines()
        .filter_map(|line| {
            let value = line.split(['#', ';']).next().unwrap_or("").trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect())
}
pub fn normalize_domain(text: &str) -> Result<String> {
    let text = text.trim().trim_end_matches('.');
    ensure!(
        !text.is_empty()
            && !text.chars().any(|c| c.is_whitespace() || c.is_control())
            && !text.contains(['/', ':', '*', '@', '\\', '[', ']']),
        "Invalid domain"
    );
    ensure!(
        text.parse::<IpAddr>().is_err(),
        "An IP address is not a domain"
    );
    let value = idna::domain_to_ascii(text)
        .map_err(|e| anyhow::anyhow!("Invalid international domain: {e:?}"))?
        .to_ascii_lowercase();
    ensure!(
        value.len() <= 253 && value.contains('.'),
        "Domain must be a full hostname"
    );
    ensure!(
        value.split('.').all(|label| !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "Invalid domain label"
    );
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpNetwork {
    pub address: IpAddr,
    pub prefix: u8,
}
impl IpNetwork {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (address, prefix) = text
            .split_once('/')
            .map_or((text, None), |(a, p)| (a, Some(p)));
        let address = address.parse::<IpAddr>()?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.map(str::parse::<u8>).transpose()?.unwrap_or(bits);
        ensure!(prefix <= bits, "Invalid network prefix");
        let address = match address {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(
                u32::from(ip)
                    & if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    },
            )),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
                u128::from(ip)
                    & if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    },
            )),
        };
        Ok(Self { address, prefix })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}
impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}
pub fn normalize_ip_network(text: &str) -> Result<String> {
    Ok(IpNetwork::parse(text)?.to_string())
}
/// Legacy public-address policy used by the game scanner; documentation ranges remain representable.
pub fn is_public_ip(text: &str) -> bool {
    text.parse::<IpAddr>().is_ok_and(is_public_address)
}
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            !(ip.is_loopback()
                || b[0] == 0
                || b[0] == 10
                || b[0] >= 224
                || (b[0] == 172 && (16..=31).contains(&b[1]))
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && (64..=127).contains(&b[1]))
                || (b[0] == 198 && [18, 19].contains(&b[1])))
        }
        IpAddr::V6(ip) => {
            let b = ip.octets();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || b[0] == 0xff
                || (b[0] == 0xfe && b[1] & 0xc0 == 0x80)
                || (b[0] == 0xfe && b[1] & 0xc0 == 0xc0)
                || b[0] & 0xfe == 0xfc)
        }
    }
}
pub fn normalize_list(text: &str, ipset: bool) -> Result<Vec<String>> {
    let mut values = BTreeSet::new();
    for line in text.lines() {
        let value = line.split(['#', ';']).next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        values.insert(if ipset {
            normalize_ip_network(value)?
        } else {
            normalize_domain(value)?
        });
    }
    Ok(values.into_iter().collect())
}
pub fn save_list(path: &Path, values: &[String], ipset: bool) -> Result<()> {
    let values = normalize_list(&values.join("\n"), ipset)?;
    atomic_write(path, format!("{}\r\n", values.join("\r\n")).as_bytes())
}
pub fn remove_autolist_ips(root: &Path) -> Result<Vec<String>> {
    let path = root.join("lists/autohostlist.txt");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = read_text(&path, 32 * 1024 * 1024)?;
    let ips: Vec<_> = list_lines(&path)?
        .into_iter()
        .filter(|line| line.parse::<Ipv4Addr>().is_ok() || line.contains(':'))
        .collect();
    if ips.is_empty() {
        return Ok(ips);
    }
    let keep: Vec<_> = text
        .lines()
        .filter(|line| !ips.iter().any(|ip| ip == line.trim()))
        .collect();
    atomic_write(&path, format!("{}\r\n", keep.join("\r\n")).as_bytes())?;
    Ok(ips)
}
pub fn prepare_runtime(root: &Path, settings: &Settings) -> Result<()> {
    std::fs::create_dir_all(root.join("runtime/ring"))?;
    if settings.get("game").eq_ignore_ascii_case("selected") {
        for game in crate::selected_game_names(settings.get("gameapps"))? {
            let path = root.join("lists").join(crate::game_server_list(&game));
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    write!(file, "# {game}.exe\r\n203.0.113.113/32\r\n")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    atomic_write(
        &root.join("runtime/ipset-any.txt"),
        b"0.0.0.0/0\r\n::/0\r\n",
    )?;
    let auto = root.join("lists/autohostlist.txt");
    if !auto.exists() {
        atomic_write(
            &auto,
            "# Автосписок: сайты, которые три раза подряд не открылись\r\n".as_bytes(),
        )?;
    }
    remove_autolist_ips(root)?;
    let debug = root.join("runtime/autohostlist-debug.log");
    if debug.exists() && debug.metadata()?.len() > 1024 * 1024 {
        // Copy the complete old log before replacing; a failed rotation retains recoverable evidence.
        atomic_write(
            &root.join("runtime/autohostlist-debug.log.old"),
            &crate::read_bounded(&debug, 128 * 1024 * 1024)?,
        )?;
        atomic_write(&debug, b"")?;
    }
    Ok(())
}
