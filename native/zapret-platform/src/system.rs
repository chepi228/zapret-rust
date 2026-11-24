use crate::{
    ProcessIdentity, RunOptions,
    process::{Handle, path_key, wide},
    process_identity, run_owned,
    storage::{hash, no_reparse, read_limited},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::IpHelper::*,
    Networking::{WinHttp::*, WinSock::*},
    System::{Diagnostics::ToolHelp::*, Registry::*},
};

pub(crate) unsafe fn text16(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    unsafe {
        while n < 32768 && *p.add(n) != 0 {
            n += 1;
        }
        OsString::from_wide(std::slice::from_raw_parts(p, n))
            .to_string_lossy()
            .into_owned()
    }
}
pub(crate) fn system_directory() -> Result<PathBuf> {
    let mut directory = vec![0u16; 32768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            directory.as_mut_ptr(),
            directory.len() as u32,
        )
    };
    ensure!(
        length > 0 && (length as usize) < directory.len(),
        "Windows system directory lookup failed"
    );
    Ok(PathBuf::from(OsString::from_wide(
        &directory[..length as usize],
    )))
}
pub(crate) fn system_exe(name: &str) -> Result<PathBuf> {
    ensure!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'),
        "Invalid system executable"
    );
    let p = system_directory()?.join(name);
    no_reparse(&p)?;
    Ok(p)
}
pub(crate) fn native(name: &str, args: &[String], cwd: &Path, timeout: u64) -> Result<Value> {
    let o = RunOptions {
        cwd: Some(cwd.into()),
        timeout: Duration::from_millis(timeout),
        ..Default::default()
    };
    let a = args.iter().map(OsString::from).collect::<Vec<_>>();
    let r = run_owned(&system_exe(name)?, &a, &o)?;
    Ok(
        json!({"exit_code":r.exit_code,"timed_out":r.timed_out,"stdout":String::from_utf8_lossy(&r.stdout),"stderr":String::from_utf8_lossy(&r.stderr),"output_truncated":r.output_truncated}),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub identity: Option<ProcessIdentity>,
}
pub(crate) fn processes() -> Result<Vec<ProcessRow>> {
    scan_processes(|_| true)
}

pub(crate) fn scan_processes(include: impl Fn(&str) -> bool) -> Result<Vec<ProcessRow>> {
    unsafe {
        let snapshot = Handle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut rows = Vec::new();
        let mut ok = Process32FirstW(snapshot.0, &mut e);
        while ok != 0 {
            let name = process_name(&text16(e.szExeFile.as_ptr()));
            if include(&name) {
                rows.push(ProcessRow {
                    pid: e.th32ProcessID,
                    name,
                    identity: process_identity(e.th32ProcessID).ok(),
                });
            }
            ok = Process32NextW(snapshot.0, &mut e);
        }
        let error = GetLastError();
        ensure!(
            error == ERROR_NO_MORE_FILES,
            "Process snapshot is incomplete: Windows error {error}"
        );
        rows.sort_by_key(|r| r.pid);
        Ok(rows)
    }
}
pub(crate) fn zapret_processes() -> Result<Vec<ProcessRow>> {
    scan_processes(|name| name.eq_ignore_ascii_case("winws") || name.eq_ignore_ascii_case("winws2"))
}

pub(crate) fn zapret_image(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some_and(|name| {
            name.eq_ignore_ascii_case("winws.exe") || name.eq_ignore_ascii_case("winws2.exe")
        })
}

fn process_name(executable: &str) -> String {
    executable
        .rsplit_once('.')
        .filter(|(_, extension)| extension.eq_ignore_ascii_case("exe"))
        .map_or(executable, |(name, _)| name)
        .into()
}
pub(crate) struct EngineObservation {
    pub processes: Vec<ProcessIdentity>,
    pub unidentified: Vec<ProcessRow>,
}
pub(crate) fn engine_observation(root: &Path, rows: Vec<ProcessRow>) -> EngineObservation {
    let engine = path_key(&root.join("bin/winws2.exe"));
    let mut processes = Vec::new();
    let mut unidentified = Vec::new();
    for row in rows {
        if let Some(identity) = row.identity.as_ref() {
            if path_key(&identity.executable) == engine {
                processes.push(identity.clone());
            }
        } else if row.name.eq_ignore_ascii_case("winws2") {
            unidentified.push(row);
        }
    }
    EngineObservation {
        processes,
        unidentified,
    }
}
pub(crate) fn owned(root: &Path) -> Result<Vec<ProcessIdentity>> {
    let observation = engine_observation(root, processes()?);
    ensure!(
        observation.unidentified.is_empty(),
        "Владелец процесса winws2 не подтверждён; управление отложено"
    );
    Ok(observation.processes)
}
pub(crate) fn game_name(name: &str) -> bool {
    let n = name.to_lowercase();
    [
        "nba2k",
        "easyanticheat",
        "beservice",
        "fortniteclient",
        "r5apex",
        "gta5",
        "tslgame",
        "valorant",
        "fc2",
    ]
    .iter()
    .any(|x| n.starts_with(x))
        || [
            "dota2",
            "cs2",
            "csgo",
            "rocketleague",
            "eldenring",
            "overwatch",
            "destiny2",
        ]
        .contains(&n.as_str())
}
pub(crate) fn games(root: &Path) -> Result<Vec<ProcessRow>> {
    let settings = zapret_core::read_settings(root)?;
    if !settings.get("game").eq_ignore_ascii_case("selected") {
        return scan_processes(game_name);
    }
    let selected = zapret_core::selected_game_names(settings.get("gameapps"))?;
    scan_processes(|name| game_name(name) || selected.binary_search(&name.to_lowercase()).is_ok())
}
pub(crate) fn reg_string(root: HKEY, key: &str, name: &str) -> Result<Option<String>> {
    unsafe {
        let k = wide(key)?;
        let n = wide(name)?;
        let mut bytes = 0;
        let e = RegGetValueW(
            root,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            null_mut(),
            null_mut(),
            &mut bytes,
        );
        if e == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        ensure!(e == 0, "Registry query: {e}");
        ensure!(bytes <= 131072, "Registry value exceeds size budget");
        let mut data = vec![0u16; (bytes as usize).div_ceil(2)];
        let e = RegGetValueW(
            root,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            null_mut(),
            data.as_mut_ptr().cast(),
            &mut bytes,
        );
        ensure!(e == 0, "Registry read: {e}");
        Ok(Some(
            OsString::from_wide(&data)
                .to_string_lossy()
                .trim_end_matches('\0')
                .into(),
        ))
    }
}
pub(crate) fn reg_dword(root: HKEY, key: &str, name: &str) -> Result<Option<u32>> {
    unsafe {
        let k = wide(key)?;
        let n = wide(name)?;
        let mut bytes = 4;
        let mut v = 0u32;
        let e = RegGetValueW(
            root,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut v as *mut u32).cast(),
            &mut bytes,
        );
        if e == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        ensure!(e == 0, "Registry DWORD: {e}");
        Ok(Some(v))
    }
}
pub(crate) fn reg_set(root: HKEY, key: &str, name: &str, data: &Value) -> Result<()> {
    unsafe {
        let k = wide(key)?;
        let n = wide(name)?;
        let mut h = null_mut();
        let e = RegCreateKeyExW(
            root,
            k.as_ptr(),
            0,
            null(),
            0,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            null(),
            &mut h,
            null_mut(),
        );
        ensure!(e == 0, "Registry open: {e}");
        let result = if let Some(s) = data.as_str() {
            let v = wide(s)?;
            RegSetValueExW(
                h,
                n.as_ptr(),
                0,
                REG_SZ,
                v.as_ptr().cast(),
                (v.len() * 2) as u32,
            )
        } else if let Some(v) = data.as_u64() {
            let v = u32::try_from(v)?;
            RegSetValueExW(h, n.as_ptr(), 0, REG_DWORD, (&v as *const u32).cast(), 4)
        } else {
            RegDeleteValueW(h, n.as_ptr())
        };
        RegCloseKey(h);
        ensure!(
            result == 0 || result == ERROR_FILE_NOT_FOUND,
            "Registry write: {result}"
        );
        Ok(())
    }
}
unsafe fn sock(p: *const SOCKADDR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe {
        match (*p).sa_family {
            AF_INET => {
                let a = &*p.cast::<SOCKADDR_IN>();
                Some(IpAddr::V4(Ipv4Addr::from(a.sin_addr.S_un.S_addr.to_ne_bytes())).to_string())
            }
            AF_INET6 => {
                let a = &*p.cast::<SOCKADDR_IN6>();
                Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.u.Byte)).to_string())
            }
            _ => None,
        }
    }
}
pub(crate) fn adapters() -> Result<Value> {
    unsafe {
        let mut bytes = 16384u32;
        let mut memory = Vec::<usize>::new();
        let mut result = ERROR_BUFFER_OVERFLOW;
        for _ in 0..4 {
            ensure!(bytes <= 8 * 1024 * 1024, "Adapter table exceeds budget");
            memory.resize(
                (bytes as usize + size_of::<usize>() - 1) / size_of::<usize>(),
                0,
            );
            result = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                null(),
                memory.as_mut_ptr().cast(),
                &mut bytes,
            );
            if result != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        ensure!(result == 0, "GetAdaptersAddresses: {result}");
        let mut cur = memory.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut rows = Vec::new();
        let mut count = 0;
        while !cur.is_null() {
            count += 1;
            ensure!(count <= 1024, "Too many adapters");
            let a = &*cur;
            let mut addresses = Vec::new();
            let mut p = a.FirstUnicastAddress;
            while !p.is_null() {
                let x = &*p;
                if let Some(ip) = sock(x.Address.lpSockaddr) {
                    addresses.push(json!({"address":ip,"prefix_length":x.OnLinkPrefixLength}));
                }
                p = x.Next;
            }
            let mut dns = Vec::new();
            let mut p = a.FirstDnsServerAddress;
            while !p.is_null() {
                if let Some(ip) = sock((*p).Address.lpSockaddr) {
                    dns.push(ip);
                }
                p = (*p).Next;
            }
            let mut gateways = Vec::new();
            let mut p = a.FirstGatewayAddress;
            while !p.is_null() {
                if let Some(ip) = sock((*p).Address.lpSockaddr) {
                    gateways.push(ip);
                }
                p = (*p).Next;
            }
            addresses.sort_by_key(ToString::to_string);
            gateways.sort();
            let name = text16(a.FriendlyName);
            let description = text16(a.Description);
            let lower = format!("{name} {description}").to_lowercase();
            let tun = [
                "wintun",
                "tap-windows",
                "wireguard",
                "sing-box",
                "clash",
                "mihomo",
                "meta tunnel",
                "hiddify",
                "happ",
                "amneziawg",
                "openvpn",
                "xray",
            ]
            .iter()
            .any(|x| lower.contains(x))
                || lower
                    .split([' ', '-', '_'])
                    .any(|x| x == "tun" || x == "wg");
            rows.push(json!({"id":crate::wifi::interface_id(&a.Luid),"index":a.Anonymous1.Anonymous.IfIndex,"ipv6_index":a.Ipv6IfIndex,"name":name,"description":description,"up":a.OperStatus==1,"if_type":a.IfType,"mtu":a.Mtu,"addresses":addresses,"dns_servers":dns,"dns_suffix":text16(a.DnsSuffix),"gateways":gateways,"ipv4_metric":a.Ipv4Metric,"ipv6_metric":a.Ipv6Metric,"tun":tun}));
            cur = a.Next;
        }
        rows.sort_by_key(|x| x["index"].as_u64());
        Ok(json!(rows))
    }
}
fn routes() -> Result<Value> {
    unsafe {
        let mut table = null_mut();
        let e = GetIpForwardTable2(AF_UNSPEC, &mut table);
        ensure!(e == 0, "GetIpForwardTable2: {e}");
        struct Table(*mut MIB_IPFORWARD_TABLE2);
        impl Drop for Table {
            fn drop(&mut self) {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
        let table = Table(table);
        ensure!((*table.0).NumEntries <= 65536, "Route table exceeds budget");
        let rows =
            std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize);
        let mut out = Vec::new();
        for r in rows {
            let destination = sock((&r.DestinationPrefix.Prefix as *const SOCKADDR_INET).cast());
            let next = sock((&r.NextHop as *const SOCKADDR_INET).cast());
            out.push(json!({"interface_index":r.InterfaceIndex,"destination":destination,"prefix_length":r.DestinationPrefix.PrefixLength,"next_hop":next,"metric":r.Metric,"protocol":r.Protocol}));
        }
        out.sort_by_key(ToString::to_string);
        Ok(json!(out))
    }
}
pub(crate) fn tcp_table() -> Result<Vec<Value>> {
    unsafe {
        let header_bytes = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let mut bytes = 0;
        GetExtendedTcpTable(
            null_mut(),
            &mut bytes,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        ensure!(
            (header_bytes..=8 * 1024 * 1024).contains(&(bytes as usize)),
            "Invalid TCP table size"
        );
        let mut mem = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        let e = GetExtendedTcpTable(
            mem.as_mut_ptr().cast(),
            &mut bytes,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        ensure!(e == 0, "GetExtendedTcpTable: {e}");
        let returned_bytes = bytes as usize;
        let count = mem.as_ptr().cast::<u32>().read() as usize;
        ensure!(
            returned_bytes >= header_bytes
                && returned_bytes <= mem.len() * size_of::<usize>()
                && count <= (returned_bytes - header_bytes) / size_of::<MIB_TCPROW_OWNER_PID>(),
            "Invalid TCP row count"
        );
        let rows = std::slice::from_raw_parts(
            mem.as_ptr()
                .cast::<u8>()
                .add(header_bytes)
                .cast::<MIB_TCPROW_OWNER_PID>(),
            count,
        );
        Ok(rows.iter().map(|r|json!({"pid":r.dwOwningPid,"state":r.dwState,"state_known":(1..=12).contains(&r.dwState),"local_address":Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(),"local_port":u16::from_be(r.dwLocalPort as u16),"remote_address":Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()).to_string(),"remote_port":u16::from_be(r.dwRemotePort as u16)})).collect())
    }
}
pub(crate) fn tcp_connections() -> Result<Value> {
    let observed = crate::time_filetime();
    let mut rows = tcp_table()?;
    let identities = rows
        .iter()
        .filter_map(|row| row["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|pid| {
            let identity = process_identity(pid)
                .ok()
                .filter(|identity| identity.created_filetime <= observed);
            (pid, identity)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut ownership_known = true;
    for row in &mut rows {
        let identity = row["pid"]
            .as_u64()
            .and_then(|pid| identities.get(&(pid as u32)))
            .and_then(Option::as_ref);
        ownership_known &= identity.is_some();
        row["identity"] = serde_json::to_value(identity)?;
    }
    let states_known = rows.iter().all(|row| row["state_known"] == true);
    Ok(
        json!({"known":true,"family":"IPv4","observed_filetime":observed,"ownership_known":ownership_known,"states_known":states_known,"connections":rows}),
    )
}
fn redact(value: &str) -> String {
    if let Some(at) = value.rfind('@') {
        let prefix = value.find("://").map_or("", |p| &value[..p + 3]);
        format!("{prefix}<redacted>@{}", &value[at + 1..])
    } else {
        value.into()
    }
}

/// The saved WinINET proxy address is available even while the proxy is disabled.
pub fn configured_proxy_server() -> Result<Option<String>> {
    reg_string(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyServer",
    )
}

pub(crate) fn proxy() -> Result<Value> {
    unsafe {
        let mut config: WINHTTP_CURRENT_USER_IE_PROXY_CONFIG = zeroed();
        let known = WinHttpGetIEProxyConfigForCurrentUser(&mut config) != 0
            || GetLastError() == ERROR_FILE_NOT_FOUND;
        let proxy = text16(config.lpszProxy);
        let pac = text16(config.lpszAutoConfigUrl);
        let bypass = text16(config.lpszProxyBypass);
        let data = json!({"auto_detect":config.fAutoDetect!=0,"proxy":proxy,"pac":pac,"bypass":bypass,"environment":std::env::vars().filter(|(k,_)|["http_proxy","https_proxy","all_proxy","no_proxy"].contains(&k.to_lowercase().as_str())).collect::<std::collections::BTreeMap<_,_>>()});
        for p in [
            config.lpszProxy,
            config.lpszAutoConfigUrl,
            config.lpszProxyBypass,
        ] {
            if !p.is_null() {
                GlobalFree(p.cast());
            }
        }
        let ports = tcp_table()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                r["state"] == 2
                    && r["local_address"]
                        .as_str()
                        .is_some_and(|x| x.starts_with("127."))
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"known":known,"auto_detect":data["auto_detect"],"proxy":redact(&proxy),"pac":redact(&pac),"bypass":bypass,"environment_names":data["environment"].as_object().unwrap().keys().collect::<Vec<_>>(),"configuration_hash":hash(serde_json::to_string(&data)?.as_bytes()),"loopback_listeners":ports}),
        )
    }
}
// Keep the full Windows tables for diagnostics. Rank measurements identify the
// path to remote services, which does not change when an IPv6 privacy IID rotates.
fn network_key_parts(data: &Value) -> Value {
    let mut interfaces = Vec::new();
    let mut resolvers = Vec::new();
    for row in data["adapters"].as_array().into_iter().flatten() {
        if row["up"] != true || row["if_type"] == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let mut addresses = std::collections::BTreeSet::new();
        for entry in row["addresses"].as_array().into_iter().flatten() {
            let Some(ip) = entry["address"].as_str() else {
                continue;
            };
            let cidr = format!("{ip}/{}", entry["prefix_length"]);
            let address = match ip.parse::<Ipv6Addr>() {
                Ok(v6) if v6.is_unicast_link_local() => continue,
                Ok(_) => zapret_core::normalize_ip_network(&cidr).unwrap_or(cidr),
                Err(_) => cidr,
            };
            addresses.insert(address);
        }
        interfaces.push(json!([
            row["id"],
            row["index"],
            row["ipv6_index"],
            row["if_type"],
            row["ipv4_metric"],
            row["ipv6_metric"],
            row["mtu"],
            row["gateways"],
            addresses
        ]));
        resolvers.push(json!([row["index"], row["dns_suffix"], row["dns_servers"]]));
    }
    interfaces.sort_by_cached_key(ToString::to_string);
    resolvers.sort_by_cached_key(ToString::to_string);
    let routes: Vec<_> = data["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|route| {
            let ip = route["destination"]
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok());
            let local = route["protocol"] == MIB_IPPROTO_LOCAL;
            match ip {
                Some(ip) if ip.is_multicast() || ip.is_loopback() => false,
                Some(IpAddr::V6(ip)) => {
                    !ip.is_unicast_link_local() && !(local && route["prefix_length"] == 128)
                }
                Some(IpAddr::V4(ip)) => {
                    !ip.is_link_local() && !(local && route["prefix_length"] == 32)
                }
                None => true,
            }
        })
        .collect();
    let mut profiles: Vec<_> = data["profiles"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| json!([p["id"], p["category"]]))
        .collect();
    profiles.sort_by_cached_key(ToString::to_string);
    json!({"interfaces":hash(json!(interfaces).to_string().as_bytes()),
        "dns":hash(json!(resolvers).to_string().as_bytes()), "routes":hash(json!(routes).to_string().as_bytes()),
        "profiles":hash(json!(profiles).to_string().as_bytes()),"proxy":data["proxy_configuration_hash"]})
}

pub(crate) fn network(root: &Path) -> Result<Value> {
    let adapter = adapters();
    let routes = routes();
    let proxy = proxy();
    let profiles = network_profiles();
    let unavailable: Vec<_> = [
        ("interfaces", adapter.is_ok()),
        ("routes", routes.is_ok()),
        ("profiles", profiles.is_ok()),
        ("proxy", proxy.as_ref().is_ok_and(|p| p["known"] == true)),
    ]
    .into_iter()
    .filter_map(|(name, ok)| (!ok).then_some(name))
    .collect();
    let known = unavailable.is_empty();
    let profiles_error = profiles.as_ref().err().map(ToString::to_string);
    let data = json!({"adapters":adapter.unwrap_or(json!([])),"routes":routes.unwrap_or(json!([])),"profiles":profiles.unwrap_or(json!([])),"proxy_configuration_hash":proxy.as_ref().ok().map(|p|p["configuration_hash"].clone())});
    let parts = network_key_parts(&data);
    let key = hash(serde_json::to_string(&parts)?.as_bytes());
    let settings_hash = read_limited(&root.join("runtime/settings.ini"), 1024 * 1024)
        .ok()
        .map(|b| hash(&b));
    let wifi_event = crate::wifi::for_adapters(&data["adapters"]);
    let observation = engine_observation(root, processes()?);
    let ownership_known = observation.unidentified.is_empty();
    Ok(
        json!({"schema":"zapret-native-network-v1","known":known,"key_parts":parts,"unavailable":unavailable,"key":if known{key.clone()}else{String::new()},"stable_key":if known{key}else{String::new()},"adapters":data["adapters"],"routes":data["routes"],"profiles":data["profiles"],"profiles_error":profiles_error,"proxy":proxy.unwrap_or(json!({"known":false})),"processes":observation.processes,"ownership_known":ownership_known,"unidentified_engine_processes":observation.unidentified,"settings_hash":settings_hash,"wifi_event":wifi_event}),
    )
}
fn network_profiles() -> Result<Value> {
    crate::profiles::read()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network_sample() -> Value {
        json!({"adapters":[{"index":4,"if_type":71,"id":"wifi","up":true,"mtu":1500,
            "dns_servers":["192.0.2.53","192.0.2.54"],"ipv6_metric":25,"gateways":["fe80::1"],
            "addresses":[{"address":"2001:db8::3","prefix_length":64}]}],
            "routes":[{"interface_index":4,"destination":"::","prefix_length":0,"next_hop":"fe80::1","metric":20,"protocol":3},
            {"interface_index":4,"destination":"2001:db8::3","prefix_length":128,"next_hop":"::","protocol":2}],
            "profiles":[{"id":"home","category":1,"name":"Wi-Fi"}],"proxy_configuration_hash":"proxy-a"})
    }

    #[test]
    fn rotating_ipv6_addresses_and_local_routes_keep_the_same_network() {
        let mut sample = network_sample();
        let before = network_key_parts(&sample);
        sample["adapters"][0]["addresses"][0]["address"] = json!("2001:db8::5");
        sample["routes"][1]["destination"] = json!("2001:db8::5");
        sample["adapters"][0]["addresses"]
            .as_array_mut()
            .unwrap()
            .push(json!({"address":"2001:db8::7","prefix_length":64}));
        sample["adapters"]
            .as_array_mut()
            .unwrap()
            .push(json!({"index":9,"up":false,"name":"Bluetooth"}));
        sample["profiles"][0]["name"] = json!("Wi-Fi 2");
        assert_eq!(before, network_key_parts(&sample));
    }

    #[test]
    fn genuine_path_and_configuration_changes_remain_visible() {
        let sample = network_sample();
        let before = network_key_parts(&sample);
        for (pointer, replacement, part) in [
            ("/routes/0/next_hop", json!("fe80::7"), "routes"),
            ("/routes/1/protocol", json!(3), "routes"), // split-tunnel host route
            (
                "/adapters/0/addresses/0/address",
                json!("2001:db8:1::3"),
                "interfaces",
            ),
            ("/adapters/0/ipv6_metric", json!(8), "interfaces"),
            (
                "/adapters/0/dns_servers",
                json!(["192.0.2.54", "192.0.2.53"]),
                "dns",
            ),
            ("/profiles/0/id", json!("office"), "profiles"),
            ("/proxy_configuration_hash", json!("proxy-b"), "proxy"),
        ] {
            let mut changed = sample.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert_ne!(before[part], network_key_parts(&changed)[part], "{pointer}");
        }
    }
    #[test]
    fn process_snapshot_distinguishes_unknown_engine_identity_from_foreign_processes() {
        assert_eq!(process_name("WINWS2.EXE"), "WINWS2");
        assert_eq!(process_name("name.exe.exe"), "name.exe");
        assert_eq!(process_name("программа.exe"), "программа");
        let root = Path::new("C:/fixture");
        let identity = ProcessIdentity {
            pid: 42,
            created_filetime: 100,
            executable: root.join("bin/winws2.exe"),
        };
        let rows = vec![
            ProcessRow {
                pid: 42,
                name: "winws2".into(),
                identity: Some(identity.clone()),
            },
            ProcessRow {
                pid: 43,
                name: "WINWS2".into(),
                identity: None,
            },
            ProcessRow {
                pid: 44,
                name: "winws2".into(),
                identity: Some(ProcessIdentity {
                    pid: 44,
                    executable: "C:/other/winws2.exe".into(),
                    ..identity.clone()
                }),
            },
            ProcessRow {
                pid: 45,
                name: "system".into(),
                identity: None,
            },
        ];
        let observation = engine_observation(root, rows);
        assert_eq!(observation.processes, vec![identity]);
        assert_eq!(observation.unidentified.len(), 1);
        assert_eq!(observation.unidentified[0].pid, 43);
    }
}
