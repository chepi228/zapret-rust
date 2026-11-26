use crate::{diagnostic as d, http};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    task::JoinSet,
    time::{Instant, timeout},
};

#[cfg(windows)]
fn query_no_hosts(host: String, ipv6: bool) -> Result<Vec<String>> {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::{DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS},
        NetworkManagement::Dns::*,
    };
    let name: Vec<u16> = host.encode_utf16().chain(Some(0)).collect();
    let mut records = null_mut();
    // The list is returned by dnsapi and freed with its own allocator, never Rust's allocator.
    let status = unsafe {
        DnsQuery_W(
            name.as_ptr(),
            if ipv6 { 28 } else { 1 },
            DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT,
            null_mut(),
            &mut records,
            null_mut(),
        )
    };
    struct Records(*mut DNS_RECORDA);
    impl Drop for Records {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DnsFree(self.0.cast(), DnsFreeRecordList);
                }
            }
        }
    }
    let _owner = Records(records);
    if status == DNS_ERROR_RCODE_NAME_ERROR || status == DNS_INFO_NO_RECORDS as u32 {
        return Ok(Vec::new());
    }
    if status != 0 {
        bail!("Windows DNS query status {status}")
    }
    let mut values = Vec::new();
    let mut count = 0;
    while !records.is_null() && count < 256 {
        let record = unsafe { &*records };
        // Only answer records (or system cache records without a section)
        // describe this lookup. Additional records may be DNS server addresses.
        let section = unsafe { record.Flags.DW } & 3;
        if section < DnsSectionAuthority as u32 && !ipv6 && record.wType == 1 {
            values
                .push(unsafe { Ipv4Addr::from(record.Data.A.IpAddress.to_ne_bytes()) }.to_string())
        } else if section < DnsSectionAuthority as u32 && ipv6 && record.wType == 28 {
            values.push(unsafe { Ipv6Addr::from(record.Data.AAAA.Ip6Address.IP6Byte) }.to_string())
        }
        records = record.pNext;
        count += 1;
        if values.len() >= 64 {
            break;
        }
    }
    Ok(values)
}
#[cfg(windows)]
async fn system_family(host: &str, timeout_ms: u64, ipv6: bool) -> Result<Vec<String>> {
    let host = host.to_owned();
    timeout(
        Duration::from_millis(timeout_ms),
        tokio::task::spawn_blocking(move || query_no_hosts(host, ipv6)),
    )
    .await??
}

#[cfg(windows)]
fn system_answers(v4: Result<Vec<String>>, v6: Result<Vec<String>>, elapsed_ms: f64) -> d::Dns {
    let mut addresses = Vec::new();
    let mut errors = Vec::new();
    for (family, result) in [("A", v4), ("AAAA", v6)] {
        match result {
            Ok(mut values) => addresses.append(&mut values),
            Err(error) => errors.push(format!("{family}: {error:#}")),
        }
    }
    addresses.sort();
    addresses.dedup();
    let (state, reason) = if !addresses.is_empty() {
        ("OK", "Resolved")
    } else if errors.is_empty() {
        ("FAIL", "NoAddresses")
    } else {
        ("UNKNOWN", "ResolveUnconfirmed")
    };
    d::Dns { state:state.into(), reason:reason.into(), addresses, error: errors.join("; "), elapsed_ms,
        resolver:"Windows DNS API; NO_HOSTS_FILE|NO_NETBT (bounded caller; pending OS DNS may outlive deadline)".into() }
}

async fn resolve_no_hosts(host: &str, timeout_ms: u64) -> d::Dns {
    if host.parse::<IpAddr>().is_ok() {
        return d::resolve(host, timeout_ms).await;
    }
    #[cfg(windows)]
    {
        let started = Instant::now();
        let (v4, v6) = tokio::join!(
            system_family(host, timeout_ms, false),
            system_family(host, timeout_ms, true)
        );
        system_answers(v4, v6, started.elapsed().as_secs_f64() * 1000.)
    }
    #[cfg(not(windows))]
    {
        let mut row = d::resolve(host, timeout_ms).await;
        row.resolver = "system resolver (hosts bypass unavailable on this platform)".into();
        row
    }
}
fn private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let a = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || a[0] == 100 && (64..=127).contains(&a[1])
        }
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
        Err(_) => false,
    }
}
async fn tls_evidence(
    host: &str,
    values: &[String],
    timeout_ms: u64,
    connector: &tokio_native_tls::TlsConnector,
) -> Vec<Value> {
    let mut pending = JoinSet::new();
    let peers = values
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 443));
    for peer in zapret_core::connection_addresses(peers, 16) {
        let address = peer.ip();
        let host = host.to_owned();
        let connector = connector.clone();
        pending.spawn(async move{let start=Instant::now();let mut tcp=false;let result=timeout(Duration::from_millis(timeout_ms),async{let stream=TcpStream::connect((address,443)).await?;tcp=true;stream.set_nodelay(true)?;let tls=connector.connect(&host,stream).await?;drop(tls);Ok::<(),anyhow::Error>(())}).await;
            let(valid,reason,error)=match result{Ok(Ok(()))=>(true,"Validated",String::new()),Ok(Err(e))=>(false,if tcp{"TlsFailure"}else{"TcpFailure"},format!("{e:#}")),Err(_)=>(false,"Timeout",String::new())};
            json!({"address":address,"tcp_succeeded":tcp,"certificate_validated":valid,"reason":reason,"error":error,"elapsed_ms":start.elapsed().as_secs_f64()*1000.})
        });
    }
    let mut rows = Vec::new();
    while let Some(Ok(row)) = pending.join_next().await {
        rows.push(row)
    }
    rows
}
fn doh_answers(reply: &Value, ipv6: bool) -> Vec<String> {
    if reply["Status"] != 0 {
        return Vec::new();
    }
    let record_type = if ipv6 { 28 } else { 1 };
    let mut addresses: Vec<_> = reply["Answer"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|rr| rr["type"] == record_type)
        .filter_map(|rr| rr["data"].as_str()?.parse::<IpAddr>().ok())
        .filter(|ip| ip.is_ipv6() == ipv6)
        .map(|ip| ip.to_string())
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

struct DohServer {
    url: url::Url,
    bootstrap: Vec<SocketAddr>,
}

fn doh_servers(args: &Value) -> Result<Vec<DohServer>> {
    if let Some(custom) = args["doh_urls"].as_array() {
        if custom.len() > 4 {
            bail!("at most four DoH endpoints")
        }
        return custom
            .iter()
            .map(|item| {
                Ok(DohServer {
                    url: http::checked_url(item.as_str().context("invalid DoH URL")?, false)?,
                    bootstrap: Vec::new(),
                })
            })
            .collect();
    }
    // Reach the resolver even if Windows DNS has no answer. TLS and HTTP
    // still use its canonical hostname; redirects to another origin use DNS.
    [
        (
            "https://cloudflare-dns.com/dns-query",
            "1.1.1.1:443",
            "[2606:4700:4700::1111]:443",
        ),
        (
            "https://dns.google/resolve",
            "8.8.8.8:443",
            "[2001:4860:4860::8888]:443",
        ),
    ]
    .into_iter()
    .map(|(url, v4, v6)| {
        Ok(DohServer {
            url: http::checked_url(url, false)?,
            bootstrap: vec![v4.parse()?, v6.parse()?],
        })
    })
    .collect()
}

async fn doh_family(
    host: &str,
    servers: &[DohServer],
    ipv6: bool,
    budget: u64,
    ca: Option<&Path>,
) -> (Vec<String>, Vec<Value>) {
    let kind = if ipv6 { "AAAA" } else { "A" };
    let mut attempts = Vec::new();
    for server in servers {
        let mut url = server.url.clone();
        url.query_pairs_mut()
            .append_pair("name", host)
            .append_pair("type", kind);
        let started = Instant::now();
        let mut attempt = json!({"url":url.as_str(),"query_type":kind,"state":"UNKNOWN"});
        let mut addresses = Vec::new();
        match http::fetch_accept(
            url.as_str(),
            65536,
            budget,
            ca,
            "application/dns-json",
            &server.bootstrap,
        )
        .await
        {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(reply) => {
                    addresses = doh_answers(&reply, ipv6);
                    attempt["dns_status"] = reply["Status"].clone();
                    attempt["addresses"] = json!(addresses);
                    if !addresses.is_empty() {
                        attempt["state"] = json!("OK");
                    }
                }
                Err(error) => {
                    attempt["reason"] = json!("InvalidJson");
                    attempt["error"] = json!(error.to_string());
                }
            },
            Err(error) => {
                attempt["reason"] = json!("RequestFailed");
                attempt["error"] = json!(format!("{error:#}"));
            }
        }
        attempt["elapsed_ms"] = json!(started.elapsed().as_secs_f64() * 1000.);
        attempts.push(attempt);
        if !addresses.is_empty() {
            return (addresses, attempts);
        }
    }
    (Vec::new(), attempts)
}

fn verified_missing_address(system: &d::Dns, tls: &[Value]) -> bool {
    system.addresses.is_empty()
        && system.reason == "NoAddresses"
        && tls.iter().any(|row| row["certificate_validated"] == true)
}

async fn dns(root: &Path, args: &Value) -> Result<Value> {
    let explicit =
        args.get("host").is_some() || args.get("hostname").is_some() || args.get("hosts").is_some();
    let hosts = if let Some(values) = args["hosts"].as_array().filter(|v| !v.is_empty()) {
        values
            .iter()
            .map(|v| d::host(&json!({"host":v}), "localhost"))
            .collect::<Result<Vec<_>>>()?
    } else if explicit {
        vec![d::host(args, "localhost")?]
    } else {
        vec![
            "discord.com".into(),
            "x.com".into(),
            "rutracker.org".into(),
            "tr.rbxcdn.com".into(),
        ]
    };
    if hosts.len() > 16 {
        bail!("DNS checks allow at most 16 hostnames")
    }
    let compare = args["compare"].as_bool().unwrap_or(!explicit);
    let budget = d::duration_ms(args, 2000, 30000)?;
    let ca = d::ca_file(args)?;
    let servers = doh_servers(args)?;
    let bypass_on = args["bypass_on"].as_bool().unwrap_or_else(|| {
        zapret_platform::command(root, "status", &json!({}))
            .ok()
            .is_some_and(|v| v["running"] == true)
    });
    let connector = crate::tls_connector(ca.as_deref(), &["http/1.1"])?;
    let mut rows = Vec::new();
    let mut suspect = Vec::new();
    let mut checked = 0;
    for host in &hosts {
        let system = if args["no_hosts"].as_bool().unwrap_or(compare) {
            resolve_no_hosts(host, budget).await
        } else {
            d::resolve(host, budget).await
        };
        let mut doh_attempts = Vec::new();
        let mut doh_addresses = Vec::new();
        let mut system_tls = Vec::new();
        let mut doh_tls = Vec::new();
        let mut conclusion = "NotCompared";
        let mut comparable = false;
        if compare {
            let ((v4, a), (v6, aaaa)) = tokio::join!(
                doh_family(host, &servers, false, budget, ca.as_deref()),
                doh_family(host, &servers, true, budget, ca.as_deref())
            );
            doh_addresses.extend(v4);
            doh_addresses.extend(v6);
            doh_attempts.extend(a);
            doh_attempts.extend(aaaa);
            if !system.addresses.is_empty() && !doh_addresses.is_empty() {
                if system.addresses.iter().any(|s| doh_addresses.contains(s)) {
                    comparable = true;
                    conclusion = "SharedAddress"
                } else if system.addresses.iter().all(|s| private(s)) {
                    comparable = true;
                    conclusion = "SuspiciousPrivateAnswer"
                } else if bypass_on {
                    system_tls =
                        tls_evidence(host, &system.addresses, budget.min(1500), &connector).await;
                    doh_tls =
                        tls_evidence(host, &doh_addresses, budget.min(1500), &connector).await;
                    let sys_ok = system_tls
                        .iter()
                        .any(|v| v["certificate_validated"] == true);
                    let doh_ok = doh_tls.iter().any(|v| v["certificate_validated"] == true);
                    if sys_ok || doh_ok {
                        comparable = true;
                        conclusion = if !sys_ok && doh_ok {
                            "SuspiciousTlsDifference"
                        } else {
                            "DifferentAnswers"
                        }
                    } else {
                        conclusion = "TlsUnconfirmed"
                    }
                } else {
                    conclusion = "DifferentAnswersUnconfirmed"
                }
            } else if system.reason == "NoAddresses" && !doh_addresses.is_empty() {
                let public = doh_addresses
                    .iter()
                    .filter(|ip| zapret_core::is_public_ip(ip))
                    .cloned()
                    .collect::<Vec<_>>();
                doh_tls = tls_evidence(host, &public, budget.min(1500), &connector).await;
                comparable = verified_missing_address(&system, &doh_tls);
                conclusion = if comparable {
                    "SuspiciousMissingAddress"
                } else {
                    "TlsUnconfirmed"
                };
            } else {
                conclusion = "InsufficientAddresses"
            }
        }
        if comparable {
            checked += 1
        }
        if conclusion.starts_with("Suspicious") {
            suspect.push(host.clone());
        }
        let mut row = serde_json::to_value(&system)?;
        row["host"] = host.clone().into();
        row["system_dns"] = serde_json::to_value(&system)?;
        row["doh_attempts"] = doh_attempts.into();
        row["doh_addresses"] = json!(doh_addresses);
        row["system_tls"] = system_tls.into();
        row["doh_tls"] = doh_tls.into();
        row["comparable"] = comparable.into();
        row["conclusion"] = conclusion.into();
        rows.push(row);
    }
    Ok(
        json!({"schema":1,"kind":"Dns","rows":rows,"suspect":suspect,"checked":checked,"total":hosts.len(),"comparison_requested":compare,"cause":"NotEstablished","bypass_observed":bypass_on}),
    )
}
async fn ipv6(root: &Path, args: &Value) -> Result<Value> {
    let custom = args.get("url").is_some()
        || args["urls"].as_array().is_some_and(|v| !v.is_empty())
        || args["targets"].as_array().is_some_and(|v| !v.is_empty());
    let targets = if custom {
        d::targets(root, args, false)?
    } else {
        [
            (
                "Steam CDN (Fastly)",
                "fastly.cdn.steampipe.steamcontent.com",
            ),
            ("Steam CDN (Valve)", "cache1-fra1.steamcontent.com"),
            ("Fastly", "pypi.org"),
            ("Akamai", "www.akamai.com"),
            ("Microsoft", "www.microsoft.com"),
            ("Google", "www.google.com"),
            ("Cloudflare", "www.cloudflare.com"),
            ("Amazon CloudFront", "d1.awsstatic.com"),
            ("GitHub", "github.githubassets.com"),
            ("Wikipedia", "www.wikipedia.org"),
        ]
        .into_iter()
        .map(|(name, host)| d::Target {
            group: "IPv6".into(),
            name: name.into(),
            url: format!("https://{host}/"),
        })
        .collect()
    };
    let timeout_ms = d::duration_ms(args, 6000, 30000)?;
    let ca = d::ca_file(args)?;
    let connector = crate::tls_connector(ca.as_deref(), &["http/1.1"])?;
    let cancel = d::cancellation();
    let mut pending = JoinSet::new();
    for target in targets {
        let connector = connector.clone();
        let cancel = cancel.clone();
        let extra_ca = ca.is_some();
        pending.spawn(async move{
        let url=http::checked_url(&target.url,false)?;let started=Instant::now();let dns=d::resolve(&http::hostname(&url),timeout_ms.min(2000)).await;let addresses=d::select_addresses(&dns.addresses);
        let mut families=vec![json!({"ok":false,"ms":null,"reason":if dns.state=="OK"{"NoAddress"}else{"DnsUnconfirmed"}});2];
        let mut requests=JoinSet::new();let remaining=timeout_ms.saturating_sub(started.elapsed().as_millis()as u64).max(1);
        for (index,ipv6) in [false,true].into_iter().enumerate(){
            if let Some(&address)=addresses.iter().find(|a|a.is_ipv6()==ipv6){
                let url=url.clone();let connector=connector.clone();let cancel=cancel.clone();
                requests.spawn(async move{let row=crate::connection::one(url,address,1,remaining,connector,cancel,extra_ca).await;let ok=row.headers_complete&&(200..=599).contains(&row.status_code);let tls_ms=row.tcp_ms.zip(row.tls_ms).map(|(a,b)|a+b);(index,json!({"ok":ok,"ms":tls_ms,"observation":row}))});
            }
        }
        while let Some(result)=requests.join_next().await{let(index,value)=result?;families[index]=value;}
        let v4=&families[0];let v6=&families[1];let verdict=if v6["reason"]=="NoAddress"{"none"}else if v6["reason"]=="DnsUnconfirmed"{"unknown"}else if v4["ok"]!=true&&v6["ok"]!=true{"down"}else if v6["ok"]!=true{"broken"}else if v4["ok"]==true&&v6["ms"].as_f64().zip(v4["ms"].as_f64()).is_some_and(|(a,b)|a>2.*b+300.){"slow"}else{"ok"};
        Ok::<_,anyhow::Error>(json!({"name":target.name,"host":http::hostname(&url),"url":target.url,"dns":dns,"v4":v4,"v6":v6,"verdict":verdict}))
    });
    }
    let mut rows = Vec::new();
    while let Some(row) = pending.join_next().await {
        rows.push(row??)
    }
    let broken: Vec<_> = rows
        .iter()
        .filter(|r| r["verdict"] == "broken")
        .map(|r| r["name"].clone())
        .collect();
    let slow: Vec<_> = rows
        .iter()
        .filter(|r| r["verdict"] == "slow")
        .map(|r| r["name"].clone())
        .collect();
    Ok(
        json!({"schema":1,"kind":"IPv6Paths","rows":rows,"broken":broken,"slow":slow,"evidence":"Direct TCP/TLS and HTTP headers; game latency not measured","network_context":d::context(root)}),
    )
}
pub(crate) fn run(root: &Path, kind: &str, args: &Value) -> Result<Value> {
    crate::runtime(async {
        if kind == "ipv6" {
            ipv6(root, args).await
        } else {
            dns(root, args).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_compares_only_records_of_the_requested_family() {
        let reply = json!({"Status":0,"Answer":[
            {"type":5,"data":"cdn.example"}, {"type":1,"data":"192.0.2.1"},
            {"type":28,"data":"2001:db8::1"}, {"type":28,"data":"192.0.2.2"},
            {"type":1,"data":"192.0.2.1"}]});
        assert_eq!(doh_answers(&reply, false), ["192.0.2.1"]);
        assert_eq!(doh_answers(&reply, true), ["2001:db8::1"]);
        let cname = json!({"Status":0,"Answer":[{"type":5,"data":"cdn.example"}]});
        assert!(doh_answers(&cname, false).is_empty());
        assert!(doh_answers(&cname, true).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_system_answer_requires_both_families_and_alternative_tls_evidence() {
        let empty = system_answers(Ok(vec![]), Ok(vec![]), 1.);
        let verified = [json!({"certificate_validated":true})];
        assert!(verified_missing_address(&empty, &verified));
        assert!(!verified_missing_address(
            &empty,
            &[json!({"certificate_validated":false})]
        ));
        let timeout = system_answers(Err(anyhow::anyhow!("timed out")), Ok(vec![]), 1.);
        assert_eq!(timeout.state, "UNKNOWN");
        assert!(!verified_missing_address(&timeout, &verified));
        let ipv6_only = system_answers(
            Err(anyhow::anyhow!("timed out")),
            Ok(vec!["2001:db8::1".into()]),
            1.,
        );
        assert_eq!(ipv6_only.state, "OK");
        assert_eq!(ipv6_only.addresses, ["2001:db8::1"]);
        assert!(!verified_missing_address(&ipv6_only, &verified));
    }
}
