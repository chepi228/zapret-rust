use crate::{diagnostic as d, http};
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_native_tls::TlsConnector;
use url::{Position, Url};

const HEADER_LIMIT: usize = 32768;

pub(crate) async fn resolve_addresses(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(zapret_core::connection_addresses(
        lookup_host((host, port)).await?,
        16,
    ))
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Row {
    pub address: String,
    pub family: String,
    pub attempt: u64,
    pub stage: String,
    pub state: String,
    pub reason: String,
    pub error: String,
    pub tcp_succeeded: bool,
    pub tls_succeeded: bool,
    pub headers_complete: bool,
    pub certificate_observed: bool,
    pub status_code: u16,
    pub received_bytes: usize,
    pub header_bytes: usize,
    pub certificate_errors: String,
    pub tls_protocol: String,
    pub http_version: String,
    pub validation: String,
    pub revocation_check: Option<bool>,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub http_ms: Option<f64>,
    pub elapsed_ms: f64,
    pub evidence: String,
    pub client: String,
    pub tls_backend: String,
}
impl Row {
    fn new(address: IpAddr, attempt: u64) -> Self {
        Self {
            address: address.to_string(),
            family: if address.is_ipv6() { "IPv6" } else { "IPv4" }.into(),
            attempt,
            stage: "Tcp".into(),
            state: "UNKNOWN".into(),
            reason: "ControllerError".into(),
            error: String::new(),
            tcp_succeeded: false,
            tls_succeeded: false,
            headers_complete: false,
            certificate_observed: false,
            status_code: 0,
            received_bytes: 0,
            header_bytes: 0,
            certificate_errors: "NotObserved".into(),
            tls_protocol: String::new(),
            http_version: String::new(),
            validation: "System".into(),
            revocation_check: None,
            tcp_ms: None,
            tls_ms: None,
            http_ms: None,
            elapsed_ms: 0.,
            evidence: "Headers".into(),
            client: "Rust direct native-tls HTTP/1.1 HEAD".into(),
            tls_backend: if cfg!(windows) {
                "Schannel"
            } else if cfg!(target_os = "macos") {
                "SecurityFramework"
            } else {
                "OpenSSL"
            }
            .into(),
        }
    }
    fn not_run(address: IpAddr, attempt: u64, reason: &str) -> Self {
        let mut r = Self::new(address, attempt);
        r.stage = "Unknown".into();
        r.state = "NOT_RUN".into();
        r.reason = reason.into();
        r
    }
}
pub(crate) async fn one(
    url: Url,
    address: IpAddr,
    attempt: u64,
    timeout_ms: u64,
    connector: TlsConnector,
    mut cancel: watch::Receiver<bool>,
    extra_ca: bool,
) -> Row {
    let mut row = Row::new(address, attempt);
    if extra_ca {
        row.validation = "SystemPlusExtraCa".into()
    }
    let started = Instant::now();
    let result = tokio::select! {
        biased;
        _=async{if *cancel.borrow(){return}let _=cancel.changed().await;}=>{row.state="UNKNOWN".into();row.reason="Cancelled".into();Ok(())},
        result=timeout(Duration::from_millis(timeout_ms.max(1)),execute(&url,address,&connector,&mut row))=>match result{
            Ok(result)=>result,Err(_)=>{row.state="FAIL".into();row.reason="Timeout".into();Ok(())}
        }
    };
    if let Err(error) = result {
        row.state = "FAIL".into();
        row.error = error.chars().take(1024).collect();
    }
    row.elapsed_ms = started.elapsed().as_secs_f64() * 1000.;
    row
}
async fn execute(
    url: &Url,
    address: IpAddr,
    connector: &TlsConnector,
    row: &mut Row,
) -> Result<(), String> {
    let port = url.port_or_known_default().expect("HTTP port");
    let phase = Instant::now();
    let stream = TcpStream::connect(d::socket(address, port))
        .await
        .map_err(|e| {
            row.reason = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                "ConnectionRefused"
            } else {
                "ConnectError"
            }
            .into();
            row.tcp_ms = Some(phase.elapsed().as_secs_f64() * 1000.);
            e.to_string()
        })?;
    row.tcp_succeeded = true;
    row.tcp_ms = Some(phase.elapsed().as_secs_f64() * 1000.);
    stream.set_nodelay(true).map_err(|error| {
        row.reason = "SocketOptionError".into();
        error.to_string()
    })?;
    let mut stream: Box<dyn http::Io> = if url.scheme() == "https" {
        row.stage = "Tls".into();
        let phase = Instant::now();
        let stream = connector
            .connect(&http::hostname(url), stream)
            .await
            .map_err(|e| {
                row.reason = "TlsFailure".into();
                row.tls_ms = Some(phase.elapsed().as_secs_f64() * 1000.);
                e.to_string()
            })?;
        row.tls_succeeded = true;
        row.tls_ms = Some(phase.elapsed().as_secs_f64() * 1000.);
        row.certificate_observed = stream.get_ref().peer_certificate().ok().flatten().is_some();
        row.certificate_errors = "None; native TLS chain and hostname validation completed".into();
        // native-tls does not expose the negotiated TLS version uniformly across backends.
        row.tls_protocol = "TLS >= 1.2 (negotiated version not exposed)".into();
        Box::new(stream)
    } else {
        row.validation = "NotApplicable".into();
        Box::new(stream)
    };
    row.stage = "Http".into();
    row.reason = "ReadError".into();
    let phase = Instant::now();
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: zapret-rust-connection-diagnostic/1\r\nAccept: */*\r\n\r\n",
        &url[Position::BeforePath..Position::AfterQuery],
        &url[Position::BeforeHost..Position::AfterPort]
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut bytes = vec![0; HEADER_LIMIT];
    let mut used = 0;
    let mut begin = 0;
    loop {
        if let Some(end) = bytes[begin..used]
            .windows(4)
            .position(|p| p == b"\r\n\r\n")
            .map(|p| begin + p + 4)
        {
            match parse_header(&bytes[begin..end]) {
                Ok((101, _)) => {
                    row.reason = "UnsupportedUpgrade".into();
                    row.state = "FAIL".into();
                    break;
                }
                Ok((code, _)) if code < 200 => {
                    begin = end;
                    continue;
                }
                Ok((code, version)) => {
                    row.status_code = code;
                    row.http_version = version;
                    row.header_bytes = end;
                    row.headers_complete = true;
                    row.stage = "Complete".into();
                    row.state = if code >= 400 { "HTTP_ERROR" } else { "OK" }.into();
                    row.reason = if code >= 400 {
                        "HttpStatus"
                    } else {
                        "Completed"
                    }
                    .into();
                    break;
                }
                Err(()) => {
                    row.reason = "MalformedHttp".into();
                    row.state = "FAIL".into();
                    break;
                }
            }
        }
        if used == HEADER_LIMIT {
            row.reason = "HeaderLimit".into();
            row.state = "FAIL".into();
            break;
        }
        let count = stream
            .read(&mut bytes[used..(used + 2048).min(HEADER_LIMIT)])
            .await
            .map_err(|e| e.to_string())?;
        if count == 0 {
            row.reason = "TruncatedHeaders".into();
            row.state = "FAIL".into();
            break;
        }
        used += count;
        row.received_bytes = used;
    }
    row.http_ms = Some(phase.elapsed().as_secs_f64() * 1000.);
    Ok(())
}
fn parse_header(bytes: &[u8]) -> Result<(u16, String), ()> {
    let mut lines = bytes.split(|b| *b == b'\n');
    let first = lines.next().ok_or(())?.strip_suffix(b"\r").ok_or(())?;
    if first.len() < 12
        || !matches!(&first[..9], b"HTTP/1.0 " | b"HTTP/1.1 ")
        || !(b'2'..=b'5').contains(&first[9]) && first[9] != b'1'
        || !first[10..12].iter().all(u8::is_ascii_digit)
        || first.len() > 12
            && (first[12] != b' ' && first[12] != b'\t'
                || !first[13..].iter().all(|b| *b == 9 || *b >= 32 && *b != 127))
    {
        return Err(());
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r").ok_or(())?;
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|b| *b == b':').ok_or(())?;
        if colon == 0
            || !line[..colon]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            || !line[colon + 1..]
                .iter()
                .all(|b| *b == 9 || *b >= 32 && *b != 127)
        {
            return Err(());
        }
    }
    let code = ((first[9] - b'0') as u16) * 100
        + ((first[10] - b'0') as u16) * 10
        + (first[11] - b'0') as u16;
    Ok((code, String::from_utf8_lossy(&first[5..8]).into()))
}
fn assessment(dns: &[d::Dns], addresses: &[IpAddr], rows: &[Row], attempts: u64) -> Value {
    let reachable = rows.iter().any(|r| {
        r.headers_complete
            && (200..=599).contains(&r.status_code)
            && r.stage == "Complete"
            && matches!(r.state.as_str(), "OK" | "HTTP_ERROR")
    });
    let (mut stage, mut reason, mut consistency) = ("Unknown", "Unknown", "Unknown");
    if !dns.iter().any(|d| d.state == "OK") {
        stage = "Dns";
        if dns.len() >= 2
            && dns
                .iter()
                .all(|d| d.state == "FAIL" && d.reason == dns[0].reason)
        {
            reason = &dns[0].reason;
            consistency = "Repeated";
        }
    } else {
        let mut keys = std::collections::HashSet::new();
        let valid = !addresses.is_empty()
            && rows.len() == addresses.len() * attempts as usize
            && rows.iter().all(|r| {
                addresses.iter().any(|a| a.to_string() == r.address)
                    && (1..=attempts).contains(&r.attempt)
                    && keys.insert((&r.address, r.attempt))
                    && matches!(r.state.as_str(), "OK" | "HTTP_ERROR" | "FAIL")
                    && (!matches!(r.state.as_str(), "OK" | "HTTP_ERROR")
                        || r.stage == "Complete"
                            && r.headers_complete
                            && (200..=599).contains(&r.status_code))
            });
        if !valid {
            consistency = "Incomplete"
        } else if rows
            .iter()
            .all(|r| matches!(r.state.as_str(), "OK" | "HTTP_ERROR"))
        {
            stage = "Complete";
            reason = "ReachedHttp";
            consistency = if attempts >= 2 {
                "Repeated"
            } else {
                "SingleObservation"
            }
        } else if rows
            .iter()
            .all(|r| r.state == "FAIL" && r.stage == rows[0].stage && r.reason == rows[0].reason)
        {
            stage = &rows[0].stage;
            reason = &rows[0].reason;
            consistency = if attempts >= 2 {
                "Repeated"
            } else {
                "SingleObservation"
            }
        } else {
            consistency = "Mixed"
        }
        if dns.iter().any(|d| d.state != "OK") {
            consistency = "Mixed";
            stage = "Unknown";
            reason = "DnsRecovered";
        }
    }
    json!({"stage":stage,"reason":reason,"consistency":consistency,"reachable_http":reachable,"observations":rows.len()})
}
pub(crate) fn run(root: &Path, args: &Value) -> Result<Value> {
    let targets = d::targets(root, args, false)?;
    let budget = d::duration_ms(args, 8000, 30000)?;
    let attempts = d::integer(args, "attempts", 2, 1, 2)?;
    let ca = d::ca_file(args)?;
    let connector = crate::tls_connector(ca.as_deref(), &["http/1.1"])?;
    let before = d::context(root);
    let started = d::now();
    let output = crate::runtime(async {
        let cancel = d::cancellation();
        let mut output = Vec::new();
        for target in targets {
            let url = http::checked_url(&target.url, false)?;
            let deadline = Instant::now() + Duration::from_millis(budget);
            let mut dns = Vec::new();
            let mut addresses = Vec::new();
            if !*cancel.borrow() {
                for _ in 0..2 {
                    let remaining = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64;
                    if remaining == 0 || *cancel.borrow() {
                        break;
                    }
                    let result = d::resolve(&http::hostname(&url), remaining.min(1500)).await;
                    if result.state == "OK" {
                        addresses = d::select_addresses(&result.addresses);
                        dns.push(result);
                        break;
                    }
                    dns.push(result);
                }
            }
            let mut rows = Vec::new();
            for attempt in 1..=attempts {
                let mut pending = JoinSet::new();
                for &address in &addresses {
                    let remaining = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64;
                    if remaining == 0 || *cancel.borrow() {
                        rows.push(Row::not_run(
                            address,
                            attempt,
                            if *cancel.borrow() {
                                "Cancelled"
                            } else {
                                "BudgetExhausted"
                            },
                        ));
                    } else {
                        pending.spawn(one(
                            url.clone(),
                            address,
                            attempt,
                            remaining.min(3000),
                            connector.clone(),
                            cancel.clone(),
                            ca.is_some(),
                        ));
                    }
                }
                while let Some(row) = pending.join_next().await {
                    rows.push(row?)
                }
            }
            let assessment = assessment(&dns, &addresses, &rows, attempts);
            output.push(json!({"group":target.group,"name":target.name,"url":target.url,"execution":if *cancel.borrow(){"Interrupted"}else{"Completed"},"dns_attempts":dns,"selected_addresses":addresses,"rows":rows,"assessment":assessment}));
        }
        Ok(output)
    })?;
    let after = d::context(root);
    let control = output
        .iter()
        .filter(|v| v["group"] == "Clean")
        .collect::<Vec<_>>();
    let reached = !control.is_empty()
        && control.iter().all(|v| {
            v["assessment"]["stage"] == "Complete" && v["assessment"]["consistency"] == "Repeated"
        });
    Ok(
        json!({"schema":1,"kind":"ConnectionStages","started_utc_ms":started,"finished_utc_ms":d::now(),"completion":if output.iter().any(|v|v["execution"]=="Interrupted"){"Interrupted"}else{"Completed"},"client":"Rust native-tls HTTP/1.1 HEAD","header_limit":HEADER_LIMIT,"evidence":"Headers","proxy_mode":"Direct","attempts":attempts,"context_before":before,"context_after":after,"connection_state":d::context_state(&before,&after),"control_state":if reached{"ReachedHttp"}else{"Unknown"},"targets":output}),
    )
}
