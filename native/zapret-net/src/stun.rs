use crate::diagnostic as d;
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::watch,
    time::{Instant, timeout},
};

#[derive(Default, Debug)]
struct Parsed {
    valid: bool,
    success: bool,
    mapped: bool,
    reason: &'static str,
    mapped_address: Option<String>,
    mapped_port: Option<u16>,
}
fn word(data: &[u8], at: usize) -> usize {
    u16::from_be_bytes([data[at], data[at + 1]]) as usize
}
fn fingerprint(data: &[u8]) -> u32 {
    let mut crc = 0xffffffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !crc ^ 0x5354554e
}
fn parse(data: &[u8], transaction: &[u8; 12]) -> Parsed {
    let mut result = Parsed {
        reason: "MalformedResponse",
        ..Default::default()
    };
    if !(20..=2048).contains(&data.len())
        || data[0] & 0xc0 != 0
        || data[4..8] != [0x21, 0x12, 0xa4, 0x42]
    {
        return result;
    }
    let length = word(data, 2);
    if length % 4 != 0 || length + 20 != data.len() {
        return result;
    }
    if data[8..20] != *transaction {
        result.reason = "TransactionMismatch";
        return result;
    }
    let kind = word(data, 0);
    if kind != 0x0101 && kind != 0x0111 {
        return result;
    }
    let mut error = false;
    let mut at = 20;
    while at < data.len() {
        if at + 4 > data.len() {
            return result;
        }
        let attr = word(data, at);
        let size = word(data, at + 2);
        at += 4;
        if at + size > data.len() {
            return result;
        }
        if attr == 0x0020 {
            if size < 4
                || data[at] != 0
                || !((data[at + 1] == 1 && size == 8) || (data[at + 1] == 2 && size == 20))
            {
                return result;
            }
            result.mapped = true;
            result.mapped_port = Some((word(data, at + 2) as u16) ^ 0x2112);
            let mut mask = [0; 16];
            mask[..4].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
            mask[4..].copy_from_slice(transaction);
            let decoded: Vec<_> = data[at + 4..at + size]
                .iter()
                .zip(mask)
                .map(|(b, m)| *b ^ m)
                .collect();
            result.mapped_address = Some(
                if size == 8 {
                    IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(decoded).expect("four address bytes"),
                    ))
                } else {
                    IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(decoded).expect("sixteen address bytes"),
                    ))
                }
                .to_string(),
            );
        }
        if attr == 0x0009 {
            if size < 4
                || data[at] != 0
                || data[at + 1] != 0
                || !(3..=6).contains(&data[at + 2])
                || data[at + 3] > 99
            {
                return result;
            }
            error = true
        }
        if attr < 0x8000 && attr != 0x0020 && attr != 0x0009 {
            return result;
        }
        if attr == 0x8028 {
            if size != 4 || at + 4 != data.len() {
                return result;
            }
            if fingerprint(&data[..at - 4])
                != u32::from_be_bytes(data[at..at + 4].try_into().expect("fingerprint length"))
            {
                return result;
            }
        }
        at += (size + 3) & !3;
        if at > data.len() {
            return result;
        }
    }
    if kind == 0x0101 && result.mapped {
        result.valid = true;
        result.success = true;
        result.reason = "BindingResponse"
    } else if kind == 0x0111 && error {
        result.valid = true;
        result.reason = "ErrorResponse"
    }
    result
}
#[derive(Debug, Serialize)]
struct Row {
    address: String,
    port: u16,
    attempt: u64,
    state: String,
    reason: String,
    error: String,
    sent_bytes: usize,
    received_bytes: usize,
    datagrams: u32,
    rejected: u32,
    response_validated: bool,
    mapped_address_present: bool,
    mapped_address: Option<String>,
    mapped_port: Option<u16>,
    elapsed_ms: f64,
    evidence: &'static str,
}
async fn one(
    endpoint: SocketAddr,
    attempt: u64,
    timeout_ms: u64,
    mut cancel: watch::Receiver<bool>,
) -> Row {
    let mut row = Row {
        address: endpoint.ip().to_string(),
        port: endpoint.port(),
        attempt,
        state: "UNKNOWN".into(),
        reason: "ControllerError".into(),
        error: String::new(),
        sent_bytes: 0,
        received_bytes: 0,
        datagrams: 0,
        rejected: 0,
        response_validated: false,
        mapped_address_present: false,
        mapped_address: None,
        mapped_port: None,
        elapsed_ms: 0.,
        evidence: "StunControl",
    };
    let start = Instant::now();
    let operation = async {
        let bind = if endpoint.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(endpoint).await?;
        let mut transaction = [0; 12];
        getrandom::fill(&mut transaction).map_err(std::io::Error::other)?;
        let mut request = vec![0; 20];
        request[1] = 1;
        request[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        request[8..].copy_from_slice(&transaction);
        row.sent_bytes = socket.send(&request).await?;
        let mut buffer = [0; 2049];
        while row.datagrams < 8 {
            let (count, peer) = socket.recv_from(&mut buffer).await?;
            row.datagrams += 1;
            row.received_bytes += count;
            if peer != endpoint {
                row.rejected += 1;
                continue;
            }
            let parsed = parse(&buffer[..count], &transaction);
            if !parsed.valid {
                row.rejected += 1;
                continue;
            }
            row.response_validated = true;
            row.mapped_address_present = parsed.mapped;
            row.mapped_address = parsed.mapped_address;
            row.mapped_port = parsed.mapped_port;
            row.state = if parsed.success {
                "OK"
            } else {
                "ERROR_RESPONSE"
            }
            .into();
            row.reason = parsed.reason.into();
            break;
        }
        if !row.response_validated {
            row.reason = "MalformedResponses".into()
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        biased;
        _=async{if *cancel.borrow(){return}let _=cancel.changed().await;}=>{row.reason="Cancelled".into();},
        result=timeout(Duration::from_millis(timeout_ms),operation)=>match result{
            Ok(Ok(()))=>{},Ok(Err(e))=>{row.reason="SocketError".into();row.error=e.to_string();},Err(_)=>{row.reason="Timeout".into();}
        }
    }
    row.elapsed_ms = start.elapsed().as_secs_f64() * 1000.;
    row
}
pub fn assess_voice(capture: &Value, control: &Value, audio: &str, context: &str) -> Result<Value> {
    if !matches!(
        audio,
        "Unknown" | "Both" | "OnlyReceive" | "OnlySend" | "None"
    ) {
        bail!("invalid audio observation")
    }
    let flows = capture["flows"].as_array();
    let mut traffic = "CaptureUnknown";
    let completed = capture["status"] == "Completed"
        || (capture["status"] == "Captured" && capture["cleanup_confirmed"] == true);
    if completed
        && capture["truncated"] == false
        && capture["events_lost"].as_u64().unwrap_or(0) == 0
        && capture["decode_errors"].as_u64().unwrap_or(0) == 0
    {
        let out = |v: &Value| v["out"].as_u64().unwrap_or(0) > 0;
        let inbound = |v: &Value| v["in"].as_u64().unwrap_or(0) > 0;
        let values = flows.map_or(&[][..], Vec::as_slice);
        traffic = if values.iter().any(|v| out(v) && inbound(v)) {
            "BidirectionalUdpObserved"
        } else if values.iter().any(out) && values.iter().any(inbound) {
            "SeparateDirectionsObserved"
        } else if values.iter().any(out) {
            "OutboundOnly"
        } else if values.iter().any(inbound) {
            "InboundOnly"
        } else {
            "NoUdpObserved"
        };
    }
    let controls = control.as_array().map_or(&[][..], Vec::as_slice);
    let control_state = if controls.iter().any(|v| v["response_validated"] == true) {
        "StunResponseObserved"
    } else if !controls.is_empty() {
        "NoResponseObserved"
    } else {
        "Unknown"
    };
    let audio_state = if audio == "Both" {
        "UserReportedBoth"
    } else if audio == "Unknown" {
        "NotProvided"
    } else {
        "UserReportedIssue"
    };
    let outcome = if context == "Changed" {
        "ContextChanged"
    } else if audio == "Both" {
        "UserReportedBoth"
    } else if audio != "Unknown" {
        "UserReportedIssue"
    } else if traffic == "BidirectionalUdpObserved" || control_state == "StunResponseObserved" {
        "NeedsAudioCheck"
    } else {
        "InsufficientEvidence"
    };
    Ok(
        json!({"traffic":traffic,"control":control_state,"audio":audio_state,"outcome":outcome,"cause":"NotEstablished","profile_hit":"NotObserved"}),
    )
}
pub(crate) fn run(root: &Path, kind: &str, args: &Value) -> Result<Value> {
    let mut options = args.clone();
    if let Some(host) = args.get("stun_host") {
        options["host"] = host.clone()
    }
    if let Some(port) = args.get("stun_port") {
        options["port"] = port.clone()
    }
    let host = d::host(&options, "stun.cloudflare.com")?;
    let port = d::integer(&options, "port", 3478, 1, 65535)? as u16;
    let attempts = d::integer(args, "attempts", 2, 1, 2)?;
    let timeout_ms = if args.get("timeout_ms").is_some() {
        d::integer(args, "timeout_ms", 1200, 1, 5000)?
    } else {
        1200
    };
    let duration = d::integer(args, "duration_sec", 30, 1, 120)?;
    let audio = args["audio"].as_str().unwrap_or("Unknown");
    assess_voice(&json!({}), &json!([]), audio, "Unknown")?;
    let before = d::context(root);
    let started = d::now();
    let (dns, controls, cancelled) = crate::runtime(async {
        let cancel = d::cancellation();
        let dns = d::resolve(&host, 2000).await;
        let addresses = d::select_addresses(&dns.addresses);
        let mut rows = Vec::new();
        for attempt in 1..=attempts {
            let probe = |address, remaining| {
                one(
                    SocketAddr::new(address, port),
                    attempt,
                    remaining,
                    cancel.clone(),
                )
            };
            let Some(row) = d::first_confirmed(&addresses, timeout_ms, probe, |row| {
                row.response_validated || row.reason == "Cancelled"
            })
            .await
            else {
                break;
            };
            let cancelled = row.reason == "Cancelled";
            rows.push(row);
            if cancelled {
                break;
            }
        }
        let cancelled = *cancel.borrow() || rows.iter().any(|row| row.reason == "Cancelled");
        Ok((dns, rows, cancelled))
    })?;
    let control = serde_json::to_value(controls)?;
    let capture = if cancelled {
        json!({"status":"NotStarted","reason":"Cancelled","truncated":false,"flows":[]})
    } else if kind != "voice" || args["control_only"] == true {
        json!({"status":"NotStarted","reason":"ControlOnly","truncated":false,"flows":[]})
    } else {
        zapret_platform::command(root,"voice-capture",&json!({"duration_sec":duration,"process_name":"Discord"})).unwrap_or_else(|error|json!({"status":"Unknown","reason":"CaptureError","error":format!("{error:#}"),"truncated":true,"flows":[]}))
    };
    let after = d::context(root);
    let state = d::context_state(&before, &after);
    let assessment = assess_voice(&capture, &control, audio, state)?;
    let result = json!({"schema":1,"kind":"DiscordVoice","started_utc_ms":started,"finished_utc_ms":d::now(),"audio_observation":audio,"audio_reported_utc_ms":if audio=="Unknown"{None}else{Some(d::now())},"control_dns":dns,"control":control,"capture":capture,"assessment":assessment,"context_before":before,"context_after":after,"connection_state":state,"completion":if cancelled{"Interrupted"}else{"Completed"}});
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unauthenticated_control_rejects_unknown_required_attributes() {
        let tx = [3; 12];
        let mut response = vec![1, 1, 0, 4, 0x21, 0x12, 0xa4, 0x42];
        response.extend_from_slice(&tx);
        response.extend_from_slice(&[0, 1, 0, 0]);
        assert!(!parse(&response, &tx).valid);
    }
    #[test]
    fn incomplete_capture_never_proves_bidirectional_udp() {
        let assessment = assess_voice(
            &json!({"status":"Completed","truncated":true,"flows":[{"out":2,"in":2}]}),
            &json!([]),
            "Unknown",
            "ObservedStable",
        )
        .unwrap();
        assert_eq!(assessment["traffic"], "CaptureUnknown");
        assert_eq!(assessment["cause"], "NotEstablished");
    }
}
