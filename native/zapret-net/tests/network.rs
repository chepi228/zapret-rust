use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};
use zapret_net::{BatchOptions, Job, Termination};

fn fixture(response: impl AsRef<[u8]> + Send + 'static) -> (String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    (
        url,
        thread::spawn(move || {
            let start = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(s) => break s,
                    Err(_) if start.elapsed() < Duration::from_secs(2) => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("fixture not contacted: {e}"),
                }
            };
            // Windows inherits the listener's nonblocking setting on accept.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut header = Vec::new();
            let mut byte = [0; 1];
            while !header.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap() == 0 {
                    break;
                }
                header.push(byte[0]);
            }
            assert!(
                header.ends_with(b"\r\n\r\n"),
                "fixture received incomplete request"
            );
            let _ = stream.write_all(response.as_ref());
            header
        }),
    )
}
#[test]
fn head_has_no_response_body_and_preserves_http_status() {
    let (url, server) = fixture(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 999\r\n\r\n");
    let job: Job =
        serde_json::from_value(json!({"version":1,"id":"head","url":url,"method":"HEAD"})).unwrap();
    let rows = zapret_net::probe(&[job], &BatchOptions::default()).unwrap();
    assert_eq!(rows[0].termination, Termination::Complete);
    assert_eq!(rows[0].status_code, Some(503));
    assert_eq!(rows[0].body_bytes, 0);
    assert!(server.join().unwrap().starts_with(b"HEAD / HTTP/1.1"));
}
#[test]
fn fetch_rejects_truncated_response() {
    let (url, server) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc");
    assert!(zapret_net::fetch(&url, 128, 1000).is_err());
    server.join().unwrap();
}
#[test]
fn fetch_returns_complete_payload() {
    let (url, server) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
    assert_eq!(zapret_net::fetch(&url, 128, 1000).unwrap(), b"abc");
    server.join().unwrap();
}
#[test]
fn fetch_total_deadline_closes_stalled_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut b = [0; 4096];
        assert!(s.read(&mut b).unwrap() > 0);
        s.read(&mut b).unwrap_or(0)
    });
    let started = Instant::now();
    assert!(zapret_net::fetch(&url, 128, 100).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.join().unwrap(), 0);
}
#[test]
fn connection_records_complete_error_headers_without_reading_body() {
    let (url, server) = fixture(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 999\r\n\r\n");
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "connection",
        &json!({"url":url,"attempts":1,"timeout_ms":1000}),
    )
    .unwrap();
    let row = &result["targets"][0]["rows"][0];
    assert_eq!(row["stage"], "Complete");
    assert_eq!(row["state"], "HTTP_ERROR");
    assert_eq!(row["status_code"], 503);
    assert_eq!(row["headers_complete"], true);
    assert_eq!(result["targets"][0]["assessment"]["reachable_http"], true);
    assert!(server.join().unwrap().starts_with(b"HEAD / HTTP/1.1"));
}
#[test]
fn connection_retains_partial_truncated_header_evidence() {
    let (url, server) = fixture(b"HTTP/1.1 200 OK\r\nX-Partial: abc");
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "connection",
        &json!({"url":url,"attempts":1,"timeout_ms":1000}),
    )
    .unwrap();
    let row = &result["targets"][0]["rows"][0];
    assert_eq!(row["reason"], "TruncatedHeaders");
    assert_eq!(
        row["received_bytes"],
        b"HTTP/1.1 200 OK\r\nX-Partial: abc".len()
    );
    assert_eq!(row["headers_complete"], false);
    assert_eq!(result["targets"][0]["assessment"]["reachable_http"], false);
    server.join().unwrap();
}

#[test]
fn connection_counts_interim_and_final_headers_against_the_same_inclusive_limit() {
    const LIMIT: usize = 32768;
    let interim = "HTTP/1.1 103 Early Hints\r\nX-Pad: ";
    let final_headers = "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for length in [LIMIT, LIMIT + 1] {
        let padding = "x".repeat(length - interim.len() - final_headers.len());
        let (url, server) = fixture(format!("{interim}{padding}{final_headers}"));
        let result = zapret_net::diagnostics(
            std::path::Path::new("."),
            "connection",
            &json!({"url":url,"attempts":1,"timeout_ms":2000}),
        )
        .unwrap();
        let target = &result["targets"][0];
        let row = &target["rows"][0];
        assert!(server.join().unwrap().starts_with(b"HEAD / HTTP/1.1"));
        assert_eq!(row["tcp_succeeded"], true);
        assert_eq!(row["received_bytes"], LIMIT);
        if length == LIMIT {
            assert_eq!(row["stage"], "Complete");
            assert_eq!(row["state"], "OK");
            assert_eq!(row["status_code"], 200);
            assert_eq!(row["header_bytes"], LIMIT);
            assert_eq!(row["headers_complete"], true);
            assert_eq!(target["assessment"]["reachable_http"], true);
        } else {
            assert_eq!(row["stage"], "Http");
            assert_eq!(row["state"], "FAIL");
            assert_eq!(row["reason"], "HeaderLimit");
            assert_eq!(row["headers_complete"], false);
            assert_eq!(target["assessment"]["reachable_http"], false);
        }
    }
}

#[test]
fn connection_rejects_upgrades_and_malformed_headers_without_claiming_reachability() {
    for (response, reason) in [
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            "UnsupportedUpgrade",
        ),
        ("HTTP/1.1 200 OK\0bad\r\n\r\n", "MalformedHttp"),
        ("HTTP/1.1 200 OK\r\nMissing colon\r\n\r\n", "MalformedHttp"),
    ] {
        let (url, server) = fixture(response);
        let result = zapret_net::diagnostics(
            std::path::Path::new("."),
            "connection",
            &json!({"url":url,"attempts":1,"timeout_ms":1000}),
        )
        .unwrap();
        server.join().unwrap();
        let target = &result["targets"][0];
        let row = &target["rows"][0];
        assert_eq!(row["stage"], "Http");
        assert_eq!(row["state"], "FAIL");
        assert_eq!(row["reason"], reason);
        assert_eq!(row["received_bytes"], response.len());
        assert_eq!(row["headers_complete"], false);
        assert_eq!(target["assessment"]["reachable_http"], false);
    }
}
#[test]
fn stun_rejects_mismatched_transaction_before_validating_response() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut b = [0; 2048];
        let (n, remote) = socket.recv_from(&mut b).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&b[..2], &[0, 1]);
        let mut response = b[..20].to_vec();
        response[..2].copy_from_slice(&[1, 1]);
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&[0, 32, 0, 8, 0, 1, 0x21, 0x13, 0x5e, 0x12, 0xa4, 0x43]);
        response[8] ^= 1;
        socket.send_to(&response, remote).unwrap();
        response[8] ^= 1;
        socket.send_to(&response, remote).unwrap();
    });
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "stun",
        &json!({"host":"127.0.0.1","port":port,"attempts":1,"timeout_ms":500}),
    )
    .unwrap();
    assert_eq!(result["control"][0]["response_validated"], true);
    assert_eq!(result["control"][0]["rejected"], 1);
    assert_eq!(result["control"][0]["datagrams"], 2);
    server.join().unwrap();
}
#[test]
fn native_web_head_reports_http_status_separately_from_protocol_confirmation() {
    let (url, server) = fixture(b"HTTP/1.1 403 Denied\r\nContent-Length: 100\r\n\r\n");
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "webcheck",
        &json!({"url":url,"modes":["Http1"],"timeout_ms":1000,"browser_path":"","curl_path":""}),
    )
    .unwrap();
    assert_eq!(result["rows"][0]["state"], "HTTP_ERROR");
    assert_eq!(result["rows"][0]["protocol_confirmed"], true);
    assert_eq!(result["rows"][0]["quic_confirmed"], false);
    server.join().unwrap();
}
#[test]
fn unavailable_browser_is_explicit_evidence() {
    let result=zapret_net::diagnostics(std::path::Path::new("."),"webcheck",&json!({"url":"http://127.0.0.1:9/","modes":["BrowserAuto","Http3"],"timeout_ms":100,"browser_path":"","curl_path":""})).unwrap();
    for row in result["rows"].as_array().unwrap() {
        assert_eq!(row["state"], "UNAVAILABLE");
        assert_eq!(row["protocol_confirmed"], false);
        assert_eq!(row["complete"], false);
    }
}
#[test]
#[cfg(windows)]
fn native_http3_runs_without_curl_and_keeps_unconfirmed_requests_explicit() {
    let root = std::path::Path::new(".");
    let capabilities = zapret_net::diagnostics(
        root,
        "webcheck",
        &json!({"capabilities_only":true,"browser_path":""}),
    )
    .unwrap();
    if capabilities["native_http3"] != true {
        return; // Older Windows builds can lack the required WinHTTP options.
    }
    assert!(capabilities["curl_path"].is_null());
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let url = format!("https://{}/", blackhole.local_addr().unwrap());
    let started = std::time::Instant::now();
    let result = zapret_net::diagnostics(
        root,
        "webcheck",
        &json!({"url":url,"modes":["Http3"],"timeout_ms":100,"browser_path":""}),
    )
    .unwrap();
    let row = &result["rows"][0];
    assert_eq!(row["client"], "Windows WinHTTP HTTP/3 HEAD");
    assert_eq!(row["tls_backend"], "Schannel");
    assert_eq!(row["trust_source"], "System");
    assert_ne!(row["state"], "UNAVAILABLE");
    assert_ne!(row["state"], "OK");
    assert_eq!(row["protocol_confirmed"], false);
    assert_eq!(row["quic_confirmed"], false);
    assert_eq!(row["complete"], false);
    assert!(started.elapsed().as_secs() < 5);
}
#[test]
fn provider_parses_only_a_complete_valid_ip_identity() {
    let body = r#"{"success":true,"ip":"203.0.113.9","country":"Russia","country_code":"RU","connection":{"isp":"Fixture ISP","org":"Fixture Org","asn":64500}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (url, server) = fixture(response);
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "provider",
        &json!({"primary_url":url,"timeout_ms":1000}),
    )
    .unwrap();
    assert_eq!(result["rows"][0]["provider"]["isp"], "Fixture ISP");
    assert_eq!(result["rows"][0]["provider"]["masked_ip"], "203.0.113.x");
    assert_eq!(result["rows"][0]["provider"]["is_russia"], true);
    server.join().unwrap();
}
#[test]
fn failed_download_preserves_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("download");
    std::fs::write(&path, b"previous").unwrap();
    let (url, server) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc");
    assert!(zapret_net::download(&url, &path, 128, 1000).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"previous");
    server.join().unwrap();
}
#[test]
fn fetch_follows_checked_redirect_and_rejects_public_http_downgrade() {
    let (destination, server) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
    let response =
        format!("HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: {destination}\r\n\r\n");
    let (url, redirect) = fixture(response);
    assert_eq!(zapret_net::fetch(&url, 128, 1000).unwrap(), b"abc");
    redirect.join().unwrap();
    server.join().unwrap();
    let (url, redirect) = fixture(
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://203.0.113.1/\r\n\r\n",
    );
    assert!(
        zapret_net::fetch(&url, 128, 1000)
            .unwrap_err()
            .to_string()
            .contains("expected HTTPS")
    );
    redirect.join().unwrap();
}
#[test]
fn thirty_minute_batch_ceiling_preserves_slow_legacy_inputs() {
    assert!(
        zapret_net::probe(
            &[],
            &BatchOptions {
                deadline_ms: 1_800_000,
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        zapret_net::probe(
            &[],
            &BatchOptions {
                deadline_ms: 1_800_001,
                ..Default::default()
            }
        )
        .is_err()
    );
}
#[test]
fn latency_requires_an_explicit_measurement_target() {
    assert!(
        zapret_net::diagnostics(
            std::path::Path::new("."),
            "latency",
            &json!({"count":1,"timeout_ms":10,"protocol":"icmp"})
        )
        .is_err()
    );
}
#[test]
fn ipv6_family_is_probed_in_parallel_with_a_stalled_ipv4_path() {
    let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).unwrap();
    let stalled = thread::spawn(move || {
        let (mut stream, _) = v4.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut b = [0; 4096];
        assert!(stream.read(&mut b).unwrap() > 0);
        let _ = stream.read(&mut b);
    });
    let complete = thread::spawn(move || {
        let (mut stream, _) = v6.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut b = [0; 4096];
        assert!(stream.read(&mut b).unwrap() > 0);
        thread::sleep(Duration::from_millis(60));
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    let result = zapret_net::diagnostics(
        std::path::Path::new("."),
        "ipv6",
        &json!({"url":format!("http://localhost:{port}/"),"timeout_ms":300}),
    )
    .unwrap();
    assert_eq!(result["rows"][0]["v4"]["ok"], false);
    assert_eq!(result["rows"][0]["v6"]["ok"], true);
    assert_eq!(result["rows"][0]["verdict"], "ok");
    stalled.join().unwrap();
    complete.join().unwrap();
}
