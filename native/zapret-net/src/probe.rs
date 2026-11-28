use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::BodyExt;
use hyper::{
    Request,
    body::{Body, Bytes, Frame, SizeHint},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_native_tls::TlsConnector;
use url::{Host, Position};

use crate::protocol::{Observation, ProbeMode, Stage, Target, Termination};
#[cfg(test)]
use tokio::time::timeout;

pub fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

// Dropping a probe on timeout also closes its independently polled HTTP connection.
struct ConnectionDriver(JoinHandle<Result<(), hyper::Error>>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn run_probe(
    target: Target,
    connector: TlsConnector,
    batch_start: Instant,
    deadline: Instant,
    mut cancellation: watch::Receiver<bool>,
    ca_file: Option<PathBuf>,
    post_body: Option<Arc<[u8]>>,
) -> Observation {
    let mut row = Observation::queued(&target, Termination::Cancelled);
    if ca_file.is_some() {
        row.trust_source = "SystemPlusExtraCa".into();
    }
    if *cancellation.borrow() {
        return row;
    }
    if Instant::now() >= deadline {
        row.termination = Termination::Deadline;
        return row;
    }
    let start = Instant::now();
    row.started_ms = Some(elapsed_ms(batch_start));
    row.started_monotonic_ms = zapret_platform::monotonic_ms().ok();
    let request_deadline = start + Duration::from_millis(target.job.timeout_ms);
    let provided = Arc::new(AtomicUsize::new(0));
    let cutoff = deadline.min(request_deadline);
    let quic_tls_error =
        (target.job.mode == ProbeMode::Http3Head).then(|| crate::http3::PeerTlsError::new(None));
    let outcome = tokio::select! {
        biased;
        _ = cancellation.changed() => Termination::Cancelled,
        result = timeout_at(cutoff, execute(&target, &connector, &mut row, provided.clone(), post_body.as_deref(), ca_file, quic_tls_error.clone())) => {
            match result {
                Ok(Ok(termination)) => termination,
                Ok(Err((termination, error))) => {
                    row.error = Some(error);
                    termination
                }
                Err(_) if deadline <= request_deadline => Termination::Deadline,
                Err(_) if let Some(error) = quic_tls_error.and_then(|e| e.borrow().clone()) => {
                    row.error = Some(format!("QUIC/HTTP3: {error}"));
                    Termination::TlsFailure
                }
                Err(_) => Termination::Timeout,
            }
        }
    };
    row.termination = outcome;
    row.request_body_bytes_provided = provided.load(Ordering::Acquire);
    row.total_ms = elapsed_ms(start);
    row.finished_monotonic_ms = zapret_platform::monotonic_ms().ok();
    row
}

type ProbeError = (Termination, String);

async fn execute(
    target: &Target,
    connector: &TlsConnector,
    row: &mut Observation,
    provided: Arc<AtomicUsize>,
    post_body: Option<&[u8]>,
    ca_file: Option<PathBuf>,
    quic_tls_error: Option<crate::http3::PeerTlsError>,
) -> Result<Termination, ProbeError> {
    let media_target;
    let target = if target.job.mode == ProbeMode::RobloxIcon {
        row.stage = Stage::Http;
        let start = Instant::now();
        let url = crate::roblox::resolve(&target.url, connector)
            .await
            .map_err(|e| (Termination::HttpFailure, format!("Roblox API: {e:#}")))?;
        row.media_url = Some(url.to_string());
        row.media_lookup_ms = Some(elapsed_ms(start));
        media_target = Target {
            job: target.job.clone(),
            url,
        };
        &media_target
    } else {
        target
    };
    let host = match target.url.host().expect("validated URL") {
        Host::Domain(name) => name.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    let port = target.url.port_or_known_default().expect("HTTP(S) port");
    row.stage = Stage::Dns;
    let start = Instant::now();
    let addresses: Vec<SocketAddr> = if let Some(address) = target.job.connect_ip {
        row.dns_source = "connect_ip override".into();
        vec![SocketAddr::new(address, port)]
    } else {
        if target
            .url
            .host()
            .is_some_and(|host| !matches!(host, Host::Domain(_)))
        {
            row.dns_source = "IP literal".into();
        }
        crate::connection::resolve_addresses(&host, port)
            .await
            .map_err(|error| (Termination::DnsFailure, error.to_string()))?
    };
    row.dns_ms = Some(elapsed_ms(start));
    row.resolved_addresses = addresses.iter().map(ToString::to_string).collect();
    if addresses.is_empty() {
        return Err((
            Termination::DnsFailure,
            "resolver returned no addresses".into(),
        ));
    }

    if let Some(peer_tls_error) = quic_tls_error {
        row.stage = Stage::Tls;
        let response =
            crate::http3::probe_head(target.url.clone(), addresses, ca_file, peer_tls_error)
                .await
                .map_err(|error| {
                    let cause = match crate::http3::failure(&error) {
                        "Timeout" => Termination::Timeout,
                        "TlsFailure" => Termination::TlsFailure,
                        _ => Termination::HttpFailure,
                    };
                    (cause, format!("{error:#}"))
                })?;
        row.remote_address = Some(response.remote.to_string());
        row.tls_ms = Some(response.handshake_ms);
        row.headers_ms = Some(response.headers_ms);
        row.certificate_validated = true;
        row.status_code = Some(response.headers.status().as_u16());
        row.body_complete = true;
        row.stage = Stage::Complete;
        return Ok(Termination::Complete);
    }
    row.stage = Stage::Tcp;
    if target.url.scheme() == "https" {
        let (tls, tls_ms) = crate::tcp::connect_tls(
            &addresses,
            &mut row.tcp_attempts,
            &host,
            connector,
            None,
            |connected| {
                row.stage = if connected.is_some() {
                    Stage::Tls
                } else {
                    Stage::Tcp
                };
                row.tcp_ms = connected.map(|(_, ms)| ms);
                row.remote_address = connected.map(|(peer, _)| peer.to_string());
            },
        )
        .await?;
        row.tls_ms = Some(tls_ms);
        row.certificate_validated = true;
        exchange(tls, target, row, provided, post_body).await
    } else {
        let start = Instant::now();
        let stream = connect(&addresses, row).await?;
        row.tcp_ms = Some(elapsed_ms(start));
        row.remote_address = stream.peer_addr().ok().map(|address| address.to_string());
        exchange(stream, target, row, provided, post_body).await
    }
}

async fn connect(addresses: &[SocketAddr], row: &mut Observation) -> Result<TcpStream, ProbeError> {
    crate::tcp::connect(addresses, &mut row.tcp_attempts)
        .await
        .map_err(|error| (Termination::TcpFailure, error))
}

#[cfg(test)]
async fn connect_with<T, F, Fut>(
    addresses: &[SocketAddr],
    row: &mut Observation,
    connector: F,
) -> Result<T, String>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    crate::tcp::connect_with(addresses, &mut row.tcp_attempts, connector).await
}
async fn exchange<S>(
    stream: S,
    target: &Target,
    row: &mut Observation,
    provided: Arc<AtomicUsize>,
    post_body: Option<&[u8]>,
) -> Result<Termination, ProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    row.stage = Stage::Http;
    let start = Instant::now();
    let (mut sender, connection) = http1::Builder::new()
        .max_buf_size(32768)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| (Termination::HttpFailure, error.to_string()))?;
    let _driver = ConnectionDriver(tokio::spawn(connection));
    let authority = &target.url[Position::BeforeHost..Position::AfterPort];
    let path = &target.url[Position::BeforePath..Position::AfterQuery];
    let method = target
        .job
        .method
        .as_deref()
        .unwrap_or(if target.job.post_bytes > 0 {
            "POST"
        } else {
            "GET"
        });
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", authority)
        .header("connection", "close")
        .header("accept", "*/*")
        .header("user-agent", "zapret-rust-probe/0.1.0");
    let full = matches!(
        target.job.mode,
        ProbeMode::FullGet | ProbeMode::Jwks | ProbeMode::RobloxIcon
    );
    let request = if full {
        request.header("accept-encoding", "identity")
    } else {
        request.header("range", format!("bytes=0-{}", target.job.body_limit - 1))
    };
    let request = request
        .body(CountedBody {
            bytes: Some(match post_body {
                Some(body) => Bytes::copy_from_slice(&body[..target.job.post_bytes]),
                None => Bytes::from(vec![0; target.job.post_bytes]),
            }),
            provided,
        })
        .map_err(|error| (Termination::HttpFailure, error.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| (Termination::HttpFailure, error.to_string()))?;
    row.headers_ms = Some(elapsed_ms(start));
    row.status_code = Some(response.status().as_u16());
    if target.job.mode == ProbeMode::Jwks && response.status().as_u16() != 200 {
        return Err((
            Termination::HttpFailure,
            format!("JWKS HTTP status {}", response.status()),
        ));
    }
    row.stage = Stage::Body;
    let mut body = response.into_body();
    let mut digest = full.then(Sha256::new);
    let mut payload =
        matches!(target.job.mode, ProbeMode::RobloxIcon | ProbeMode::Jwks).then(Vec::new);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| (Termination::TransferError, error.to_string()))?;
        if let Some(data) = frame.data_ref() {
            row.received_body_bytes += data.len();
            // Count only the accepted payload. TLS, HTTP and socket buffers may receive more.
            row.body_bytes += data.len().min(target.job.body_limit - row.body_bytes);
            if row.body_bytes == target.job.body_limit {
                row.target_reached = true;
                return Ok(Termination::BodyLimit);
            }
            if let Some(hash) = &mut digest {
                hash.update(data);
            }
            if let Some(bytes) = &mut payload {
                bytes.extend_from_slice(data);
            }
        }
    }
    if let Some(bytes) = payload {
        if target.job.mode == ProbeMode::Jwks {
            validate_jwks(&bytes).map_err(|e| (Termination::TransferError, e.to_string()))?;
        } else {
            crate::roblox::validate(&bytes)
                .map_err(|e| (Termination::TransferError, format!("Roblox PNG: {e:#}")))?;
        }
    }
    row.body_sha256 = digest.map(|hash| format!("{:x}", hash.finalize()));
    row.body_complete = true;
    row.stage = Stage::Complete;
    Ok(Termination::Complete)
}

/// Check the published key set without pinning key IDs or key material across rotations.
pub fn validate_jwks(bytes: &[u8]) -> anyhow::Result<()> {
    let data: serde_json::Value = serde_json::from_slice(bytes)?;
    let usable = data["keys"].as_array().is_some_and(|keys| {
        keys.iter().any(|key| {
            let present = |field: &str| key[field].as_str().is_some_and(|s| !s.is_empty());
            key.get("use").is_none_or(|usage| usage == "sig")
                && match key["kty"].as_str() {
                    Some("RSA") => present("n") && present("e"),
                    Some("EC") => present("crv") && present("x") && present("y"),
                    Some("OKP") => present("crv") && present("x"),
                    _ => false,
                }
        })
    });
    anyhow::ensure!(usable, "JWKS contains no public signing key");
    Ok(())
}

// Count what Hyper actually asks this request body to provide, including interrupted sends.
// Socket/TLS acknowledgement is intentionally not inferred from this measurement.
struct CountedBody {
    bytes: Option<Bytes>,
    provided: Arc<AtomicUsize>,
}
impl Body for CountedBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.bytes.take().filter(|b| !b.is_empty()).map(|bytes| {
            self.provided.fetch_add(bytes.len(), Ordering::AcqRel);
            Ok(Frame::data(bytes))
        }))
    }
    fn is_end_stream(&self) -> bool {
        self.bytes.as_ref().is_none_or(Bytes::is_empty)
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.bytes.as_ref().map_or(0, Bytes::len) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    fn connection_row() -> Observation {
        let target = crate::protocol::read_jobs(
            br#"{"version":1,"id":"connect","url":"https://example.com/"}"#.as_slice(),
        )
        .unwrap()
        .pop()
        .unwrap();
        Observation::queued(&target, Termination::Cancelled)
    }

    #[test]
    fn login_check_accepts_rotated_public_keys_and_rejects_error_pages() {
        for body in [
            r#"{"keys":[{"kid":"new","kty":"RSA","n":"abc","e":"AQAB"}]}"#,
            r#"{"keys":[{"use":"enc","kty":"oct"},{"use":"sig","kty":"EC","crv":"P-256","x":"a","y":"b"}]}"#,
        ] {
            assert!(validate_jwks(body.as_bytes()).is_ok());
        }
        for body in [
            "<html>sign in</html>",
            r#"{"error":"temporarily unavailable"}"#,
            r#"{"keys":[]}"#,
            r#"{"keys":[{"kty":"RSA","e":"AQAB"}]}"#,
            r#"{"keys":[{"kty":"RSA","use":"enc","n":"abc","e":"AQAB"}]}"#,
        ] {
            assert!(validate_jwks(body.as_bytes()).is_err());
        }
    }

    #[tokio::test]
    async fn jwks_http_check_cannot_pass_on_a_404_html_or_cut_off_reply() {
        let keys = r#"{"keys":[{"kty":"RSA","n":"abc","e":"AQAB"}]}"#;
        for (status, body, extra, expected) in [
            (200, keys, 0, Termination::Complete),
            (404, keys, 0, Termination::HttpFailure),
            (
                200,
                "<html>temporarily unavailable</html>",
                0,
                Termination::TransferError,
            ),
            (200, keys, 4, Termination::TransferError),
        ] {
            let target = crate::protocol::read_jobs(br#"{"version":1,"id":"epic","url":"https://example.test/keys","method":"GET","mode":"jwks"}"#.as_slice()).unwrap().pop().unwrap();
            let mut row = Observation::queued(&target, Termination::Cancelled);
            let (client, mut server) = tokio::io::duplex(4096);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len() + extra
            );
            let peer = tokio::spawn(async move {
                let mut request = vec![];
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"GET /keys HTTP/1.1"));
                server.write_all(response.as_bytes()).await.unwrap();
            });
            let result = exchange(
                client,
                &target,
                &mut row,
                Arc::new(AtomicUsize::new(0)),
                None,
            )
            .await;
            assert_eq!(result.unwrap_or_else(|(kind, _)| kind), expected);
            assert_eq!(row.body_complete, expected == Termination::Complete);
            peer.await.unwrap();
        }
    }

    struct ActiveAttempt(Arc<AtomicUsize>);
    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn probe_connections_disable_nagle_for_request_latency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut row = connection_row();
        let stream = connect(&[listener.local_addr().unwrap()], &mut row)
            .await
            .unwrap();
        assert!(stream.nodelay().unwrap());
        assert!(row.tcp_attempts[0].error.is_none());
    }

    #[tokio::test]
    async fn unreachable_ipv6_does_not_add_one_second_per_record_before_ipv4() {
        let addresses: Vec<SocketAddr> = ["[::1]:1", "[::2]:2", "[::3]:3", "127.0.0.1:4"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let active = Arc::new(AtomicUsize::new(0));
        let mut row = connection_row();
        let start = Instant::now();
        let addresses = zapret_core::connection_addresses(addresses, 16);
        let connected = connect_with(&addresses, &mut row, |address| {
            let active = active.clone();
            async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveAttempt(active);
                if address.is_ipv6() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
                } else {
                    Ok(address)
                }
            }
        })
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(900),
            "IPv4 waited {:?}",
            start.elapsed()
        );
        assert!(connected.is_ipv4());
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "losing connections were not dropped"
        );
        assert_eq!(row.tcp_attempts[1].address, "127.0.0.1:4");
        assert!(
            row.tcp_attempts[0]
                .error
                .as_deref()
                .unwrap()
                .contains("cancelled")
        );
    }

    #[tokio::test]
    async fn a_slow_preferred_connection_survives_while_other_addresses_are_tried() {
        let addresses = [1, 2, 3].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let mut row = connection_row();
        let result = timeout(
            Duration::from_secs(4),
            connect_with(&addresses, &mut row, |address| async move {
                if address.port() == 1 {
                    tokio::time::sleep(Duration::from_millis(1300)).await;
                    Ok(address)
                } else {
                    Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, addresses[0]);
        assert_eq!(row.tcp_attempts.len(), 3);
        assert!(row.tcp_attempts[0].error.is_none());
    }

    #[tokio::test]
    async fn cancelling_address_selection_drops_all_connection_attempts() {
        let addresses: Vec<SocketAddr> = ["[::1]:1", "127.0.0.1:4"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let active = Arc::new(AtomicUsize::new(0));
        let mut row = connection_row();
        let result = timeout(
            Duration::from_millis(350),
            connect_with(&addresses, &mut row, |_| {
                let active = active.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveAttempt(active);
                    std::future::pending::<std::io::Result<SocketAddr>>().await
                }
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_preserves_progress_and_closes_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready, received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            let mut byte = [0; 1];
            while !header.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).await.unwrap();
                header.push(byte[0]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nabc")
                .await
                .unwrap();
            ready.send(()).unwrap();
            socket.read(&mut byte).await.unwrap()
        });
        let input = format!(r#"{{"version":1,"id":"cancel","url":"http://127.0.0.1:{port}/"}}"#);
        let target = crate::protocol::read_jobs(input.as_bytes())
            .unwrap()
            .pop()
            .unwrap();
        let connector = native_tls::TlsConnector::new().unwrap().into();
        let start = Instant::now();
        let (cancel, cancellation) = watch::channel(false);
        let worker = tokio::spawn(run_probe(
            target,
            connector,
            start,
            start + Duration::from_secs(5),
            cancellation,
            None,
            None,
        ));
        received.await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.send(true).unwrap();
        let row = timeout(Duration::from_millis(500), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.termination, Termination::Cancelled);
        assert_eq!(row.stage, Stage::Body);
        assert_eq!(row.body_bytes, 3);
        assert!(!row.body_complete);
        assert_eq!(
            timeout(Duration::from_millis(500), server)
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}
