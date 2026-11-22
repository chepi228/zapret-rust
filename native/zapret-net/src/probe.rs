use std::{
    convert::Infallible,
    net::SocketAddr,
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
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, lookup_host},
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_native_tls::TlsConnector;
use url::{Host, Position};

use crate::protocol::{Observation, Stage, Target, Termination};
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
    extra_ca: bool,
    post_body: Option<Arc<[u8]>>,
) -> Observation {
    let mut row = Observation::queued(&target, Termination::Cancelled);
    if extra_ca {
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
    let outcome = tokio::select! {
        biased;
        _ = cancellation.changed() => Termination::Cancelled,
        result = timeout_at(cutoff, execute(&target, &connector, &mut row, provided.clone(), post_body.as_deref())) => {
            match result {
                Ok(Ok(termination)) => termination,
                Ok(Err((termination, error))) => {
                    row.error = Some(error);
                    termination
                }
                Err(_) if deadline <= request_deadline => Termination::Deadline,
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
) -> Result<Termination, ProbeError> {
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
        lookup_host((host.as_str(), port))
            .await
            .map_err(|error| (Termination::DnsFailure, error.to_string()))?
            .take(16)
            .collect()
    };
    row.dns_ms = Some(elapsed_ms(start));
    row.resolved_addresses = addresses.iter().map(ToString::to_string).collect();
    if addresses.is_empty() {
        return Err((
            Termination::DnsFailure,
            "resolver returned no addresses".into(),
        ));
    }

    row.stage = Stage::Tcp;
    let start = Instant::now();
    let stream = connect(&addresses, row).await?;
    row.tcp_ms = Some(elapsed_ms(start));
    row.remote_address = stream.peer_addr().ok().map(|address| address.to_string());
    if target.url.scheme() == "https" {
        row.stage = Stage::Tls;
        let start = Instant::now();
        let tls = connector
            .connect(&host, stream)
            .await
            .map_err(|error| (Termination::TlsFailure, error.to_string()))?;
        row.tls_ms = Some(elapsed_ms(start));
        row.certificate_validated = true;
        exchange(tls, target, row, provided, post_body).await
    } else {
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
        .header("range", format!("bytes=0-{}", target.job.body_limit - 1))
        .header("user-agent", "zapret-rust-probe/0.1.0")
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
    row.stage = Stage::Body;
    let mut body = response.into_body();
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
        }
    }
    row.body_complete = true;
    row.stage = Stage::Complete;
    Ok(Termination::Complete)
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
            false,
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
