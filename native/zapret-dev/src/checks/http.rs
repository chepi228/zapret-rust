use anyhow::{Context, Result, ensure};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) struct Fixture {
    pub address: SocketAddr,
    pub requests: Arc<Mutex<Vec<Value>>>,
    pub names: Arc<Mutex<Vec<String>>>,
    active: Arc<AtomicUsize>,
    errors: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn new(ipv6: bool, tls: Option<Arc<ServerConfig>>) -> Result<Self> {
        let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let names = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let context = (
            requests.clone(),
            names.clone(),
            active.clone(),
            errors.clone(),
            stop.clone(),
        );
        let thread = thread::spawn(move || {
            let (requests, names, active, errors, stop) = context;
            let mut handlers = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (requests, names, active, errors, stop, tls) = (
                            requests.clone(),
                            names.clone(),
                            active.clone(),
                            errors.clone(),
                            stop.clone(),
                            tls.clone(),
                        );
                        active.fetch_add(1, Ordering::SeqCst);
                        handlers.push(thread::spawn(move || {
                            let result = (|| -> Result<()> {
                                // Accepted WinSock sockets inherit the listener's
                                // nonblocking mode. Each fixture handler owns a
                                // blocking socket with an explicit I/O deadline.
                                stream.set_nonblocking(false)?;
                                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                                if let Some(tls) = tls {
                                    let connection = ServerConnection::new(tls)?;
                                    let mut tls = StreamOwned::new(connection, stream);
                                    while tls.conn.is_handshaking() {
                                        tls.conn.complete_io(&mut tls.sock)?;
                                    }
                                    if let Some(name) = tls.conn.server_name() {
                                        names.lock().unwrap().push(name.into());
                                    }
                                    serve(&mut tls, &requests, &stop)
                                } else {
                                    serve(&mut stream, &requests, &stop)
                                }
                            })();
                            // Client cancellation, byte limits, and certificate rejection
                            // intentionally close sockets. Parser/fixture defects remain failures.
                            if let Err(error) = result {
                                if error.downcast_ref::<std::io::Error>().is_none() {
                                    errors.lock().unwrap().push(format!("{error:#}"));
                                }
                            }
                            active.fetch_sub(1, Ordering::SeqCst);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => {
                        errors.lock().unwrap().push(error.to_string());
                        break;
                    }
                }
                // Reap completed handlers to bound memory in a benchmark.
                let mut index = 0;
                while index < handlers.len() {
                    if handlers[index].is_finished() {
                        let _ = handlers.swap_remove(index).join();
                    } else {
                        index += 1
                    }
                }
            }
            for handler in handlers {
                let _ = handler.join();
            }
        });
        Ok(Self {
            address,
            requests,
            names,
            active,
            errors,
            stop,
            thread: Some(thread),
        })
    }
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }
    pub fn idle(&self) -> bool {
        self.active.load(Ordering::SeqCst) == 0
    }
    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    stream: &mut impl ReadWrite,
    requests: &Mutex<Vec<Value>>,
    stop: &AtomicBool,
) -> Result<()> {
    let mut data = Vec::new();
    let end = loop {
        if let Some(position) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break position + 4;
        }
        ensure!(data.len() <= 32768, "oversized fixture request");
        let mut part = [0; 8192];
        let size = stream.read(&mut part)?;
        if size == 0 {
            return Ok(());
        }
        data.extend_from_slice(&part[..size]);
    };
    let header = std::str::from_utf8(&data[..end])?;
    let mut lines = header.split("\r\n");
    let mut first = lines.next().context("request line")?.split_whitespace();
    let method = first.next().context("method")?.to_owned();
    let target = first.next().context("target")?.to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), Value::String(v.trim().into())))
        .collect::<serde_json::Map<_, _>>();
    let length = headers
        .get("content-length")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .parse::<usize>()?;
    ensure!(length <= 65536, "oversized fixture POST");
    let mut body = data[end..].to_vec();
    while body.len() < length {
        let mut buffer = [0; 8192];
        let size = stream.read(&mut buffer[..8192.min(length - body.len())])?;
        if size == 0 {
            return Ok(());
        }
        body.extend_from_slice(&buffer[..size]);
    }
    requests
        .lock()
        .unwrap()
        .push(json!({"method":method,"target":target,"headers":headers,
        "post_bytes":body.len(),"post_sha256":zapret_core::sha256(&body)}));
    let path = target.split('?').next().unwrap_or(&target);
    match path {
        "/headers-stall" => return wait_closed(stream, stop),
        "/malformed" => {
            stream.write_all(b"THIS IS NOT HTTP\r\n\r\n")?;
            return Ok(());
        }
        "/oversized" => {
            stream.write_all(b"HTTP/1.1 200 OK\r\nX-Huge: ")?;
            stream.write_all(&vec![b'x'; 65536])?;
            stream.write_all(b"\r\n\r\n")?;
            return Ok(());
        }
        "/empty" => {
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
        "/denied" => {
            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!")?;
            return Ok(());
        }
        "/redirect" => {
            stream.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: /small\r\nContent-Length: 0\r\n\r\n",
            )?;
            return Ok(());
        }
        "/chunked-short" => {
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n")?;
            return Ok(());
        }
        "/chunked" => {
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")?;
            for _ in 0..128 {
                stream.write_all(b"2000\r\n")?;
                stream.write_all(&[b'x'; 8192])?;
                stream.write_all(b"\r\n")?;
                thread::sleep(Duration::from_millis(1));
            }
            stream.write_all(b"0\r\n\r\n")?;
            return Ok(());
        }
        _ => {}
    }
    if path == "/interim" {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let length = match path {
        "/small" | "/interim" => 128,
        "/smoke" => 7,
        _ => 2_097_152,
    };
    stream.write_all(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    if method == "HEAD" {
        return Ok(());
    }
    if matches!(path, "/stall" | "/truncated" | "/exact") {
        stream.write_all(&vec![b'x'; if path == "/exact" { 65536 } else { 8192 }])?;
        if path != "/truncated" {
            wait_closed(stream, stop)?;
        }
        return Ok(());
    }
    for offset in (0..length).step_by(8192) {
        stream.write_all(&vec![b'x'; 8192.min(length - offset)])?;
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
fn wait_closed(stream: &mut impl ReadWrite, stop: &AtomicBool) -> Result<()> {
    stream.flush()?;
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && !stop.load(Ordering::SeqCst) {
        match stream.read(&mut [0]) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(super) fn tls() -> Result<(Arc<ServerConfig>, String)> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let mut ca = CertificateParams::default();
    ca.distinguished_name
        .push(DnType::CommonName, "Local probe fixture CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate()?;
    let ca = ca.self_signed(&ca_key)?;
    let mut params =
        CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca, &ca_key)?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), ca.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), ca.pem()))
}
