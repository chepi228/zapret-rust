//! Direct HTTP/3 HEAD fallback with system certificate verification.
use crate::http;
use anyhow::{Context, Result, ensure};
use futures_util::{StreamExt, stream};
use hyper::{Request, Response, body::Bytes, header};
use quinn::{
    Connection, ConnectionError, Endpoint,
    crypto::rustls::{HandshakeData, QuicClientConfig},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls_platform_verifier::Verifier;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout, timeout_at},
};
use url::Url;

const MAX_HEADER_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_REDIRECTS: usize = 5;
const ALPN: &[u8] = b"h3";

pub(crate) struct ResponseHeaders {
    pub(crate) status: u16,
    pub(crate) protocol: &'static str,
    pub(crate) final_url: Url,
}

pub(crate) fn redirect(url: &Url, location: &str) -> Result<Url> {
    let next = url
        .join(location)
        .context("Invalid HTTPS redirect Location")?;
    let next = http::checked_url(next.as_str(), false)?;
    ensure!(next.scheme() == "https", "HTTP/3 redirect must use HTTPS");
    Ok(next)
}

pub(crate) fn failure(error: &anyhow::Error) -> &'static str {
    if error.is::<tokio::time::error::Elapsed>() {
        return "Timeout";
    }
    let tls_code = match error.downcast_ref::<ConnectionError>() {
        Some(ConnectionError::TimedOut) => return "Timeout",
        Some(ConnectionError::VersionMismatch) => return "ProtocolMismatch",
        Some(ConnectionError::TransportError(error)) => Some(error.code),
        Some(ConnectionError::ConnectionClosed(error)) => Some(error.error_code),
        _ => None,
    };
    match tls_code.map(u64::from) {
        Some(0x178) => "ProtocolMismatch", // TLS no_application_protocol
        Some(0x100..=0x1ff) => "TlsFailure",
        _ => "RequestFailed",
    }
}

fn client_config(ca_file: Option<&Path>) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let verifier = match ca_file {
        Some(path) => {
            let pem = crate::read_ca(path)?;
            let roots =
                CertificateDer::pem_slice_iter(&pem).collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(!roots.is_empty(), "No PEM certificate found");
            Verifier::new_with_extra_roots(roots, provider)?
        }
        None => Verifier::new(provider)?,
    };
    let mut tls = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )))
}

async fn addresses(url: &Url) -> Result<Vec<SocketAddr>> {
    let host = http::hostname(url);
    let port = url.port_or_known_default().context("URL port")?;
    crate::connection::resolve_addresses(&host, port)
        .await
        .context("DNS lookup failed")
}

async fn connect(
    url: &Url,
    config: &quinn::ClientConfig,
    addresses: &[SocketAddr],
) -> Result<Connection> {
    let host = http::hostname(url);
    let alternatives = addresses.len().saturating_sub(2);
    // Try the preferred address first. A second attempt can run alongside it
    // after a short delay, so an unavailable address family cannot block HEAD.
    let attempts = stream::iter(addresses.iter().copied().enumerate())
        .map(|(index, address)| {
            let host = &host;
            async move {
                if index == 1 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                let local = if address.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let endpoint = Endpoint::client(local.parse()?).context("Open QUIC socket")?;
                let connecting = endpoint.connect_with(config.clone(), address, host)?;
                if index < alternatives {
                    Ok::<_, anyhow::Error>(timeout(Duration::from_secs(2), connecting).await??)
                } else {
                    Ok(connecting.await?)
                }
            }
        })
        .buffer_unordered(2);
    tokio::pin!(attempts);
    let mut error = None;
    while let Some(attempt) = attempts.next().await {
        match attempt {
            Ok(connection) => return Ok(connection),
            Err(cause) if failure(&cause) == "TlsFailure" => {
                return Err(cause);
            }
            Err(cause)
                if error.as_ref().is_none_or(|previous| {
                    failure(previous) == "Timeout"
                        || (failure(&cause) == "ProtocolMismatch"
                            && failure(previous) != "ProtocolMismatch")
                }) =>
            {
                error = Some(cause);
            }
            Err(_) => {}
        }
    }
    Err(error.unwrap_or_else(|| anyhow::anyhow!("Resolver returned no addresses")))
}

pub(crate) struct HeadResult {
    pub headers: Response<()>,
    pub remote: SocketAddr,
    pub handshake_ms: f64,
    pub headers_ms: f64,
}

async fn head(
    url: &Url,
    config: &quinn::ClientConfig,
    addresses: &[SocketAddr],
) -> Result<HeadResult> {
    let start = Instant::now();
    let connection = connect(url, config, addresses).await?;
    let handshake_ms = crate::probe::elapsed_ms(start);
    let remote = connection.remote_address();
    let start = Instant::now();
    let protocol = connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol);
    ensure!(
        protocol.as_deref() == Some(ALPN),
        "QUIC peer did not negotiate h3"
    );
    let (mut driver, mut client) = h3::client::builder()
        .max_field_section_size(MAX_HEADER_BYTES)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .context("Open HTTP/3 connection")?;
    let request = Request::head(url.as_str())
        .header(header::ACCEPT, "*/*")
        .header(header::USER_AGENT, "zapret-rust-webcheck/1")
        .body(())?;
    tokio::select! {
        biased;
        response = async {
            let mut stream = client.send_request(request).await?;
            stream.finish().await?;
            loop {
                let response = stream.recv_response().await?;
                if !response.status().is_informational() {
                    return Ok(HeadResult {headers: response, remote, handshake_ms, headers_ms: crate::probe::elapsed_ms(start)});
                }
            }
        } => response,
        error = driver.wait_idle() => Err(error).context("HTTP/3 connection closed before response headers"),
    }
}

async fn request_headers(mut url: Url, ca_file: Option<&Path>) -> Result<ResponseHeaders> {
    let config = client_config(ca_file).context("Configure QUIC TLS")?;
    for redirects in 0..=MAX_REDIRECTS {
        let headers = head(&url, &config, &addresses(&url).await?).await?.headers;
        let status = headers.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            ensure!(redirects < MAX_REDIRECTS, "HTTP/3 redirect limit exceeded");
            let location = headers
                .headers()
                .get(header::LOCATION)
                .context("HTTP/3 redirect without Location")?
                .to_str()
                .context("Invalid HTTP/3 redirect Location")?;
            url = redirect(&url, location)?;
        } else {
            return Ok(ResponseHeaders {
                status,
                protocol: "h3",
                final_url: url,
            });
        }
    }
    unreachable!("The redirect limit is enforced on the last request")
}

pub(crate) async fn request(
    url: Url,
    timeout_ms: u64,
    ca_file: Option<&Path>,
) -> Result<ResponseHeaders> {
    ensure!(url.scheme() == "https", "HTTP/3 requires HTTPS");
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let ca_file = ca_file.map(Path::to_owned);
    // OS certificate verification can block inside the QUIC driver. Keep the
    // calling runtime free to enforce the deadline and respond to cancellation.
    timeout_at(
        deadline,
        isolated(async move { request_headers(url, ca_file.as_deref()).await }),
    )
    .await?
}

pub(crate) async fn probe_head(
    url: Url,
    addresses: Vec<SocketAddr>,
    ca_file: Option<PathBuf>,
) -> Result<HeadResult> {
    isolated(async move {
        let config = client_config(ca_file.as_deref())?;
        head(&url, &config, &addresses).await
    })
    .await
}

// Keep blocking certificate checks off the batch runtime. Dropping the caller cancels the request.
async fn isolated<T: Send + 'static>(
    request: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    let (_cancel_on_drop, stopped) = oneshot::channel::<()>();
    tokio::task::spawn_blocking(move || {
        crate::runtime(async {
            tokio::select! {
                biased;
                _ = stopped => anyhow::bail!("HTTP/3 request cancelled"),
                result = request => result,
            }
        })
    })
    .await
    .context("HTTP/3 task failed")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::QuicServerConfig;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use serde_json::json;

    fn fixture(path: &Path, alpn: &[u8]) -> Result<Endpoint> {
        let mut ca = CertificateParams::default();
        ca.distinguished_name
            .push(DnType::CommonName, "Local HTTP/3 fixture CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate()?;
        let ca = ca.self_signed(&ca_key)?;
        std::fs::write(path, ca.pem())?;

        let key = KeyPair::generate()?;
        let mut cert = CertificateParams::new(vec!["localhost".into()])?;
        cert.distinguished_name
            .push(DnType::CommonName, "localhost");
        cert.use_authority_key_identifier_extension = true;
        cert.key_usages.push(KeyUsagePurpose::DigitalSignature);
        cert.extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let cert = cert.signed_by(&key, &ca, &ca_key)?;
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone(), ca.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        server.alpn_protocols = vec![alpn.to_vec()];
        let server =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server)?));
        Ok(Endpoint::server(server, "127.0.0.1:0".parse()?)?)
    }

    async fn serve(incoming: quinn::Incoming) -> Result<()> {
        let mut connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(incoming.await?))
                .await?;
        let Some(resolver) = connection.accept().await? else {
            return Ok(());
        };
        let (request, mut stream) = resolver.resolve_request().await?;
        assert_eq!(request.method(), hyper::Method::HEAD);
        let response = match request.uri().path() {
            "/stall" => return std::future::pending().await,
            "/redirect" => Response::builder()
                .status(302)
                .header(header::LOCATION, "/denied"),
            "/loop" => Response::builder()
                .status(307)
                .header(header::LOCATION, "/loop"),
            "/downgrade" => Response::builder()
                .status(302)
                .header(header::LOCATION, "http://127.0.0.1:9/"),
            "/denied" => Response::builder().status(403),
            _ => Response::builder().status(200),
        };
        stream.send_response(response.body(())?).await?;
        stream.finish().await?;
        while connection.accept().await?.is_some() {}
        Ok(())
    }

    #[tokio::test]
    async fn direct_head_verifies_tls_and_redirects_under_one_deadline() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let ca = dir.path().join("fixture.pem");
        let server = fixture(&ca, ALPN)?;
        let port = server.local_addr()?.port();
        let h2_ca = dir.path().join("h2.pem");
        let h2_server = fixture(&h2_ca, b"h2")?;
        let h2_port = h2_server.local_addr()?.port();
        let mut requests = tokio::task::JoinSet::new();
        let url = |host, path| Url::parse(&format!("https://{host}:{port}{path}")).unwrap();
        let client = async {
            let invalid = request(url("localhost", "/"), 5000, None)
                .await
                .err()
                .unwrap();
            assert_eq!(failure(&invalid), "TlsFailure", "{invalid:#}");
            let wrong_host = request(url("127.0.0.1", "/"), 5000, Some(&ca))
                .await
                .err()
                .unwrap();
            assert_eq!(failure(&wrong_host), "TlsFailure", "{wrong_host:#}");
            let h2 = Url::parse(&format!("https://127.0.0.1:{h2_port}/"))?;
            let wrong_protocol = request(h2, 5000, Some(&h2_ca)).await.err().unwrap();
            assert_eq!(
                failure(&wrong_protocol),
                "ProtocolMismatch",
                "{wrong_protocol:#}"
            );
            let config = client_config(Some(&ca))?;
            let alternate = head(
                &url("localhost", "/"),
                &config,
                &[h2_server.local_addr()?, server.local_addr()?],
            )
            .await?;
            assert_eq!(alternate.remote, server.local_addr()?);
            assert_eq!(alternate.headers.status(), 200);
            let redirect = request(url("localhost", "/redirect"), 5000, Some(&ca)).await?;
            assert_eq!(
                (
                    redirect.status,
                    redirect.protocol,
                    redirect.final_url.path()
                ),
                (403, "h3", "/denied")
            );
            let deadline = request(url("localhost", "/stall"), 600, Some(&ca))
                .await
                .err()
                .unwrap();
            assert_eq!(failure(&deadline), "Timeout", "{deadline:#}");
            let job = crate::Job {
                version: 1,
                id: "quic".into(),
                url: url("localhost", "/redirect").to_string(),
                timeout_ms: 3000,
                body_limit: 1,
                post_bytes: 0,
                method: Some("HEAD".into()),
                mode: crate::ProbeMode::Http3Head,
                connect_ip: Some("127.0.0.1".parse()?),
            };
            let options = crate::BatchOptions {
                ca_file: Some(ca.clone()),
                ..Default::default()
            };
            let row = tokio::task::spawn_blocking(move || crate::probe(&[job], &options))
                .await??
                .pop()
                .unwrap();
            assert_eq!(row.status_code, Some(302)); // Judge the specified endpoint itself.
            assert_eq!(row.mode, crate::ProbeMode::Http3Head);
            assert_eq!(row.termination, crate::Termination::Complete);
            assert_eq!(row.remote_address, Some(format!("127.0.0.1:{port}")));
            assert!(row.certificate_validated && row.tcp_ms.is_none() && row.tls_ms.is_some());
            for (path, message) in [
                ("/downgrade", "redirect must use https"),
                ("/loop", "redirect limit exceeded"),
            ] {
                let error = request(url("localhost", path), 5000, Some(&ca))
                    .await
                    .err()
                    .unwrap();
                assert!(
                    format!("{error:#}").to_lowercase().contains(message),
                    "{error:#}"
                );
            }

            // Exercise the production diagnostics entry point with the same
            // fixture and a process-local CA, including transport selection.
            let options = json!({
                "url": url("localhost", "/").as_str(),
                "modes": ["Http3"], "timeout_ms": 5000, "ca_file": ca, "browser_path": "",
            });
            let root = dir.path().to_owned();
            let answer = tokio::task::spawn_blocking(move || {
                crate::diagnostics(&root, "webcheck", &options)
            })
            .await??;
            assert_eq!(answer["capabilities"]["rust_http3"], true);
            assert!(answer["capabilities"]["curl_path"].is_null());
            let row = &answer["rows"][0];
            assert_eq!(row["status_code"], 200, "{row}");
            assert_eq!(row["quic_confirmed"], true);
            assert_eq!(row["trust_source"], "SystemPlusExtraCa");
            Ok(())
        };
        tokio::pin!(client);
        loop {
            tokio::select! {
                result = &mut client => return result,
                Some(incoming) = server.accept() => { requests.spawn(serve(incoming)); }
                Some(incoming) = h2_server.accept() => { requests.spawn(serve(incoming)); }
                Some(result) = requests.join_next(), if !requests.is_empty() => {
                    // TLS rejections and request cancellations close fixture
                    // connections. A panic (e.g. wrong method) still fails.
                    let _ = result?;
                }
            }
        }
    }
}
