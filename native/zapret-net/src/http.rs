use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::lookup_host,
    task::JoinHandle,
    time::timeout,
};
use url::{Host, Position, Url};

pub(crate) const MAX_DOWNLOAD: usize = 128 * 1024 * 1024;
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) struct Driver(JoinHandle<Result<(), hyper::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn checked_url(text: &str, allow_http: bool) -> Result<Url> {
    if text.len() > 4096 {
        bail!("URL exceeds 4096 bytes")
    }
    let url = Url::parse(text).context("invalid URL")?;
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(s)) => s.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && (allow_http || loopback)))
    {
        bail!(
            "expected HTTPS URL without credentials or fragment (HTTP is allowed only for loopback fixtures)"
        )
    }
    Ok(url)
}
pub(crate) fn hostname(url: &Url) -> String {
    match url.host().expect("validated host") {
        Host::Domain(s) => s.into(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
}
async fn response_accept(
    url: &Url,
    method: &str,
    connector: &tokio_native_tls::TlsConnector,
    accept: &str,
) -> Result<(Response<Incoming>, Driver)> {
    let host = hostname(url);
    let port = url.port_or_known_default().context("URL port")?;
    let addresses: Vec<_> = lookup_host((host.as_str(), port))
        .await
        .context("DNS lookup failed")?
        .take(16)
        .collect();
    let stream = crate::tcp::connect(&addresses, &mut Vec::new())
        .await
        .map_err(anyhow::Error::msg)
        .context("TCP connection failed")?;
    let io: Box<dyn Io> = if url.scheme() == "https" {
        Box::new(
            connector
                .connect(&host, stream)
                .await
                .context("TLS certificate validation or handshake failed")?,
        )
    } else {
        Box::new(stream)
    };
    let (mut sender, connection) = http1::Builder::new()
        .max_buf_size(32768)
        .handshake(TokioIo::new(io))
        .await
        .context("HTTP handshake failed")?;
    let driver = Driver(tokio::spawn(connection));
    let request = Request::builder()
        .method(method)
        .uri(&url[Position::BeforePath..Position::AfterQuery])
        .header("Host", &url[Position::BeforeHost..Position::AfterPort])
        .header("Connection", "close")
        .header("Accept", accept)
        .header(
            "User-Agent",
            concat!("zapret-rust/", env!("CARGO_PKG_VERSION")),
        )
        .body(Full::new(Bytes::new()))?;
    let response = sender
        .send_request(request)
        .await
        .context("HTTP request failed")?;
    Ok((response, driver))
}
pub(crate) async fn fetch_async(
    text: &str,
    max_bytes: usize,
    timeout_ms: u64,
    ca_file: Option<&Path>,
) -> Result<Vec<u8>> {
    fetch_accept(text, max_bytes, timeout_ms, ca_file, "*/*").await
}
pub(crate) async fn fetch_accept(
    text: &str,
    max_bytes: usize,
    timeout_ms: u64,
    ca_file: Option<&Path>,
    accept: &str,
) -> Result<Vec<u8>> {
    if !(1..=MAX_DOWNLOAD).contains(&max_bytes) || !(1..=300_000).contains(&timeout_ms) {
        bail!("invalid download limits")
    }
    let mut url = checked_url(text, false)?;
    let connector = crate::tls_connector(ca_file, &["http/1.1"])?;
    timeout(Duration::from_millis(timeout_ms), async {
        for redirects in 0..=5 {
            let (mut response, _driver) = response_accept(&url, "GET", &connector, accept).await?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if redirects == 5 {
                    bail!("redirect limit exceeded")
                }
                let location = response
                    .headers()
                    .get(hyper::header::LOCATION)
                    .context("redirect without Location")?
                    .to_str()
                    .context("invalid redirect Location")?;
                let next = url.join(location).context("invalid redirect URL")?;
                checked_url(next.as_str(), false)?;
                if url.scheme() == "https" && next.scheme() != "https" {
                    bail!("HTTPS redirect downgrade rejected")
                }
                url = next;
                continue;
            }
            if !response.status().is_success() {
                bail!("HTTP status {}", response.status().as_u16())
            }
            if let Some(length) = response.headers().get(hyper::header::CONTENT_LENGTH) {
                let length: u64 = length
                    .to_str()
                    .context("invalid Content-Length")?
                    .parse()
                    .context("invalid Content-Length")?;
                if length > max_bytes as u64 {
                    bail!("response Content-Length exceeds {max_bytes} bytes")
                }
            }
            let mut bytes = Vec::new();
            while let Some(frame) = response.body_mut().frame().await {
                let frame = frame.context("incomplete HTTP transfer")?;
                if let Some(data) = frame.data_ref() {
                    if data.len() > max_bytes - bytes.len() {
                        bail!("response exceeds {max_bytes} bytes")
                    }
                    bytes.extend_from_slice(data);
                }
            }
            return Ok(bytes);
        }
        unreachable!()
    })
    .await
    .context("HTTP download deadline expired")?
}

pub fn fetch(url: &str, max_bytes: usize, timeout_ms: u64) -> Result<Vec<u8>> {
    crate::runtime(fetch_async(url, max_bytes, timeout_ms, None))
}
pub fn download(url: &str, path: &Path, max_bytes: usize, timeout_ms: u64) -> Result<()> {
    use std::io::Write;
    let bytes = fetch(url, max_bytes, timeout_ms)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("create staged download")?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .context("atomically publish download")?;
    Ok(())
}
