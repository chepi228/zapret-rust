use crate::{
    diagnostic::{self as d, Target},
    http,
};
use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, body::Bytes, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    ffi::OsString,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{Instant, timeout, timeout_at},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use zapret_platform::{OwnedChild, RunOptions, run_owned, terminate_owned};

#[derive(Debug, Clone, Serialize)]
struct Row {
    group: String,
    name: String,
    url: String,
    final_url: String,
    mode: String,
    observed_protocol: String,
    status_code: u16,
    complete: bool,
    protocol_confirmed: bool,
    quic_confirmed: bool,
    state: String,
    reason: String,
    error: String,
    elapsed_ms: f64,
    sample: u64,
    encoded_bytes: Option<f64>,
    session_restarted: bool,
    evidence: String,
    client: String,
    cleanup_complete: Option<bool>,
    tls_backend: String,
    trust_source: String,
}
fn row(
    target: &Target,
    mode: &str,
    protocol: &str,
    status: u16,
    complete: bool,
    elapsed_ms: f64,
    failure: &str,
) -> Row {
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "1.0" | "http/1.0" => "http/1.0",
        "1.1" | "http/1.1" => "http/1.1",
        "2" | "2.0" | "http/2" | "h2" => "h2",
        "3" | "3.0" | "http/3" | "h3" => "h3",
        _ => protocol,
    };
    let valid = match mode {
        "Http1" => matches!(protocol, "http/1.0" | "http/1.1"),
        "Http2" => protocol == "h2",
        "Http3" => protocol == "h3",
        "BrowserTcp" => matches!(protocol, "http/1.0" | "http/1.1" | "h2"),
        _ => matches!(protocol, "http/1.0" | "http/1.1" | "h2" | "h3"),
    };
    let confirmed = (100..=599).contains(&status) && valid;
    let (state, reason) = if failure == "Unavailable" {
        ("UNAVAILABLE", failure)
    } else if matches!(
        failure,
        "ControllerError" | "Cancelled" | "UnsupportedScheme" | "ProtocolMismatch"
    ) {
        ("UNKNOWN", failure)
    } else if !failure.is_empty() {
        ("FAIL", failure)
    } else if !complete || !(100..=599).contains(&status) {
        ("UNKNOWN", "Incomplete")
    } else if !valid {
        ("UNKNOWN", "ProtocolMismatch")
    } else if status >= 400 {
        ("HTTP_ERROR", "HttpStatus")
    } else if status >= 200 {
        ("OK", "Completed")
    } else {
        ("UNKNOWN", "Incomplete")
    };
    Row {
        group: target.group.clone(),
        name: target.name.clone(),
        url: target.url.clone(),
        final_url: target.url.clone(),
        mode: mode.into(),
        observed_protocol: protocol.into(),
        status_code: status,
        complete,
        protocol_confirmed: confirmed,
        quic_confirmed: confirmed && protocol == "h3",
        state: state.into(),
        reason: reason.into(),
        error: String::new(),
        elapsed_ms,
        sample: 1,
        encoded_bytes: None,
        session_restarted: false,
        evidence: if mode.starts_with("Browser") {
            "MainDocument"
        } else {
            "Headers"
        }
        .into(),
        client: match mode {
            "Http1" => "Rust direct HTTP/1.1 native-tls",
            "Http2" => "Rust direct HTTP/2 native-tls ALPN",
            "Http3" => "HTTP/3 HEAD",
            _ => "Chromium CDP actual main-document navigation",
        }
        .into(),
        cleanup_complete: None,
        tls_backend: match mode {
            "Http1" | "Http2" => {
                if cfg!(windows) {
                    "Schannel"
                } else if cfg!(target_os = "macos") {
                    "SecurityFramework"
                } else {
                    "OpenSSL"
                }
            }
            "Http3" => "Unavailable",
            _ => "Browser defaults",
        }
        .into(),
        trust_source: if mode.starts_with("Browser") {
            "Browser defaults"
        } else {
            "System"
        }
        .into(),
    }
}
fn explicit_path(args: &Value, key: &str) -> Result<Option<Option<PathBuf>>> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .with_context(|| format!("{key} must be an executable path"))?;
    if value.is_empty() {
        return Ok(Some(None));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        bail!("{key} must be an existing absolute executable path")
    }
    Ok(Some(Some(path.canonicalize()?)))
}
fn browser_path(args: &Value) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit_path(args, "browser_path")? {
        return Ok(path);
    }
    let mut paths = Vec::new();
    for var in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(var) {
            let root = PathBuf::from(root);
            paths.push(root.join("Microsoft/Edge/Application/msedge.exe"));
            paths.push(root.join("Google/Chrome/Application/chrome.exe"));
        }
    }
    if !cfg!(windows) {
        paths.extend(
            [
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/usr/bin/google-chrome",
            ]
            .map(PathBuf::from),
        );
    }
    Ok(paths
        .into_iter()
        .find(|p| p.is_file())
        .and_then(|p| p.canonicalize().ok()))
}
#[derive(Serialize)]
struct Capabilities {
    native_http1: bool,
    native_http2: bool,
    native_http3: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_http3_error: Option<String>,
    rust_http3: bool,
    curl_path: Option<PathBuf>,
    curl_version: String,
    curl_http3: bool,
    browser_path: Option<PathBuf>,
}
fn capabilities(root: &Path, args: &Value, http3: bool, extra_ca: bool) -> Result<Capabilities> {
    let curl_override = explicit_path(args, "curl_path")?;
    let builtin = http3 && curl_override.is_none();
    let (native_http3, native_http3_error) = if builtin && !extra_ca {
        #[cfg(windows)]
        match crate::winhttp::http3_available() {
            Ok(available) => (available, None),
            Err(error) => (false, Some(format!("{error:#}"))),
        }
        #[cfg(not(windows))]
        (false, None)
    } else {
        (false, None)
    };
    let curl = curl_override.flatten();
    let mut version = String::new();
    let mut h3 = false;
    if let Some(path) = curl.as_ref().filter(|_| http3) {
        if let Ok(result) = run_owned(
            path,
            &["--disable".into(), "--version".into()],
            &RunOptions {
                timeout: Duration::from_secs(3),
                cwd: Some(root.into()),
                max_output_bytes: 65536,
                ..Default::default()
            },
        ) {
            if result.exit_code == 0 && !result.timed_out && !result.output_truncated {
                let text = String::from_utf8_lossy(&result.stdout);
                version = text.lines().next().unwrap_or("").into();
                let https = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Protocols:"))
                    .is_some_and(|l| l.split_whitespace().any(|s| s == "https"));
                h3 = https
                    && text
                        .lines()
                        .find_map(|l| l.strip_prefix("Features:"))
                        .is_some_and(|l| l.split_whitespace().any(|s| s == "HTTP3"));
            }
        }
    }
    Ok(Capabilities {
        native_http1: true,
        native_http2: true,
        native_http3,
        native_http3_error,
        rust_http3: builtin && !native_http3,
        curl_path: curl,
        curl_version: version,
        curl_http3: h3,
        browser_path: browser_path(args)?,
    })
}
async fn http1(target: &Target, timeout_ms: u64, ca_file: Option<&Path>) -> Result<Row> {
    let url = http::checked_url(&target.url, false)?;
    let dns = d::resolve(&http::hostname(&url), timeout_ms.min(1500)).await;
    let Some(address) = d::select_addresses(&dns.addresses).first().copied() else {
        let mut result = row(
            target,
            "Http1",
            "",
            0,
            false,
            dns.elapsed_ms,
            if dns.reason == "Timeout" {
                "Timeout"
            } else {
                "RequestFailed"
            },
        );
        result.error = dns.error;
        return Ok(result);
    };
    let remaining = timeout_ms
        .saturating_sub(dns.elapsed_ms.ceil() as u64)
        .max(1);
    let result = crate::connection::one(
        url,
        address,
        1,
        remaining,
        crate::tls_connector(ca_file, &["http/1.1"])?,
        d::cancellation(),
        ca_file.is_some(),
    )
    .await;
    let failure = if result.headers_complete {
        ""
    } else if result.reason == "Timeout" {
        "Timeout"
    } else if result.reason == "Cancelled" {
        "Cancelled"
    } else {
        "RequestFailed"
    };
    let mut answer = row(
        target,
        "Http1",
        &format!("http/{}", result.http_version),
        result.status_code,
        result.headers_complete,
        result.elapsed_ms + dns.elapsed_ms,
        failure,
    );
    answer.error = result.error;
    Ok(answer)
}
async fn http2(target: &Target, timeout_ms: u64, ca_file: Option<&Path>) -> Result<Row> {
    let started = Instant::now();
    let mut current = http::checked_url(&target.url, false)?;
    if current.scheme() != "https" {
        return Ok(row(target, "Http2", "", 0, false, 0., "UnsupportedScheme"));
    }
    let connector = crate::tls_connector(ca_file, &["h2"])?;
    let mut observed = String::new();
    let mut code = 0;
    let mut phase = "DNS";
    let result = timeout(Duration::from_millis(timeout_ms), async {
        for redirects in 0..=5 {
            let host = http::hostname(&current);
            let port = current.port_or_known_default().context("HTTP port")?;
            phase = "DNS";
            let addresses = crate::connection::resolve_addresses(&host, port).await?;
            phase = "TCP";
            let (stream, _) = crate::tcp::connect_tls(
                &addresses,
                &mut Vec::new(),
                &host,
                &connector,
                |connected| {
                    phase = if connected.is_some() { "TLS" } else { "TCP" };
                },
            )
            .await
            .map_err(|(_, error)| anyhow::Error::msg(error))?;
            let protocol = stream.get_ref().negotiated_alpn()?;
            if protocol.as_deref() != Some(b"h2") {
                return Ok(false);
            }
            observed = "h2".into();
            phase = "HTTP/2";
            let (mut sender, connection) = http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                .await?;
            struct Abort(tokio::task::JoinHandle<Result<(), hyper::Error>>);
            impl Drop for Abort {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _driver = Abort(tokio::spawn(connection));
            let request = Request::builder()
                .method("HEAD")
                .uri(current.as_str())
                .header("User-Agent", "zapret-rust-web/0.1")
                .body(Empty::<Bytes>::new())?;
            let mut response = sender.send_request(request).await?;
            code = response.status().as_u16();
            if matches!(code, 301 | 302 | 303 | 307 | 308) {
                if redirects == 5 {
                    bail!("redirect limit exceeded")
                }
                let next = current.join(
                    response
                        .headers()
                        .get(hyper::header::LOCATION)
                        .context("redirect without Location")?
                        .to_str()?,
                )?;
                if http::checked_url(next.as_str(), false)?.scheme() != "https" {
                    bail!("HTTPS downgrade rejected")
                }
                current = next;
                code = 0;
                observed.clear();
                continue;
            }
            while let Some(frame) = response.body_mut().frame().await {
                frame?;
            }
            return Ok::<bool, anyhow::Error>(true);
        }
        unreachable!()
    })
    .await;
    let (complete, failure, error) = match result {
        Ok(Ok(true)) => (true, "", String::new()),
        Ok(Ok(false)) => (false, "", String::new()),
        Ok(Err(e)) => (false, "RequestFailed", format!("{phase}: {e:#}")),
        Err(_) => (
            false,
            "Timeout",
            format!("HTTP/2 deadline expired during {phase}"),
        ),
    };
    let mut answer = row(
        target,
        "Http2",
        &observed,
        code,
        complete,
        started.elapsed().as_secs_f64() * 1000.,
        failure,
    );
    if observed.is_empty() && failure.is_empty() {
        answer.reason = "ProtocolMismatch".into()
    }
    answer.final_url = current.into();
    answer.error = error;
    Ok(answer)
}
async fn http3(
    root: &Path,
    target: &Target,
    capabilities: &Capabilities,
    timeout_ms: u64,
    ca_file: Option<&Path>,
) -> Result<Row> {
    if capabilities.native_http3 || capabilities.rust_http3 {
        let url = http::checked_url(&target.url, false)?;
        if url.scheme() != "https" {
            return Ok(row(target, "Http3", "", 0, false, 0., "UnsupportedScheme"));
        }
        let start = Instant::now();
        let mut cancel = d::cancellation();
        let outcome = tokio::select! {
            result = async {
                #[cfg(windows)]
                if capabilities.native_http3 {
                    return crate::winhttp::http3(url, timeout_ms)
                        .await
                        .map_err(|error| (crate::winhttp::failure(&error), error));
                }
                crate::http3::request(url, timeout_ms, ca_file)
                    .await
                    .map_err(|error| (crate::http3::failure(&error), error))
            } => Some(result),
            _ = cancel.wait_for(|cancelled| *cancelled) => None,
        };
        let elapsed = start.elapsed().as_secs_f64() * 1000.;
        let mut answer = match outcome {
            Some(Ok(response)) => {
                let mut answer = row(
                    target,
                    "Http3",
                    response.protocol,
                    response.status,
                    true,
                    elapsed,
                    "",
                );
                answer.final_url = response.final_url.into();
                answer
            }
            Some(Err((reason, error))) => {
                let mut answer = row(target, "Http3", "", 0, false, elapsed, reason);
                answer.error = format!("{error:#}");
                answer
            }
            None => row(target, "Http3", "", 0, false, elapsed, "Cancelled"),
        };
        if capabilities.native_http3 {
            answer.client = "Windows WinHTTP HTTP/3 HEAD".into();
            answer.tls_backend = "Schannel".into();
        } else {
            answer.client = "Rust direct Quinn HTTP/3 HEAD".into();
            answer.tls_backend = "rustls".into();
            if ca_file.is_some() {
                answer.trust_source = "SystemPlusExtraCa".into();
            }
        }
        return Ok(answer);
    }
    if !capabilities.curl_http3 {
        let mut answer = row(target, "Http3", "", 0, false, 0., "Unavailable");
        if let Some(error) = &capabilities.native_http3_error {
            answer.error.clone_from(error);
        }
        return Ok(answer);
    }
    if http::checked_url(&target.url, false)?.scheme() != "https" {
        return Ok(row(target, "Http3", "", 0, false, 0., "UnsupportedScheme"));
    }
    let start = std::time::Instant::now();
    let seconds = format!("{:.3}", timeout_ms as f64 / 1000.);
    let args = [
        "--disable",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--http3-only",
        "--head",
        "--location",
        "--max-redirs",
        "5",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        &seconds,
        "--max-time",
        &seconds,
        "--output",
        if cfg!(windows) { "NUL" } else { "/dev/null" },
        "--write-out",
        "%{http_code}|%{http_version}|%{url_effective}",
        "--url",
        &target.url,
    ]
    .map(OsString::from);
    let result = run_owned(
        capabilities.curl_path.as_ref().context("curl path")?,
        &args,
        &RunOptions {
            timeout: Duration::from_millis(timeout_ms + 1000),
            cwd: Some(root.into()),
            max_output_bytes: 65536,
            ..Default::default()
        },
    )?;
    let text = String::from_utf8_lossy(&result.stdout);
    let parts: Vec<_> = text.trim().splitn(3, '|').collect();
    let code = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let protocol = parts.get(1).copied().unwrap_or("");
    let failure = if result.output_truncated {
        "ControllerError"
    } else if result.timed_out || result.exit_code == 28 {
        "Timeout"
    } else if matches!(result.exit_code, 2 | 4) {
        "Unavailable"
    } else if result.exit_code != 0 {
        "RequestFailed"
    } else {
        ""
    };
    let mut answer = row(
        target,
        "Http3",
        protocol,
        code,
        failure.is_empty(),
        start.elapsed().as_secs_f64() * 1000.,
        failure,
    );
    if let Some(url) = parts.get(2) {
        answer.final_url = (*url).into()
    }
    answer.error = String::from_utf8_lossy(&result.stderr)
        .chars()
        .take(1024)
        .collect();
    answer.client = "curl HTTP/3".into();
    answer.tls_backend = "See curl_version capability".into();
    Ok(answer)
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Cdp {
    socket: Socket,
    sequence: u64,
    session: String,
    events: VecDeque<Value>,
}
impl Cdp {
    async fn receive(&mut self, deadline: Instant) -> Result<Value> {
        loop {
            let message = timeout_at(deadline, self.socket.next())
                .await
                .context("DevTools deadline expired")?
                .context("DevTools connection closed")??;
            match message {
                Message::Text(text) => {
                    return serde_json::from_str(&text).context("invalid DevTools JSON");
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => bail!("DevTools sent non-text data or closed"),
            }
        }
    }
    async fn command(&mut self, method: &str, params: Value, deadline: Instant) -> Result<Value> {
        self.sequence += 1;
        let mut message = json!({"id":self.sequence,"method":method,"params":params});
        if !self.session.is_empty() {
            message["sessionId"] = self.session.clone().into()
        }
        timeout_at(
            deadline,
            self.socket.send(Message::Text(message.to_string().into())),
        )
        .await
        .context("DevTools send deadline")??;
        loop {
            let message = self
                .receive(deadline)
                .await
                .with_context(|| format!("DevTools {method}"))?;
            if message["id"].as_u64() == Some(self.sequence) {
                if let Some(error) = message.get("error") {
                    bail!("DevTools rejected {method}: {error}")
                }
                return Ok(message["result"].clone());
            }
            if message.get("method").is_some() {
                if self.events.len() >= 2048 {
                    bail!("DevTools event queue exceeded 2048 entries")
                }
                self.events.push_back(message);
            }
        }
    }
}
#[derive(Default)]
struct Navigation {
    frame: String,
    loader: String,
    request: String,
    url: String,
    protocol: String,
    status: u16,
    complete: bool,
    done: bool,
    failure: String,
    encoded: Option<f64>,
}
impl Navigation {
    fn update(&mut self, event: &Value) {
        let p = &event["params"];
        match event["method"].as_str().unwrap_or("") {
            "Network.requestWillBeSent"
                if p["type"] == "Document"
                    && p["frameId"] == self.frame
                    && p["loaderId"] == self.loader =>
            {
                self.request = p["requestId"].as_str().unwrap_or("").into();
                self.url = p["request"]["url"].as_str().unwrap_or("").into();
                self.protocol.clear();
                self.status = 0;
                self.complete = false;
                self.done = false;
                self.failure.clear();
                self.encoded = None;
            }
            "Network.responseReceived"
                if p["type"] == "Document"
                    && p["frameId"] == self.frame
                    && p["requestId"] == self.request =>
            {
                self.url = p["response"]["url"].as_str().unwrap_or("").into();
                self.protocol = p["response"]["protocol"].as_str().unwrap_or("").into();
                self.status = p["response"]["status"].as_f64().unwrap_or(0.) as u16;
            }
            "Network.loadingFinished" if p["requestId"] == self.request && self.status >= 100 => {
                self.complete = true;
                self.done = true;
                self.encoded = p["encodedDataLength"]
                    .as_f64()
                    .filter(|n| n.is_finite() && *n >= 0.);
            }
            "Network.loadingFailed" if p["requestId"] == self.request => {
                self.failure = p["errorText"]
                    .as_str()
                    .unwrap_or("Unknown browser failure")
                    .into();
                self.done = true;
            }
            _ => {}
        }
    }
}
fn browser_failure(error: &str) -> &'static str {
    if matches!(
        error,
        "net::ERR_TIMED_OUT" | "net::ERR_CONNECTION_TIMED_OUT"
    ) {
        "Timeout"
    } else {
        "RequestFailed"
    }
}
async fn endpoint(
    path: &Path,
    worker: &thread::JoinHandle<Result<zapret_platform::RunOutput>>,
    deadline: Instant,
) -> Result<String> {
    loop {
        if Instant::now() >= deadline {
            bail!("browser startup deadline expired")
        }
        if worker.is_finished() {
            bail!("browser exited before DevTools became available")
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.len() > 4096 {
                bail!("oversized browser endpoint file")
            }
            let lines: Vec<_> = text.lines().collect();
            if lines.len() >= 2 {
                if let Ok(port) = lines[0].parse::<u16>() {
                    if port > 0
                        && lines[1]
                            .strip_prefix("/devtools/browser/")
                            .is_some_and(|s| {
                                !s.is_empty()
                                    && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                            })
                    {
                        return Ok(format!("ws://127.0.0.1:{port}{}", lines[1]));
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
async fn browser(
    target: &Target,
    mode: &str,
    path: Option<&Path>,
    timeout_ms: u64,
    visits: u64,
) -> Result<Vec<Row>> {
    let Some(path) = path else {
        return Ok(vec![row(target, mode, "", 0, false, 0., "Unavailable")]);
    };
    let profile = tempfile::Builder::new()
        .prefix("zapret-rust-web-")
        .tempdir()?;
    let profile_path = profile.path().to_path_buf();
    let executable = path.to_path_buf();
    let mut args: Vec<OsString> = [
        "--headless=new",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-component-update",
        "--no-proxy-server",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
    ]
    .map(OsString::from)
    .into();
    args.push(format!("--user-data-dir={}", profile.path().display()).into());
    if mode == "BrowserTcp" {
        args.push("--disable-quic".into())
    }
    args.push("about:blank".into());
    let (identity_send, identity_receive) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let child = OwnedChild::spawn(
            &executable,
            &args,
            &RunOptions {
                timeout: Duration::from_millis(timeout_ms * (visits + 1) + 2000),
                max_output_bytes: 4 * 1024 * 1024,
                desktop_user: true,
                ..Default::default()
            },
        )?;
        let _ = identity_send.send(child.identity().clone());
        child.finish()
    });
    let start = Instant::now();
    let startup = start + Duration::from_millis(timeout_ms);
    let mut cdp = None;
    let mut rows = Vec::new();
    let mut navigation = Navigation {
        url: target.url.clone(),
        ..Default::default()
    };
    let mut sample = 1;
    let mut navigating = false;
    let operation = async {
        let endpoint = endpoint(&profile_path.join("DevToolsActivePort"), &worker, startup).await?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(1_048_576))
            .max_frame_size(Some(1_048_576));
        let (socket, _) = timeout_at(
            startup,
            tokio_tungstenite::connect_async_with_config(&endpoint, Some(config), false),
        )
        .await
        .context("DevTools connection deadline")??;
        cdp = Some(Cdp {
            socket,
            sequence: 0,
            session: String::new(),
            events: VecDeque::new(),
        });
        let connection = cdp.as_mut().context("DevTools socket")?;
        let created = connection
            .command("Target.createTarget", json!({"url":"about:blank"}), startup)
            .await?;
        let attached = connection
            .command(
                "Target.attachToTarget",
                json!({"targetId":created["targetId"],"flatten":true}),
                startup,
            )
            .await?;
        connection.session = attached["sessionId"]
            .as_str()
            .context("missing DevTools session")?
            .into();
        for (method, params) in [
            ("Page.enable", json!({})),
            ("Network.enable", json!({})),
            ("Network.setCacheDisabled", json!({"cacheDisabled":true})),
            ("Network.setBypassServiceWorker", json!({"bypass":true})),
        ] {
            connection.command(method, params, startup).await?;
        }
        for visit in 1..=visits {
            sample = visit;
            navigating = true;
            connection.events.clear();
            let visit_start = Instant::now();
            let deadline = visit_start + Duration::from_millis(timeout_ms);
            navigation = Navigation {
                url: target.url.clone(),
                ..Default::default()
            };
            let result = connection
                .command("Page.navigate", json!({"url":target.url}), deadline)
                .await?;
            if let Some(error) = result["errorText"].as_str() {
                let mut answer = row(
                    target,
                    mode,
                    "",
                    0,
                    false,
                    visit_start.elapsed().as_secs_f64() * 1000.,
                    browser_failure(error),
                );
                answer.error = error.into();
                answer.sample = visit;
                rows.push(answer);
                continue;
            }
            navigation.frame = result["frameId"]
                .as_str()
                .context("missing navigation frame")?
                .into();
            navigation.loader = result["loaderId"]
                .as_str()
                .context("missing navigation loader")?
                .into();
            while !navigation.done {
                let event = if let Some(event) = connection.events.pop_front() {
                    event
                } else {
                    connection.receive(deadline).await?
                };
                if event
                    .get("sessionId")
                    .is_some_and(|s| s != &connection.session)
                {
                    continue;
                }
                navigation.update(&event);
            }
            let failure = if navigation.failure.is_empty() {
                ""
            } else {
                browser_failure(&navigation.failure)
            };
            let mut answer = row(
                target,
                mode,
                &navigation.protocol,
                navigation.status,
                navigation.complete,
                visit_start.elapsed().as_secs_f64() * 1000.,
                failure,
            );
            answer.final_url = navigation.url.clone();
            answer.error = navigation.failure.clone();
            answer.sample = visit;
            answer.encoded_bytes = navigation.encoded;
            rows.push(answer);
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = operation {
        let text = format!("{error:#}");
        let failure = if navigating && text.to_lowercase().contains("deadline") {
            "Timeout"
        } else {
            "ControllerError"
        };
        let mut answer = row(
            target,
            mode,
            &navigation.protocol,
            navigation.status,
            false,
            start.elapsed().as_secs_f64() * 1000.,
            failure,
        );
        answer.sample = sample;
        answer.error = text;
        answer.final_url = navigation.url;
        answer.encoded_bytes = navigation.encoded;
        rows.push(answer);
    }
    if let Some(connection) = &mut cdp {
        connection.session.clear();
        let _ = connection
            .command(
                "Browser.close",
                json!({}),
                Instant::now() + Duration::from_millis(1000),
            )
            .await;
    }
    drop(cdp);
    if !worker.is_finished() {
        if let Ok(identity) = identity_receive.try_recv() {
            let _ = terminate_owned(&identity);
        }
    }
    // The runner owns a kill-on-close job from the first instruction, including startup failures.
    let owned = worker
        .join()
        .map_err(|_| anyhow::anyhow!("owned browser runner panicked"))?;
    if let Err(error) = &owned {
        for row in &mut rows {
            row.error = format!("{}; process owner: {error:#}", row.error);
            row.state = "UNKNOWN".into();
            row.reason = "ControllerError".into();
        }
    }
    if let Ok(output) = &owned {
        let details = String::from_utf8_lossy(&output.stderr);
        for row in &mut rows {
            if row.reason == "ControllerError" && !details.trim().is_empty() {
                row.error = format!(
                    "{}; browser: {}",
                    row.error,
                    details.chars().take(2048).collect::<String>().trim()
                );
            }
        }
    }
    let cleaned = profile.close().is_ok();
    for row in &mut rows {
        row.cleanup_complete = Some(cleaned);
    }
    if visits == 2
        && rows.len() == 1
        && matches!(rows[0].reason.as_str(), "Timeout" | "ControllerError")
    {
        // A timed-out WebSocket may no longer carry the second sample: use a fresh bounded profile.
        let retries = Box::pin(browser(target, mode, Some(path), timeout_ms, 1)).await?;
        for mut retry in retries {
            retry.sample = 2;
            retry.session_restarted = true;
            rows.push(retry);
        }
    }
    Ok(rows)
}
pub(crate) fn run(root: &Path, args: &Value) -> Result<Value> {
    if args["capabilities_only"] == true {
        return Ok(serde_json::to_value(capabilities(
            root,
            args,
            true,
            d::ca_file(args)?.is_some(),
        )?)?);
    }
    let targets = d::targets(root, args, false)?;
    let timeout_ms = d::duration_ms(args, 8000, 30000)?;
    let visits = d::integer(args, "visits", 2, 1, 2)?;
    let ca = d::ca_file(args)?;
    let modes = if let Some(values) = args["modes"].as_array().filter(|a| !a.is_empty()) {
        values
            .iter()
            .map(|v| v.as_str().map(str::to_owned).context("invalid web mode"))
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![
            "Http2".into(),
            "Http3".into(),
            "BrowserAuto".into(),
            "BrowserTcp".into(),
        ]
    };
    if modes.len() > 5
        || modes.iter().any(|m| {
            !matches!(
                m.as_str(),
                "Http1" | "Http2" | "Http3" | "BrowserAuto" | "BrowserTcp"
            )
        })
    {
        bail!("invalid web modes")
    }
    let capabilities = capabilities(
        root,
        args,
        modes.iter().any(|mode| mode == "Http3"),
        ca.is_some(),
    )?;
    let before = d::context(root);
    let started = d::now();
    let rows = crate::runtime(async {
        let mut rows = Vec::new();
        for target in targets {
            for mode in &modes {
                let result = match mode.as_str() {
                    "Http1" => http1(&target, timeout_ms, ca.as_deref())
                        .await
                        .map(|v| vec![v]),
                    "Http2" => http2(&target, timeout_ms, ca.as_deref())
                        .await
                        .map(|v| vec![v]),
                    "Http3" => http3(root, &target, &capabilities, timeout_ms, ca.as_deref())
                        .await
                        .map(|v| vec![v]),
                    _ => {
                        browser(
                            &target,
                            mode,
                            capabilities.browser_path.as_deref(),
                            timeout_ms,
                            visits,
                        )
                        .await
                    }
                };
                match result {
                    Ok(values) => rows.extend(values),
                    Err(error) => {
                        let mut observation =
                            row(&target, mode, "", 0, false, 0., "ControllerError");
                        observation.error = format!("{error:#}");
                        rows.push(observation);
                    }
                }
            }
        }
        Ok(rows)
    })?;
    let mut rows = rows;
    if ca.is_some() {
        for row in &mut rows {
            if matches!(row.mode.as_str(), "Http1" | "Http2") {
                row.trust_source = "SystemPlusExtraCa".into();
            }
        }
    }
    let after = d::context(root);
    let quic = rows.iter().any(|row| row.quic_confirmed);
    Ok(
        json!({"schema":1,"kind":"WebVerification","mode":"Advisory","started_utc_ms":started,"finished_utc_ms":d::now(),"proxy_mode":"Direct","capabilities":capabilities,"context_before":before,"context_after":after,"connection_state":d::context_state(&before,&after),"quic":if quic{"Observed"}else{"Unconfirmed"},"rows":rows}),
    )
}
