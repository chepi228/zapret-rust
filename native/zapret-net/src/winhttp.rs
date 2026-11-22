//! WinHTTP HEAD requests with one deadline across DNS, QUIC, TLS and redirects.
use crate::{
    http,
    http3::{MAX_REDIRECTS, ResponseHeaders, redirect},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    mem::{size_of, size_of_val},
    ptr::{null, null_mut},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::{Instant, timeout_at},
};
use url::{Position, Url};
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, GetLastError,
        },
        Networking::WinHttp::*,
    },
    core::w,
};

const MAX_HEADER_BYTES: u32 = 64 * 1024;
const MAX_URL_BYTES: u32 = 8192;

#[derive(Debug)]
struct ApiError {
    operation: &'static str,
    code: u32,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}: WinHTTP error {}", self.operation, self.code)
    }
}
impl std::error::Error for ApiError {}

pub(crate) fn failure(error: &anyhow::Error) -> &'static str {
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        return "Timeout";
    }
    match error.downcast_ref::<ApiError>().map(|error| error.code) {
        Some(ERROR_WINHTTP_TIMEOUT) => "Timeout",
        Some(ERROR_WINHTTP_OPERATION_CANCELLED) => "Cancelled",
        Some(ERROR_WINHTTP_HTTP_PROTOCOL_MISMATCH) => "ProtocolMismatch",
        Some(
            ERROR_WINHTTP_SECURE_FAILURE
            | ERROR_WINHTTP_SECURE_INVALID_CA
            | ERROR_WINHTTP_SECURE_CERT_CN_INVALID
            | ERROR_WINHTTP_SECURE_CERT_DATE_INVALID
            | ERROR_WINHTTP_SECURE_CERT_REVOKED
            | ERROR_WINHTTP_SECURE_CERT_REV_FAILED
            | ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE
            | ERROR_WINHTTP_SECURE_INVALID_CERT
            | ERROR_WINHTTP_SECURE_CHANNEL_ERROR,
        ) => "TlsFailure",
        _ => "RequestFailed",
    }
}

fn last_error(operation: &'static str) -> anyhow::Error {
    ApiError {
        operation,
        code: unsafe { GetLastError() },
    }
    .into()
}

fn check(ok: i32, operation: &'static str) -> Result<()> {
    if ok == 0 {
        return Err(last_error(operation));
    }
    Ok(())
}

struct Handle(*mut c_void);

// Each handle is exclusively owned. Futures may move it between threads, and
// WinHTTP callbacks publish events without using or closing the handle.
unsafe impl Send for Handle {}

impl Handle {
    fn new(raw: *mut c_void, operation: &'static str) -> Result<Self> {
        if raw.is_null() {
            return Err(last_error(operation));
        }
        Ok(Self(raw))
    }

    fn option(&self, option: u32, value: u32) -> Result<()> {
        check(
            unsafe {
                WinHttpSetOption(
                    self.0,
                    option,
                    (&raw const value).cast(),
                    size_of_val(&value) as u32,
                )
            },
            "WinHttpSetOption",
        )
        .with_context(|| format!("option {option}"))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn open() -> Result<Handle> {
    Handle::new(
        unsafe {
            WinHttpOpen(
                w!("zapret-rust diagnostics"),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                null(),
                null(),
                WINHTTP_FLAG_SECURE_DEFAULTS,
            )
        },
        "WinHttpOpen",
    )
}

fn connection(session: &Handle, host: &[u16], port: u16) -> Result<Handle> {
    Handle::new(
        unsafe { WinHttpConnect(session.0, host.as_ptr(), port, 0) },
        "WinHttpConnect",
    )
}

fn request(connection: &Handle, path: &[u16]) -> Result<Handle> {
    Handle::new(
        unsafe {
            WinHttpOpenRequest(
                connection.0,
                w!("HEAD"),
                path.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE,
            )
        },
        "WinHttpOpenRequest",
    )
}

fn require_h3(request: &Handle) -> Result<()> {
    request.option(
        WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
        WINHTTP_PROTOCOL_FLAG_HTTP3,
    )?;
    request.option(WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED, 1)
}

/// Tests local support without opening a connection to any server.
pub(crate) fn http3_available() -> Result<bool> {
    let capability = (|| {
        let session = open()?;
        let connection = connection(&session, &wide("127.0.0.1"), 443)?;
        require_h3(&request(&connection, &wide("/"))?)
    })();
    match capability {
        Ok(()) => Ok(true),
        Err(error)
            if error.downcast_ref::<ApiError>().is_some_and(|error| {
                matches!(
                    error.code,
                    ERROR_WINHTTP_INVALID_OPTION
                        | ERROR_INVALID_PARAMETER
                        | ERROR_NOT_SUPPORTED
                        | ERROR_WINHTTP_FEATURE_DISABLED
                )
            }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
enum Event {
    Sent,
    Headers,
    Error(u32),
}

// Contexts are IDs, not pointers. A callback arriving after request cleanup
// finds no listener, including when another request has reused the raw handle.
static NEXT_CONTEXT: AtomicUsize = AtomicUsize::new(1);
static CALLBACKS: Mutex<BTreeMap<usize, UnboundedSender<Event>>> = Mutex::new(BTreeMap::new());

struct Notifications {
    id: usize,
    receive: UnboundedReceiver<Event>,
}

impl Notifications {
    fn attach(request: &Handle) -> Result<Self> {
        let id = NEXT_CONTEXT.fetch_add(1, Ordering::Relaxed);
        let (send, receive) = mpsc::unbounded_channel();
        CALLBACKS
            .lock()
            .map_err(|_| anyhow::anyhow!("WinHTTP notification registry is unavailable"))?
            .insert(id, send);
        let notifications = Self { id, receive };
        let previous = unsafe {
            WinHttpSetStatusCallback(
                request.0,
                Some(callback),
                WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE
                    | WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE
                    | WINHTTP_CALLBACK_FLAG_REQUEST_ERROR,
                0,
            )
        };
        let previous = previous.map_or(0, |callback| callback as usize);
        if previous == usize::MAX {
            return Err(last_error("WinHttpSetStatusCallback"));
        }
        Ok(notifications)
    }

    async fn next(&mut self, deadline: Instant, operation: &'static str) -> Result<Event> {
        let event = timeout_at(deadline, self.receive.recv())
            .await?
            .context("WinHTTP notification channel closed")?;
        if let Event::Error(code) = event {
            return Err(ApiError { operation, code }.into());
        }
        Ok(event)
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        if let Ok(mut callbacks) = CALLBACKS.lock() {
            callbacks.remove(&self.id);
        }
    }
}

unsafe extern "system" fn callback(
    _handle: *mut c_void,
    id: usize,
    status: u32,
    info: *mut c_void,
    length: u32,
) {
    let event = match status {
        WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE => Event::Sent,
        WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE => Event::Headers,
        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
            let code = if !info.is_null() && length as usize >= size_of::<WINHTTP_ASYNC_RESULT>() {
                // The notification owns the struct until this callback returns.
                unsafe { info.cast::<WINHTTP_ASYNC_RESULT>().read_unaligned().dwError }
            } else {
                ERROR_WINHTTP_INTERNAL_ERROR
            };
            Event::Error(code)
        }
        _ => return,
    };
    if let Ok(callbacks) = CALLBACKS.lock() {
        if let Some(send) = callbacks.get(&id) {
            let _ = send.send(event);
        }
    }
}

struct Headers {
    status: u16,
    protocol: u32,
    location: Option<String>,
}

fn status_code(request: &Handle) -> Result<u16> {
    let mut status = 0u32;
    let mut size = size_of_val(&status) as u32;
    check(
        unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                null(),
                (&raw mut status).cast(),
                &mut size,
                null_mut(),
            )
        },
        "WinHttpQueryHeaders status",
    )?;
    ensure!((100..=599).contains(&status), "Invalid WinHTTP status code");
    Ok(status as u16)
}

fn protocol_used(request: &Handle) -> Result<u32> {
    let mut protocol = 0u32;
    let mut size = size_of_val(&protocol) as u32;
    check(
        unsafe {
            WinHttpQueryOption(
                request.0,
                WINHTTP_OPTION_HTTP_PROTOCOL_USED,
                (&raw mut protocol).cast(),
                &mut size,
            )
        },
        "WinHttpQueryOption HTTP protocol used",
    )?;
    Ok(protocol)
}

fn location(request: &Handle) -> Result<String> {
    let mut size = 0;
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_LOCATION,
            null(),
            null_mut(),
            &mut size,
            null_mut(),
        )
    };
    let error = unsafe { GetLastError() };
    ensure!(ok == 0, "Empty redirect Location");
    if error != ERROR_INSUFFICIENT_BUFFER {
        return Err(ApiError {
            operation: "Read redirect Location size",
            code: error,
        }
        .into());
    }
    ensure!(
        (2..=MAX_URL_BYTES).contains(&size) && size % 2 == 0,
        "Redirect Location exceeds size limit"
    );
    let mut words = vec![0u16; size as usize / 2];
    check(
        unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_LOCATION,
                null(),
                words.as_mut_ptr().cast(),
                &mut size,
                null_mut(),
            )
        },
        "WinHttpQueryHeaders Location",
    )?;
    let text = String::from_utf16(&words[..size as usize / 2])?;
    Ok(text.trim_end_matches('\0').to_owned())
}

async fn head(
    session: &Handle,
    url: &Url,
    deadline: Instant,
    #[cfg(test)] fixture_allow_unknown_ca: bool,
) -> Result<Headers> {
    let host = wide(&http::hostname(url));
    let path = wide(&url[Position::BeforePath..]);
    let connection = connection(
        session,
        &host,
        url.port_or_known_default().context("HTTPS port")?,
    )?;
    let request = request(&connection, &path)?;
    require_h3(&request)?;
    request.option(
        WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION,
    )?;
    request.option(WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, MAX_HEADER_BYTES)?;
    // The opt-in loopback fixture exercises QUIC without changing system trust.
    #[cfg(test)]
    if fixture_allow_unknown_ca {
        ensure!(
            url.host_str().is_some_and(|name| name == "127.0.0.1"),
            "Fixture trust is limited to IPv4 loopback"
        );
        request.option(
            WINHTTP_OPTION_SECURITY_FLAGS,
            SECURITY_FLAG_IGNORE_UNKNOWN_CA,
        )?;
    }

    let mut notifications = Notifications::attach(&request)?;
    check(
        unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, notifications.id) },
        "WinHttpSendRequest",
    )?;
    ensure!(
        matches!(
            notifications.next(deadline, "WinHttpSendRequest").await?,
            Event::Sent
        ),
        "Unexpected WinHTTP send notification"
    );
    check(
        unsafe { WinHttpReceiveResponse(request.0, null_mut()) },
        "WinHttpReceiveResponse",
    )?;
    ensure!(
        matches!(
            notifications
                .next(deadline, "WinHttpReceiveResponse")
                .await?,
            Event::Headers
        ),
        "Unexpected WinHTTP receive notification"
    );

    let protocol = protocol_used(&request)?;
    let status = status_code(&request)?;
    let location = (protocol == WINHTTP_PROTOCOL_FLAG_HTTP3
        && matches!(status, 301 | 302 | 303 | 307 | 308))
    .then(|| location(&request))
    .transpose()?;
    Ok(Headers {
        status,
        protocol,
        location,
    })
}

pub(crate) async fn http3(url: Url, timeout_ms: u64) -> Result<ResponseHeaders> {
    request_headers(
        url,
        timeout_ms,
        #[cfg(test)]
        false,
    )
    .await
}

async fn request_headers(
    mut url: Url,
    timeout_ms: u64,
    #[cfg(test)] fixture_allow_unknown_ca: bool,
) -> Result<ResponseHeaders> {
    ensure!(url.scheme() == "https", "HTTP/3 requires HTTPS");
    let deadline = Instant::now() + std::time::Duration::from_millis(timeout_ms);
    timeout_at(deadline, async {
        let session = open()?;
        let timeout = timeout_ms as i32;
        check(
            unsafe { WinHttpSetTimeouts(session.0, timeout, timeout, timeout, timeout) },
            "WinHttpSetTimeouts",
        )?;
        for redirects in 0..=MAX_REDIRECTS {
            let headers = head(
                &session,
                &url,
                deadline,
                #[cfg(test)]
                fixture_allow_unknown_ca,
            )
            .await?;
            if let Some(location) = headers.location {
                ensure!(redirects < MAX_REDIRECTS, "HTTP/3 redirect limit exceeded");
                url = redirect(&url, &location)?;
            } else {
                return Ok(ResponseHeaders {
                    status: headers.status,
                    protocol: match headers.protocol {
                        WINHTTP_PROTOCOL_FLAG_HTTP3 => "h3",
                        WINHTTP_PROTOCOL_FLAG_HTTP2 => "h2",
                        _ => "",
                    },
                    final_url: url,
                });
            }
        }
        unreachable!("The redirect limit is enforced on the last request")
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_preserve_https_authority_and_reject_credentials_or_downgrades() {
        let url = Url::parse("https://example.test/start").unwrap();
        assert_eq!(
            redirect(&url, "/end?q=1").unwrap().as_str(),
            "https://example.test/end?q=1"
        );
        assert!(redirect(&url, "http://127.0.0.1/end").is_err());
        assert!(redirect(&url, "//user:password@example.test/end").is_err());
    }

    #[test]
    #[ignore = "requires the disposable QUIC fixture listening on IPv4 loopback"]
    fn loopback_http3_refuses_unknown_certificate_and_reports_confirmed_headers() {
        let port = std::env::var("ZAPRET_HTTP3_FIXTURE_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        assert!(port > 1024);
        let url = |path| Url::parse(&format!("https://127.0.0.1:{port}{path}")).unwrap();
        crate::runtime(async {
            let error = http3(url("/"), 3000)
                .await
                .err()
                .expect("self-signed certificate accepted");
            assert_eq!(failure(&error), "TlsFailure", "{error:#}");
            let answer = request_headers(url("/redirect"), 3000, true).await?;
            assert_eq!(answer.protocol, "h3");
            assert_eq!(answer.status, 403);
            assert_eq!(answer.final_url.path(), "/denied");
            assert!(
                request_headers(url("/downgrade"), 3000, true)
                    .await
                    .is_err()
            );
            let start = Instant::now();
            let error = request_headers(url("/stall"), 200, true)
                .await
                .err()
                .expect("stalled request completed");
            assert_eq!(failure(&error), "Timeout", "{error:#}");
            assert!(start.elapsed().as_millis() < 1500);
            let answer = request_headers(url("/"), 3000, true).await?;
            assert_eq!(answer.status, 200);
            Ok(())
        })
        .unwrap();
    }
}
