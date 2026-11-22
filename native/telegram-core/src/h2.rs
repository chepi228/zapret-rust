use crate::{
    protocol::{self, Handshake, MAX_PACKET},
    transport::{self, Io},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use ctr::cipher::StreamCipher;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const CHANNEL_REQUESTS: usize = 8;
const REPLAY_BYTES: usize = 64 * 1024;
const DOMAIN_COOLDOWN: Duration = Duration::from_secs(30);
const REPLAY_DELAY: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(8);
const WAITING_HEADERS: u8 = 1;
const RESPONSE_BODY: u8 = 2;
pub(crate) struct Lane {
    host: String,
    sender: SendRequest<Full<Bytes>>,
    task: JoinHandle<()>,
    slots: Arc<Semaphore>,
    request_bytes: Arc<Semaphore>,
    reply_bytes: Arc<Semaphore>,
    retry_after: std::sync::Mutex<Option<Instant>>,
}
pub(crate) struct Reply {
    pub body: Vec<u8>,
    _memory: OwnedSemaphorePermit,
}
#[derive(Debug)]
struct TransportError(i32);
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MTProto transport error {}", self.0)
    }
}
impl std::error::Error for TransportError {}
impl Drop for Lane {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Lane {
    pub(crate) async fn connect(host: String, buffer: usize) -> Result<Arc<Self>> {
        let tcp = transport::open_tcp(&host, 443, buffer).await?;
        let io = transport::tls(tcp, &host, true).await?;
        let lane = Self::from_io(host, io).await?;
        lane.preflight().await?;
        Ok(lane)
    }
    pub(crate) async fn from_io(host: String, io: Box<dyn Io>) -> Result<Arc<Self>> {
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(256 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024)
            .max_send_buf_size(64 * 1024)
            .max_header_list_size(32 * 1024)
            .handshake(TokioIo::new(io))
            .await?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(Self {
            host,
            sender,
            task,
            slots: Arc::new(Semaphore::new(64)),
            request_bytes: Arc::new(Semaphore::new(32 * 1024 * 1024)),
            reply_bytes: Arc::new(Semaphore::new(32 * 1024 * 1024)),
            retry_after: std::sync::Mutex::new(None),
        }))
    }
    pub(crate) fn reusable(&self) -> bool {
        !self.sender.is_closed() && !self.cooling_down()
    }
    pub(crate) fn cooling_down(&self) -> bool {
        self.retry_after
            .lock()
            .is_ok_and(|retry_after| retry_after.is_some_and(|until| until > Instant::now()))
    }
    async fn preflight(&self) -> Result<()> {
        let request = Request::builder()
            .method(Method::HEAD)
            .uri(format!("https://{}/api", self.host))
            .body(Full::new(Bytes::new()))?;
        let mut sender = self.sender.clone();
        let response = timeout(transport::CONNECT_TIMEOUT, async {
            sender.ready().await?;
            sender.send_request(request).await
        })
        .await??;
        let status = response.status().as_u16();
        ensure!(
            (200..300).contains(&status) || status == 405 || status == 501,
            "HTTP/2 preflight failed with status {status}"
        );
        Ok(())
    }
    async fn post(&self, body: Bytes, phase: Option<&AtomicU8>) -> Result<Reply> {
        let result = timeout(REQUEST_TIMEOUT, self.post_inner(body, phase))
            .await
            .context("HTTP/2 request timed out")
            .and_then(|response| response);
        if result.is_err() {
            self.defer_reuse();
        }
        result
    }
    fn defer_reuse(&self) {
        if let Ok(mut retry_after) = self.retry_after.lock() {
            *retry_after = Some(Instant::now() + DOMAIN_COOLDOWN);
        }
    }
    async fn post_inner(&self, body: Bytes, phase: Option<&AtomicU8>) -> Result<Reply> {
        ensure!(
            body.len() <= MAX_PACKET,
            "HTTP/2 request exceeds packet bound"
        );
        let _slot = self.slots.clone().acquire_owned().await?;
        let _request_bytes = self
            .request_bytes
            .clone()
            .acquire_many_owned(body.len() as u32)
            .await?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{}/api", self.host))
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .body(Full::new(body))?;
        let mut sender = self.sender.clone();
        sender.ready().await?;
        if let Some(phase) = phase {
            phase.store(WAITING_HEADERS, Ordering::Relaxed);
        }
        let response = sender.send_request(request).await?;
        if let Some(phase) = phase {
            phase.store(RESPONSE_BODY, Ordering::Relaxed);
        }
        let status = response.status().as_u16();
        if [403, 404, 429, 444].contains(&status) {
            return Err(TransportError(-(status as i32)).into());
        }
        ensure!(status == 200, "HTTP/2 POST failed with status {status}");
        ensure!(
            !response
                .headers()
                .get("content-type")
                .and_then(|s| s.to_str().ok())
                .is_some_and(|s| s.to_ascii_lowercase().contains("text/html")),
            "HTTP/2 endpoint returned HTML"
        );
        ensure!(
            response
                .headers()
                .get("content-encoding")
                .is_none_or(|s| s == "identity"),
            "HTTP/2 endpoint returned unsupported compression"
        );
        let declared = response
            .headers()
            .get("content-length")
            .map(|s| {
                s.to_str()?
                    .parse::<usize>()
                    .context("invalid HTTP/2 Content-Length")
            })
            .transpose()?;
        ensure!(
            declared.is_none_or(|n| n <= MAX_PACKET),
            "HTTP/2 response exceeds packet bound"
        );
        let mut incoming = response.into_body();
        let mut content = Vec::new();
        let mut memory = self.reply_bytes.clone().try_acquire_many_owned(0)?;
        while let Some(frame) = incoming.frame().await {
            if let Ok(data) = frame?.into_data() {
                ensure!(
                    content.len() + data.len() <= MAX_PACKET,
                    "HTTP/2 response exceeds packet bound"
                );
                if !data.is_empty() {
                    // This is a limit, not a wait: waiting while retaining part
                    // of every response could deadlock all streams on a lane.
                    memory.merge(
                        self.reply_bytes
                            .clone()
                            .try_acquire_many_owned(data.len() as u32)
                            .context("HTTP/2 lane reply memory limit")?,
                    );
                    content.extend_from_slice(&data);
                }
            }
        }
        ensure!(
            declared.is_none_or(|n| n == content.len()),
            "incomplete HTTP/2 response"
        );
        ensure!(content.len() % 4 == 0, "unaligned HTTP/2 MTProto reply");
        if content.len() == 4 {
            let code = i32::from_le_bytes(content[..4].try_into()?);
            if code < 0 {
                return Err(TransportError(code).into());
            }
        }
        Ok(Reply {
            body: content,
            _memory: memory,
        })
    }
}

fn can_replay(body: &[u8]) -> bool {
    (24..=REPLAY_BYTES).contains(&body.len()) && body[..8] != [0; 8]
}

async fn exchange(
    lane: &Lane,
    body: Bytes,
    replay_slots: &Semaphore,
    delay: Duration,
) -> Result<Reply> {
    if !can_replay(&body) {
        return lane.post(body, None).await;
    }
    let phase = AtomicU8::new(0);
    let original = lane.post(body.clone(), Some(&phase));
    tokio::pin!(original);
    tokio::select! {
        reply = &mut original => return reply,
        () = tokio::time::sleep(delay) => {},
    }
    if phase.load(Ordering::Relaxed) != WAITING_HEADERS {
        return original.await;
    }
    let Ok(_slot) = replay_slots.try_acquire() else {
        return original.await;
    };
    // The replay only races the response headers. Once the original receives
    // headers, allow its body to finish under the normal request deadline.
    let replay = timeout(POLL_TIMEOUT, lane.post(body, None));
    tokio::select! {
        biased;
        reply = &mut original => reply,
        reply = replay => match reply {
            Ok(Ok(reply)) if !reply.body.is_empty()
                && phase.load(Ordering::Relaxed) == WAITING_HEADERS => Ok(reply),
            _ => original.await,
        },
    }
}

struct Channel {
    slots: Arc<Semaphore>,
    budget: Arc<Semaphore>,
    replay_slots: Semaphore,
    sequence: AtomicU64,
}

struct RequestBudget {
    _slot: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

impl Channel {
    fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(CHANNEL_REQUESTS)),
            budget: Arc::new(Semaphore::new(CHANNEL_BYTES)),
            replay_slots: Semaphore::new(2),
            sequence: AtomicU64::new(0),
        }
    }

    async fn send(
        &self,
        lane: &Lane,
        body: Bytes,
        sequence: u64,
        sender: mpsc::Sender<(Result<Reply>, Arc<RequestBudget>)>,
        budget: Arc<RequestBudget>,
    ) {
        let started = tokio::time::Instant::now();
        let reply = exchange(lane, body.clone(), &self.replay_slots, REPLAY_DELAY).await;
        let poll = reply.is_ok() && can_replay(&body);
        if sender.send((reply, budget.clone())).await.is_err() || !poll {
            return;
        }
        // An encrypted request can collect further Telegram messages on an
        // idle native channel. A new packet ends polling the older request.
        for _ in 0..3 {
            tokio::time::sleep(POLL_INTERVAL).await;
            if self.sequence.load(Ordering::Relaxed) != sequence
                || self.slots.available_permits() != CHANNEL_REQUESTS - 1
                || started.elapsed() >= Duration::from_secs(30)
                || sender.is_closed()
            {
                return;
            }
            let Ok(_replay) = self.replay_slots.try_acquire() else {
                return;
            };
            match timeout(POLL_TIMEOUT, lane.post(body.clone(), None)).await {
                Ok(Ok(reply)) if !reply.body.is_empty() => {
                    if sender.send((Ok(reply), budget.clone())).await.is_err() {
                        return;
                    }
                }
                Ok(Err(error)) if error.is::<TransportError>() => {
                    let _ = sender.send((Err(error), budget)).await;
                    return;
                }
                _ => {}
            }
        }
    }
}

pub(crate) async fn bridge(client: TcpStream, mut auth: Handshake, lane: Arc<Lane>) -> Result<()> {
    let (mut reader, mut writer) = client.into_split();
    let channel = Arc::new(Channel::new());
    let (sender, mut receiver) = mpsc::channel(2);
    let upload = async {
        let mut tasks = JoinSet::new();
        while let Some(frame) =
            protocol::read_frame(&mut reader, &mut auth.decrypt, auth.tag).await?
        {
            // HTTP MTProto has no quick-ack wire format; upstream also sends
            // the request body unchanged and lets the endpoint supply replies.
            let _quick = frame.quick;
            let body = protocol::http_body(frame, auth.tag)?;
            let sequence = channel.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            let budget = Arc::new(RequestBudget {
                _slot: channel.slots.clone().acquire_owned().await?,
                _bytes: channel
                    .budget
                    .clone()
                    .acquire_many_owned(body.len() as u32)
                    .await?,
            });
            let lane = lane.clone();
            let sender = sender.clone();
            let channel = channel.clone();
            tasks.spawn(async move { channel.send(&lane, body, sequence, sender, budget).await });
            while tasks.try_join_next().is_some() {}
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        while let Some((reply, _budget)) = receiver.recv().await {
            let transport_code;
            let (body, transport_error) = match &reply {
                Ok(reply) => (reply.body.as_slice(), false),
                Err(error) => {
                    let Some(error) = error.downcast_ref::<TransportError>() else {
                        return reply.map(|_| ());
                    };
                    transport_code = error.0.to_le_bytes();
                    (transport_code.as_slice(), true)
                }
            };
            if !body.is_empty() {
                let mut wire = protocol::encode_reply(body, auth.tag)?;
                auth.encrypt.apply_keystream(&mut wire);
                transport::write_bytes(&mut writer, &wire).await?;
            }
            if transport_error {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {result=upload=>result,result=download=>result}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{self, Tag},
        transport::tests::{client_init, local_pair},
    };
    use ctr::cipher::StreamCipher;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
        time::timeout,
    };

    async fn lane<F, Fut>(handler: F) -> (Arc<Lane>, tokio::task::JoinHandle<()>)
    where
        F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request| {
                let handler = handler.clone();
                async move { Ok::<_, Infallible>(handler(request).await) }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let lane = Lane::from_io("kws2.fixture.example".into(), Box::new(stream))
            .await
            .unwrap();
        (lane, task)
    }
    #[tokio::test]
    async fn multiplexes_posts_without_crossing_out_of_order_replies() {
        let release = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let (lane, server) = lane({
            let release = release.clone();
            let started = started.clone();
            move |request| {
                let release = release.clone();
                let started = started.clone();
                async move {
                    assert_eq!(request.version(), hyper::Version::HTTP_2);
                    assert_eq!(request.uri().path(), "/api");
                    assert_eq!(
                        request.headers()["content-type"],
                        "application/octet-stream"
                    );
                    assert_eq!(request.headers()["accept-encoding"], "identity");
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    if body[0] == b'a' {
                        started.notify_one();
                        release.notified().await;
                    }
                    Response::new(Full::new(body))
                }
            }
        })
        .await;
        let first = tokio::spawn({
            let lane = lane.clone();
            async move {
                lane.post(Bytes::from(vec![b'a'; 40]), None)
                    .await
                    .unwrap()
                    .body
            }
        });
        started.notified().await;
        assert_eq!(
            timeout(
                Duration::from_secs(1),
                lane.post(Bytes::from(vec![b'b'; 40]), None)
            )
            .await
            .unwrap()
            .unwrap()
            .body,
            vec![b'b'; 40]
        );
        release.notify_one();
        assert_eq!(first.await.unwrap(), vec![b'a'; 40]);
        drop(lane);
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn bridge_strips_native_padding_and_returns_transport_errors_with_client_cipher() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (lane, server) = lane({
            let calls = calls.clone();
            move |request| {
                let calls = calls.clone();
                async move {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(body.len(), 40);
                    assert_eq!(&body[16..20], &20u32.to_le_bytes());
                    calls.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(404)
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                }
            }
        })
        .await;
        let (mut client, proxy) = local_pair().await;
        let (init, mut encrypt, mut decrypt) = client_init(-2, Tag::Padded);
        let auth = protocol::authenticate(&init, &[0x11; 16], false).unwrap();
        let task = tokio::spawn(bridge(proxy, auth, lane.clone()));
        let mut body = vec![0u8; 8];
        body.extend([b'm'; 8]);
        body.extend(20u32.to_le_bytes());
        body.extend([b'p'; 20]);
        body.extend([b'z'; 200]);
        let mut packet = ((body.len() as u32) | 0x80000000).to_le_bytes().to_vec();
        packet.extend(body);
        encrypt.apply_keystream(&mut packet);
        client.write_all(&packet).await.unwrap();
        let mut length = [0u8; 4];
        timeout(Duration::from_secs(2), client.read_exact(&mut length))
            .await
            .unwrap()
            .unwrap();
        decrypt.apply_keystream(&mut length);
        let length = u32::from_le_bytes(length) as usize;
        assert!((4..=7).contains(&length));
        let mut body = vec![0u8; length];
        client.read_exact(&mut body).await.unwrap();
        decrypt.apply_keystream(&mut body);
        assert_eq!(&body[..4], &(-404i32).to_le_bytes());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(lane.cooling_down());
        assert!(!lane.reusable());
        drop(lane);
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn oversize_and_html_responses_are_rejected() {
        let (lane, server) = lane(|request| async move {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            if body[0] == b'o' {
                Response::builder()
                    .header("content-length", protocol::MAX_PACKET + 4)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            } else {
                Response::builder()
                    .header("content-type", "text/html")
                    .body(Full::new(Bytes::from_static(b"bad!")))
                    .unwrap()
            }
        })
        .await;
        assert!(lane.post(Bytes::from(vec![b'o'; 40]), None).await.is_err());
        assert!(lane.post(Bytes::from(vec![b'h'; 40]), None).await.is_err());
        drop(lane);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn an_encrypted_request_waiting_for_headers_can_recover_through_the_same_lane() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (lane, server) = lane({
            let calls = calls.clone();
            move |request| {
                let calls = calls.clone();
                async move {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        std::future::pending::<()>().await;
                    }
                    Response::new(Full::new(body))
                }
            }
        })
        .await;
        let payload = Bytes::from(vec![b'p'; 40]);
        let slots = Semaphore::new(1);
        let reply = timeout(
            Duration::from_secs(2),
            exchange(&lane, payload.clone(), &slots, Duration::from_millis(100)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply.body, payload);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!can_replay(&[0; 40]));
        drop(lane);
        server.abort();
        let _ = server.await;
    }
}
