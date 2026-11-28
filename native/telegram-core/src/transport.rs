use crate::protocol::{self, AesCtr, Handshake, MAX_PACKET};
use anyhow::{Context, Result, ensure};
use ctr::cipher::StreamCipher;
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    time::{Instant, timeout},
};
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, protocol::WebSocketConfig,
};
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Ws = tokio_tungstenite::WebSocketStream<Box<dyn Io>>;
#[derive(Clone)]
pub(crate) struct WsEndpoint {
    pub connect_host: String,
    pub port: u16,
    pub host: String,
    pub path: String,
    pub secure: bool,
}
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) async fn open_tcp(host: &str, port: u16, buffer: usize) -> Result<TcpStream> {
    open_upstream(host, port, buffer, |stream| std::future::ready(Ok(stream))).await
}

async fn open_upstream<T, Fut>(
    host: &str,
    port: u16,
    buffer: usize,
    negotiate: impl Fn(TcpStream) -> Fut,
) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T>>,
{
    timeout(CONNECT_TIMEOUT, async {
        let addresses = tokio::net::lookup_host((host, port)).await?;
        let negotiate = &negotiate;
        connect_addresses_with(addresses, |address| async move {
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.set_send_buffer_size(buffer as u32)?;
            socket.set_recv_buffer_size(buffer as u32)?;
            let stream = socket.connect(address).await?;
            stream.set_nodelay(true)?;
            negotiate(stream).await.map_err(std::io::Error::other)
        })
        .await
        .map_err(anyhow::Error::from)
    })
    .await
    .context("upstream connection timed out")?
}

async fn connect_addresses_with<T, F, Fut>(
    addresses: impl IntoIterator<Item = SocketAddr>,
    connector: F,
) -> std::io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let addresses = zapret_core::connection_addresses(addresses, 8);
    let mut pending = FuturesUnordered::new();
    let mut next = 0;
    let mut launch_at = Instant::now();
    let mut last_error =
        std::io::Error::new(std::io::ErrorKind::NotFound, "DNS returned no addresses");
    loop {
        if next < addresses.len()
            && pending.len() < 2
            && (pending.is_empty() || Instant::now() >= launch_at)
        {
            let connection = connector(addresses[next]);
            let rotate = next != 0 && next + 1 < addresses.len();
            next += 1;
            pending.push(async move {
                if !rotate {
                    return connection.await;
                }
                timeout(Duration::from_secs(2), connection)
                    .await
                    .unwrap_or_else(|_| {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "address connect timeout",
                        ))
                    })
            });
            launch_at = Instant::now() + Duration::from_millis(250);
        }
        if pending.is_empty() && next == addresses.len() {
            return Err(last_error);
        }
        tokio::select! {
            biased;
            Some(result) = pending.next(), if !pending.is_empty() => {
                match result {
                    // Losing futures stay local and close their sockets on return or cancellation.
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = error,
                }
                launch_at = Instant::now();
            }
            _ = tokio::time::sleep_until(launch_at), if next < addresses.len() && pending.len() < 2 => {}
        }
    }
}
pub(crate) async fn open_tls(
    connect_host: &str,
    port: u16,
    buffer: usize,
    host: &str,
    h2: bool,
) -> Result<Box<dyn Io>> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.request_alpns(if h2 { &["h2"] } else { &["http/1.1"] });
    // Native TLS uses Schannel and the Windows certificate store. Never disable
    // chain or hostname checks, including when connecting to a redirected IP.
    let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
    open_upstream(connect_host, port, buffer, |stream| async {
        let stream = connector.connect(host, stream).await?;
        if h2 {
            ensure!(
                stream.get_ref().negotiated_alpn()?.as_deref() == Some(b"h2"),
                "upstream did not negotiate HTTP/2"
            );
        }
        Ok(Box::new(stream) as Box<dyn Io>)
    })
    .await
}
pub(crate) async fn connect_ws(endpoint: &WsEndpoint, buffer: usize) -> Result<Ws> {
    timeout(CONNECT_TIMEOUT, async {
        let stream: Box<dyn Io> = if endpoint.secure {
            open_tls(
                &endpoint.connect_host,
                endpoint.port,
                buffer,
                &endpoint.host,
                false,
            )
            .await?
        } else {
            Box::new(open_tcp(&endpoint.connect_host, endpoint.port, buffer).await?)
        };
        let scheme = if endpoint.secure { "wss" } else { "ws" };
        let mut request =
            format!("{scheme}://{}{}", endpoint.host, endpoint.path).into_client_request()?;
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "binary".parse()?);
        let limits = WebSocketConfig::default()
            .read_buffer_size(buffer.min(64 * 1024))
            .write_buffer_size(64 * 1024)
            .max_write_buffer_size(MAX_PACKET + 256 + 128 * 1024)
            .max_frame_size(Some(16 * 1024 * 1024))
            .max_message_size(Some(16 * 1024 * 1024));
        let (ws, _) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(limits)).await?;
        Ok(ws)
    })
    .await
    .context("WebSocket setup timed out")?
}
pub(crate) async fn write_bytes<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    timeout(WRITE_TIMEOUT, writer.write_all(bytes))
        .await
        .context("peer write timed out")??;
    Ok(())
}
pub(crate) async fn bridge_ws(client: TcpStream, mut auth: Handshake, mut ws: Ws) -> Result<()> {
    let mut relay = protocol::relay(&auth)?;
    timeout(
        WRITE_TIMEOUT,
        ws.send(Message::Binary(relay.init.to_vec().into())),
    )
    .await??;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut ws_write, mut ws_read) = ws.split();
    let upload = async {
        while let Some(mut frame) =
            protocol::read_frame(&mut client_read, &mut auth.decrypt, auth.tag).await?
        {
            relay.encrypt.apply_keystream(&mut frame.wire);
            timeout(
                WRITE_TIMEOUT,
                ws_write.send(Message::Binary(frame.wire.into())),
            )
            .await??;
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        while let Some(message) = ws_read.next().await {
            match message {
                Ok(Message::Binary(data))=>{
                    let mut data = bytes::BytesMut::from(data);
                    relay.decrypt.apply_keystream(&mut data);
                    auth.encrypt.apply_keystream(&mut data);
                    write_bytes(&mut client_write,&data).await?;
                },
                Ok(Message::Close(_))=>break,
                Ok(Message::Ping(_)|Message::Pong(_))=>{},
                Ok(_)=>anyhow::bail!("upstream sent a non-binary WebSocket message"),
                Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed | tokio_tungstenite::tungstenite::Error::AlreadyClosed)=>break,
                Err(tokio_tungstenite::tungstenite::Error::Protocol(tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake))=>break,
                Err(error)=>return Err(error.into()),
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {result=upload=>result,result=download=>result}
}
pub(crate) async fn bridge_tcp(
    client: TcpStream,
    mut auth: Handshake,
    mut upstream: TcpStream,
) -> Result<()> {
    let mut relay = protocol::relay(&auth)?;
    write_bytes(&mut upstream, &relay.init).await?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut remote_read, mut remote_write) = upstream.into_split();
    tokio::select! {
        result=copy_cipher(&mut client_read,&mut remote_write,&mut auth.decrypt,&mut relay.encrypt)=>result,
        result=copy_cipher(&mut remote_read,&mut client_write,&mut relay.decrypt,&mut auth.encrypt)=>result,
    }
}
async fn copy_cipher<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    decrypt: &mut AesCtr,
    encrypt: &mut AesCtr,
) -> Result<()> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        let chunk = &mut buffer[..count];
        decrypt.apply_keystream(chunk);
        encrypt.apply_keystream(chunk);
        write_bytes(writer, chunk).await?;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::{AesCtr, Tag};
    use aes::cipher::{KeyIvInit, StreamCipher};
    use futures_util::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{Duration, timeout},
    };

    struct ActiveConnection(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for ActiveConnection {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn address_fallback_reaches_ipv4_and_drops_stalled_ipv6() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let addresses = ["[::1]:1", "[::1]:2", "127.0.0.1:3"].map(|text| text.parse().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let connected = connect_addresses_with(addresses, |address| {
            let active = active.clone();
            async move {
                assert!(active.fetch_add(1, Ordering::SeqCst) < 2);
                let _active = ActiveConnection(active);
                if address.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok(address)
            }
        })
        .await
        .unwrap();
        assert!(connected.is_ipv4());
        assert!(started.elapsed() < Duration::from_millis(900));
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelling_address_fallback_closes_every_pending_attempt() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let addresses = ["[::1]:1", "127.0.0.1:2"].map(|text| text.parse().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let result = timeout(
            Duration::from_millis(350),
            connect_addresses_with(addresses, |_| {
                let active = active.clone();
                async move {
                    assert!(active.fetch_add(1, Ordering::SeqCst) < 2);
                    let _active = ActiveConnection(active);
                    std::future::pending::<std::io::Result<SocketAddr>>().await
                }
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn secure_websocket_and_h2_try_the_other_family_during_a_stalled_handshake() {
        let peers = zapret_core::connection_addresses(
            tokio::net::lookup_host(("localhost", 0)).await.unwrap(),
            2,
        );
        let [preferred, alternate] = peers.as_slice() else {
            return;
        };
        let first = TcpListener::bind(preferred).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = TcpListener::bind(SocketAddr::new(alternate.ip(), port))
            .await
            .unwrap();
        let endpoint = WsEndpoint {
            connect_host: "localhost".into(),
            port,
            host: "telegram.test".into(),
            path: "/".into(),
            secure: true,
        };
        for h2 in [false, true] {
            let client = async {
                if h2 {
                    open_tls("localhost", port, 65536, &endpoint.host, true)
                        .await
                        .map(drop)
                } else {
                    connect_ws(&endpoint, 65536).await.map(drop)
                }
            };
            let servers = async {
                let (mut preferred, _) = first.accept().await.unwrap();
                assert_eq!(preferred.read_u8().await.unwrap(), 22);
                let (mut alternate, _) = second.accept().await.unwrap();
                assert_eq!(alternate.read_u8().await.unwrap(), 22);
                // Neither server presents a certificate. Both setups must fail.
            };
            let (result, _) = timeout(Duration::from_secs(4), async {
                tokio::join!(client, servers)
            })
            .await
            .unwrap();
            assert!(result.is_err());
        }
    }

    #[test]
    fn address_selection_interleaves_families_deduplicates_and_stays_bounded() {
        let mut addresses = vec!["[::1]:1".parse().unwrap(); 3];
        addresses
            .extend((2..20).map(|port| format!("[::1]:{port}").parse::<SocketAddr>().unwrap()));
        addresses.push("127.0.0.1:80".parse().unwrap());
        let selected = zapret_core::connection_addresses(addresses.iter().copied(), 8);
        assert_eq!(selected.len(), 8);
        assert_eq!(selected[0], addresses[0]);
        assert_eq!(selected[1], *addresses.last().unwrap());
        assert_eq!(
            selected
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8
        );
    }

    #[tokio::test]
    async fn a_single_upstream_address_uses_the_outer_connection_deadline() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 443));
        let connected = timeout(
            CONNECT_TIMEOUT,
            connect_addresses_with([peer], |address| async move {
                tokio::time::sleep(Duration::from_millis(2200)).await;
                Ok(address)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer, connected);
    }

    #[tokio::test]
    async fn failed_address_is_replaced_without_waiting_for_the_stagger() {
        let addresses = ["127.0.0.1:1", "127.0.0.1:2"].map(|text| text.parse().unwrap());
        let started = Instant::now();
        let connected = connect_addresses_with(addresses, |address| async move {
            if address.port() == 1 {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            } else {
                Ok(address)
            }
        })
        .await
        .unwrap();
        assert_eq!(connected.port(), 2);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    // Independent test-side MTProxy client. The fixed Python fixture in
    // protocol.rs separately checks the crypto without this constructor.
    pub(crate) fn client_init(dc: i16, tag: Tag) -> ([u8; 64], AesCtr, AesCtr) {
        let mut wire = std::array::from_fn(|i| (i + 1) as u8);
        wire[56..60].fill(match tag {
            Tag::Abridged => 0xef,
            Tag::Intermediate => 0xee,
            Tag::Padded => 0xdd,
        });
        wire[60..62].copy_from_slice(&dc.to_le_bytes());
        let key = Sha256::digest([&wire[8..40], &[0x11; 16]].concat());
        let mut encrypt = AesCtr::new(&key, wire[40..56].into());
        let mut ciphertext = wire;
        encrypt.apply_keystream(&mut ciphertext);
        wire[56..].copy_from_slice(&ciphertext[56..]);
        let reverse: Vec<u8> = wire[8..56].iter().rev().copied().collect();
        let decrypt = AesCtr::new(
            &Sha256::digest([&reverse[..32], &[0x11; 16]].concat()),
            reverse[32..].into(),
        );
        (wire, encrypt, decrypt)
    }
    pub(crate) fn raw_peer(init: &[u8]) -> (AesCtr, AesCtr) {
        let mut decrypt = AesCtr::new(init[8..40].into(), init[40..56].into());
        let mut plain = init.to_vec();
        decrypt.apply_keystream(&mut plain);
        assert_eq!(&plain[56..60], &[0xee; 4]);
        assert_eq!(i16::from_le_bytes(plain[60..62].try_into().unwrap()), -2);
        let reverse: Vec<u8> = init[8..56].iter().rev().copied().collect();
        let encrypt = AesCtr::new(reverse[..32].into(), reverse[32..].into());
        (decrypt, encrypt)
    }
    pub(crate) async fn local_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap());
        let (client, server) = tokio::join!(client, listener.accept());
        (client.unwrap(), server.unwrap().0)
    }
    #[tokio::test]
    #[allow(clippy::result_large_err)] // The tungstenite handshake callback fixes this return type.
    async fn websocket_bridge_authenticates_reencrypts_and_preserves_packet_boundaries() {
        use tokio_tungstenite::tungstenite::{
            Message,
            handshake::server::{Request, Response},
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = WsEndpoint {
            connect_host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            host: "kws2.web.telegram.org".into(),
            path: "/apiws_test".into(),
            secure: false,
        };
        let remote = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &Request, mut response: Response| {
                    assert_eq!(request.uri().path(), "/apiws_test");
                    assert_eq!(request.headers()["host"], "kws2.web.telegram.org");
                    assert_eq!(request.headers()["sec-websocket-protocol"], "binary");
                    response
                        .headers_mut()
                        .insert("sec-websocket-protocol", "binary".parse().unwrap());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            assert_eq!(init.len(), 64);
            let (mut decrypt, mut encrypt) = raw_peer(&init);
            let mut packet = ws.next().await.unwrap().unwrap().into_data().to_vec();
            decrypt.apply_keystream(&mut packet);
            assert_eq!(packet, [&[40, 0, 0, 128][..], &[b'k'; 40]].concat());
            let mut reply = vec![4, 0, 0, 0, 108, 254, 255, 255];
            encrypt.apply_keystream(&mut reply);
            ws.send(Message::Binary(reply.into())).await.unwrap();
            // Three ordinary media chunks cross the socket buffers and keep one continuous cipher.
            for tag in [0x31, 0x52, 0x93] {
                let mut frame = (1024u32 * 1024).to_le_bytes().to_vec();
                frame.resize(4 + 1024 * 1024, tag);
                encrypt.apply_keystream(&mut frame);
                ws.send(Message::Binary(frame.into())).await.unwrap();
            }
        });
        let (mut client, server) = local_pair().await;
        let (init, mut enc, mut dec) = client_init(-10002, Tag::Intermediate);
        let auth = crate::protocol::authenticate(&init, &[0x11; 16], false).unwrap();
        let ws = connect_ws(&endpoint, 65536).await.unwrap();
        let bridge = tokio::spawn(bridge_ws(server, auth, ws));
        let mut packet = [&[40, 0, 0, 128][..], &[b'k'; 40]].concat();
        enc.apply_keystream(&mut packet);
        for chunk in packet.chunks(3) {
            client.write_all(chunk).await.unwrap();
        }
        let mut reply = [0u8; 8];
        timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        dec.apply_keystream(&mut reply);
        assert_eq!(reply, [4, 0, 0, 0, 108, 254, 255, 255]);
        let mut chunk = vec![0; 4 + 1024 * 1024];
        for tag in [0x31, 0x52, 0x93] {
            timeout(Duration::from_secs(10), client.read_exact(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            dec.apply_keystream(&mut chunk);
            assert_eq!(&chunk[..4], &(1024u32 * 1024).to_le_bytes());
            assert!(chunk[4..].iter().all(|byte| *byte == tag));
        }
        drop(client);
        timeout(Duration::from_secs(2), bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        remote.await.unwrap();
    }
    #[tokio::test]
    async fn tcp_bridge_reencrypts_both_directions_and_stops_when_remote_closes() {
        let (mut client, server) = local_pair().await;
        let (remote, mut peer) = local_pair().await;
        let (init, mut enc, mut dec) = client_init(-2, Tag::Intermediate);
        let auth = crate::protocol::authenticate(&init, &[0x11; 16], false).unwrap();
        let bridge = tokio::spawn(bridge_tcp(server, auth, remote));
        let mut relay = [0u8; 64];
        timeout(Duration::from_secs(2), peer.read_exact(&mut relay))
            .await
            .unwrap()
            .unwrap();
        let (mut peer_dec, mut peer_enc) = raw_peer(&relay);
        let mut packet = vec![b'a'; 4096];
        enc.apply_keystream(&mut packet);
        client.write_all(&packet).await.unwrap();
        let mut plain = vec![0u8; 4096];
        peer.read_exact(&mut plain).await.unwrap();
        peer_dec.apply_keystream(&mut plain);
        assert_eq!(plain, vec![b'a'; 4096]);
        let mut reply = vec![b'r'; 4096];
        peer_enc.apply_keystream(&mut reply);
        peer.write_all(&reply).await.unwrap();
        let mut received = vec![0u8; 4096];
        client.read_exact(&mut received).await.unwrap();
        dec.apply_keystream(&mut received);
        assert_eq!(received, vec![b'r'; 4096]);
        drop(peer);
        timeout(Duration::from_secs(2), bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
    }
}
