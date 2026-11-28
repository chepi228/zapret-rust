//! Bounded, staggered address fallback shared by probes, downloads and HTTP/2.
use crate::protocol::{TcpAttempt, Termination};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::BTreeMap, fmt::Display, future::Future, io, net::SocketAddr, time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{Instant, timeout},
};

async fn open(address: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub(crate) async fn connect(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
) -> Result<TcpStream, String> {
    connect_with(addresses, attempts, open).await
}

pub(crate) async fn connect_with<T, F, Fut>(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
    connector: F,
) -> Result<T, String>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    race(
        addresses,
        attempts,
        connector,
        |stream| std::future::ready(Ok(stream)),
        |_| {},
    )
    .await
    .map(|(stream, _)| stream)
    .map_err(|(_, reason)| reason)
}

pub(crate) const ALPN_MISMATCH: &str = "peer did not negotiate the required application protocol";

pub(crate) async fn connect_tls(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
    host: &str,
    connector: &tokio_native_tls::TlsConnector,
    required_alpn: Option<&[u8]>,
    progress: impl FnMut(Option<(SocketAddr, f64)>),
) -> Result<(tokio_native_tls::TlsStream<TcpStream>, f64), (Termination, String)> {
    race(
        addresses,
        attempts,
        open,
        |stream| async move {
            let tls = connector
                .connect(host, stream)
                .await
                .map_err(|error| error.to_string())?;
            if let Some(required) = required_alpn
                && tls
                    .get_ref()
                    .negotiated_alpn()
                    .map_err(|err| err.to_string())?
                    .as_deref()
                    != Some(required)
            {
                return Err(ALPN_MISMATCH.to_owned());
            }
            Ok(tls)
        },
        progress,
    )
    .await
}

struct PendingPeer {
    address: SocketAddr,
    started: Instant,
    connected: Option<Instant>,
    rotate: bool,
}

impl PendingPeer {
    fn tcp_progress(&self, start: Instant) -> Option<(SocketAddr, f64)> {
        Some((
            self.address,
            (self.connected? - start).as_secs_f64() * 1000.,
        ))
    }
}

async fn phase<T, E: Display>(
    slot: usize,
    operation: impl Future<Output = Result<T, E>>,
    limit: Option<Duration>,
) -> (usize, Result<T, String>) {
    let result = match limit {
        Some(limit) => match timeout(limit, operation).await {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err(format!(
                "address attempt timed out after {} ms",
                limit.as_millis()
            )),
        },
        None => operation.await.map_err(|error| error.to_string()),
    };
    (slot, result)
}

// Keep the preferred peer alive while rotating a second slot through the DNS
// answers. Both TCP and TLS occupy a slot. HTTP starts only on the winning stream.
async fn race<T, S, Tcp, Tls>(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
    connect: impl Fn(SocketAddr) -> Tcp,
    negotiate: impl Fn(T) -> Tls,
    mut progress: impl FnMut(Option<(SocketAddr, f64)>),
) -> Result<(S, f64), (Termination, String)>
where
    Tcp: Future<Output = io::Result<T>>,
    Tls: Future<Output = Result<S, String>>,
{
    let start = Instant::now();
    let mut next = 0;
    let mut launch_at = start;
    let mut active = BTreeMap::new();
    let mut sockets = FuturesUnordered::new();
    let mut handshakes = FuturesUnordered::new();
    let mut last_tls_failure = None;
    progress(None);
    loop {
        if next < addresses.len()
            && active.len() < 2
            && (active.is_empty() || Instant::now() >= launch_at)
        {
            let address = addresses[next];
            let rotate = next != 0 && next + 1 < addresses.len();
            next += 1;
            let slot = attempts.len();
            let started = Instant::now();
            attempts.push(TcpAttempt {
                address: address.to_string(),
                elapsed_ms: 0.,
                error: Some("connection attempt unfinished (cancelled or request deadline)".into()),
                tls_error: None,
            });
            active.insert(
                slot,
                PendingPeer {
                    address,
                    started,
                    connected: None,
                    rotate,
                },
            );
            sockets.push(phase(
                slot,
                connect(address),
                rotate.then_some(Duration::from_secs(1)),
            ));
            launch_at = started + Duration::from_millis(250);
        }
        if active.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            Some((slot, result)) = handshakes.next(), if !handshakes.is_empty() => {
                let result: Result<S, String> = result;
                let peer = active.remove(&slot).expect("pending TLS");
                let tcp = peer.tcp_progress(start);
                match result {
                    Ok(stream) => {
                        attempts[slot].tls_error = None;
                        progress(tcp);
                        for (other, peer) in active {
                            if peer.connected.is_some() {
                                attempts[other].tls_error = Some("cancelled after another address completed TLS".into());
                            } else {
                                attempts[other].elapsed_ms = peer.started.elapsed().as_secs_f64() * 1000.;
                                attempts[other].error = Some("cancelled after another address connected".into());
                            }
                        }
                        let tls_ms = peer.connected.expect("TCP before TLS").elapsed().as_secs_f64() * 1000.;
                        return Ok((stream, tls_ms));
                    }
                    Err(reason) => {
                        attempts[slot].tls_error = Some(reason.clone());
                        last_tls_failure = Some((tcp, reason));
                        progress(active.values().find_map(|other| other.tcp_progress(start)));
                        launch_at = Instant::now();
                    }
                }
            }
            Some((slot, result)) = sockets.next(), if !sockets.is_empty() => {
                let peer = active.get_mut(&slot).expect("pending TCP");
                attempts[slot].elapsed_ms = peer.started.elapsed().as_secs_f64() * 1000.;
                match result {
                    Ok(stream) => {
                        peer.connected = Some(Instant::now());
                        attempts[slot].error = None;
                        attempts[slot].tls_error = Some("handshake unfinished (cancelled or request deadline)".into());
                        progress(peer.tcp_progress(start));
                        handshakes.push(phase(slot, negotiate(stream), peer.rotate.then_some(Duration::from_secs(2))));
                    }
                    Err(reason) => {
                        attempts[slot].error = Some(reason);
                        active.remove(&slot);
                        launch_at = Instant::now();
                    }
                }
            }
            _ = tokio::time::sleep_until(launch_at), if next < addresses.len() && active.len() < 2 => {}
        }
    }
    if let Some((tcp, reason)) = last_tls_failure {
        progress(tcp);
        return Err((Termination::TlsFailure, reason));
    }
    let last = attempts
        .last()
        .map(|attempt| {
            format!(
                "{}: {}",
                attempt.address,
                attempt.error.as_deref().unwrap_or("unknown error")
            )
        })
        .unwrap_or_else(|| "DNS returned no addresses".into());
    Err((
        Termination::TcpFailure,
        format!("all selected addresses failed: {last}; see tcp_attempts"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preferred_tls_can_finish_after_the_backup_has_connected() {
        let peers = [1, 2].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let backup_started = tokio::sync::Notify::new();
        let backup_started = &backup_started;
        let mut attempts = Vec::new();
        let mut observed = None;
        let (winner, _) = timeout(
            Duration::from_secs(3),
            race(
                &peers,
                &mut attempts,
                |peer| std::future::ready(Ok(peer)),
                |peer| async move {
                    if peer == peers[0] {
                        backup_started.notified().await;
                        Ok(peer)
                    } else {
                        backup_started.notify_one();
                        std::future::pending().await
                    }
                },
                |peer| observed = peer,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner, peers[0]);
        assert_eq!(observed.unwrap().0, winner);
        assert!(attempts[0].tls_error.is_none());
        assert!(attempts[1].error.is_none());
        assert!(
            attempts[1]
                .tls_error
                .as_deref()
                .unwrap()
                .contains("cancelled")
        );
    }

    #[tokio::test]
    async fn two_stalled_handshakes_leave_a_slot_for_the_third_address() {
        let peers = [1, 2, 3].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
        let mut attempts = Vec::new();
        let (winner, _) = timeout(
            Duration::from_secs(5),
            race(
                &peers,
                &mut attempts,
                |peer| std::future::ready(Ok(peer)),
                |peer| async move {
                    if peer == peers[2] {
                        Ok(peer)
                    } else {
                        std::future::pending().await
                    }
                },
                |_| {},
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner, peers[2]);
        assert!(attempts.iter().all(|attempt| attempt.error.is_none()));
        assert!(
            attempts[1]
                .tls_error
                .as_deref()
                .unwrap()
                .contains("timed out")
        );
        assert!(attempts[2].tls_error.is_none());
    }
}
