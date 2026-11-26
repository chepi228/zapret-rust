//! Bounded, staggered address fallback shared by probes, downloads and HTTP/2.
use crate::protocol::{TcpAttempt, Termination};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::TcpStream,
    time::{Instant, timeout},
};

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.
}

pub(crate) async fn connect(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
) -> Result<TcpStream, String> {
    connect_peer(addresses, attempts)
        .await
        .map(|(_, stream)| stream)
}

async fn connect_peer(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
) -> Result<(SocketAddr, TcpStream), String> {
    connect_with(addresses, attempts, |address| async move {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        Ok((address, stream))
    })
    .await
}

/// An address can accept TCP and then reject TLS. Try remaining addresses from
/// the same lookup before sending the request. The caller owns the total deadline.
pub(crate) async fn connect_tls(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
    host: &str,
    connector: &tokio_native_tls::TlsConnector,
    mut progress: impl FnMut(Option<(SocketAddr, f64)>),
) -> Result<(tokio_native_tls::TlsStream<TcpStream>, f64), (Termination, String)> {
    let mut remaining = addresses.to_vec();
    let mut tcp_ms = 0.;
    let mut tls_ms = 0.;
    let mut last_rejection = None;
    loop {
        progress(None);
        let started = Instant::now();
        let (peer, stream) = match connect_peer(&remaining, attempts).await {
            Ok(connected) => connected,
            Err(error) => {
                if let Some((previous, elapsed, reason)) = last_rejection {
                    progress(Some((previous, elapsed)));
                    return Err((Termination::TlsFailure, reason));
                }
                return Err((Termination::TcpFailure, error));
            }
        };
        tcp_ms += elapsed_ms(started);
        progress(Some((peer, tcp_ms)));
        let started = Instant::now();
        let handshake = connector.connect(host, stream).await;
        tls_ms += elapsed_ms(started);
        match handshake {
            Ok(stream) => return Ok((stream, tls_ms)),
            Err(error) => {
                remaining.retain(|address| *address != peer);
                let reason = error.to_string();
                if let Some(connected) = attempts.iter_mut().rev().find(|a| a.error.is_none()) {
                    connected.tls_error = Some(reason.clone());
                }
                if remaining.is_empty() {
                    return Err((Termination::TlsFailure, reason));
                }
                last_rejection = Some((peer, tcp_ms, reason));
            }
        }
    }
}

pub(crate) async fn connect_with<T, F, Fut>(
    addresses: &[SocketAddr],
    attempts: &mut Vec<TcpAttempt>,
    connector: F,
) -> Result<T, String>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let mut pending = FuturesUnordered::new();
    let mut active = std::collections::BTreeMap::new();
    let mut next = 0;
    let mut launch_at = Instant::now();
    loop {
        if next < addresses.len()
            && pending.len() < 2
            && (pending.is_empty() || Instant::now() >= launch_at)
        {
            let address = addresses[next];
            // The preferred address can use the request deadline. Rotate the
            // second slot while alternatives remain, then let the last one finish.
            let rotate = next != 0 && next + 1 < addresses.len();
            next += 1;
            let slot = attempts.len();
            active.insert(slot, Instant::now());
            attempts.push(TcpAttempt {
                address: address.to_string(),
                elapsed_ms: 0.,
                tls_error: None,
                error: Some("connection attempt unfinished (cancelled or request deadline)".into()),
            });
            let connection = connector(address);
            pending.push(async move {
                let result = if rotate {
                    match timeout(Duration::from_secs(1), connection).await {
                        Ok(result) => result.map_err(|e| e.to_string()),
                        Err(_) => Err("address connect timeout (1000 ms)".to_owned()),
                    }
                } else {
                    connection.await.map_err(|e| e.to_string())
                };
                (slot, result)
            });
            launch_at = Instant::now() + Duration::from_millis(250);
        }
        if pending.is_empty() && next == addresses.len() {
            break;
        }
        tokio::select! {
            biased;
            Some((slot,result))=pending.next(), if !pending.is_empty()=> {
                let start=active.remove(&slot).expect("active connect attempt");
                attempts[slot].elapsed_ms=elapsed_ms(start);
                match result {
                    Ok(stream)=> {
                        attempts[slot].error=None;
                        for (slot,start) in active {
                            attempts[slot].elapsed_ms=elapsed_ms(start);
                            attempts[slot].error=Some("cancelled after another address connected".into());
                        }
                        // Futures stay owned by this request. Dropping losers closes their sockets.
                        return Ok(stream);
                    }
                    Err(error)=>attempts[slot].error=Some(error),
                }
                launch_at=Instant::now();
            }
            _=tokio::time::sleep_until(launch_at), if next<addresses.len() && pending.len()<2=>{}
        }
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
    Err(format!(
        "all selected addresses failed: {last}; see tcp_attempts"
    ))
}
