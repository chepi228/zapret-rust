//! Bounded, staggered address fallback shared by probes, downloads and HTTP/2.
use crate::protocol::TcpAttempt;
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
    connect_with(addresses, attempts, |address| async move {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    })
    .await
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
    let ordered = crate::connection::connection_order(addresses);
    let mut pending = FuturesUnordered::new();
    let mut active = std::collections::BTreeMap::new();
    let mut next = 0;
    let mut launch_at = Instant::now();
    loop {
        if next < ordered.len()
            && pending.len() < 2
            && (pending.is_empty() || Instant::now() >= launch_at)
        {
            let address = ordered[next];
            next += 1;
            let slot = attempts.len();
            active.insert(slot, Instant::now());
            attempts.push(TcpAttempt {
                address: address.to_string(),
                elapsed_ms: 0.,
                error: Some("connection attempt unfinished (cancelled or request deadline)".into()),
            });
            let connection = connector(address);
            pending.push(async move {
                let result = match timeout(Duration::from_secs(1), connection).await {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("address connect timeout (1000 ms)".to_owned()),
                };
                (slot, result)
            });
            launch_at = Instant::now() + Duration::from_millis(250);
        }
        if pending.is_empty() && next == ordered.len() {
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
            _=tokio::time::sleep_until(launch_at), if next<ordered.len() && pending.len()<2=>{}
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
