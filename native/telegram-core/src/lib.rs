//! Native port of Flowseal/tg-ws-proxy 1.11.4's MTProto transport core.
use anyhow::{Context, Result, ensure};
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};

pub const CORE_VERSION: &str = "flowseal-1.11.4-rust-1";

mod config;
mod h2;
mod media_check;
pub use media_check::check as check_media;
mod protocol;
mod routes;
mod transport;
pub use config::Config;

const MAX_CLIENTS: usize = 96;
const CLIENT_INIT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(config: Config) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = TcpListener::bind(config.listener_addr())
                .await
                .context("Не удалось открыть локальный порт Telegram")?;
            serve(config, listener).await
        })
}

pub async fn serve(config: Config, listener: TcpListener) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "Telegram listener must be loopback"
    );
    let router = Arc::new(routes::Router::new(config));
    let clients = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut tasks = JoinSet::new();
    router.maintain(&mut tasks);
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            result = listener.accept() => {
                let (mut socket, remote) = result.context("Telegram listener failed")?;
                if !remote.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = clients.clone().try_acquire_owned() else { continue };
                let router = router.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut init = [0; 64];
                    if !matches!(timeout(CLIENT_INIT_TIMEOUT, socket.read_exact(&mut init)).await, Ok(Ok(_))) {
                        return;
                    }
                    let Ok(auth) = router.authenticate(&init) else { return };
                    let _ = socket.set_nodelay(true);
                    router.relay(socket, auth).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tests::client_init;
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };

    #[tokio::test]
    async fn serving_rejects_invalid_handshake_without_opening_a_route() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Config::from_value(&json!({
            "secret":"11111111111111111111111111111111",
            "dc_ip":[], "cfproxy":false, "pool_size":0
        }))
        .unwrap();
        let service = tokio::spawn(serve(config, listener));
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut init, _, _) = client_init(-2, protocol::Tag::Padded);
        init[56] ^= 1;
        client.write_all(&init[..20]).await.unwrap();
        client.write_all(&init[20..]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), client.read(&mut [0u8; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(
            !service.is_finished(),
            "listener must survive invalid clients"
        );
        service.abort();
    }
}
