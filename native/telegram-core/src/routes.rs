//! Upstream DC routing and bounded connections to the configured relays.
use crate::{
    Config,
    config::supported_dc,
    h2,
    protocol::{self, Handshake},
    transport::{self, Ws, WsEndpoint},
};
use anyhow::Result;
use futures_util::{StreamExt, stream};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{Mutex as AsyncMutex, Notify, Semaphore},
    task::JoinSet,
    time::{sleep, timeout},
};

const POOL_AGE: Duration = Duration::from_secs(60);
const PROBE_TIME: Duration = Duration::from_secs(4);
const ROUTE_TIME: Duration = Duration::from_secs(8);
const COOLDOWN: Duration = Duration::from_secs(30);
const MAX_IDLE: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Dc {
    number: u16,
    media: bool,
    test: bool,
}

impl From<&Handshake> for Dc {
    fn from(auth: &Handshake) -> Self {
        Self {
            number: auth.dc,
            media: auth.media,
            test: auth.test,
        }
    }
}

impl Dc {
    fn tcp_ip(self) -> Ipv4Addr {
        let octets = match (self.test, self.number) {
            (true, 1) => [149, 154, 175, 10],
            (true, 2) => [149, 154, 167, 40],
            (true, 3) => [149, 154, 175, 117],
            (false, 1) => [149, 154, 175, 50],
            (false, 2) => [149, 154, 167, 51],
            (false, 3) => [149, 154, 175, 100],
            (false, 4) => [149, 154, 167, 91],
            (false, 5) => [149, 154, 171, 5],
            (false, 203) => [91, 105, 192, 100],
            _ => unreachable!("only an authenticated DC enters routing"),
        };
        Ipv4Addr::from(octets)
    }

    fn direct(self, target: Ipv4Addr) -> Vec<WsEndpoint> {
        let number = if self.number == 203 { 2 } else { self.number };
        let normal = format!("kws{number}.web.telegram.org");
        let hosts = if self.media {
            vec![format!("kws{number}-1.web.telegram.org"), normal]
        } else {
            vec![normal]
        };
        let path = if self.test { "/apiws_test" } else { "/apiws" };
        hosts
            .into_iter()
            .map(|host| WsEndpoint {
                connect_host: target.to_string(),
                host,
                port: 443,
                path: path.into(),
                secure: true,
            })
            .collect()
    }

    fn worker(self, domain: &str, secure: bool) -> WsEndpoint {
        // This is an upstream Telegram DC address, never an address supplied
        // by the client. Keep the original CF Worker query contract.
        let path = format!("/apiws?dst={}&dc={}", self.tcp_ip(), self.number);
        websocket(domain.into(), path, secure)
    }

    fn cf_host(self, domain: &str) -> String {
        format!("kws{}.{domain}", self.number)
    }
}

fn websocket(host: String, path: String, secure: bool) -> WsEndpoint {
    WsEndpoint {
        connect_host: host.clone(),
        host,
        port: if secure { 443 } else { 80 },
        path,
        secure,
    }
}

struct IdleWs {
    socket: Ws,
    opened: Instant,
    _capacity: tokio::sync::OwnedSemaphorePermit,
}

struct WsPool {
    endpoints: Vec<WsEndpoint>,
    idle: Mutex<VecDeque<IdleWs>>,
    taken: Notify,
}

impl WsPool {
    fn new(endpoints: Vec<WsEndpoint>) -> Self {
        Self {
            endpoints,
            idle: Mutex::new(VecDeque::new()),
            taken: Notify::new(),
        }
    }

    fn take(&self) -> Option<Ws> {
        let mut queue = self.idle.lock().ok()?;
        queue.retain(|item| item.opened.elapsed() < POOL_AGE);
        let item = queue.pop_front()?;
        self.taken.notify_one();
        Some(item.socket)
    }

    async fn fill(&self, capacity: Arc<Semaphore>, target: usize, buffer: usize) {
        let mut failure_delay = Duration::from_secs(1);
        loop {
            let needed = {
                let Ok(mut idle) = self.idle.lock() else {
                    return;
                };
                idle.retain(|item| item.opened.elapsed() < POOL_AGE);
                target.saturating_sub(idle.len())
            };
            if needed == 0 {
                let _ = timeout(Duration::from_secs(5), self.taken.notified()).await;
                continue;
            }
            let Ok(permit) = capacity.clone().try_acquire_owned() else {
                sleep(Duration::from_secs(1)).await;
                continue;
            };
            let mut socket = None;
            for endpoint in &self.endpoints {
                if let Ok(Ok(ws)) =
                    timeout(PROBE_TIME, transport::connect_ws(endpoint, buffer)).await
                {
                    socket = Some(ws);
                    break;
                }
            }
            if let Some(socket) = socket {
                let Ok(mut idle) = self.idle.lock() else {
                    return;
                };
                idle.push_back(IdleWs {
                    socket,
                    opened: Instant::now(),
                    _capacity: permit,
                });
                failure_delay = Duration::from_secs(1);
            } else {
                drop(permit);
                sleep(failure_delay).await;
                failure_delay = (failure_delay * 2).min(Duration::from_secs(120));
            }
        }
    }
}

#[derive(Default)]
struct H2Slot {
    lane: Option<Arc<h2::Lane>>,
    retry_at: Option<Instant>,
}

#[derive(Default)]
struct Backoff {
    failures: u8,
    retry_at: Option<Instant>,
}

enum Upstream {
    Ws(Box<Ws>, &'static str),
    H2(Arc<h2::Lane>),
    Tcp(TcpStream),
}

pub(crate) struct Router {
    config: Config,
    direct: BTreeMap<Dc, Arc<WsPool>>,
    lanes: Mutex<BTreeMap<String, Arc<AsyncMutex<H2Slot>>>>,
    tcp: Mutex<BTreeMap<Ipv4Addr, Arc<AsyncMutex<Backoff>>>>,
    cf_ws_backoff: Mutex<BTreeMap<String, Instant>>,
    preferred_cf: Mutex<BTreeMap<u16, String>>,
    dial_limit: Semaphore,
}

impl Router {
    pub(crate) fn new(config: Config) -> Self {
        let mut direct = BTreeMap::new();
        if config.pool_size > 0 {
            for (&number, &target) in &config.dc_ips {
                for test in [false, true] {
                    if !supported_dc(number, test) || (config.force_test_dc && !test) {
                        continue;
                    }
                    for media in [false, true] {
                        let dc = Dc {
                            number,
                            media,
                            test,
                        };
                        direct.insert(dc, Arc::new(WsPool::new(dc.direct(target))));
                    }
                }
            }
        }
        Self {
            config,
            direct,
            lanes: Mutex::default(),
            tcp: Mutex::default(),
            cf_ws_backoff: Mutex::default(),
            preferred_cf: Mutex::default(),
            dial_limit: Semaphore::new(24),
        }
    }

    pub(crate) fn maintain(&self, tasks: &mut JoinSet<()>) {
        let capacity = Arc::new(Semaphore::new(MAX_IDLE));
        for (dc, pool) in &self.direct {
            // Test DCs are cold until requested unless the package runs in
            // test mode. A normal session must not preconnect to test servers.
            if dc.test != self.config.force_test_dc {
                continue;
            }
            let pool = pool.clone();
            let capacity = capacity.clone();
            let size = self.config.pool_size;
            let buffer = self.config.buffer_size;
            tasks.spawn(async move { pool.fill(capacity, size, buffer).await });
        }
    }

    pub(crate) fn authenticate(&self, init: &[u8; 64]) -> Result<Handshake> {
        protocol::authenticate(init, &self.config.secret, self.config.force_test_dc)
    }

    pub(crate) async fn relay(&self, socket: TcpStream, auth: Handshake) {
        let dc = Dc::from(&auth);
        let mut first_byte = [0];
        let route = tokio::select! {
            route = self.select(dc) => route,
            peek = socket.peek(&mut first_byte) => {
                if !matches!(peek, Ok(1)) { return; }
                self.select(dc).await
            }
        };
        let Some(route) = route else { return };
        let (kind, result) = match route {
            Upstream::Ws(ws, kind) => (kind, transport::bridge_ws(socket, auth, *ws).await),
            Upstream::H2(lane) => ("cf-h2", h2::bridge(socket, auth, lane).await),
            Upstream::Tcp(tcp) => ("tcp", transport::bridge_tcp(socket, auth, tcp).await),
        };
        if self.config.verbose && result.is_err() {
            eprintln!(
                "Telegram DC {} route {kind} closed with an I/O error",
                dc.number
            );
        }
    }

    async fn select(&self, dc: Dc) -> Option<Upstream> {
        if let Some(pool) = self.direct.get(&dc) {
            if let Some(socket) = pool.take() {
                return Some(Upstream::Ws(Box::new(socket), "telegram-ws"));
            }
            if dc.test && !self.config.force_test_dc {
                // Explicit test-mode handshakes can use a cold direct route.
                if let Some(socket) = self.first_ws(pool.endpoints.clone()).await {
                    return Some(Upstream::Ws(Box::new(socket), "telegram-ws"));
                }
            }
        }
        let secure = !self.config.no_secure;
        let workers = self
            .config
            .worker_domains
            .iter()
            .map(|domain| dc.worker(domain, secure))
            .collect();
        if let Some(socket) = self.first_ws(workers).await {
            return Some(Upstream::Ws(Box::new(socket), "cf-worker"));
        }
        if self.config.cfproxy && !dc.test {
            let hosts = self.cf_hosts(dc);
            if dc.media && self.config.h2_enabled() {
                if let Some(lane) = self.h2_lane(&hosts).await {
                    return Some(Upstream::H2(lane));
                }
            }
            let endpoints = hosts
                .into_iter()
                .map(|host| websocket(host, "/apiws".into(), secure))
                .collect();
            if let Some(socket) = self.first_ws(endpoints).await {
                return Some(Upstream::Ws(Box::new(socket), "cf-ws"));
            }
        }
        self.tcp_fallback(dc.tcp_ip()).await.map(Upstream::Tcp)
    }

    fn cf_hosts(&self, dc: Dc) -> Vec<String> {
        let mut hosts: Vec<_> = self
            .config
            .cf_domains
            .iter()
            .map(|domain| dc.cf_host(domain))
            .collect();
        if let Ok(preferred) = self.preferred_cf.lock() {
            if let Some(index) = preferred
                .get(&dc.number)
                .and_then(|host| hosts.iter().position(|candidate| candidate == host))
            {
                hosts.swap(0, index);
            }
        }
        hosts
    }

    async fn first_ws(&self, endpoints: Vec<WsEndpoint>) -> Option<Ws> {
        let probes = endpoints.into_iter().map(|endpoint| async move {
            let key = format!("{}{}", endpoint.host, endpoint.path);
            if self
                .cf_ws_backoff
                .lock()
                .ok()?
                .get(&key)
                .is_some_and(|until| *until > Instant::now())
            {
                return None;
            }
            let _permit = self.dial_limit.acquire().await.ok()?;
            let connection = timeout(
                PROBE_TIME,
                transport::connect_ws(&endpoint, self.config.buffer_size),
            )
            .await;
            match connection {
                Ok(Ok(ws)) => Some(ws),
                _ => {
                    self.cf_ws_backoff
                        .lock()
                        .ok()?
                        .insert(key, Instant::now() + COOLDOWN);
                    None
                }
            }
        });
        first_route(probes).await
    }

    async fn h2_lane(&self, hosts: &[String]) -> Option<Arc<h2::Lane>> {
        // Reuse any already verified lane before opening more connections.
        for host in hosts {
            let slot = self.h2_slot(host)?;
            if let Ok(slot) = slot.try_lock() {
                if let Some(lane) = slot.lane.as_ref().filter(|lane| lane.reusable()) {
                    return Some(lane.clone());
                }
            }
        }
        let probes = hosts.iter().cloned().map(|host| async move {
            let slot = self.h2_slot(&host)?;
            let mut slot = slot.lock().await;
            if let Some(lane) = &slot.lane {
                if lane.reusable() {
                    return Some((host, lane.clone()));
                }
                if lane.cooling_down() {
                    return None;
                }
            }
            if slot.retry_at.is_some_and(|until| until > Instant::now()) {
                return None;
            }
            let _permit = self.dial_limit.acquire().await.ok()?;
            match timeout(
                PROBE_TIME,
                h2::Lane::connect(host.clone(), self.config.buffer_size),
            )
            .await
            {
                Ok(Ok(lane)) => {
                    slot.lane = Some(lane.clone());
                    slot.retry_at = None;
                    Some((host, lane))
                }
                _ => {
                    slot.lane = None;
                    slot.retry_at = Some(Instant::now() + COOLDOWN);
                    None
                }
            }
        });
        let (host, lane) = first_route(probes).await?;
        if let Some(number) = host
            .strip_prefix("kws")
            .and_then(|host| host.split('.').next())
            .and_then(|dc| dc.parse().ok())
        {
            self.preferred_cf.lock().ok()?.insert(number, host);
        }
        Some(lane)
    }

    fn h2_slot(&self, host: &str) -> Option<Arc<AsyncMutex<H2Slot>>> {
        Some(
            self.lanes
                .lock()
                .ok()?
                .entry(host.to_owned())
                .or_default()
                .clone(),
        )
    }

    async fn tcp_fallback(&self, address: Ipv4Addr) -> Option<TcpStream> {
        let slot = self.tcp.lock().ok()?.entry(address).or_default().clone();
        let mut slot = slot.try_lock().ok()?;
        if slot.retry_at.is_some_and(|until| until > Instant::now()) {
            return None;
        }
        let _permit = self.dial_limit.acquire().await.ok()?;
        match transport::open_tcp(&address.to_string(), 443, self.config.buffer_size).await {
            Ok(stream) => {
                *slot = Backoff::default();
                Some(stream)
            }
            Err(_) => {
                slot.failures = slot.failures.saturating_add(1);
                let delay =
                    (COOLDOWN * (1 << (slot.failures - 1).min(7))).min(Duration::from_secs(3600));
                slot.retry_at = Some(Instant::now() + delay);
                None
            }
        }
    }
}

async fn first_route<T>(
    probes: impl IntoIterator<Item = impl Future<Output = Option<T>>>,
) -> Option<T> {
    timeout(ROUTE_TIME, async {
        let mut probes = stream::iter(probes).buffer_unordered(4);
        while let Some(result) = probes.next().await {
            if result.is_some() {
                return result;
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_and_test_routes_keep_separate_hosts_and_dc_addresses() {
        let dc = Dc {
            number: 2,
            media: true,
            test: true,
        };
        let direct = dc.direct(Ipv4Addr::new(149, 154, 167, 220));
        assert_eq!(direct[0].host, "kws2-1.web.telegram.org");
        assert_eq!(direct[1].host, "kws2.web.telegram.org");
        assert_eq!(direct[0].connect_host, "149.154.167.220");
        assert_eq!(direct[0].path, "/apiws_test");
        let worker = dc.worker("worker.example", true);
        assert_eq!(worker.path, "/apiws?dst=149.154.167.40&dc=2");
        let cdn = Dc {
            number: 203,
            media: false,
            test: false,
        };
        assert_eq!(
            cdn.direct(Ipv4Addr::LOCALHOST)[0].host,
            "kws2.web.telegram.org"
        );
        assert_eq!(cdn.cf_host("edge.example"), "kws203.edge.example");
    }
}
