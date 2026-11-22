//! Bounded direct network observations. Network failures are result data, never success.
//! Synchronous entry points own a Tokio runtime; call them outside another runtime.
mod connection;
mod diagnostic;
mod dns;
mod http;
mod http3;
mod latency;
mod probe;
mod protocol;
mod provider;
mod stun;
mod tcp;
mod tracker;
mod web;
#[cfg(windows)]
mod winhttp;

use anyhow::{Context, Result, bail};
pub use diagnostic::diagnostics;
pub use http::{download, fetch};
pub use latency::{LatencyOutcome, LatencySample, LatencyStore, LatencyStream, LatencySummary};
pub use protocol::{Job, Observation, Stage, TcpAttempt, Termination};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
pub use stun::assess_voice;
use tokio::{sync::watch, task::JoinSet, time::Instant};
pub use tracker::enrich_tracker;

#[derive(Clone, Debug)]
pub struct BatchOptions {
    pub parallel: usize,
    pub deadline_ms: u64,
    /// Additional process-local CA. Never modifies system certificate stores.
    pub ca_file: Option<PathBuf>,
    /// Optional captured POST payload shared by all probes in this batch.
    pub post_body: Option<Vec<u8>>,
}
impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            parallel: 16,
            deadline_ms: 30_000,
            ca_file: None,
            post_body: None,
        }
    }
}
impl BatchOptions {
    fn validate(&self) -> Result<()> {
        if !(1..=64).contains(&self.parallel) || !(1..=1_800_000).contains(&self.deadline_ms) {
            bail!("parallel or deadline outside supported range");
        }
        if self
            .post_body
            .as_ref()
            .is_some_and(|body| body.len() != 65536)
        {
            bail!("captured POST body must contain exactly 65536 bytes");
        }
        Ok(())
    }
}
pub(crate) fn tls_connector(
    ca_file: Option<&Path>,
    alpns: &[&str],
) -> Result<tokio_native_tls::TlsConnector> {
    let mut tls = native_tls::TlsConnector::builder();
    tls.min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .request_alpns(alpns);
    if let Some(path) = ca_file {
        let pem = read_ca(path)?;
        tls.add_root_certificate(native_tls::Certificate::from_pem(&pem).context("invalid CA")?);
    }
    Ok(tls.build().context("TLS setup failed")?.into())
}
fn read_ca(path: &Path) -> Result<Vec<u8>> {
    let mut pem = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("cannot read CA {}", path.display()))?
        .take(65_537)
        .read_to_end(&mut pem)?;
    if pem.len() > 65_536 {
        bail!("CA exceeds 64 KiB");
    }
    Ok(pem)
}
pub(crate) fn runtime<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(64)
        .build()
        .context("runtime setup failed")?;
    let result = runtime.block_on(future);
    // System DNS uses OS resolver work. Its blocking threads cannot hold up the API deadline.
    runtime.shutdown_background();
    result
}
/// Validate all jobs before opening sockets, then return exactly one row per id.
pub fn probe(jobs: &[Job], options: &BatchOptions) -> Result<Vec<Observation>> {
    options.validate()?;
    if jobs.len() > 256
        || jobs
            .iter()
            .any(|j| j.url.len() > protocol::MAX_INPUT as usize || j.id.len() > 128)
    {
        bail!("jobs exceed supported input limits")
    }
    let mut input = Vec::new();
    for job in jobs {
        serde_json::to_writer(&mut input, job)?;
        input.push(b'\n');
        if input.len() > protocol::MAX_INPUT as usize {
            bail!("input exceeds 1 MiB")
        }
    }
    let targets = protocol::read_jobs(input.as_slice()).map_err(anyhow::Error::msg)?;
    let connector = tls_connector(options.ca_file.as_deref(), &["http/1.1"])?;
    let mut rows = Vec::with_capacity(jobs.len());
    runtime(batch(targets, options, connector, |row| {
        rows.push(row);
        Ok(())
    }))?;
    Ok(rows)
}
/// Version-1 JSONL through EOF, streaming observations to stdout.
pub fn run_stdio(options: BatchOptions) -> Result<()> {
    options.validate()?;
    let targets = protocol::read_jobs(std::io::stdin().lock()).map_err(anyhow::Error::msg)?;
    let connector = tls_connector(options.ca_file.as_deref(), &["http/1.1"])?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    runtime(batch(targets, &options, connector, |row| {
        serde_json::to_writer(&mut output, &row)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }))
}
async fn batch(
    jobs: Vec<protocol::Target>,
    options: &BatchOptions,
    connector: tokio_native_tls::TlsConnector,
    mut emit: impl FnMut(Observation) -> Result<()>,
) -> Result<()> {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(options.deadline_ms);
    let mut queue: VecDeque<_> = jobs.into();
    let mut running = JoinSet::new();
    let (cancel, cancellation) = watch::channel(false);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let mut cancelled = false;
    let post_body = options.post_body.clone().map(std::sync::Arc::<[u8]>::from);
    loop {
        while running.len() < options.parallel {
            let Some(target) = queue.pop_front() else {
                break;
            };
            if cancelled || Instant::now() >= deadline {
                let mut row = Observation::queued(
                    &target,
                    if cancelled {
                        Termination::Cancelled
                    } else {
                        Termination::Deadline
                    },
                );
                if options.ca_file.is_some() {
                    row.trust_source = "SystemPlusExtraCa".into();
                }
                emit(row)?;
            } else {
                running.spawn(probe::run_probe(
                    target,
                    connector.clone(),
                    start,
                    deadline,
                    cancellation.clone(),
                    options.ca_file.is_some(),
                    post_body.clone(),
                ));
            }
        }
        if running.is_empty() {
            return Ok(());
        }
        tokio::select! {
            result=running.join_next()=>emit(result.context("nonempty probe tasks")?.context("probe task failed")?)?,
            signal=&mut interrupt,if !cancelled=>{signal.context("interrupt handler failed")?;cancelled=true;let _=cancel.send(true);}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_batch_completes_without_network() {
        assert!(probe(&[], &BatchOptions::default()).unwrap().is_empty());
    }
    #[test]
    fn rejects_unknown_kind() {
        assert!(diagnostics(Path::new("."), "invalid", &serde_json::json!({})).is_err());
    }
    #[test]
    fn dns_literal_has_observed_family() {
        let row = diagnostics(
            Path::new("."),
            "dns",
            &serde_json::json!({"host":"127.0.0.1"}),
        )
        .unwrap();
        assert_eq!(row["rows"][0]["addresses"][0], "127.0.0.1");
        assert_eq!(row["rows"][0]["reason"], "AddressLiteral");
    }
}
