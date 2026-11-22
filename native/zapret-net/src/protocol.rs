use std::{collections::HashSet, io::Read, net::IpAddr};

use serde::{Deserialize, Serialize};
use url::Url;

pub const MAX_INPUT: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub version: u32,
    pub id: String,
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,
    #[serde(default)]
    pub post_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    pub connect_ip: Option<IpAddr>,
}

fn default_timeout() -> u64 {
    5000
}

fn default_body_limit() -> usize {
    65536
}

#[derive(Clone, Debug)]
pub struct Target {
    pub job: Job,
    pub url: Url,
}

pub fn read_jobs(reader: impl Read) -> Result<Vec<Target>, String> {
    let mut input = String::new();
    reader
        .take(MAX_INPUT + 1)
        .read_to_string(&mut input)
        .map_err(|error| format!("cannot read UTF-8 jobs: {error}"))?;
    if input.len() as u64 > MAX_INPUT {
        return Err("input exceeds 1 MiB".into());
    }
    let mut targets = Vec::new();
    let mut ids = HashSet::new();
    for (index, line) in input.trim_start_matches('\u{feff}').lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let job: Job =
            serde_json::from_str(line).map_err(|error| format!("line {}: {error}", index + 1))?;
        if job.version != 1
            || job.id.is_empty()
            || job.id.len() > 128
            || !ids.insert(job.id.clone())
            || !(1..=60000).contains(&job.timeout_ms)
            || !(1..=1_048_576).contains(&job.body_limit)
            || job.post_bytes > 65536
            || job
                .method
                .as_deref()
                .is_some_and(|m| !matches!(m, "GET" | "HEAD" | "POST"))
            || (job.method.as_deref().is_some_and(|m| m != "POST") && job.post_bytes > 0)
            || targets.len() >= 256
        {
            return Err(format!("line {}: invalid limits, version or id", index + 1));
        }
        let url = Url::parse(&job.url).map_err(|error| format!("line {}: {error}", index + 1))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(format!(
                "line {}: expected HTTP(S) URL without credentials or fragment",
                index + 1
            ));
        }
        targets.push(Target { job, url });
    }
    Ok(targets)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Stage {
    Queued,
    Dns,
    Tcp,
    Tls,
    Http,
    Body,
    Complete,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Termination {
    Complete,
    BodyLimit,
    DnsFailure,
    TcpFailure,
    TlsFailure,
    HttpFailure,
    TransferError,
    Timeout,
    Deadline,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpAttempt {
    pub address: String,
    pub elapsed_ms: f64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub version: u32,
    pub worker_version: String,
    pub id: String,
    pub url: String,
    pub stage: Stage,
    pub termination: Termination,
    pub error: Option<String>,
    pub status_code: Option<u16>,
    pub body_bytes: usize,
    pub received_body_bytes: usize,
    pub body_limit: usize,
    pub body_complete: bool,
    pub target_reached: bool,
    pub post_bytes: usize,
    #[serde(default)]
    pub request_body_bytes_provided: usize,
    #[serde(default)]
    pub request_body_measurement: String,
    pub dns_source: String,
    pub resolved_addresses: Vec<String>,
    pub tcp_attempts: Vec<TcpAttempt>,
    pub remote_address: Option<String>,
    pub tls_backend: String,
    pub tls_profile: String,
    pub trust_source: String,
    pub certificate_validated: bool,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub headers_ms: Option<f64>,
    pub started_ms: Option<f64>,
    /// QPC milliseconds share one monotonic origin across the parent and worker.
    #[serde(default)]
    pub started_monotonic_ms: Option<f64>,
    #[serde(default)]
    pub finished_monotonic_ms: Option<f64>,
    pub total_ms: f64,
}

impl Observation {
    pub fn queued(target: &Target, termination: Termination) -> Self {
        Self {
            version: 1,
            worker_version: env!("CARGO_PKG_VERSION").into(),
            id: target.job.id.clone(),
            url: target.job.url.clone(),
            stage: Stage::Queued,
            termination,
            error: None,
            status_code: None,
            body_bytes: 0,
            received_body_bytes: 0,
            body_limit: target.job.body_limit,
            body_complete: false,
            target_reached: false,
            post_bytes: target.job.post_bytes,
            request_body_bytes_provided: 0,
            request_body_measurement: "bytes yielded to HTTP encoder; not peer acknowledgement"
                .into(),
            dns_source: "system".into(),
            resolved_addresses: Vec::new(),
            tcp_attempts: Vec::new(),
            remote_address: None,
            tls_backend: (if cfg!(windows) {
                "Schannel"
            } else if cfg!(target_os = "macos") {
                "SecurityFramework"
            } else {
                "OpenSSL"
            })
            .into(),
            tls_profile: "native-tls defaults; TLS >= 1.2; ALPN http/1.1; system trust".into(),
            trust_source: "System".into(),
            certificate_validated: false,
            dns_ms: None,
            tcp_ms: None,
            tls_ms: None,
            headers_ms: None,
            started_ms: None,
            started_monotonic_ms: None,
            finished_monotonic_ms: None,
            total_ms: 0.0,
        }
    }
}
