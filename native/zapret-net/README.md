# Native network tools

`zapret-net` contains the bounded network implementation used by the native control application. Importing it starts no process or request. All ordinary HTTP, TLS, DNS, UDP, STUN, ICMP and TCP logic is Rust; finite optional browser/curl clients use `zapret-platform` ownership with a Windows job created before the child can run.

Public synchronous APIs:

```rust,ignore
BatchOptions { parallel: usize, deadline_ms: u64, ca_file: Option<PathBuf> }
probe(&[Job], &BatchOptions) -> anyhow::Result<Vec<Observation>>
run_stdio(BatchOptions) -> anyhow::Result<()>
diagnostics(&Path, &str, &serde_json::Value) -> anyhow::Result<Value>
fetch(&str, usize, u64) -> anyhow::Result<Vec<u8>>
download(&str, &Path, usize, u64) -> anyhow::Result<()>
assess_voice(&Value, &Value, &str, &str) -> anyhow::Result<Value>
```

`Job` and `Observation` are cloneable and support JSON serialization/deserialization. The worker retains version-1 JSONL evidence and rejects malformed jobs before opening sockets. Limits are 256 jobs, 1 MiB input, parallelism 1–64, per-job 1–60000 ms and batch 1–1800000 ms. `Job.method` optionally accepts `GET`, `HEAD` or `POST`; absent values retain POST inference from `post_bytes`. `post_bytes` is the configured size. `request_body_bytes_provided` measures actual bytes yielded to Hyper's HTTP encoder and does **not** assert peer receipt or acknowledgement. Existing stage, termination, TLS backend/trust, address attempts and accepted/received partial-body fields remain distinct.

`fetch` and `download` require verified HTTPS outside loopback fixtures, accept at most five redirects, reject credential-bearing URLs and HTTPS downgrades, require a complete 2xx body, and enforce a 128 MiB maximum and a total deadline up to 300000 ms. `download` stages and syncs the result beside the destination before atomic publication. Failed downloads preserve the existing destination. No proxy environment variables or system certificate-store changes are used.

`diagnostics` accepts these kinds:

| Kind | Arguments and evidence |
| --- | --- |
| `connection` | `url`, nonempty `urls`, or `targets:[{group,name,url}]`; otherwise bundled YouTube/Discord/Bing. Repeated system DNS, up to two addresses in each family, parallel per-address HTTP/1.1 HEAD, strict bounded headers, exact partial-byte and stage observations. `attempts:1..2`, `timeout_ms:1..30000`, optional `ca_file` for process-local native TLS trust. |
| `webcheck` | Same targets, optional `modes:[Http1,Http2,Http3,BrowserAuto,BrowserTcp]`, `visits:1..2`, `timeout_ms`, `capabilities_only`, and `browser_path`/`curl_path` absolute overrides. HTTP/2 requires ALPN h2 and complete HEAD. HTTP/3 uses WinHTTP when available and falls back to built-in Quinn and rustls with the system certificate verifier. `ca_file` selects Quinn with an additional process-local trust anchor. Explicit `curl_path` selects curl. An empty `curl_path` disables HTTP/3. Actual Chromium navigation uses CDP main-document events, temporary profiles, disabled cache and service workers, ordinary certificate validation and a separate no-QUIC mode. |
| `stun`, `voice-control` | `host`/`stun_host`, `port`/`stun_port`, `attempts:1..2`, `timeout_ms:1..5000`. Random transaction, connected UDP source, framing/required attributes/XOR mapping/fingerprint checks and real counters. A verified STUN error response stays distinct from Binding success. |
| `voice` | STUN plus platform `voice-capture` with `duration_sec:1..120`, optional `control_only`, and `audio:Unknown/Both/OnlyReceive/OnlySend/None`. ETW requires the native application's platform worker and platform permissions. Lost/truncated/unconfirmed capture cannot prove traffic absence or bidirectionality. Neither STUN nor ETW establishes audio success, blocking cause or profile hit. |
| `latency` | Literal `ip` or `addresses`, `protocol:icmp/tcp/both`, `port`, `count:1..20`, `timeout_ms:1..5000`, `interval_ms`, `deadline_ms:1..60000`. Windows IP Helper ICMPv4/ICMPv6 and native TCP handshakes stay separate from game latency. |
| `dns` | Explicit `host` or `hosts` performs system resolution. Without names, compares the legacy Discord/X/Rutracker names with native JSON DoH. `compare`, `no_hosts`, `doh_urls`, `bypass_on` and `ca_file` allow explicit control/fixtures. Windows no-hosts resolution uses DNS API flags and preserves errors. Different CDN answers alone do not become a forgery conclusion; private answers and validated TLS differences are reported as suspicion with coverage. |
| `ipv6` | Default ten legacy CDN hosts or supplied targets; separate selected IPv4/IPv6 direct TCP/TLS and HTTP-header evidence, no-address/unknown/down/broken/slow/ok outcomes. Network context is returned without modifying adapter or prefix policy. |
| `provider`, `ipinfo` | `ip` or `ips`; bounded native `ipwho.is` lookup with `ipinfo.io` fallback. `primary_url`/`fallback_url` and `ca_file` support fixtures. Both source attempts and unknown/malformed failures remain visible; report-safe masked IP is supplied alongside the internal observation. |

`LatencyStore`, `LatencySummary`, `LatencyOutcome`, `LatencySample` and `LatencyStream` expose the legacy bounded stream window, LRU capacity, delayed completion timestamps, TCP/ICMP scheduling intervals, median and P95 (at least 20 replies), spike/failure counts and 60-second freshness rules.

Support boundaries are explicit evidence:

- `native_http3` indicates selection of the [WinHTTP HTTP/3 API](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags). `rust_http3` indicates selection of Quinn. Both require completed HEAD response headers and observed `h3` to confirm QUIC. Both use direct connections, one deadline across DNS, TLS and QUIC, and at most five HTTPS redirects. Redirects reject URL credentials and HTTPS downgrades. Browser h3 is confirmed from its CDP response protocol.
- Browser tests require an installed supported Chromium executable. Browser startup and all child processes are bounded and owned; unrelated browser sessions are never operated on.
- Native TLS performs ordinary backend chain/hostname validation. A failed handshake may not expose its peer certificate or negotiated TLS version through `native-tls`; fields report that absence and retain the actual backend error instead of fabricating certificate observations. Revocation policy is backend-dependent and is not asserted.
- OS DNS work can outlive the asynchronous caller deadline in a blocking resolver thread. The library returns at the deadline without waiting for it; the native controller also gives the worker an owned hard lifetime. No background DNS completion can change a returned failure into success.
- Tracker enrichment reads cached PTR names and uses the local [Windows DNS cache provider](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/dnsclientcimprov/msft-dnsclientcache) for A/AAAA records matching captured peer IPs. Reports distinguish a completed, partial or unavailable forward-cache read. Names describe the machine-wide cache and are collected without network queries.
- ICMP uses native Windows APIs; other platforms return an explicit unsupported observation. ETW collection and elevated state changes are owned by `zapret-platform`; this crate never changes bypass, services, adapters, hosts, registry or trust stores.

Checks from the repository root:

```powershell
cargo zapret test -p zapret-net
cargo zapret check -p zapret-net
python native/zapret-net/tests/acceptance.py dist/native/debug/zapret-net-probe.exe --output dist/native/net-acceptance.json --benchmark-rounds 1
python native/zapret-net/tests/protocol_fixtures.py dist/native/debug/zapret-net-probe.exe --output dist/native/net-protocol.json
python native/zapret-net/tests/http3_fixtures.py --test-binary dist/native/debug/deps/zapret_net-<hash>.exe --dependencies dist/native/dns-http3/test-python
```

The Rust test suite starts a loopback QUIC server and checks the Quinn transport with both system and process-local trust. The 38-case acceptance corpus includes the PowerShell/curl loopback baseline from `dev/rust-probe`. Extended browser and protocol fixtures optionally use the Python `h2` package. The opt-in WinHTTP fixture uses Python `aioquic` and `cryptography` and a `zapret_net` unit-test executable. Its positive trust override is compiled into the test executable and restricted to IPv4 loopback.
