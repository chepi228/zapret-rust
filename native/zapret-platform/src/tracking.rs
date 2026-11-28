use crate::{
    OwnedChild, ProcessIdentity, RunOptions,
    process::wide,
    storage::{atomic_write, no_reparse, read_limited},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::*,
        Security::Cryptography::*,
        System::{Diagnostics::Etw::*, Time::FileTimeToSystemTime},
    },
    core::GUID,
};
const PROVIDER: GUID = GUID {
    data1: 0x7dd42a49,
    data2: 0x5329,
    data3: 0x4832,
    data4: [0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88],
};
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Identity {
    identity: ProcessIdentity,
    name: String,
    observed_until: u64,
}
#[derive(Clone, Debug)]
struct Event {
    pid: u32,
    bytes: u32,
    destination: IpAddr,
    source: IpAddr,
    destination_port: u16,
    source_port: u16,
    id: u16,
    at: u64,
}
fn parse_event(id: u16, at: u64, data: &[u8]) -> Option<Event> {
    let v6 = match id {
        10..=16 | 18 | 42 | 43 => false,
        26..=32 | 34 | 58 | 59 => true,
        _ => return None,
    };
    let address_length = if v6 { 16 } else { 4 };
    let needed = 8 + address_length * 2 + 4;
    if data.len() < needed {
        return None;
    }
    let pid = u32::from_le_bytes(data[..4].try_into().ok()?);
    let bytes = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let ip = |b: &[u8]| -> Option<IpAddr> {
        if v6 {
            Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?)))
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b).ok()?)))
        }
    };
    let destination = ip(&data[8..8 + address_length])?;
    let source = ip(&data[8 + address_length..8 + 2 * address_length])?;
    let p = 8 + address_length * 2;
    let destination_port = u16::from_be_bytes([data[p], data[p + 1]]);
    let source_port = u16::from_be_bytes([data[p + 2], data[p + 3]]);
    if destination_port == 0 || source_port == 0 {
        return None;
    }
    Some(Event {
        pid,
        bytes,
        destination,
        source,
        destination_port,
        source_port,
        id,
        at,
    })
}
fn utc(at: u64) -> String {
    unsafe {
        let f = FILETIME {
            dwLowDateTime: at as u32,
            dwHighDateTime: (at >> 32) as u32,
        };
        let mut s = zeroed();
        if FileTimeToSystemTime(&f, &mut s) == 0 {
            return String::new();
        }
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond, s.wMilliseconds
        )
    }
}
#[derive(Default)]
struct Gaps {
    last: Option<u64>,
    events: u64,
    gap_count: u64,
    maximum: u64,
    over_100_ms: u64,
    over_250_ms: u64,
    out_of_order_events: u64,
}
impl Gaps {
    fn observe(&mut self, at: u64) {
        self.events += 1;
        if let Some(previous) = self.last {
            let Some(gap) = at.checked_sub(previous) else {
                self.out_of_order_events += 1;
                return;
            };
            self.gap_count += 1;
            self.maximum = self.maximum.max(gap);
            self.over_100_ms += u64::from(gap > 100 * 10000);
            self.over_250_ms += u64::from(gap > 250 * 10000);
        }
        self.last = Some(at);
    }
    fn value(&self) -> Value {
        json!({
            "events": self.events,
            "gap_count": self.gap_count,
            "max_gap_ms": if self.gap_count > 0 { Some(self.maximum as f64 / 10000.0) } else { None },
            "over_100_ms": self.over_100_ms,
            "over_250_ms": self.over_250_ms,
            "out_of_order_events": self.out_of_order_events
        })
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    pid: u32,
    created: u64,
    protocol: &'static str,
    remote: SocketAddr,
    local: SocketAddr,
}
#[derive(Default)]
struct FlowCounts<'a> {
    name: &'a str,
    first: u64,
    last: u64,
    incoming: Gaps,
    outgoing: Gaps,
    bytes_in: u64,
    bytes_out: u64,
    retransmits: u64,
    control: u64,
    syn_attempts: u64,
}
fn flows(
    events: &[Event],
    identities: &[Identity],
    local: &BTreeSet<IpAddr>,
    voice: bool,
) -> (Vec<Value>, bool, Value) {
    let mut rows = BTreeMap::<FlowKey, FlowCounts>::new();
    let owners: Vec<_> = identities
        .iter()
        .filter(|p| identity_name_matches(p) && (!voice || discord_name(&p.name)))
        .collect();
    let mut cross_flow = Gaps::default();
    let mut truncated = false;
    let limit = if voice { 128 } else { 512 };
    for event in events {
        if voice && ![42, 43, 58, 59].contains(&event.id) {
            continue;
        }
        let Some(identity) = owners.iter().find(|p| {
            p.identity.pid == event.pid
                && p.identity.created_filetime <= event.at
                && p.observed_until >= event.at
        }) else {
            continue;
        };
        let send = [10, 26, 42, 58].contains(&event.id);
        let receive = [11, 27, 43, 59].contains(&event.id);
        let source_local = local.contains(&event.source);
        let destination_local = local.contains(&event.destination);
        let udp = matches!(event.id, 42 | 43 | 58 | 59);
        // Kernel-Network TCP receive events can use the connection's local-to-remote
        // endpoint order. The event ID specifies the transfer direction.
        if source_local == destination_local
            || (send && !source_local)
            || (udp && receive && !destination_local)
        {
            continue;
        }
        let source = SocketAddr::new(event.source, event.source_port);
        let destination = SocketAddr::new(event.destination, event.destination_port);
        let (local_endpoint, remote) = if source_local {
            (source, destination)
        } else {
            (destination, source)
        };
        if !zapret_core::is_public_address(remote.ip()) {
            continue;
        }
        let key = FlowKey {
            pid: event.pid,
            created: identity.identity.created_filetime,
            protocol: if udp { "udp" } else { "tcp" },
            remote,
            local: local_endpoint,
        };
        let at_limit = rows.len() >= limit;
        let row = match rows.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(_) if at_limit => {
                truncated = true;
                continue;
            }
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(FlowCounts {
                name: &identity.name,
                first: event.at,
                last: event.at,
                ..Default::default()
            }),
        };
        row.first = row.first.min(event.at);
        row.last = row.last.max(event.at);
        if send {
            row.outgoing.observe(event.at);
            row.bytes_out += u64::from(event.bytes);
            cross_flow.observe(event.at);
        } else if receive {
            row.incoming.observe(event.at);
            row.bytes_in += u64::from(event.bytes);
            cross_flow.observe(event.at);
        } else if matches!(event.id, 14 | 30) {
            row.retransmits += 1;
        } else {
            row.control += 1;
            row.syn_attempts += u64::from(matches!(event.id, 12 | 16 | 28 | 32));
        }
    }
    // Preserve the report order used by bounded follow-up probes.
    let mut rows: Vec<_> = rows.into_iter().collect();
    rows.sort_by_cached_key(|(k, _)| {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            k.pid,
            k.created,
            k.protocol,
            k.remote.ip(),
            k.remote.port(),
            k.local.ip(),
            k.local.port()
        )
    });
    let rows = rows.into_iter().map(|(key, row)| {
        let port = key.remote.port();
        json!({
            "process_id":key.pid, "process_name":row.name, "process_created_filetime":key.created,
            "process_started_utc":utc(key.created),"address":key.remote.ip(),"port":port,
            "local_address":key.local.ip(),"local_port":key.local.port(),"protocol":key.protocol,
            "in":row.incoming.events,"out":row.outgoing.events,"bytes_in":row.bytes_in,"bytes_out":row.bytes_out,
            "retx":row.retransmits,"ctl":row.control,"syn_attempts":row.syn_attempts,
            "packets":row.incoming.events+row.outgoing.events+row.retransmits+row.control,
            "first_utc":utc(row.first),"last_utc":utc(row.last),
            "timing":{"incoming":row.incoming.value(),"outgoing":row.outgoing.value()},
            "voice_port_configured":(19294..=19344).contains(&port)||(50000..=50100).contains(&port),
            "voice_attribution":"NotConfirmed","profile_hit":"NotObserved"
        })
    }).collect();
    let mut context = cross_flow.value();
    context["observed_data_events"] = json!(cross_flow.events);
    context["scope"] = json!("RetainedAttributedFlows");
    context["clock"] = json!("EtwFiletime");
    context["cause"] = json!("NotEstablished");
    (rows, truncated, context)
}
fn wildcard(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let p = pattern.to_lowercase();
    if !p.contains('*') {
        return name == p;
    }
    let pieces = p.split('*').collect::<Vec<_>>();
    let mut rest = name.as_str();
    for (i, p) in pieces.iter().enumerate() {
        if p.is_empty() {
            continue;
        }
        let Some(at) = rest.find(p) else {
            return false;
        };
        if i == 0 && at != 0 {
            return false;
        }
        rest = &rest[at + p.len()..];
    }
    p.ends_with('*') || rest.is_empty()
}
fn discord_name(name: &str) -> bool {
    ["discord", "discordcanary", "discordptb"]
        .iter()
        .any(|expected| name.eq_ignore_ascii_case(expected))
}
fn identity_name_matches(identity: &Identity) -> bool {
    identity
        .identity
        .executable
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(&identity.name))
}
fn observe(
    identities: &mut Vec<Identity>,
    pattern: &str,
    voice: bool,
    selected: bool,
) -> Result<bool> {
    let now = crate::time_filetime();
    let mut incomplete = false;
    let processes = crate::system::scan_processes(|name| {
        if voice {
            discord_name(name)
        } else {
            wildcard(name, pattern)
                || (!selected && {
                    let lower = name.to_ascii_lowercase();
                    lower.starts_with("easyanticheat") || lower.starts_with("start_protected_game")
                })
        }
    })?;
    for p in processes {
        let Some(identity) = p.identity else {
            incomplete = true;
            continue;
        };
        let observed = Identity {
            identity,
            name: p.name,
            observed_until: now,
        };
        if !identity_name_matches(&observed) {
            incomplete = true;
            continue;
        }
        if let Some(row) = identities
            .iter_mut()
            .find(|p| p.identity == observed.identity)
        {
            row.observed_until = now;
        } else if identities.len() < 256 {
            identities.push(observed);
        } else {
            incomplete = true;
        }
    }
    Ok(incomplete)
}
fn local_addresses() -> Result<BTreeSet<IpAddr>> {
    let adapters = crate::system::adapters()?;
    Ok(adapters
        .as_array()
        .context("Adapter list missing")?
        .iter()
        .filter_map(|a| a["addresses"].as_array())
        .flatten()
        .filter_map(|a| a["address"].as_str())
        .filter_map(|address| address.parse().ok())
        .collect())
}
struct Properties {
    data: Vec<usize>,
}
impl Properties {
    fn new(session: &str, path: &Path) -> Result<Self> {
        let name = wide(session)?;
        let file = wide(path)?;
        let name_offset = size_of::<EVENT_TRACE_PROPERTIES>();
        let file_offset = name_offset + name.len() * 2;
        let bytes = file_offset + file.len() * 2;
        let mut result = Self {
            data: vec![0; (bytes + size_of::<usize>() - 1) / size_of::<usize>()],
        };
        unsafe {
            let p = &mut *result.ptr();
            p.Wnode.BufferSize = bytes as u32;
            p.Wnode.ClientContext = 2;
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.BufferSize = 64;
            p.MinimumBuffers = 2;
            p.MaximumBuffers = 16;
            p.MaximumFileSize = 32;
            p.LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR;
            p.FlushTimer = 1;
            p.LoggerNameOffset = name_offset as u32;
            p.LogFileNameOffset = file_offset as u32;
            let dest = result.data.as_mut_ptr().cast::<u8>();
            std::ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                dest.add(name_offset),
                name.len() * 2,
            );
            std::ptr::copy_nonoverlapping(
                file.as_ptr().cast::<u8>(),
                dest.add(file_offset),
                file.len() * 2,
            );
        }
        Ok(result)
    }
    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.data.as_mut_ptr().cast()
    }
}
struct Session {
    handle: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    properties: Properties,
    stopped: bool,
}
impl Session {
    fn start(name: &str, path: &Path) -> Result<Self> {
        ensure!(!path.exists(), "Owned trace output already exists");
        no_reparse(path)?;
        let mut properties = Properties::new(name, path)?;
        let name = wide(name)?;
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let e = unsafe { StartTraceW(&mut handle, name.as_ptr(), properties.ptr()) };
        ensure!(e == 0, "StartTraceW: Windows error {e}");
        let mut session = Self {
            handle,
            name,
            properties,
            stopped: false,
        };
        let e = unsafe {
            EnableTraceEx2(
                handle,
                &PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                255,
                u64::MAX,
                0,
                5000,
                null(),
            )
        };
        if e != 0 {
            let _ = session.stop();
            anyhow::bail!("EnableTraceEx2: Windows error {e}");
        }
        Ok(session)
    }
    fn stop(&mut self) -> Result<Value> {
        if self.stopped {
            return Ok(json!({"cleanup_confirmed":true}));
        }
        let e = unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                self.properties.ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        ensure!(
            e == 0 || e == ERROR_WMI_INSTANCE_NOT_FOUND,
            "ControlTraceW stop: Windows error {e}"
        );
        self.stopped = true;
        let p = unsafe { &*self.properties.ptr() };
        Ok(
            json!({"cleanup_confirmed":true,"events_lost":p.EventsLost,"log_buffers_lost":p.LogBuffersLost,"realtime_buffers_lost":p.RealTimeBuffersLost}),
        )
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
struct Replay {
    events: Vec<Event>,
    deadline: Instant,
    truncated: bool,
    decode_errors: u32,
}
unsafe extern "system" fn event_callback(raw: *mut EVENT_RECORD) {
    let _ = std::panic::catch_unwind(|| unsafe {
        if raw.is_null() {
            return;
        }
        let record = &*raw;
        if record.UserContext.is_null() {
            return;
        }
        let state = &mut *record.UserContext.cast::<Replay>();
        if state.events.len() >= 50000 || Instant::now() >= state.deadline {
            state.truncated = true;
            return;
        }
        let provider = &record.EventHeader.ProviderId;
        if provider.data1 != PROVIDER.data1
            || provider.data2 != PROVIDER.data2
            || provider.data3 != PROVIDER.data3
            || provider.data4 != PROVIDER.data4
        {
            return;
        }
        if record.UserData.is_null() {
            return;
        }
        let id = record.EventHeader.EventDescriptor.Id;
        let data = std::slice::from_raw_parts(
            record.UserData.cast::<u8>(),
            record.UserDataLength as usize,
        );
        let at = record.EventHeader.TimeStamp as u64;
        if let Some(event) = parse_event(id, at, data) {
            state.events.push(event);
        } else if [10, 11, 26, 27, 42, 43, 58, 59].contains(&id) {
            state.decode_errors += 1;
        }
    });
}
unsafe extern "system" fn buffer_callback(raw: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    unsafe {
        if raw.is_null() || (*raw).Context.is_null() {
            return 0;
        }
        let s = &mut *(*raw).Context.cast::<Replay>();
        if s.events.len() >= 50000 || Instant::now() >= s.deadline {
            s.truncated = true;
            0
        } else {
            1
        }
    }
}
fn replay(path: &Path) -> Result<(Vec<Event>, Value)> {
    let metadata = std::fs::metadata(path)?;
    ensure!(
        metadata.len() <= 64 * 1024 * 1024,
        "ETL exceeds replay budget"
    );
    no_reparse(path)?;
    let mut file = wide(path)?;
    let mut state = Box::new(Replay {
        events: Vec::new(),
        deadline: Instant::now() + Duration::from_secs(8),
        truncated: false,
        decode_errors: 0,
    });
    let mut log: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
    log.LogFileName = file.as_mut_ptr();
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(event_callback);
    log.BufferCallback = Some(buffer_callback);
    log.Context = (&mut *state as *mut Replay).cast();
    let handle = unsafe { OpenTraceW(&mut log) };
    ensure!(
        handle.Value != u64::MAX,
        "OpenTraceW: {}",
        std::io::Error::last_os_error()
    );
    struct Trace(PROCESSTRACE_HANDLE);
    impl Drop for Trace {
        fn drop(&mut self) {
            unsafe {
                CloseTrace(self.0);
            }
        }
    }
    let trace = Trace(handle);
    let result = unsafe { ProcessTrace(&trace.0, 1, null(), null()) };
    ensure!(
        result == 0 || (result == ERROR_CANCELLED && state.truncated),
        "ProcessTrace: Windows error {result}"
    );
    let info = json!({"events_lost":log.EventsLost,"truncated":state.truncated,"decode_errors":state.decode_errors,"observed_events":state.events.len()});
    Ok((std::mem::take(&mut state.events), info))
}
fn trace_paths(root: &Path, args: &Value) -> Result<(String, PathBuf)> {
    let session = args["session"]
        .as_str()
        .context("Owned trace session required")?;
    // Stable ownership prefix lets guards clean up sessions from previous controllers.
    let id = session
        .strip_prefix("zapretNative-")
        .context("Invalid owned trace session prefix")?;
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid owned trace session identity"
    );
    let path = root
        .join("runtime/native-traces")
        .join(format!("track-{id}.etl"));
    ensure!(
        args["path"]
            .as_str()
            .is_some_and(|p| crate::process::same_path(Path::new(p), &path)),
        "Owned trace path does not match its session"
    );
    no_reparse(&path)?;
    Ok((session.into(), path))
}
fn signal(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}
fn guard_finished(
    expected: &ProcessIdentity,
    actual: Option<&ProcessIdentity>,
    stop: bool,
    expired: bool,
) -> Option<&'static str> {
    if stop {
        return Some("StopRequested");
    }
    if !actual.is_some_and(|actual| {
        actual.pid == expected.pid
            && actual.created_filetime == expected.created_filetime
            && crate::process::same_path(&actual.executable, &expected.executable)
    }) {
        return Some("ParentExitedOrChanged");
    }
    expired.then_some("DeadlineReached")
}
fn guard(root: &Path, args: &Value) -> Result<Value> {
    let (session, path) = trace_paths(root, args)?;
    let parent: ProcessIdentity = serde_json::from_value(args["parent"].clone())?;
    let seconds = args["max_seconds"]
        .as_u64()
        .context("Trace guard deadline required")?;
    ensure!(
        (1..=145).contains(&seconds),
        "Trace guard deadline must be 1..145 seconds"
    );
    ensure!(
        crate::process_identity(parent.pid)? == parent,
        "Trace parent identity changed"
    );
    ensure!(
        crate::trusted_path(path.parent().unwrap())?,
        "Trace storage is untrusted"
    );
    let ready = signal(&path, ".ready");
    let stop = signal(&path, ".stop");
    let done = signal(&path, ".done");
    let guard_identity = crate::process_identity(std::process::id())?;
    let mut result = json!({"cleanup_confirmed":false,"reason":"NotStarted"});
    let outcome = (|| -> Result<()> {
        let mut trace = Session::start(&session, &path)?;
        atomic_write(
            &ready,
            &serde_json::to_vec(&json!({"session":session,"guard":guard_identity}))?,
        )?;
        let end = Instant::now() + Duration::from_secs(seconds);
        let reason = loop {
            let current = crate::process_identity(parent.pid).ok();
            if let Some(reason) = guard_finished(
                &parent,
                current.as_ref(),
                stop.exists(),
                Instant::now() >= end,
            ) {
                break reason;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        result = trace.stop()?;
        result["reason"] = json!(reason);
        Ok(())
    })();
    if let Err(e) = outcome {
        result["error"] = json!(e.to_string());
    }
    result["session"] = json!(session);
    result["guard"] = json!(guard_identity);
    atomic_write(&done, &serde_json::to_vec(&result)?)?;
    Ok(result)
}
fn capture(root: &Path, args: &Value, voice: bool) -> Result<Value> {
    ensure!(
        crate::is_admin()?,
        "Network ETW capture requires administrator rights"
    );
    let seconds = args["duration_sec"]
        .as_u64()
        .unwrap_or(if voice { 30 } else { 5 });
    ensure!(
        (1..=120).contains(&seconds),
        "Tracking duration must be 1..120 seconds"
    );
    let lower = args["process_name"]
        .as_str()
        .unwrap_or(if voice { "Discord" } else { "NBA2K*" })
        .trim()
        .to_lowercase();
    let pattern = lower.strip_suffix(".exe").unwrap_or(&lower);
    let selected = args["selected_only"] == true;
    ensure!(
        !pattern.is_empty()
            && pattern.encode_utf16().count() <= 255
            && !pattern.chars().any(char::is_control)
            && !pattern.contains(['/', '\\', ':', '?', '"', '<', '>', '|'])
            && (!selected || !pattern.contains('*')),
        "Invalid process pattern"
    );
    let store = root.join("runtime/native-traces");
    no_reparse(&store)?;
    std::fs::create_dir_all(&store)?;
    crate::protect_path(&store)?;
    let mut random = [0u8; 16];
    ensure!(
        unsafe {
            BCryptGenRandom(
                null_mut(),
                random.as_mut_ptr(),
                16,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } >= 0,
        "Trace identity generation failed"
    );
    let id = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let session = format!("zapretNative-{id}");
    let path = store.join(format!("track-{id}.etl"));
    let parent = crate::process_identity(std::process::id())?;
    let payload = json!({"session":session,"path":path,"parent":parent,"max_seconds":seconds+12});
    let executable = crate::tasks::executable(root, args)?;
    let a = [
        OsString::from("--root"),
        root.as_os_str().into(),
        "platform-worker".into(),
        "trace-guard".into(),
        "--arguments-json".into(),
        serde_json::to_string(&payload)?.into(),
    ];
    let options = RunOptions {
        cwd: Some(root.into()),
        timeout: Duration::from_secs(seconds + 15),
        ..Default::default()
    };
    let child = OwnedChild::spawn_background(&executable, &a, &options, &store.join("guard.log"))?;
    let guard_identity = child.identity().clone();
    child.detach()?;
    let ready = signal(&path, ".ready");
    let stop = signal(&path, ".stop");
    let done = signal(&path, ".done");
    struct StopOnDrop(Option<PathBuf>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            if let Some(path) = self.0.as_ref() {
                let _ = atomic_write(path, b"stop");
            }
        }
    }
    let mut stop_owner = StopOnDrop(Some(stop.clone()));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) && !ready.exists() && !done.exists() {
        if crate::process_identity(guard_identity.pid).ok().as_ref() != Some(&guard_identity) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready.exists() {
        let failure = if done.exists() {
            serde_json::from_slice::<Value>(&read_limited(&done, 16384)?)?
        } else {
            json!({"cleanup_confirmed":false,"error":"Trace guard did not acknowledge startup"})
        };
        return Ok(
            json!({"status":"Unavailable","reason":"CaptureStartFailed","capture":failure,"flows":[],"truncated":true,"cleanup_confirmed":failure["cleanup_confirmed"]}),
        );
    }
    let acknowledgement: Value = serde_json::from_slice(&read_limited(&ready, 16384)?)?;
    let actual: ProcessIdentity = serde_json::from_value(acknowledgement["guard"].clone())?;
    ensure!(
        actual == guard_identity && acknowledgement["session"] == session,
        "Trace guard acknowledgement identity mismatch"
    );
    let local = local_addresses()?;
    let mut identities = Vec::new();
    let mut identities_incomplete = false;
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        identities_incomplete |= observe(&mut identities, pattern, voice, selected)?;
        std::thread::sleep(Duration::from_millis(200));
    }
    identities_incomplete |= observe(&mut identities, pattern, voice, selected)?;
    atomic_write(&stop, b"stop")?;
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end && !done.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    ensure!(
        done.exists(),
        "Trace guard did not confirm cleanup; trace retained for investigation"
    );
    let cleanup: Value = serde_json::from_slice(&read_limited(&done, 16384)?)?;
    let cleaned_by: ProcessIdentity = serde_json::from_value(cleanup["guard"].clone())?;
    ensure!(
        cleanup["session"] == session
            && cleanup["cleanup_confirmed"] == true
            && cleaned_by == guard_identity,
        "Trace session cleanup is unconfirmed: {cleanup}"
    );
    stop_owner.0.take();
    // Only extend the ownership window through the trace tail for identities still observed.
    identities_incomplete |= observe(&mut identities, pattern, voice, selected).unwrap_or(true);
    let (events, info) = replay(&path)?;
    let (flows, flow_limit, timing_context) = flows(&events, &identities, &local, voice);
    let lost =
        cleanup["events_lost"].as_u64().unwrap_or(0) + info["events_lost"].as_u64().unwrap_or(0);
    let truncated = flow_limit
        || identities_incomplete
        || info["truncated"] == true
        || lost > 0
        || info["decode_errors"].as_u64().unwrap_or(0) > 0;
    let record = json!({"status":if truncated{"Partial"}else{"Captured"},"reason":"EtwObservedEvents","coverage":"EtwObservedEvents","duration_sec":seconds,"session":session,"path":path,"identities":identities,"flows":flows,"timing_context":timing_context,"truncated":truncated,"identities_incomplete":identities_incomplete,"events_lost":lost,"cleanup_confirmed":true,"decode_errors":info["decode_errors"],"observed_events":info["observed_events"],"voice_attribution":"NotConfirmed","profile_hit":"NotObserved"});
    atomic_write(
        &signal(&path, ".json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    for p in [&ready, &stop, &done] {
        if p.exists() {
            no_reparse(p)?;
            std::fs::remove_file(p)?;
        }
    }
    if !args["keep_trace"].as_bool().unwrap_or(false) {
        no_reparse(&path)?;
        std::fs::remove_file(&path)?;
    }
    Ok(record)
}
pub(crate) fn dispatch(root: &Path, action: &str, args: &Value) -> Result<Value> {
    match action {
        "trace-guard" => guard(root, args),
        "track-replay" => {
            let path = PathBuf::from(args["path"].as_str().context("Replay path required")?);
            let (events, info) = replay(&path)?;
            let identities: Vec<Identity> = serde_json::from_value(args["identities"].clone())
                .context("Replay identities require exact pid/creation/path/observed_until")?;
            validate_identities(&identities)?;
            let local = args["local_addresses"]
                .as_array()
                .context("Replay local_addresses required")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .context("Local address string required")?
                        .parse::<std::net::IpAddr>()
                        .context("Invalid local IP address")
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(local.len() <= 256, "Replay local address limit exceeded");
            let (flows, truncated, timing_context) = flows(
                &events,
                &identities,
                &local,
                args["voice"].as_bool().unwrap_or(false),
            );
            let partial = truncated
                || info["truncated"] == true
                || info["events_lost"].as_u64().unwrap_or(0) > 0
                || info["decode_errors"].as_u64().unwrap_or(0) > 0;
            Ok(
                json!({"status":"Replayed","capture_kind":"OfflineReplay","flows":flows,"timing_context":timing_context,"truncated":partial,"trace":info,"cleanup_required":false,"voice_attribution":"NotConfirmed","profile_hit":"NotObserved"}),
            )
        }
        "voice-capture" => capture(root, args, true),
        "track" => capture(root, args, false),
        _ => anyhow::bail!("Unsupported tracking action"),
    }
}
fn validate_identities(identities: &[Identity]) -> Result<()> {
    ensure!(identities.len() <= 256, "Replay identity limit exceeded");
    for (index, identity) in identities.iter().enumerate() {
        ensure!(
            identity.identity.pid > 0
                && identity.identity.created_filetime > 0
                && identity.identity.created_filetime <= identity.observed_until
                && identity.identity.executable.is_absolute()
                && identity.name.len() <= 128
                && identity_name_matches(identity),
            "Invalid replay process identity"
        );
        ensure!(
            !identities[..index].iter().any(|other| {
                other.identity.pid == identity.identity.pid
                    && other.identity.created_filetime <= identity.observed_until
                    && identity.identity.created_filetime <= other.observed_until
            }),
            "Replay process identities overlap for a reused PID"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn etw_gap_summaries_count_real_intervals_and_do_not_invent_an_outage_cause() {
        let mut gaps = Gaps::default();
        gaps.observe(10000000);
        assert_eq!(gaps.value()["max_gap_ms"], Value::Null);
        gaps.observe(11000000);
        gaps.observe(14000000);
        gaps.observe(13000000);
        assert_eq!(gaps.value()["gap_count"], 2);
        assert_eq!(gaps.value()["max_gap_ms"], 300.0);
        assert_eq!(gaps.value()["over_100_ms"], 1);
        assert_eq!(gaps.value()["over_250_ms"], 1);
        assert_eq!(gaps.value()["out_of_order_events"], 1);
    }
    fn packet(pid: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(pid.to_le_bytes());
        b.extend(160u32.to_le_bytes());
        b.extend([203, 0, 113, 8]);
        b.extend([192, 168, 1, 2]);
        b.extend(50001u16.to_be_bytes());
        b.extend(55000u16.to_be_bytes());
        b
    }
    #[test]
    fn decode_network_payload_and_network_order_ports() {
        let e = parse_event(42, 100, &packet(123)).expect("supported UDP event");
        assert_eq!(e.pid, 123);
        assert_eq!(e.bytes, 160);
        assert_eq!(e.destination, "203.0.113.8".parse::<IpAddr>().unwrap());
        assert_eq!(e.source, "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(e.destination_port, 50001);
        assert_eq!(e.source_port, 55000);
        assert!(parse_event(42, 100, &[0; 19]).is_none());
        for id in [17, 33, 49, 65] {
            assert!(parse_event(id, 100, &packet(123)).is_none());
        }
        assert!(parse_event(999, 100, &packet(123)).is_none());
    }
    #[test]
    fn tcp_receive_keeps_both_endpoint_layouts_and_coalesced_byte_counts() {
        let owner = Identity {
            identity: ProcessIdentity {
                pid: 123,
                created_filetime: 100,
                executable: "C:/Game.exe".into(),
            },
            name: "Game".into(),
            observed_until: 200,
        };
        for (send, receive, local, peer) in [
            (10, 11, "192.168.1.2", "203.0.113.8"),
            (26, 27, "fd00::2", "2001:db8::8"),
        ] {
            let local: IpAddr = local.parse().unwrap();
            let peer: IpAddr = peer.parse().unwrap();
            let encode = |id, bytes: u32, source: IpAddr, dest: IpAddr, sport: u16, dport: u16| {
                let mut payload = 123u32.to_le_bytes().to_vec();
                payload.extend(bytes.to_le_bytes());
                for address in [dest, source] {
                    match address {
                        IpAddr::V4(ip) => payload.extend(ip.octets()),
                        IpAddr::V6(ip) => payload.extend(ip.octets()),
                    }
                }
                payload.extend(dport.to_be_bytes());
                payload.extend(sport.to_be_bytes());
                parse_event(id, 150, &payload).unwrap()
            };
            let events = [
                encode(send, 270, local, peer, 50000, 443),
                encode(receive, 90000, local, peer, 50000, 443),
                encode(receive, 1100, peer, local, 443, 50000),
                encode(receive, 999, local, local, 50000, 443),
                encode(receive, 999, peer, peer, 50000, 443),
                encode(send, 999, peer, local, 443, 50000),
            ];
            let (flows, truncated, _) = flows(
                &events,
                std::slice::from_ref(&owner),
                &BTreeSet::from([local]),
                false,
            );
            assert!(!truncated);
            assert_eq!(flows.len(), 1);
            let flow = &flows[0];
            assert_eq!(flow["address"], peer.to_string());
            assert_eq!(flow["port"], 443);
            assert_eq!(flow["in"], 2);
            assert_eq!(flow["out"], 1);
            assert_eq!(flow["bytes_in"], 91100);
            assert_eq!(flow["bytes_out"], 270);
        }
    }
    #[test]
    fn pid_reuse_and_unconfirmed_direction_cannot_be_voice_evidence() {
        let id = Identity {
            identity: ProcessIdentity {
                pid: 123,
                created_filetime: 100,
                executable: PathBuf::from("C:/Discord.exe"),
            },
            name: "Discord".into(),
            observed_until: 200,
        };
        let local = BTreeSet::from(["192.168.1.2".parse::<IpAddr>().unwrap()]);
        let event = parse_event(42, 150, &packet(123)).unwrap();
        let (out, _, _) = flows(
            std::slice::from_ref(&event),
            std::slice::from_ref(&id),
            &local,
            true,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["out"], 1);
        assert_eq!(out[0]["bytes_out"], 160);
        assert_eq!(out[0]["voice_port_configured"], true);
        assert_eq!(out[0]["voice_attribution"], "NotConfirmed");
        assert_eq!(out[0]["profile_hit"], "NotObserved");
        let mut early = event.clone();
        early.at = 99;
        assert!(
            flows(&[early], std::slice::from_ref(&id), &local, true)
                .0
                .is_empty()
        );
        let mut late = event.clone();
        late.at = 201;
        assert!(
            flows(&[late], std::slice::from_ref(&id), &local, true)
                .0
                .is_empty()
        );
        assert!(flows(&[event], &[id], &BTreeSet::new(), true).0.is_empty());
    }
    #[test]
    fn parent_guard_stops_for_exit_pid_reuse_path_change_and_deadline() {
        let parent = ProcessIdentity {
            pid: 42,
            created_filetime: 100,
            executable: "C:/fixture/zapret-rust.exe".into(),
        };
        assert_eq!(guard_finished(&parent, Some(&parent), false, false), None);
        assert_eq!(
            guard_finished(&parent, None, false, false),
            Some("ParentExitedOrChanged")
        );
        let reused = ProcessIdentity {
            created_filetime: 101,
            ..parent.clone()
        };
        assert_eq!(
            guard_finished(&parent, Some(&reused), false, false),
            Some("ParentExitedOrChanged")
        );
        let foreign = ProcessIdentity {
            executable: "C:/foreign/zapret-rust.exe".into(),
            ..parent.clone()
        };
        assert_eq!(
            guard_finished(&parent, Some(&foreign), false, false),
            Some("ParentExitedOrChanged")
        );
        assert_eq!(
            guard_finished(&parent, Some(&parent), true, false),
            Some("StopRequested")
        );
        assert_eq!(
            guard_finished(&parent, Some(&parent), false, true),
            Some("DeadlineReached")
        );
    }
    #[test]
    fn replay_rejects_ambiguous_identities_and_mislabelled_voice_ownership() {
        let identity = Identity {
            identity: ProcessIdentity {
                pid: 123,
                created_filetime: 100,
                executable: "C:/Discord.exe".into(),
            },
            name: "Discord".into(),
            observed_until: 200,
        };
        validate_identities(std::slice::from_ref(&identity)).unwrap();
        let reused = Identity {
            identity: ProcessIdentity {
                created_filetime: 201,
                ..identity.identity.clone()
            },
            observed_until: 300,
            ..identity.clone()
        };
        validate_identities(&[identity.clone(), reused]).unwrap();
        assert!(validate_identities(&[identity.clone(), identity.clone()]).is_err());
        let foreign = Identity {
            identity: ProcessIdentity {
                executable: "C:/unrelated.exe".into(),
                ..identity.identity.clone()
            },
            ..identity
        };
        assert!(validate_identities(std::slice::from_ref(&foreign)).is_err());
        let local = BTreeSet::from(["192.168.1.2".parse::<IpAddr>().unwrap()]);
        let event = parse_event(42, 150, &packet(123)).unwrap();
        assert!(flows(&[event], &[foreign], &local, true).0.is_empty());
    }
    #[test]
    fn voice_flow_limit_is_explicit_and_direction_must_match_local_endpoint() {
        let identity = Identity {
            identity: ProcessIdentity {
                pid: 123,
                created_filetime: 100,
                executable: "C:/Discord.exe".into(),
            },
            name: "Discord".into(),
            observed_until: 200,
        };
        let local = BTreeSet::from(["192.168.1.2".parse::<IpAddr>().unwrap()]);
        let event = parse_event(42, 150, &packet(123)).unwrap();
        let mut wrong = event.clone();
        std::mem::swap(&mut wrong.source, &mut wrong.destination);
        assert!(
            flows(&[wrong], std::slice::from_ref(&identity), &local, true)
                .0
                .is_empty()
        );
        let events = (1..=129)
            .map(|port| Event {
                destination_port: port,
                ..event.clone()
            })
            .collect::<Vec<_>>();
        let (rows, truncated, _) = flows(&events, &[identity], &local, true);
        assert_eq!(rows.len(), 128);
        assert!(truncated);
    }
}
