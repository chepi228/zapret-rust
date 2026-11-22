//! Bounded native network settings, with an explicit compatibility path for
//! providers that cannot expose or update the persistent policy store.
use crate::{
    ProcessIdentity, RunOptions,
    com::Apartment,
    process::{Handle, same_path},
    storage::read_shared_limited,
    wmi::{Connection, Instance},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

const PREFIX: &str = "::ffff:0:0/96";
const PREFIX_QUERY: &str = "SELECT * FROM MSFT_NetPrefixPolicy";
const TCP_QUERY: &str = "SELECT * FROM MSFT_NetTCPSetting";
static OBSERVATION_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Request {
    PrefixStatus,
    PrefixSet { enabled: bool },
    Timestamps { apply: bool },
}
impl Request {
    fn writes(self) -> bool {
        matches!(
            self,
            Self::PrefixSet { .. } | Self::Timestamps { apply: true }
        )
    }
    fn budget(self) -> Duration {
        Duration::from_secs(if matches!(self, Self::PrefixSet { .. }) {
            25
        } else {
            10
        })
    }
}

fn request(root: &Path, action: Request, safety: &Value) -> Result<Value> {
    // A native worker preserves the previous hard process deadline even when
    // local WMI connection setup or a provider stops responding.
    let executable = std::env::current_exe()?;
    let parent = crate::process_identity(std::process::id())?;
    let arguments: Vec<OsString> = vec![
        "--root".into(),
        root.as_os_str().into(),
        "platform-worker".into(),
        "network-settings-worker".into(),
        "--arguments-json".into(),
        serde_json::to_string(&json!({"request":action,"parent":parent,"safety":safety}))?.into(),
    ];
    let result = crate::run_owned(
        &executable,
        &arguments,
        &RunOptions {
            cwd: Some(root.into()),
            timeout: action.budget(),
            max_output_bytes: 65536,
            ..Default::default()
        },
    )?;
    ensure!(
        !result.timed_out && !result.output_truncated && result.exit_code == 0,
        "Windows network settings were not confirmed (exit {}, timeout {}): {}",
        result.exit_code,
        result.timed_out,
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout)
        .context("Invalid Windows network settings result")?;
    ensure!(
        value.is_object(),
        "Windows network settings result must be an object"
    );
    Ok(value)
}

pub(crate) fn prefix_status(root: &Path) -> Result<Value> {
    observe(root, Request::PrefixStatus)
}
pub(crate) fn timestamps_status(root: &Path) -> Result<Value> {
    observe(root, Request::Timestamps { apply: false })
}
pub(crate) fn set_preference(root: &Path, args: &Value, enabled: bool) -> Result<Value> {
    request(root, Request::PrefixSet { enabled }, args)
}
pub(crate) fn enable_timestamps(root: &Path, args: &Value) -> Result<Value> {
    request(root, Request::Timestamps { apply: true }, args)
}

fn observe(root: &Path, action: Request) -> Result<Value> {
    ensure!(
        !action.writes(),
        "A read-only observer cannot update network settings"
    );
    let deadline = Instant::now() + action.budget();
    let attempt = (|| {
        ensure!(
            !OBSERVATION_IN_PROGRESS.swap(true, Ordering::AcqRel),
            "A Windows network observation is still finishing"
        );
        struct Slot;
        impl Drop for Slot {
            fn drop(&mut self) {
                OBSERVATION_IN_PROGRESS.store(false, Ordering::Release);
            }
        }
        let slot = Slot;
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("network-settings-read".into())
            .spawn(move || {
                let result = (|| {
                    let _apartment = Apartment::enter("Windows network observation")?;
                    let connection = Connection::open(deadline - Duration::from_secs(2))?;
                    match action {
                        Request::PrefixStatus => read_preference(&connection),
                        Request::Timestamps { apply: false } => {
                            native_timestamps(&connection, false, &|| {
                                anyhow::bail!("A read-only observer cannot write settings")
                            })
                        }
                        _ => anyhow::bail!("Invalid network observation request"),
                    }
                })();
                drop(slot);
                let _ = send.send(result);
            })
            .context("Start Windows network observation")?;
        // A stuck COM connection may outlive this read-only caller. The slot
        // permits at most one such thread per controller, and it cannot write.
        receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("Windows network observation did not finish in time")?
    })();
    match attempt {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut value = compatibility(root, action, deadline)?;
            value["backend"] = json!("NetshCompatibility");
            value["native_error"] = json!(format!("{error:#}"));
            Ok(value)
        }
    }
}

fn parent_pid() -> Result<u32> {
    unsafe {
        let snapshot = Handle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot.0, &mut entry);
        while more != 0 {
            if entry.th32ProcessID == std::process::id() {
                return Ok(entry.th32ParentProcessID);
            }
            more = Process32NextW(snapshot.0, &mut entry);
        }
    }
    anyhow::bail!("Native network worker parent is unavailable")
}
fn validate_parent(
    root: &Path,
    parent: &ProcessIdentity,
    safety: &Value,
    writes: bool,
) -> Result<()> {
    ensure!(
        parent_pid()? == parent.pid && crate::process_identity(parent.pid)? == *parent,
        "Native network worker parent exited or changed"
    );
    ensure!(
        same_path(&parent.executable, &std::env::current_exe()?),
        "Native network worker executable differs from its parent"
    );
    if writes {
        validate_control_lease(root, parent.pid)?;
        crate::launch::allowed(root, safety)?;
    }
    Ok(())
}

fn validate_control_lease(root: &Path, parent_pid: u32) -> Result<()> {
    // Windows sharing is reciprocal: the reader must allow the parent's already
    // open write handle. The parent continues to deny other writers/deletion.
    let lease = read_shared_limited(&root.join("runtime/control.lock"), 4096)?;
    let owner = std::str::from_utf8(&lease)?
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<u32>().ok());
    ensure!(
        owner == Some(parent_pid),
        "Native network update requires the parent control lease"
    );
    Ok(())
}

#[derive(Debug, PartialEq)]
struct PrefixPolicy {
    prefix: String,
    precedence: u32,
    label: u32,
    store: u32,
}
fn prefix_policy(row: &Instance) -> Result<PrefixPolicy> {
    Ok(PrefixPolicy {
        prefix: row
            .text("Prefix")?
            .context("Missing network policy prefix")?,
        precedence: row
            .number("Precedence")?
            .context("Missing network policy precedence")?,
        label: row
            .number("Label")?
            .context("Missing network policy label")?,
        store: row
            .number("Store")?
            .context("Missing network policy store")?,
    })
}
fn preference(rows: &[PrefixPolicy]) -> Result<Value> {
    let find = |prefix: &str| -> Result<Option<u32>> {
        let mut found = rows.iter().filter(|r| r.store == 1 && r.prefix == prefix);
        let result = found.next().map(|r| r.precedence);
        ensure!(
            found.next().is_none(),
            "Ambiguous active prefix policy for {prefix}"
        );
        Ok(result)
    };
    let v4 = find(PREFIX)?;
    let v6 = find("::/0")?;
    Ok(
        json!({"known":v4.is_some()&&v6.is_some(),"enabled":v4.zip(v6).is_some_and(|(a,b)|a>b),
        "ipv4_precedence":v4,"ipv6_precedence":v6,"backend":"WindowsCim"}),
    )
}
fn read_preference(connection: &Connection) -> Result<Value> {
    preference(
        &connection
            .query(PREFIX_QUERY, 256)?
            .iter()
            .map(prefix_policy)
            .collect::<Result<Vec<_>>>()?,
    )
}
fn native_preference(
    connection: &Connection,
    enabled: bool,
    before_write: &impl Fn() -> Result<()>,
) -> Result<Value> {
    let desired = if enabled { 45 } else { 35 };
    // Do not substitute an active-only write for netsh's persistent update.
    // Some versions expose enumeration but cannot read this exact instance.
    let path = format!("MSFT_NetPrefixPolicy.Prefix=\"{PREFIX}\",Store=0");
    let persistent = connection.get(&path)?;
    let previous = prefix_policy(&persistent)?;
    ensure!(
        previous.prefix == PREFIX && previous.store == 0,
        "Persistent prefix policy is unavailable through the Windows provider"
    );
    if previous.precedence != desired || previous.label != 4 {
        before_write()?;
        persistent.set_number("Precedence", desired)?;
        persistent.set_number("Label", 4)?;
        connection.update(&persistent, &["Precedence", "Label"])?;
    }
    let rows = connection.query(PREFIX_QUERY, 256)?;
    let active = rows
        .iter()
        .find(|row| prefix_policy(row).is_ok_and(|p| p.prefix == PREFIX && p.store == 1))
        .context("Active IPv4 prefix policy is unavailable")?;
    let active_state = prefix_policy(active)?;
    if active_state.precedence != desired || active_state.label != 4 {
        before_write()?;
        active.set_number("Precedence", desired)?;
        active.set_number("Label", 4)?;
        connection.update(active, &["Precedence", "Label"])?;
    }
    let stored = prefix_policy(&connection.get(&path)?)?;
    ensure!(
        stored.precedence == desired && stored.label == 4 && stored.store == 0,
        "Persistent IPv4 preference was not confirmed"
    );
    let status = read_preference(connection)?;
    ensure!(
        status["ipv4_precedence"] == desired,
        "Active IPv4 preference was not confirmed"
    );
    ensure!(
        connection
            .query(PREFIX_QUERY, 256)?
            .iter()
            .any(|row| prefix_policy(row).is_ok_and(|p| p.store == 1
                && p.prefix == PREFIX
                && p.precedence == desired
                && p.label == 4)),
        "Active IPv4 policy label was not confirmed"
    );
    Ok(status)
}

#[derive(Debug, PartialEq)]
struct TcpSetting {
    name: String,
    timestamps: Option<u32>,
}
fn tcp_setting(row: &Instance) -> Result<TcpSetting> {
    let result = TcpSetting {
        name: row
            .text("SettingName")?
            .context("Missing TCP template name")?,
        timestamps: row.number("Timestamps")?,
    };
    ensure!(
        matches!(result.timestamps, Some(0..=2))
            || result.name == "Automatic" && result.timestamps.is_none(),
        "Unknown TCP timestamp setting for {}",
        result.name
    );
    Ok(result)
}
fn timestamps_enabled(settings: &[TcpSetting]) -> bool {
    let concrete = settings
        .iter()
        .filter(|r| r.name != "Automatic")
        .collect::<Vec<_>>();
    !concrete.is_empty() && concrete.iter().all(|r| r.timestamps == Some(1))
}
fn native_timestamps(
    connection: &Connection,
    apply: bool,
    before_write: &impl Fn() -> Result<()>,
) -> Result<Value> {
    let rows = connection.query(TCP_QUERY, 64)?;
    let settings = rows.iter().map(tcp_setting).collect::<Result<Vec<_>>>()?;
    ensure!(
        settings.iter().any(|r| r.name == "Internet"),
        "Internet TCP template is unavailable"
    );
    let before = timestamps_enabled(&settings);
    if !apply || before {
        return Ok(json!({"enabled":before,"changed":false,"backend":"WindowsCim"}));
    }
    if apply {
        for (row, setting) in rows.iter().zip(&settings) {
            if setting.name == "Automatic" || setting.timestamps == Some(1) {
                continue;
            }
            before_write()?;
            row.set_number("Timestamps", 1)?;
            connection.update(row, &["Timestamps"])?;
            let observed = connection
                .query(TCP_QUERY, 64)?
                .iter()
                .map(tcp_setting)
                .collect::<Result<Vec<_>>>()?;
            if timestamps_enabled(&observed) {
                return Ok(json!({"enabled":true,"changed":true,"backend":"WindowsCim"}));
            }
        }
    }
    let current = connection
        .query(TCP_QUERY, 64)?
        .iter()
        .map(tcp_setting)
        .collect::<Result<Vec<_>>>()?;
    let enabled = timestamps_enabled(&current);
    ensure!(
        !apply || enabled,
        "Enabled TCP timestamps were not confirmed by the provider"
    );
    Ok(json!({"enabled":enabled,"changed":apply&&!before,"backend":"WindowsCim"}))
}

fn compatibility(root: &Path, action: Request, deadline: Instant) -> Result<Value> {
    let run = |arguments: Vec<String>| -> Result<Value> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        ensure!(
            remaining > 0,
            "Network settings compatibility deadline reached"
        );
        let output = crate::system::native("netsh.exe", &arguments, root, remaining)?;
        ensure!(
            output["exit_code"] == 0
                && output["timed_out"] == false
                && output["output_truncated"] == false,
            "Windows network compatibility command failed: {output}"
        );
        Ok(output)
    };
    match action {
        Request::PrefixSet { enabled } => {
            run(vec![
                "interface".into(),
                "ipv6".into(),
                "set".into(),
                "prefixpolicy".into(),
                format!("prefix={PREFIX}"),
                format!("precedence={}", if enabled { 45 } else { 35 }),
                "label=4".into(),
                "store=persistent".into(),
            ])?;
            let value = compatibility(root, Request::PrefixStatus, deadline)?;
            ensure!(
                value["ipv4_precedence"] == if enabled { 45 } else { 35 },
                "IPv4 prefix policy update was not observed"
            );
            Ok(value)
        }
        Request::PrefixStatus => {
            let output = run(vec![
                "interface".into(),
                "ipv6".into(),
                "show".into(),
                "prefixpolicies".into(),
            ])?;
            let rows = output["stdout"]
                .as_str()
                .unwrap_or("")
                .lines()
                .filter_map(|line| {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    if fields.len() != 3 {
                        return None;
                    }
                    Some(PrefixPolicy {
                        prefix: fields[2].into(),
                        precedence: fields[0].parse().ok()?,
                        label: fields[1].parse().ok()?,
                        store: 1,
                    })
                })
                .collect::<Vec<_>>();
            preference(&rows)
        }
        Request::Timestamps { apply: true } => {
            run(vec![
                "interface".into(),
                "tcp".into(),
                "set".into(),
                "global".into(),
                "timestamps=enabled".into(),
            ])?;
            // A successful finite netsh command is the legacy confirmation
            // contract when the WMI provider itself is unavailable.
            Ok(json!({"enabled":true,"changed":null,"verification":"CommandCompleted"}))
        }
        Request::Timestamps { apply: false } => {
            anyhow::bail!("TCP timestamp observation requires the Windows provider")
        }
    }
}

pub(crate) fn worker(root: &Path, args: &Value) -> Result<Value> {
    let action: Request = serde_json::from_value(args["request"].clone())?;
    let parent: ProcessIdentity = serde_json::from_value(args["parent"].clone())?;
    validate_parent(root, &parent, &args["safety"], action.writes())?;
    let start = Instant::now();
    let _apartment = Apartment::enter("Windows network settings")?;
    let before_write = || {
        ensure!(
            start.elapsed() < action.budget(),
            "Windows network settings deadline reached"
        );
        validate_parent(root, &parent, &args["safety"], true)
    };
    let attempt = (|| {
        let connection = Connection::open(start + Duration::from_secs(8))?;
        match action {
            Request::PrefixStatus => read_preference(&connection),
            Request::PrefixSet { enabled } => {
                native_preference(&connection, enabled, &before_write)
            }
            Request::Timestamps { apply } => native_timestamps(&connection, apply, &before_write),
        }
    })();
    match attempt {
        Ok(value) => Ok(value),
        Err(error) => {
            if action.writes() {
                before_write()?;
            }
            let mut value = compatibility(root, action, start + action.budget())?;
            value["backend"] = json!("NetshCompatibility");
            value["native_error"] = json!(format!("{error:#}"));
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_worker_reads_parent_lease_while_writes_and_deletion_stay_blocked() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("пакет & пробел");
        std::fs::create_dir(&root).unwrap();
        let guard = crate::ControlGuard::acquire(&root, "network fixture").unwrap();
        let parent = crate::process_identity(std::process::id()).unwrap();
        let arguments: Vec<OsString> = [
            "--exact",
            "network_settings::tests::control_lease_child",
            "--ignored",
            "--nocapture",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let mut options = RunOptions {
            timeout: Duration::from_secs(8),
            ..Default::default()
        };
        options
            .env
            .insert("ZAPRET_NETWORK_LEASE_ROOT".into(), root.as_os_str().into());
        options.env.insert(
            "ZAPRET_NETWORK_LEASE_PARENT".into(),
            serde_json::to_string(&parent).unwrap().into(),
        );
        let result =
            crate::run_owned(&std::env::current_exe().unwrap(), &arguments, &options).unwrap();
        assert!(!result.timed_out && !result.output_truncated);
        assert_eq!(
            result.exit_code,
            0,
            "stdout: {}; stderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("parent_lease_validated"));

        let path = root.join("runtime/control.lock");
        let writer = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap_err();
        assert_eq!(writer.raw_os_error(), Some(32));
        assert_eq!(
            std::fs::remove_file(&path).unwrap_err().raw_os_error(),
            Some(32)
        );
        drop(guard);
        let next = crate::ControlGuard::acquire(&root, "next operation").unwrap();
        drop(next);
    }

    #[test]
    #[ignore = "child process fixture invoked by the parent lease regression test"]
    fn control_lease_child() {
        let root = std::path::PathBuf::from(
            std::env::var_os("ZAPRET_NETWORK_LEASE_ROOT").expect("explicit lease fixture root"),
        );
        let parent: ProcessIdentity = serde_json::from_str(
            &std::env::var("ZAPRET_NETWORK_LEASE_PARENT").expect("explicit lease fixture parent"),
        )
        .unwrap();
        validate_parent(&root, &parent, &json!({}), false).unwrap();
        validate_control_lease(&root, parent.pid).unwrap();
        assert!(validate_control_lease(&root, std::process::id()).is_err());
        println!("parent_lease_validated");
    }

    #[test]
    fn control_lease_rejects_missing_malformed_foreign_and_oversized_owners() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let pid = std::process::id();
        assert!(validate_control_lease(root, pid).is_err());
        std::fs::create_dir(root.join("runtime")).unwrap();
        let path = root.join("runtime/control.lock");
        for bytes in [
            Vec::new(),
            b"not-a-pid 123 fixture".to_vec(),
            b"0 123 fixture".to_vec(),
            vec![0xff],
            format!("{pid} 123 {}", "x".repeat(4096)).into_bytes(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(validate_control_lease(root, pid).is_err());
        }
    }

    #[test]
    fn read_only_observation_rejects_writes_before_entering_the_compatibility_path() {
        let root = tempfile::tempdir().unwrap();
        let error = observe(root.path(), Request::PrefixSet { enabled: true }).unwrap_err();
        assert!(error.to_string().contains("read-only"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
    #[test]
    fn preference_never_invents_missing_defaults_or_uses_the_persistent_store_as_active() {
        let policy = |prefix: &str, precedence, store| PrefixPolicy {
            prefix: prefix.into(),
            precedence,
            store,
            label: 4,
        };
        let missing = preference(&[policy(PREFIX, 45, 1)]).unwrap();
        assert_eq!(missing["known"], false);
        assert!(missing["ipv6_precedence"].is_null());
        let active = preference(&[
            policy(PREFIX, 45, 0),
            policy(PREFIX, 35, 1),
            policy("::/0", 40, 1),
        ])
        .unwrap();
        assert_eq!(active["known"], true);
        assert_eq!(active["enabled"], false);
        assert!(preference(&[policy(PREFIX, 45, 1), policy(PREFIX, 35, 1)]).is_err());
    }
    #[test]
    fn enabled_timestamps_require_every_concrete_template() {
        let setting = |name: &str, timestamps| TcpSetting {
            name: name.into(),
            timestamps,
        };
        assert!(!timestamps_enabled(&[]));
        assert!(!timestamps_enabled(&[setting("Automatic", None)]));
        assert!(timestamps_enabled(&[
            setting("Automatic", None),
            setting("Internet", Some(1))
        ]));
        assert!(!timestamps_enabled(&[
            setting("Internet", Some(1)),
            setting("InternetCustom", Some(2))
        ]));
    }
    #[test]
    fn native_worker_rejects_requests_without_the_real_parent_before_any_wmi_access() {
        let root = tempfile::tempdir().unwrap();
        let args = json!({"request":{"operation":"PrefixStatus"},"parent":crate::process_identity(std::process::id()).unwrap()});
        assert!(
            worker(root.path(), &args)
                .unwrap_err()
                .to_string()
                .contains("parent")
        );
        assert!(!root.path().join("runtime").exists());
    }
}
