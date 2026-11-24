use crate::storage::{atomic_write, no_reparse, read_limited};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::ErrorKind,
    net::{Ipv4Addr, TcpListener},
    path::Path,
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
pub(crate) const TG_TAG: &str = telegram_core::CORE_VERSION;
pub(crate) const TG_EXE: &str = "bin/zapret-rust.exe";
const LEGACY_TAG: &str = "v1.11.4";
const LEGACY_EXE: &str = "bin/tgws/TgWsProxy_windows.exe";
const JOB_PREFIX: &str = r"Local\zapret-rust-tgws-";
const LEGACY_JOB_PREFIX: &str = r"Local\zapret-tgws-";
pub(crate) fn read_config(root: &Path, create: bool, args: &Value) -> Result<Value> {
    let config = resolve_config(root, create, args)?;
    if create {
        atomic_write(
            &root.join("runtime/telegram.txt"),
            format!(
                "port={}\r\nsecret={}\r\n",
                config["port"],
                config["secret"].as_str().unwrap_or("")
            )
            .as_bytes(),
        )?;
    }
    Ok(config)
}
fn resolve_config(root: &Path, create: bool, args: &Value) -> Result<Value> {
    let path = root.join("runtime/telegram.txt");
    let mut port = 1443u64;
    let mut secret = String::new();
    if path.exists() {
        let bytes = read_config_file(&path, 8192)?;
        for line in std::str::from_utf8(&bytes)?.lines() {
            if let Some(v) = line.strip_prefix("port=") {
                port = v.parse()?;
            } else if let Some(v) = line.strip_prefix("secret=") {
                secret = v.into();
            }
        }
    }
    if secret.is_empty() {
        for p in [
            root.join("runtime/tgws/TgWsProxy/config.json"),
            root.join("runtime/tg-ws-proxy/TgWsProxy_data/config.json"),
            std::env::var_os("APPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_default()
                .join("TgWsProxy/config.json"),
        ] {
            if p.is_absolute() && p.exists() {
                if let Ok(bytes) = read_limited(&p, 65536) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(s) = v["secret"].as_str() {
                            if valid_secret(s) {
                                secret = s.to_lowercase();
                                port = v["port"].as_u64().unwrap_or(1443);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(p) = args.get("port").filter(|v| !v.is_null()) {
        port = p.as_u64().context("Telegram port must be an integer")?;
    }
    if let Some(s) = args.get("secret").filter(|v| !v.is_null()) {
        secret = s
            .as_str()
            .context("Telegram secret must be a string")?
            .to_lowercase();
    }
    ensure!(
        (1..=65535).contains(&port),
        "Telegram port must be 1..65535"
    );
    if secret.is_empty() && create {
        let mut bytes = [0u8; 16];
        ensure!(
            unsafe {
                BCryptGenRandom(
                    null_mut(),
                    bytes.as_mut_ptr(),
                    16,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            } >= 0,
            "Secure Telegram secret generation failed"
        );
        secret = bytes.iter().map(|b| format!("{b:02x}")).collect();
    }
    if !secret.is_empty() {
        ensure!(
            valid_secret(&secret),
            "Telegram secret must be 32 hexadecimal characters"
        );
    }
    Ok(
        json!({"port":port,"secret":secret,"link":if secret.is_empty(){String::new()}else{format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret}")}}),
    )
}
fn read_config_file(path: &Path, budget: u64) -> Result<Vec<u8>> {
    let started = Instant::now();
    loop {
        match read_limited(path, budget) {
            Err(error)
                if started.elapsed() < Duration::from_millis(250)
                    && error.chain().any(|cause| {
                        cause
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|error| matches!(error.raw_os_error(), Some(32 | 33)))
                    }) =>
            {
                // Keep the snapshot reader's original sharing restrictions;
                // an atomic publisher briefly holds DELETE access to the name.
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}
fn valid_secret(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn open_link(args: &Value) -> Result<Value> {
    open_link_with(args, |link| {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::UI::{Shell::*, WindowsAndMessaging::SW_SHOWNORMAL};

        let verb = crate::process::wide("open")?;
        let uri = crate::process::wide(link)?;
        let mut request: SHELLEXECUTEINFOW = unsafe { zeroed() };
        request.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        request.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        request.lpVerb = verb.as_ptr();
        request.lpFile = uri.as_ptr();
        request.nShow = SW_SHOWNORMAL;
        // The shell dispatches the URI directly; neither cmd.exe nor a console
        // worker is involved, and the Telegram client may outlive this menu.
        ensure!(
            unsafe { ShellExecuteExW(&mut request) } != 0,
            "Не удалось открыть Telegram: Windows {}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        );
        Ok(())
    })
}

fn open_link_with(args: &Value, open: impl FnOnce(&str) -> Result<()>) -> Result<Value> {
    let link = args["link"]
        .as_str()
        .context("Missing Telegram proxy link")?;
    let (port, secret) = link
        .strip_prefix("tg://proxy?server=127.0.0.1&port=")
        .and_then(|query| query.split_once("&secret=dd"))
        .context("Only this computer's Telegram proxy link may be opened")?;
    ensure!(
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0)
            && valid_secret(secret),
        "Invalid local Telegram proxy link"
    );
    open(link)?;
    Ok(json!({"opened":true}))
}
pub(crate) fn configure(root: &Path, args: &Value) -> Result<Value> {
    // Validate edits before taking a control lease or changing any package file.
    read_config(root, false, args)?;
    let _guard = crate::ControlGuard::acquire(root, "telegram-config")?;
    crate::launch::allowed(root, args)?;
    let _initializing = PackageMutex::acquire(root, "initializing", 5000)?;
    read_marker(root)?;
    let spec = prepare_config(root, args)?;
    let mut state = inspect(root, true)?;
    for key in ["config", "app_data", "executable", "tag"] {
        state[key] = spec[key].clone();
    }
    state["saved"] = json!(true);
    Ok(state)
}
fn prepare_config(root: &Path, args: &Value) -> Result<Value> {
    let user = read_config(root, false, args)?;
    let path = root.join("runtime/tgws/TgWsProxy/config.json");
    no_reparse(&path)?;
    let mut config = json!({"port":1443,"host":"127.0.0.1","secret":"","dc_ip":["2:149.154.167.220","4:149.154.167.220"],"verbose":false,"check_updates":false,"autostart":false,"log_max_mb":2,"buf_kb":256,"pool_size":4,"cfproxy":true,"h2":true,"no_secure":false,"force_test_dc":false,"language":"ru"});
    if path.exists() {
        let old: Value = serde_json::from_slice(&read_limited(&path, 65536)?)?;
        for (k, v) in old
            .as_object()
            .context("TG WS Proxy config must be a JSON object")?
        {
            config[k] = v.clone();
        }
    }
    if config.get("media_pool_size").is_none() && config["pool_size"] == 4 {
        config["media_pool_size"] = json!(8);
    }
    // A malformed existing JSON file must not commit half of a new configuration.
    let user = if user["secret"].as_str().is_none_or(str::is_empty) {
        resolve_config(root, true, args)?
    } else {
        user
    };
    config["port"] = user["port"].clone();
    config["secret"] = user["secret"].clone();
    config["host"] = json!("127.0.0.1");
    config["autostart"] = json!(false);
    config["check_updates"] = json!(false);
    telegram_core::Config::from_value(&config)?;
    atomic_write(&path, &serde_json::to_vec_pretty(&config)?)?;
    atomic_write(
        &root.join("runtime/telegram.txt"),
        format!(
            "port={}\r\nsecret={}\r\n",
            user["port"],
            user["secret"].as_str().unwrap()
        )
        .as_bytes(),
    )?;
    Ok(
        json!({"port":user["port"],"secret":user["secret"],"link":user["link"],"config_hash":config_hash(&config)?,"secret_hash":secret_hash(&user),"config":path,"app_data":root.join("runtime/tgws"),"executable":root.join(TG_EXE),"tag":TG_TAG}),
    )
}

fn start_port(requested: u16, already_owned: bool, automatic: bool) -> Result<u16> {
    if already_owned {
        return Ok(requested);
    }
    let bind = |port| TcpListener::bind((Ipv4Addr::LOCALHOST, port));
    match bind(requested) {
        Ok(_) => Ok(requested),
        Err(error)
            if automatic && matches!(error.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied) =>
        {
            let listener = bind(requested.saturating_add(1))
                .or_else(|_| bind(0))
                .context("Не удалось подобрать свободный порт для моста Telegram")?;
            Ok(listener.local_addr()?.port())
        }
        Err(error) => Err(error).with_context(|| {
            format!("Мост Telegram не может занять порт {requested}. Выберите свободный порт в настройках моста")
        }),
    }
}

fn prepare_start_config(root: &Path, args: &Value, marker: Option<&Marker>) -> Result<Value> {
    let user = read_config(root, false, args)?;
    let port = user["port"].as_u64().context("Missing Telegram port")? as u16;
    let owned = marker.filter(|marker| marker.port == port);
    let already_owned = owned.map(listener_owned).transpose()?.unwrap_or(false);
    let automatic = args["port"].is_null()
        && !root.join("runtime/telegram.txt").try_exists()?
        && !root
            .join("runtime/tgws/TgWsProxy/config.json")
            .try_exists()?;
    let mut options = args.as_object().cloned().unwrap_or_default();
    options.insert(
        "port".into(),
        json!(start_port(port, already_owned, automatic)?),
    );
    prepare_config(root, &Value::Object(options))
}

fn config_hash(config: &Value) -> Result<String> {
    ensure!(
        config.is_object(),
        "TG WS Proxy config must be a JSON object"
    );
    Ok(crate::storage::hash(&serde_json::to_vec(config)?))
}
pub(crate) fn run_core(path: &Path, expected_hash: &str) -> Result<()> {
    let config = load_core_config(path, expected_hash)?;
    telegram_core::run(config)
}
fn load_core_config(path: &Path, expected_hash: &str) -> Result<telegram_core::Config> {
    let value: Value = serde_json::from_slice(&read_limited(path, 65536)?)?;
    ensure!(
        expected_hash.len() == 64
            && expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            && config_hash(&value)?.eq_ignore_ascii_case(expected_hash),
        "Telegram config changed before core initialization"
    );
    telegram_core::Config::from_value(&value)
}
fn secret_hash(config: &Value) -> String {
    crate::storage::hash(config["secret"].as_str().unwrap_or("").as_bytes())
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: u32,
    wrapper: crate::ProcessIdentity,
    engine: crate::ProcessIdentity,
    job_name: String,
    tag: String,
    port: u16,
    // Older native markers have no configuration proof and require one safe restart.
    #[serde(default)]
    config_hash: Option<String>,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(skip)]
    relocated_wrapper: bool,
}

struct PackageMutex(crate::process::Handle);
impl PackageMutex {
    fn open(root: &Path, scope: &str) -> Result<crate::process::Handle> {
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let suffix = &crate::storage::hash(root.to_string_lossy().to_lowercase().as_bytes())[..24];
        // Preserve the name used by the first native supervisor implementation.
        let name = if scope == "supervisor" {
            format!(r"Local\zapret-native-telegram-{suffix}")
        } else {
            format!(r"Local\zapret-native-telegram-{scope}-{suffix}")
        };
        let name = crate::process::wide(name)?;
        crate::process::Handle::new(unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) })
    }
    fn acquire(root: &Path, scope: &str, timeout_ms: u32) -> Result<Self> {
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        let handle = Self::open(root, scope)?;
        let state = unsafe { WaitForSingleObject(handle.0, timeout_ms) };
        ensure!(
            state == WAIT_OBJECT_0 || state == WAIT_ABANDONED,
            "Telegram {scope} operation is already active or unavailable"
        );
        Ok(Self(handle))
    }
    fn held(root: &Path, scope: &str) -> Result<bool> {
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        let handle = Self::open(root, scope)?;
        match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                drop(Self(handle));
                Ok(false)
            }
            _ => anyhow::bail!("Telegram activation permit query failed"),
        }
    }
}
impl Drop for PackageMutex {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::System::Threading::ReleaseMutex(self.0.0) };
    }
}

fn marker(root: &Path) -> std::path::PathBuf {
    root.join("runtime/tgws-native.json")
}
fn same_identity(actual: &crate::ProcessIdentity, expected: &crate::ProcessIdentity) -> bool {
    actual.pid == expected.pid
        && actual.created_filetime == expected.created_filetime
        && crate::process::same_path(&actual.executable, &expected.executable)
}
fn controller_identity_matches(
    root: &Path,
    actual: &crate::ProcessIdentity,
    expected: &crate::ProcessIdentity,
) -> bool {
    if actual.pid != expected.pid || actual.created_filetime != expected.created_filetime {
        return false;
    }
    if crate::process::same_path(&actual.executable, &expected.executable) {
        return true;
    }
    if !["bin/zapret-rust.exe", "bin/zapret.exe"]
        .iter()
        .any(|path| crate::process::same_path(&expected.executable, &root.join(path)))
    {
        return false;
    }
    let Some(name) = actual.executable.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    // File.Replace renames a mapped controller without changing its process
    // lifetime. Accept only our installer's private backup names, then still
    // verify the exact supervisor command and owned engine job in read_marker.
    let current_backup = actual.executable.parent().is_some_and(|parent| {
        crate::process::same_path(parent, &root.join("dist/native/previous-controllers"))
    }) && name
        .strip_prefix("zapret-rust.exe.")
        .or_else(|| name.strip_prefix("zapret.exe."))
        .and_then(|tail| tail.strip_suffix(".old"))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    let legacy_backup = actual
        .executable
        .parent()
        .is_some_and(|parent| crate::process::same_path(parent, &root.join("bin")))
        && name.ends_with(".tmp.old")
        && zapret_core::is_native_build_artifact(&format!("bin/{name}"));
    let journal_backup = actual.executable.parent().is_some_and(|dir| {
        let lower_hex = |id: &str, len: usize| {
            id.len() == len
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        dir.parent()
            .is_some_and(|parent| crate::process::same_path(parent, &root.join("runtime/update")))
            && dir
                .file_name()
                .and_then(|id| id.to_str())
                .is_some_and(|id| lower_hex(id, 32))
            && name
                .strip_prefix("running-zapret-rust-")
                .and_then(|part| part.strip_suffix(".exe"))
                .is_some_and(|id| lower_hex(id, 24))
    });
    current_backup || legacy_backup || journal_backup
}
fn live_identity(expected: &crate::ProcessIdentity) -> Result<Option<crate::ProcessIdentity>> {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            expected.pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(None);
        }
        return Err(error).context("Telegram process identity is unknown");
    }
    let handle = crate::process::Handle(raw);
    if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_OBJECT_0 {
        return Ok(None);
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match crate::process::identity_handle(handle.0, expected.pid) {
            Ok(actual) => return Ok(Some(actual)),
            Err(error) => {
                // Image teardown can deny QueryFullProcessImageName shortly
                // before the exact process handle becomes signaled. Observe
                // that handle briefly; never infer exit from access denied.
                if unsafe { WaitForSingleObject(handle.0, 25) } == WAIT_OBJECT_0 {
                    return Ok(None);
                }
                if Instant::now() >= deadline {
                    return Err(error).context("Telegram process identity is unknown");
                }
            }
        }
    }
}
fn identity_live(expected: &crate::ProcessIdentity) -> Result<bool> {
    Ok(live_identity(expected)?.is_some_and(|actual| same_identity(&actual, expected)))
}
fn read_marker(root: &Path) -> Result<Option<Marker>> {
    let p = marker(root);
    if !p.exists() {
        return Ok(None);
    }
    let mut m: Marker = serde_json::from_slice(&read_limited(&p, 16384)?)?;
    ensure!(
        m.schema == 1
            && [TG_TAG, LEGACY_TAG].contains(&m.tag.as_str())
            && m.port != 0
            && m.wrapper.pid != 0
            && m.wrapper.created_filetime != 0
            && m.engine.pid != 0
            && m.engine.created_filetime != 0
            && [JOB_PREFIX, LEGACY_JOB_PREFIX]
                .iter()
                .filter_map(|prefix| m.job_name.strip_prefix(prefix))
                .any(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()))
            && [&m.config_hash, &m.secret_hash].into_iter().all(|hash| {
                hash.as_ref().is_none_or(|hash| {
                    hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit())
                })
            }),
        "Invalid Telegram ownership marker"
    );
    let Some(actual) = live_identity(&m.wrapper)? else {
        return Ok(None);
    };
    if actual.pid != m.wrapper.pid || actual.created_filetime != m.wrapper.created_filetime {
        return Ok(None);
    }
    let expected = crate::tasks::executable(root, &json!({}))?;
    ensure!(
        (crate::process::same_path(&m.wrapper.executable, &expected)
            || crate::process::same_path(&m.wrapper.executable, &root.join("bin/zapret.exe")))
            && crate::process::same_path(
                &m.engine.executable,
                &root.join(if m.tag == TG_TAG { TG_EXE } else { LEGACY_EXE })
            ),
        "Telegram marker executable mismatch"
    );
    ensure!(
        controller_identity_matches(root, &actual, &m.wrapper),
        "Telegram supervisor executable changed outside an owned controller update"
    );
    m.relocated_wrapper = !same_identity(&actual, &m.wrapper);
    m.wrapper = actual;
    let command = crate::process::process_arguments(&m.wrapper)?;
    ensure!(
        command.len() == 5
            && command[1] == "--root"
            && crate::process::same_path(Path::new(&command[2]), root)
            && command[3] == "telegram"
            && command[4] == "supervise",
        "Telegram wrapper command mismatch"
    );
    if m.tag == TG_TAG {
        if let Some(actual) = live_identity(&m.engine)?.filter(|actual| {
            actual.pid == m.engine.pid && actual.created_filetime == m.engine.created_filetime
        }) {
            ensure!(
                controller_identity_matches(root, &actual, &m.engine),
                "Telegram core executable changed outside an owned controller update"
            );
            m.engine = actual;
            let arguments = crate::process::process_arguments(&m.engine)?;
            ensure!(
                core_command_matches(root, &arguments, m.config_hash.as_deref()),
                "Telegram core command mismatch"
            );
        }
    }
    Ok(Some(m))
}
fn core_arguments(root: &Path, config_hash: &str) -> Vec<std::ffi::OsString> {
    vec![
        "telegram-core".into(),
        "--config".into(),
        root.join("runtime/tgws/TgWsProxy/config.json")
            .into_os_string(),
        "--config-sha256".into(),
        config_hash.into(),
    ]
}
fn core_command_matches(root: &Path, arguments: &[String], config_hash: Option<&str>) -> bool {
    arguments.len() == 6
        && arguments[1] == "telegram-core"
        && arguments[2] == "--config"
        && crate::process::same_path(
            Path::new(&arguments[3]),
            &root.join("runtime/tgws/TgWsProxy/config.json"),
        )
        && arguments[4] == "--config-sha256"
        && config_hash == Some(arguments[5].as_str())
}
fn listener_owned(marker: &Marker) -> Result<bool> {
    use windows_sys::Win32::System::{JobObjects::*, Threading::*};
    let name = crate::process::wide(&marker.job_name)?;
    let raw = unsafe { OpenJobObjectW(0x0004, 0, name.as_ptr()) };
    if raw.is_null() {
        return job_missing();
    }
    let job = crate::process::Handle(raw);
    if !identity_live(&marker.engine)? {
        return Ok(false);
    }
    for row in crate::system::tcp_table()? {
        if row["state"] != 2
            || row["local_address"] != "127.0.0.1"
            || row["local_port"] != marker.port
        {
            continue;
        }
        let pid = row["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .context("Invalid Telegram listener PID")?;
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            continue;
        }
        let process = crate::process::Handle(raw);
        let Ok(identity) = crate::process::identity_handle(process.0, pid) else {
            continue;
        };
        // Legacy PyInstaller had a loader child; the native core must itself
        // own the listener, with the exact recorded process lifetime.
        if (marker.tag == TG_TAG && !same_identity(&identity, &marker.engine))
            || !crate::process::same_path(&identity.executable, &marker.engine.executable)
            || identity.created_filetime < marker.engine.created_filetime
        {
            continue;
        }
        let mut owned = 0;
        ensure!(
            unsafe { IsProcessInJob(process.0, job.0, &mut owned) } != 0,
            "Telegram listener job query failed: {}",
            std::io::Error::last_os_error()
        );
        if owned != 0 && identity_live(&marker.wrapper)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn job_missing() -> Result<bool> {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32) {
        Ok(false)
    } else {
        Err(error.into())
    }
}
fn job_active(record: &Marker) -> Result<bool> {
    use windows_sys::Win32::System::JobObjects::*;
    let name = crate::process::wide(&record.job_name)?;
    let raw = unsafe { OpenJobObjectW(0x0004, 0, name.as_ptr()) };
    if raw.is_null() {
        return job_missing();
    }
    // Do not keep this observer handle open while waiting for kill-on-close.
    let handle = crate::process::Handle(raw);
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            QueryInformationJobObject(
                handle.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } != 0,
        "Telegram job accounting query failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(accounting.ActiveProcesses != 0)
}
fn matches_config(record: &Marker, config: &Value, hash: Option<&str>) -> bool {
    record.tag == TG_TAG
        && !record.relocated_wrapper
        && config["port"].as_u64() == Some(u64::from(record.port))
        && record
            .config_hash
            .as_deref()
            .zip(hash)
            .is_some_and(|(a, b)| a == b)
        && record.secret_hash.as_deref() == Some(secret_hash(config).as_str())
}
fn describe(
    config: &Value,
    hash: Option<&str>,
    current: Option<&Marker>,
    running: bool,
    enabled: &str,
    error: Option<String>,
) -> Value {
    let requires_restart = current.is_some_and(|m| !matches_config(m, config, hash));
    let active = current.filter(|_| running);
    let active_link = active
        .filter(|m| m.secret_hash.as_deref() == Some(secret_hash(config).as_str()))
        .map(|m| {
            format!(
                "tg://proxy?server=127.0.0.1&port={}&secret=dd{}",
                m.port,
                config["secret"].as_str().unwrap_or("")
            )
        })
        .unwrap_or_default();
    json!({
        "running":running,"current":current.is_some(),"component_tag":TG_TAG,"backend":"rust",
        "wrapper":current.map(|m|&m.wrapper),"process":current.map(|m|&m.engine),
        "port":active.map(|m|json!(m.port)).unwrap_or_else(||config["port"].clone()),
        "link":if active.is_some(){json!(active_link)}else{config["link"].clone()},
        "active_port":active.map(|m|m.port),"active_link":active_link,
        "configured_port":config["port"],"configured_link":config["link"],
        "requires_restart":requires_restart,"enabled":enabled,"ownership_error":error
    })
}
pub(crate) fn status(root: &Path) -> Result<Value> {
    inspect(root, false)
}
fn inspect(root: &Path, strict: bool) -> Result<Value> {
    let config = read_config(root, false, &json!({}))?;
    let path = root.join("runtime/tgws/TgWsProxy/config.json");
    let hash = if path.exists() {
        Some(config_hash(&serde_json::from_slice(&read_config_file(
            &path, 65536,
        )?)?)?)
    } else {
        None
    };
    let (m, mut error) = match read_marker(root) {
        Ok(m) => (m, None),
        Err(e) if strict => return Err(e),
        Err(e) => (None, Some(e.to_string())),
    };
    let running = match m.as_ref().map(listener_owned).transpose() {
        Ok(running) => running.unwrap_or(false),
        Err(e) if strict => return Err(e),
        Err(e) => {
            error = Some(e.to_string());
            false
        }
    };
    no_reparse(&root.join("runtime/settings.ini"))?;
    let settings = zapret_core::read_settings(root)?;
    Ok(describe(
        &config,
        hash.as_deref(),
        m.as_ref(),
        running,
        settings.get("telegram"),
        error,
    ))
}
pub(crate) fn run(root: &Path) -> Result<Value> {
    let _mutex = PackageMutex::acquire(root, "supervisor", 0)?;
    let initializing = PackageMutex::acquire(root, "initializing", 5000)?;
    no_reparse(&root.join("runtime/settings.ini"))?;
    let settings = zapret_core::read_settings(root)?;
    if !activation_allowed(
        settings.get("telegram"),
        PackageMutex::held(root, "starting")?,
    ) {
        return Ok(json!({"running":false,"enabled":"off","disabled":true}));
    }
    let exe = zapret_core::verify_telegram(root)?;
    no_reparse(&exe)?;
    let spec = prepare_config(root, &json!({}))?;
    let mut pins = crate::storage::Pins::new();
    pins.directory(exe.parent().unwrap())?;
    let bytes = pins.file(&exe)?;
    let wrapper = crate::process_identity(std::process::id())?;
    let controller_hash = crate::storage::file_hash(&wrapper.executable)?;
    ensure!(
        crate::storage::hash(&bytes).eq_ignore_ascii_case(&controller_hash),
        "Native Telegram controller changed before launch"
    );
    // Pin configuration across process creation; the child verifies this hash
    // after reading. Later edits may be saved while the active core keeps its
    // own configuration and requires a deliberate restart.
    let config_path = root.join("runtime/tgws/TgWsProxy/config.json");
    let config_bytes = pins.file(&config_path)?;
    ensure!(
        config_hash(&serde_json::from_slice(&config_bytes)?)? == spec["config_hash"],
        "Telegram config changed before launch"
    );
    let options = crate::RunOptions {
        cwd: Some(root.into()),
        timeout: Duration::from_secs(24 * 3600),
        ..Default::default()
    };
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
        "Random job identity generation failed"
    );
    let job = format!(
        "{JOB_PREFIX}{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let child = crate::OwnedChild::spawn_redirect(
        &exe,
        &core_arguments(root, spec["config_hash"].as_str().unwrap()),
        &options,
        Some(&job),
        Some(&root.join("runtime/tgws-supervisor.log")),
    )?;
    drop(pins);
    let record = Marker {
        schema: 1,
        wrapper,
        engine: child.identity().clone(),
        job_name: job,
        tag: TG_TAG.into(),
        port: spec["port"].as_u64().unwrap() as u16,
        config_hash: spec["config_hash"].as_str().map(String::from),
        secret_hash: spec["secret_hash"].as_str().map(String::from),
        relocated_wrapper: false,
    };
    atomic_write(&marker(root), &serde_json::to_vec(&record)?)?;
    drop(initializing);
    let output = child.supervise()?;
    let _initializing = PackageMutex::acquire(root, "initializing", 5000)?;
    remove_marker_if(root, &record)?;
    Ok(json!({"exit_code":output.exit_code,"running":false}))
}
fn activation_allowed(preference: &str, explicit_start: bool) -> bool {
    !preference.eq_ignore_ascii_case("off") || explicit_start
}

#[derive(Clone, Copy)]
struct TaskState {
    exists: bool,
    legacy: bool,
}
fn owned_task(state: &Value) -> Result<TaskState> {
    ensure!(
        state["exists"] == false || (state["exists"] == true && state["owned"] == true),
        "Telegram task belongs to another installation or its ownership is unknown"
    );
    Ok(TaskState {
        exists: state["exists"] == true,
        legacy: state["legacy"] == true,
    })
}
fn persist_enabled(root: &Path, enabled: bool) -> Result<()> {
    no_reparse(&root.join("runtime/settings.ini"))?;
    let mut settings = zapret_core::read_settings(root)?;
    settings.set("telegram", if enabled { "on" } else { "off" })?;
    zapret_core::save_settings(root, &settings)
}

// The controller is exercised with a fake driver: tests never run tasks or Telegram.
trait StartDriver {
    fn halt(&mut self) -> Result<()>;
    fn install(&mut self) -> Result<()>;
    fn run_task(&mut self) -> Result<()>;
    fn wait_ready(&mut self) -> Result<Value>;
    fn persist_on(&mut self) -> Result<()>;
}
fn start_with(driver: &mut impl StartDriver, mut state: Value, task: TaskState) -> Result<Value> {
    let reuse = state["running"] == true
        && state["current"] == true
        && state["requires_restart"] == false
        && !task.legacy;
    if !reuse && (state["current"] == true || task.exists) {
        driver.halt()?;
    }
    if !task.exists || task.legacy {
        driver.install()?;
    }
    if !reuse {
        driver.run_task()?;
        state = driver.wait_ready()?;
    }
    ensure!(
        state["running"] == true && state["current"] == true && state["requires_restart"] == false,
        "Telegram component did not establish its owned listener with the requested configuration"
    );
    driver.persist_on()?;
    state["enabled"] = json!("on");
    Ok(state)
}
struct NativeStart<'a> {
    root: &'a Path,
    task: &'a Value,
    spec: &'a Value,
}
impl StartDriver for NativeStart<'_> {
    fn halt(&mut self) -> Result<()> {
        halt(self.root, self.task, false)
    }
    fn install(&mut self) -> Result<()> {
        crate::tasks::install(self.root, self.task)?;
        Ok(())
    }
    fn run_task(&mut self) -> Result<()> {
        crate::tasks::action(self.root, self.task, crate::tasks::Action::Run)?;
        Ok(())
    }
    fn wait_ready(&mut self) -> Result<Value> {
        let end = Instant::now() + Duration::from_secs(40);
        while Instant::now() < end {
            let state = inspect(self.root, true)?;
            if state["running"] == true
                && state["requires_restart"] == false
                && state["configured_port"] == self.spec["port"]
                && read_marker(self.root)?.is_some_and(|m| {
                    matches_config(&m, self.spec, self.spec["config_hash"].as_str())
                })
            {
                return Ok(state);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        anyhow::bail!(
            "Telegram component did not establish its owned loopback listener within 40 seconds"
        )
    }
    fn persist_on(&mut self) -> Result<()> {
        persist_enabled(self.root, true)
    }
}
pub(crate) fn start(root: &Path, args: &Value) -> Result<Value> {
    let _guard = crate::ControlGuard::acquire(root, "telegram-start")?;
    crate::launch::allowed(root, args)?;
    zapret_core::verify_telegram(root)?;
    crate::relocation::recover(root)?;
    let task = json!({"kind":"telegram"});
    let current_task = owned_task(&crate::tasks::status(root, &task)?)?;
    no_reparse(&root.join("runtime/settings.ini"))?;
    let settings = zapret_core::read_settings(root)?;
    let previously_enabled = settings.get("telegram").eq_ignore_ascii_case("on")
        || (settings.get("telegram").is_empty() && current_task.exists);
    let (spec, state) = {
        let _initializing = PackageMutex::acquire(root, "initializing", 5000)?;
        let marker = read_marker(root)?;
        let spec = prepare_start_config(root, args, marker.as_ref())?;
        (spec, inspect(root, true)?)
    };
    // The supervisor may start from saved "off" only while this deliberate start owns its permit.
    // Save "on" only after the listener has proved its process/job/configuration identity.
    let permit = PackageMutex::acquire(root, "starting", 0)?;
    let mut driver = NativeStart {
        root,
        task: &task,
        spec: &spec,
    };
    let result = start_with(&mut driver, state, current_task);
    drop(permit);
    if result.is_err() {
        if let Err(cleanup) = halt(root, &task, !previously_enabled) {
            return result.with_context(|| format!("Telegram failed-start cleanup: {cleanup:#}"));
        }
    }
    result
}
pub(crate) fn stop(root: &Path, args: &Value) -> Result<Value> {
    let _guard = crate::ControlGuard::acquire(root, "telegram-stop")?;
    crate::launch::allowed(root, args)?;
    let task = json!({"kind":"telegram"});
    let _initializing = PackageMutex::acquire(root, "initializing", 5000)?;
    read_marker(root)?;
    owned_task(&crate::tasks::status(root, &task)?)?;
    stop_with(&mut NativeStop { root, task: &task }, args)
}
trait StopDriver {
    fn persist_off(&mut self) -> Result<()>;
    fn halt_and_remove_task(&mut self) -> Result<()>;
    fn state(&mut self) -> Result<Value>;
}
fn stop_with(driver: &mut impl StopDriver, args: &Value) -> Result<Value> {
    if args["persist_setting"] != false {
        driver.persist_off()?;
    }
    driver.halt_and_remove_task()?;
    let mut state = driver.state()?;
    ensure!(
        state["running"] == false && state["current"] == false,
        "Telegram supervisor stop is unconfirmed"
    );
    state["task_removed"] = json!(true);
    Ok(state)
}
struct NativeStop<'a> {
    root: &'a Path,
    task: &'a Value,
}
impl StopDriver for NativeStop<'_> {
    fn persist_off(&mut self) -> Result<()> {
        persist_enabled(self.root, false)
    }
    fn halt_and_remove_task(&mut self) -> Result<()> {
        halt_locked(self.root, self.task, true)
    }
    fn state(&mut self) -> Result<Value> {
        inspect(self.root, true)
    }
}
fn halt(root: &Path, task: &Value, remove_task: bool) -> Result<()> {
    let _initializing = PackageMutex::acquire(root, "initializing", 5000)?;
    halt_locked(root, task, remove_task)
}
fn halt_locked(root: &Path, task: &Value, remove_task: bool) -> Result<()> {
    let before = read_marker(root)?;
    let state = crate::tasks::status(root, task)?;
    if owned_task(&state)?.exists {
        crate::tasks::action_checked(root, task, &state, crate::tasks::Action::Stop)?;
        if remove_task {
            crate::tasks::action_checked(root, task, &state, crate::tasks::Action::Delete)?;
        }
    }
    if let Some(m) = before {
        if identity_live(&m.wrapper)? {
            crate::terminate_owned(&m.wrapper)?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !identity_live(&m.engine)? && !job_active(&m)? {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        ensure!(
            !identity_live(&m.engine)? && !job_active(&m)?,
            "Telegram job did not stop after its owner exited"
        );
        remove_marker_if(root, &m)?;
    }
    Ok(())
}
fn remove_marker_if(root: &Path, expected: &Marker) -> Result<()> {
    let path = marker(root);
    if path.exists() {
        let current: Marker = serde_json::from_slice(&read_limited(&path, 16384)?)?;
        if current.wrapper.pid == expected.wrapper.pid
            && current.wrapper.created_filetime == expected.wrapper.created_filetime
            && current.job_name == expected.job_name
        {
            no_reparse(&path)?;
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_start_uses_a_free_loopback_port_and_explicit_ports_are_preserved() {
        let foreign = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let occupied = foreign.local_addr().unwrap().port();
        let selected = start_port(occupied, false, true).unwrap();
        assert_ne!(selected, occupied);
        assert!(start_port(occupied, false, false).is_err());
        assert_eq!(start_port(occupied, true, true).unwrap(), occupied);
        assert_eq!(foreign.local_addr().unwrap().port(), occupied);
    }
    #[test]
    fn proxy_uri_dispatch_keeps_the_active_link_intact_and_rejects_other_actions_before_opening() {
        let link =
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef";
        let mut opened = Vec::new();
        let result = open_link_with(&json!({"link":link}), |uri| {
            opened.push(uri.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(opened, [link]);
        assert_eq!(result["opened"], true);
        for uri in [
            link.replace("127.0.0.1", "203.0.113.1"),
            link.replace("tg://proxy?", "https://example.com/?"),
            link.replace("port=1443", "port=0"),
            link.replace("port=1443", "port=65536"),
            link.replace("port=1443", "port=1443&extra=bad"),
            format!("{link}&extra=bad"),
            format!("{link}\0"),
            "tg://resolve?domain=example".into(),
            "cmd.exe /c start telegram".into(),
        ] {
            assert!(
                open_link_with(&json!({"link":uri}), |_| {
                    panic!("Invalid URI reached the shell dispatcher")
                })
                .is_err()
            );
            assert!(open_link(&json!({"link":uri})).is_err());
        }
        assert!(
            open_link_with(&json!({"link":link}), |_| {
                anyhow::bail!("No registered protocol handler")
            })
            .is_err()
        );
    }

    const SECRET: &str = "123456789abcdef0123456789abcdef0";

    fn config(port: u16) -> Value {
        json!({
            "port":port,"secret":SECRET,
            "link":format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{SECRET}")
        })
    }
    fn record(port: u16, hash: &str) -> Marker {
        Marker {
            schema: 1,
            wrapper: crate::ProcessIdentity {
                pid: 100,
                created_filetime: 101,
                executable: r"C:\fixture\bin\zapret.exe".into(),
            },
            engine: crate::ProcessIdentity {
                pid: 200,
                created_filetime: 202,
                executable: r"C:\fixture\bin\tgws\TgWsProxy_windows.exe".into(),
            },
            job_name: format!("{JOB_PREFIX}{}", "a".repeat(32)),
            tag: TG_TAG.into(),
            port,
            config_hash: Some(hash.into()),
            secret_hash: Some(secret_hash(&config(port))),
            relocated_wrapper: false,
        }
    }
    #[test]
    fn a_dead_supervisor_marker_from_a_renamed_folder_does_not_block_a_new_start() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime")).unwrap();
        let mut old = record(1443, &"a".repeat(64));
        old.wrapper.pid = u32::MAX;
        std::fs::write(marker(root.path()), serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(read_marker(root.path()).unwrap().is_none());
    }
    #[test]
    fn mapped_controller_replacement_preserves_only_the_recorded_process_lifetime() {
        let root = Path::new(r"C:\fixture");
        let original = record(1443, "hash").wrapper;
        let mut actual = original.clone();
        actual.executable = root.join(format!(
            "dist/native/previous-controllers/zapret.exe.{}.old",
            "a".repeat(32)
        ));
        assert!(controller_identity_matches(root, &actual, &original));
        actual.created_filetime += 1;
        assert!(!controller_identity_matches(root, &actual, &original));
        actual.created_filetime = original.created_filetime;
        actual.pid += 1;
        assert!(!controller_identity_matches(root, &actual, &original));
        actual.pid = original.pid;
        for path in [
            r"C:\other\dist\native\previous-controllers\zapret.exe.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.old",
            r"C:\fixture\dist\native\previous-controllers\other.exe.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.old",
            r"C:\fixture\dist\native\previous-controllers\zapret.exe.invalid.old",
            r"C:\fixture\bin\.native-build-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp",
            r"C:\Windows\not-zapret.exe",
        ] {
            actual.executable = path.into();
            assert!(
                !controller_identity_matches(root, &actual, &original),
                "{path}"
            );
        }
        actual.executable = root.join("bin/.native-build-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp.old");
        assert!(controller_identity_matches(root, &actual, &original));
        let update = root.join("runtime/update").join("1".repeat(32));
        let moved = format!("running-zapret-rust-{}.exe", "a".repeat(24));
        actual.executable = update.join(&moved);
        assert!(controller_identity_matches(root, &actual, &original));
        for path in [
            update.join("running-zapret-rust-worker-aaaaaaaaaaaaaaaaaaaaaaaa.exe"),
            update.join("running-zapret-rust-invalid.exe"),
            root.join("runtime/update/untrusted").join(&moved),
            root.join("runtime/other").join("1".repeat(32)).join(&moved),
        ] {
            actual.executable = path;
            assert!(!controller_identity_matches(root, &actual, &original));
        }
    }
    fn ready(port: u16) -> Value {
        json!({"running":true,"current":true,"requires_restart":false,"port":port})
    }
    struct FakeDriver {
        calls: Vec<&'static str>,
        ready: Value,
        wait_fails: bool,
    }
    impl FakeDriver {
        fn new(port: u16) -> Self {
            Self {
                calls: Vec::new(),
                ready: ready(port),
                wait_fails: false,
            }
        }
    }
    impl StartDriver for FakeDriver {
        fn halt(&mut self) -> Result<()> {
            self.calls.push("halt-preserving-task-and-preference");
            Ok(())
        }
        fn install(&mut self) -> Result<()> {
            self.calls.push("install");
            Ok(())
        }
        fn run_task(&mut self) -> Result<()> {
            self.calls.push("run");
            Ok(())
        }
        fn wait_ready(&mut self) -> Result<Value> {
            self.calls.push("wait-ready");
            ensure!(!self.wait_fails, "fixture startup timed out");
            Ok(self.ready.clone())
        }
        fn persist_on(&mut self) -> Result<()> {
            self.calls.push("save-on");
            Ok(())
        }
    }
    impl StopDriver for FakeDriver {
        fn persist_off(&mut self) -> Result<()> {
            self.calls.push("save-off");
            Ok(())
        }
        fn halt_and_remove_task(&mut self) -> Result<()> {
            self.calls.push("halt-and-delete-owned-task");
            Ok(())
        }
        fn state(&mut self) -> Result<Value> {
            self.calls.push("confirm-stopped");
            Ok(json!({"running":false,"current":false}))
        }
    }

    #[test]
    fn pending_port_keeps_the_proved_active_link_and_restart_is_not_a_false_success() {
        let old = record(1443, "old-config");
        let pending = describe(
            &config(2443),
            Some("new-config"),
            Some(&old),
            true,
            "on",
            None,
        );
        assert_eq!(pending["port"], 1443);
        assert_eq!(pending["configured_port"], 2443);
        assert_eq!(pending["active_link"], config(1443)["link"]);
        assert_eq!(pending["link"], config(1443)["link"]);
        assert_eq!(pending["configured_link"], config(2443)["link"]);
        assert_eq!(pending["requires_restart"], true);
        let mut driver = FakeDriver::new(2443);
        let started = start_with(
            &mut driver,
            pending,
            TaskState {
                exists: true,
                legacy: false,
            },
        )
        .unwrap();
        assert_eq!(started["port"], 2443);
        assert_eq!(started["enabled"], "on");
        assert_eq!(
            driver.calls,
            [
                "halt-preserving-task-and-preference",
                "run",
                "wait-ready",
                "save-on"
            ]
        );
    }

    #[test]
    fn unchanged_listener_is_reused_but_missing_autostart_task_is_restored() {
        let active = record(1443, "same-config");
        let state = describe(
            &config(1443),
            Some("same-config"),
            Some(&active),
            true,
            "off",
            None,
        );
        for exists in [false, true] {
            let mut driver = FakeDriver::new(1443);
            start_with(
                &mut driver,
                state.clone(),
                TaskState {
                    exists,
                    legacy: false,
                },
            )
            .unwrap();
            assert_eq!(
                driver.calls,
                if exists {
                    vec!["save-on"]
                } else {
                    vec!["install", "save-on"]
                }
            );
        }
    }

    #[test]
    fn changed_secret_or_advanced_configuration_and_old_markers_require_restart() {
        let mut active = record(1443, "old-config");
        assert!(!matches_config(
            &active,
            &config(1443),
            Some("changed-advanced-config")
        ));
        let mut changed = config(1443);
        changed["secret"] = json!("abcdef0123456789abcdef0123456789");
        let state = describe(
            &changed,
            Some("old-config"),
            Some(&active),
            true,
            "on",
            None,
        );
        assert_eq!(state["requires_restart"], true);
        assert_eq!(state["active_link"], "");
        active.config_hash = None;
        active.secret_hash = None;
        let state = describe(
            &config(1443),
            Some("old-config"),
            Some(&active),
            true,
            "on",
            None,
        );
        assert_eq!(state["requires_restart"], true);
        let mut driver = FakeDriver::new(1443);
        start_with(
            &mut driver,
            state,
            TaskState {
                exists: true,
                legacy: false,
            },
        )
        .unwrap();
        assert_eq!(
            driver.calls.first(),
            Some(&"halt-preserving-task-and-preference")
        );
    }

    #[test]
    fn start_never_saves_on_before_listener_confirmation_or_accepts_pending_state() {
        for timed_out in [false, true] {
            let mut driver = FakeDriver::new(1443);
            driver.wait_fails = timed_out;
            driver.ready["requires_restart"] = json!(true);
            assert!(
                start_with(
                    &mut driver,
                    json!({"running":false,"current":false}),
                    TaskState {
                        exists: false,
                        legacy: false
                    },
                )
                .is_err()
            );
            assert_eq!(driver.calls, ["install", "run", "wait-ready"]);
        }
    }

    #[test]
    fn legacy_task_is_stopped_before_replacement_without_turning_saved_preference_off() {
        let mut driver = FakeDriver::new(1443);
        start_with(
            &mut driver,
            ready(1443),
            TaskState {
                exists: true,
                legacy: true,
            },
        )
        .unwrap();
        assert_eq!(
            driver.calls,
            [
                "halt-preserving-task-and-preference",
                "install",
                "run",
                "wait-ready",
                "save-on"
            ]
        );
    }

    #[test]
    fn default_stop_disables_persistence_and_removes_the_repeating_owned_task() {
        let mut driver = FakeDriver::new(1443);
        let stopped = stop_with(&mut driver, &json!({})).unwrap();
        assert_eq!(stopped["task_removed"], true);
        assert_eq!(
            driver.calls,
            ["save-off", "halt-and-delete-owned-task", "confirm-stopped"]
        );
        assert!(!activation_allowed("off", false));
        assert!(!activation_allowed("OFF", false));
        assert!(activation_allowed("off", true));
        assert!(activation_allowed("on", false));
    }

    #[test]
    fn uninstall_can_stop_without_rewriting_its_byte_preserved_settings() {
        let mut driver = FakeDriver::new(1443);
        stop_with(&mut driver, &json!({"persist_setting":false})).unwrap();
        assert_eq!(
            driver.calls,
            ["halt-and-delete-owned-task", "confirm-stopped"]
        );
    }

    #[test]
    fn unknown_or_foreign_task_identity_never_authorizes_a_task_operation() {
        for value in [
            json!({}),
            json!({"exists":null}),
            json!({"exists":true,"owned":false}),
            json!({"exists":true}),
        ] {
            assert!(owned_task(&value).is_err());
        }
        assert!(!owned_task(&json!({"exists":false})).unwrap().exists);
        assert!(
            owned_task(&json!({"exists":true,"owned":true}))
                .unwrap()
                .exists
        );
    }

    #[test]
    fn saved_enable_disable_preserves_other_settings_in_a_temp_package() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("runtime")).unwrap();
        std::fs::write(
            directory.path().join("runtime/settings.ini"),
            "telegram=off\r\ncustom=keep\r\nalt=58\r\n",
        )
        .unwrap();
        for enabled in [true, false] {
            persist_enabled(directory.path(), enabled).unwrap();
            let settings = zapret_core::read_settings(directory.path()).unwrap();
            assert_eq!(settings.get("telegram"), if enabled { "on" } else { "off" });
            assert_eq!(settings.get("custom"), "keep");
            assert_eq!(settings.get("alt"), "58");
        }
    }

    #[test]
    fn prepared_config_hash_covers_advanced_options_and_pins_loopback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"host":"0.0.0.0","pool_size":17,"custom":{"x":true}}"#,
        )
        .unwrap();
        let spec = prepare_config(directory.path(), &json!({"port":2443,"secret":SECRET})).unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved["host"], "127.0.0.1");
        assert_eq!(saved["pool_size"], 17);
        assert!(saved.get("media_pool_size").is_none());
        assert_eq!(saved["custom"]["x"], true);
        assert_eq!(saved["autostart"], false);
        assert_eq!(saved["check_updates"], false);
        assert_eq!(spec["config_hash"], config_hash(&saved).unwrap());
        assert_eq!(
            spec["executable"],
            json!(directory.path().join("bin/zapret-rust.exe"))
        );
        assert_eq!(spec["tag"], telegram_core::CORE_VERSION);
        let mut changed = saved;
        changed["pool_size"] = json!(18);
        assert_ne!(spec["config_hash"], config_hash(&changed).unwrap());
        assert_eq!(
            read_config(directory.path(), false, &json!({})).unwrap()["port"],
            2443
        );
    }

    #[test]
    fn default_media_pool_is_migrated_once_and_a_user_override_survives() {
        let directory = tempfile::tempdir().unwrap();
        let args = json!({"port":2443,"secret":SECRET});
        let path = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, br#"{"pool_size":4}"#).unwrap();
        prepare_config(directory.path(), &args).unwrap();
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["media_pool_size"], 8);
        saved["media_pool_size"] = json!(2);
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        prepare_config(directory.path(), &args).unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            (
                saved["pool_size"].as_u64(),
                saved["media_pool_size"].as_u64()
            ),
            (Some(4), Some(2))
        );
    }

    #[test]
    fn config_read_waits_for_publisher_delete_lease_without_weakening_sharing() {
        use std::{
            fs::OpenOptions,
            os::windows::fs::OpenOptionsExt,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
                mpsc,
            },
            thread,
        };
        let directory = tempfile::tempdir().unwrap();
        let credentials = directory.path().join("runtime/telegram.txt");
        let core_config = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(core_config.parent().unwrap()).unwrap();
        std::fs::write(&credentials, format!("port=2443\nsecret={SECRET}\n")).unwrap();
        std::fs::write(&core_config, "{}").unwrap();
        for (path, inspect_status) in [(credentials, false), (core_config, true)] {
            let released = Arc::new(AtomicBool::new(false));
            let worker_released = released.clone();
            let (ready, started) = mpsc::channel();
            let worker = thread::spawn(move || {
                // Atomic publication needs DELETE access. A snapshot reader must
                // wait for this lease rather than allowing replacement mid-read.
                let lease = OpenOptions::new()
                    .read(true)
                    .access_mode(0x8001_0000)
                    .share_mode(7)
                    .open(path)
                    .unwrap();
                ready.send(()).unwrap();
                thread::sleep(Duration::from_millis(60));
                worker_released.store(true, Ordering::Release);
                drop(lease);
            });
            started.recv().unwrap();
            let result = if inspect_status {
                status(directory.path())
            } else {
                read_config(directory.path(), false, &json!({}))
            };
            let returned_while_locked = !released.load(Ordering::Acquire);
            worker.join().unwrap();
            assert!(
                !returned_while_locked,
                "configuration read returned while the publisher lease was held: {result:?}"
            );
            assert_eq!(result.unwrap()["port"], 2443);
        }
    }

    #[test]
    fn invalid_core_options_never_replace_saved_config_or_user_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = br#"{"pool_size":-1,"custom":"preserved"}"#;
        std::fs::write(&path, original).unwrap();
        assert!(prepare_config(directory.path(), &json!({"port":2443,"secret":SECRET})).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
        assert!(!directory.path().join("runtime/telegram.txt").exists());
    }

    #[test]
    fn existing_isolated_proxy_config_recovers_port_and_secret_without_an_ini_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&config(2443)).unwrap()).unwrap();
        let prepared = prepare_config(directory.path(), &json!({})).unwrap();
        assert_eq!(prepared["port"], 2443);
        assert_eq!(prepared["secret"], SECRET);
        assert_eq!(
            read_config(directory.path(), false, &json!({})).unwrap()["secret"],
            SECRET
        );
    }

    #[test]
    fn legacy_external_backend_cannot_be_reused_as_current_rust_core() {
        let mut previous = record(1443, "same-config");
        previous.tag = "v1.11.4".into();
        assert!(!matches_config(
            &previous,
            &config(1443),
            Some("same-config")
        ));
    }

    #[test]
    fn core_command_proves_its_config_path_and_hash_without_exposing_credentials() {
        let root = Path::new(r"C:\fixture with spaces");
        let hash = "A".repeat(64);
        let mut arguments = vec![root.join(TG_EXE).to_string_lossy().into_owned()];
        arguments.extend(
            core_arguments(root, &hash)
                .iter()
                .map(|v| v.to_string_lossy().into_owned()),
        );
        assert!(core_command_matches(root, &arguments, Some(&hash)));
        assert!(!arguments.join(" ").contains(SECRET));
        assert!(!core_command_matches(root, &arguments, None));
        assert!(!core_command_matches(
            root,
            &arguments,
            Some(&"B".repeat(64))
        ));
        let mut changed = arguments.clone();
        changed[3] = r"C:\foreign\config.json".into();
        assert!(!core_command_matches(root, &changed, Some(&hash)));
        arguments.push("extra".into());
        assert!(!core_command_matches(root, &arguments, Some(&hash)));
    }

    #[test]
    fn worker_refuses_configuration_changed_after_supervisor_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let mut value = config(1443);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let expected = config_hash(&value).unwrap();
        assert!(load_core_config(&path, &expected).is_ok());
        value["pool_size"] = json!(12);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_core_config(&path, &expected).is_err());
    }

    #[test]
    fn invalid_json_or_typed_edits_cannot_commit_new_user_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime/tgws/TgWsProxy/config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "invalid json").unwrap();
        let user_path = directory.path().join("runtime/telegram.txt");
        let original = format!("port=1443\r\nsecret={SECRET}\r\n");
        std::fs::write(&user_path, &original).unwrap();
        for args in [
            json!({"port":2443}),
            json!({"port":-1}),
            json!({"port":"2443"}),
            json!({"secret":true}),
        ] {
            assert!(prepare_config(directory.path(), &args).is_err());
            assert_eq!(std::fs::read_to_string(&user_path).unwrap(), original);
        }
    }

    #[test]
    fn stale_cleanup_cannot_remove_a_replacement_owners_marker() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("runtime")).unwrap();
        let previous = record(1443, "old");
        let mut replacement = previous.clone();
        replacement.wrapper.created_filetime += 1;
        atomic_write(
            &marker(directory.path()),
            &serde_json::to_vec(&replacement).unwrap(),
        )
        .unwrap();
        remove_marker_if(directory.path(), &previous).unwrap();
        assert!(marker(directory.path()).is_file());
        remove_marker_if(directory.path(), &replacement).unwrap();
        assert!(!marker(directory.path()).exists());
    }

    #[test]
    fn identity_proof_requires_pid_creation_time_and_executable() {
        let expected = record(1443, "fixture").wrapper;
        let mut actual = expected.clone();
        assert!(same_identity(&actual, &expected));
        actual.pid += 1;
        assert!(!same_identity(&actual, &expected));
        actual = expected.clone();
        actual.created_filetime += 1;
        assert!(!same_identity(&actual, &expected));
        actual = expected.clone();
        actual.executable = r"C:\foreign\zapret.exe".into();
        assert!(!same_identity(&actual, &expected));
    }
}
