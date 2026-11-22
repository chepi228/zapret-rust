use crate::{
    ProcessIdentity,
    process::{same_path, wide},
    process_identity,
    system::{ProcessRow, reg_dword, reg_string, text16, zapret_image},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    mem::{size_of, zeroed},
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::{
    Foundation::*,
    System::{Registry::HKEY_LOCAL_MACHINE, Rpc::RPC_S_INVALID_BOUND, Services::*},
    UI::Shell::CommandLineToArgvW,
};
// Keep the SCM identity so an existing installation is managed rather than duplicated.
pub(crate) const SERVICE_NAME: &str = "zapret2-bypass";
pub(crate) const LEGACY_SERVICE_NAME: &str = "nba2k27-zapret2";
#[derive(Serialize)]
pub(crate) struct ServiceRow {
    pub name: String,
    pub display_name: String,
    pub state: u32,
    pub pid: u32,
}

pub(crate) fn snapshot() -> Result<Vec<ServiceRow>> {
    unsafe {
        let manager =
            ServiceHandle::new(OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE))?;
        let mut bytes = 0;
        let mut count = 0;
        let mut resume = 0;
        let initial = EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            null_mut(),
            0,
            &mut bytes,
            &mut count,
            &mut resume,
            null(),
        );
        ensure!(
            initial != 0 || GetLastError() == ERROR_MORE_DATA,
            "Service snapshot size unavailable: {}",
            std::io::Error::last_os_error()
        );
        ensure!(bytes <= 8 * 1024 * 1024, "Service table exceeds budget");
        if bytes == 0 {
            return Ok(Vec::new());
        }
        let mut memory = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        resume = 0;
        ensure!(
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                memory.as_mut_ptr().cast(),
                (memory.len() * size_of::<usize>()) as u32,
                &mut bytes,
                &mut count,
                &mut resume,
                null()
            ) != 0,
            "Service snapshot incomplete: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            count as usize
                <= memory.len() * size_of::<usize>() / size_of::<ENUM_SERVICE_STATUS_PROCESSW>(),
            "Invalid service row count"
        );
        let rows = std::slice::from_raw_parts(
            memory.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            count as usize,
        );
        Ok(rows
            .iter()
            .map(|s| ServiceRow {
                name: text16(s.lpServiceName),
                display_name: text16(s.lpDisplayName),
                state: s.ServiceStatusProcess.dwCurrentState,
                pid: s.ServiceStatusProcess.dwProcessId,
            })
            .collect())
    }
}

pub(crate) fn active_zapret_services(engines: &[ProcessRow]) -> Result<Vec<ServiceRow>> {
    Ok(snapshot()?
        .into_iter()
        .filter(|service| {
            is_active_zapret_service(service, engines)
                || (service.state != SERVICE_STOPPED && configured_zapret_service(&service.name))
        })
        .collect())
}

fn configured_zapret_service(name: &str) -> bool {
    // An engine service can be starting before SCM publishes its PID.
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    reg_string(HKEY_LOCAL_MACHINE, &key, "ImagePath")
        .ok()
        .flatten()
        .and_then(|command| argv(&command).ok())
        .is_some_and(|args| zapret_image(Path::new(&args[0])))
}

fn is_active_zapret_service(service: &ServiceRow, engines: &[ProcessRow]) -> bool {
    service.state != SERVICE_STOPPED
        && ([SERVICE_NAME, LEGACY_SERVICE_NAME]
            .iter()
            .any(|name| service.name.eq_ignore_ascii_case(name))
            || engines.iter().any(|engine| engine.pid == service.pid))
}

struct ServiceHandle(SC_HANDLE);
impl ServiceHandle {
    fn new(h: SC_HANDLE) -> Result<Self> {
        ensure!(
            !h.is_null(),
            "Service manager: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(h))
    }
}
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ServiceInfo {
    pub name: String,
    pub state: u32,
    pub pid: u32,
    pub owned: bool,
    pub ownership_known: bool,
    pub binary: String,
    pub start_type: u32,
    pub service_type: u32,
    pub account: String,
    pub identity: Option<ProcessIdentity>,
}
pub(crate) fn argv(command: &str) -> Result<Vec<String>> {
    unsafe {
        let c = wide(command)?;
        let mut n = 0;
        let raw = CommandLineToArgvW(c.as_ptr(), &mut n);
        ensure!(
            !raw.is_null() && n > 0 && n <= 4096,
            "Invalid Windows command line"
        );
        let a = std::slice::from_raw_parts(raw, n as usize)
            .iter()
            .map(|p| text16(*p))
            .collect();
        LocalFree(raw.cast());
        Ok(a)
    }
}
fn open(name: &str, access: u32) -> Result<Option<ServiceHandle>> {
    unsafe {
        let manager = ServiceHandle::new(OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT))?;
        let name = wide(name)?;
        let raw = OpenServiceW(manager.0, name.as_ptr(), access);
        if raw.is_null() {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                return Ok(None);
            }
            return Err(e.into());
        }
        Ok(Some(ServiceHandle(raw)))
    }
}
fn query_handle(h: &ServiceHandle) -> Result<SERVICE_STATUS_PROCESS> {
    unsafe {
        let mut s: SERVICE_STATUS_PROCESS = zeroed();
        let mut n = 0;
        ensure!(
            QueryServiceStatusEx(
                h.0,
                SC_STATUS_PROCESS_INFO,
                (&mut s as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut n
            ) != 0,
            "QueryServiceStatusEx: {}",
            std::io::Error::last_os_error()
        );
        Ok(s)
    }
}
pub(crate) fn info(root: &Path) -> Result<Option<ServiceInfo>> {
    info_named(root, SERVICE_NAME)
}
pub(crate) fn status_value(result: Result<Option<ServiceInfo>>) -> Value {
    match result {
        Ok(Some(service)) => {
            let running = service.state != SERVICE_STOPPED;
            let mut value = json!(service);
            value["known"] = json!(true);
            value["installed"] = json!(true);
            value["exists"] = json!(true);
            value["running"] = json!(running);
            value
        }
        Ok(None) => {
            json!({"known":true,"installed":false,"exists":false,"running":false,"owned":false,"ownership_known":true})
        }
        Err(error) => {
            json!({"known":false,"installed":null,"exists":null,"running":null,"owned":false,"ownership_known":false,"error":format!("{error:#}")})
        }
    }
}
pub(crate) fn legacy_info(root: &Path) -> Result<Option<ServiceInfo>> {
    info_named(root, LEGACY_SERVICE_NAME)
}
fn info_named(root: &Path, name: &str) -> Result<Option<ServiceInfo>> {
    let Some(h) = open(name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)? else {
        return Ok(None);
    };
    Ok(Some(info_handle_named(root, &h, name)?))
}
fn ownership(
    engine: &Path,
    binary: &str,
    state: u32,
    pid: u32,
    identity: Option<&ProcessIdentity>,
) -> (bool, bool) {
    let configured = argv(binary)
        .ok()
        .and_then(|arguments| arguments.first().cloned())
        .is_some_and(|path| same_path(Path::new(&path), engine));
    if state == SERVICE_STOPPED {
        return (configured, true);
    }
    let Some(identity) = identity.filter(|identity| identity.pid == pid) else {
        return (false, false);
    };
    (configured && same_path(&identity.executable, engine), true)
}
fn info_handle(root: &Path, h: &ServiceHandle) -> Result<ServiceInfo> {
    info_handle_named(root, h, SERVICE_NAME)
}

const CONFIGURATION_RPC_LIMIT: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
struct Configuration {
    binary: String,
    start_type: u32,
    service_type: u32,
    account: String,
}

fn registry_configuration(name: &str) -> Result<Configuration> {
    ensure!(
        !name.is_empty() && name.encode_utf16().count() <= 256 && !name.contains(['\\', '/', '\0']),
        "Invalid SCM service name"
    );
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    let configuration = Configuration {
        binary: reg_string(HKEY_LOCAL_MACHINE, &key, "ImagePath")?
            .context("Service ImagePath is unavailable")?,
        start_type: reg_dword(HKEY_LOCAL_MACHINE, &key, "Start")?
            .context("Service Start is unavailable")?,
        service_type: reg_dword(HKEY_LOCAL_MACHINE, &key, "Type")?
            .context("Service Type is unavailable")?,
        account: reg_string(HKEY_LOCAL_MACHINE, &key, "ObjectName")?
            .context("Service ObjectName is unavailable")?,
    };
    ensure!(
        !configuration.binary.is_empty()
            && !configuration.binary.contains('\0')
            && configuration.binary.encode_utf16().count() < 32767
            && !configuration.account.contains('\0'),
        "Invalid service registry configuration"
    );
    Ok(configuration)
}

fn configuration_size_error(error: i32) -> bool {
    error == ERROR_INSUFFICIENT_BUFFER as i32
        || matches!(error, RPC_X_BAD_STUB_DATA | RPC_S_INVALID_BOUND)
}

fn oversized_configuration(error: i32, configuration: &Configuration) -> bool {
    // SCM's RPC reply has an 8 KiB limit, although CreateServiceW accepts a
    // command line up to 32K UTF-16 characters. Older zapret services contain
    // the entire composed strategy and can exceed the reply limit.
    // https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw
    configuration_size_error(error)
        && (configuration.binary.encode_utf16().count() + 1) * 2 > CONFIGURATION_RPC_LIMIT
}

fn configuration(h: &ServiceHandle, name: &str) -> Result<(Configuration, bool)> {
    let mut memory = vec![0usize; CONFIGURATION_RPC_LIMIT / size_of::<usize>()];
    let mut needed = 0;
    let result = unsafe {
        QueryServiceConfigW(
            h.0,
            memory.as_mut_ptr().cast(),
            CONFIGURATION_RPC_LIMIT as u32,
            &mut needed,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        let code = error.raw_os_error().unwrap_or(0);
        if configuration_size_error(code) {
            let stored =
                registry_configuration(name).context("Read oversized service configuration")?;
            if oversized_configuration(code, &stored) {
                return Ok((stored, true));
            }
        }
        return Err(error).context("Query service configuration");
    }
    let configuration = unsafe { &*memory.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    Ok((
        Configuration {
            binary: unsafe { text16(configuration.lpBinaryPathName) },
            start_type: configuration.dwStartType,
            service_type: configuration.dwServiceType,
            account: unsafe { text16(configuration.lpServiceStartName) },
        },
        false,
    ))
}

fn info_handle_named(root: &Path, h: &ServiceHandle, name: &str) -> Result<ServiceInfo> {
    let state = query_handle(h)?;
    let (configuration, from_registry) = configuration(h, name)?;
    let binary = configuration.binary;
    let engine = root.join("bin/winws2.exe");
    let identity = if state.dwCurrentState != SERVICE_STOPPED && state.dwProcessId > 0 {
        process_identity(state.dwProcessId).ok()
    } else {
        None
    };
    let current = query_handle(h)?;
    if from_registry {
        let repeated = registry_configuration(name)?;
        ensure!(
            repeated.binary == binary
                && repeated.start_type == configuration.start_type
                && repeated.service_type == configuration.service_type
                && repeated.account == configuration.account,
            "Service configuration changed during ownership inspection; retry the operation"
        );
    }
    ensure!(
        current.dwCurrentState == state.dwCurrentState && current.dwProcessId == state.dwProcessId,
        "Service state changed during ownership inspection; retry the operation"
    );
    let (owned, ownership_known) = ownership(
        &engine,
        &binary,
        state.dwCurrentState,
        state.dwProcessId,
        identity.as_ref(),
    );
    Ok(ServiceInfo {
        name: name.into(),
        state: state.dwCurrentState,
        pid: state.dwProcessId,
        owned,
        ownership_known,
        binary,
        start_type: configuration.start_type,
        service_type: configuration.service_type,
        account: configuration.account,
        identity,
    })
}
fn ensure_owned(service: &ServiceInfo) -> Result<()> {
    ensure!(
        service.ownership_known,
        "Владелец работающей службы {SERVICE_NAME} не подтверждён; управление отложено"
    );
    ensure!(
        service.owned,
        "Служба {SERVICE_NAME} принадлежит другой папке. Управление отменено."
    );
    Ok(())
}
pub(crate) fn assert_owned(root: &Path) -> Result<Option<ServiceInfo>> {
    let s = info(root)?;
    if let Some(service) = s.as_ref() {
        ensure_owned(service)?;
    }
    Ok(s)
}

// Engine operations can use a standalone process beside a stopped registration.
// Registration changes still use assert_owned.
pub(crate) fn engine_service(root: &Path) -> Result<Option<ServiceInfo>> {
    let Some(service) = info(root)? else {
        return Ok(None);
    };
    Ok(engine_service_owned(&service)?.then_some(service))
}

fn engine_service_owned(service: &ServiceInfo) -> Result<bool> {
    if service.ownership_known && !service.owned {
        ensure!(
            service.state == SERVICE_STOPPED && service.pid == 0 && service.identity.is_none(),
            "Служба {} из другой папки ещё работает. Остановите zapret пунктом 2 и повторите действие.",
            service.name
        );
        return Ok(false);
    }
    ensure_owned(service)?;
    Ok(true)
}

fn relocated_binary(root: &Path, previous: &Path, service: &ServiceInfo) -> Result<Option<String>> {
    if service.owned {
        return Ok(None);
    }
    let mut command = argv(&service.binary)?;
    ensure!(
        service.ownership_known
            && command
                .first()
                .is_some_and(|image| same_path(Path::new(image), &previous.join("bin/winws2.exe"))),
        "Служба принадлежит другой установке; перенос отменён"
    );
    ensure!(
        service.service_type == SERVICE_WIN32_OWN_PROCESS
            && (service.account.eq_ignore_ascii_case("LocalSystem")
                || service.account.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")),
        "Перенос службы с нестандартной учётной записью отменён"
    );
    let stopped = service.state == SERVICE_STOPPED && service.pid == 0;
    let running_here = service.state == SERVICE_RUNNING
        && service.identity.as_ref().is_some_and(|identity| {
            identity.pid == service.pid
                && identity.created_filetime != 0
                && same_path(&identity.executable, &root.join("bin/winws2.exe"))
        });
    ensure!(
        stopped || running_here,
        "Состояние или процесс переносимой службы не подтверждены"
    );
    command[0] = root.join("bin/winws2.exe").to_string_lossy().into_owned();
    for arg in &mut command[1..] {
        *arg = crate::relocation::rewrite_paths(arg, previous, root);
    }
    Ok(Some(zapret_core::windows_command_line(&command)))
}

pub(crate) fn relocate(root: &Path, previous: &Path) -> Result<()> {
    let Some(handle) = open(
        SERVICE_NAME,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
    )?
    else {
        return Ok(());
    };
    let before = info_handle(root, &handle)?;
    let Some(binary) = relocated_binary(root, previous, &before)? else {
        return Ok(());
    };
    let command = argv(&binary)?;
    crate::validate_engine_args(root, &command[1..])?;
    let repeated = info_handle(root, &handle)?;
    ensure!(
        repeated.binary == before.binary
            && repeated.state == before.state
            && repeated.pid == before.pid
            && repeated.start_type == before.start_type
            && repeated.account == before.account,
        "Служба изменилась во время переноса; повторите запуск"
    );
    let wide_binary = wide(&binary)?;
    ensure!(
        unsafe {
            ChangeServiceConfigW(
                handle.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                wide_binary.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } != 0,
        "Не удалось перенести службу: {}",
        std::io::Error::last_os_error()
    );
    let after = info_handle(root, &handle)?;
    ensure_owned(&after)?;
    ensure!(
        after.binary == binary
            && after.start_type == before.start_type
            && after.state == before.state
            && after.pid == before.pid,
        "Новое расположение службы не подтверждено"
    );
    Ok(())
}
pub(crate) fn stop(root: &Path) -> Result<()> {
    stop_named(root, SERVICE_NAME)
}
pub(crate) fn stop_legacy(root: &Path) -> Result<()> {
    stop_named(root, LEGACY_SERVICE_NAME)
}
fn stop_named(root: &Path, name: &str) -> Result<()> {
    let Some(h) = open(
        name,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    )?
    else {
        return Ok(());
    };
    let s = info_handle_named(root, &h, name)?;
    ensure_owned(&s)?;
    if s.state == SERVICE_STOPPED {
        return Ok(());
    }
    request_stop(&h, false)?;
    if wait_stopped(&h, Instant::now() + Duration::from_secs(10))? {
        return Ok(());
    }
    // Stop only the exact owned service process, then cover the configured five-second recovery window.
    if let Some(identity) = s.identity {
        crate::terminate_owned(&identity)?;
    }
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        let current = query_handle(&h)?;
        if current.dwCurrentState != SERVICE_STOPPED {
            ensure_owned(&info_handle_named(root, &h, name)?)?;
            unsafe {
                let mut status = zeroed();
                ControlService(h.0, SERVICE_CONTROL_STOP, &mut status);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    ensure!(
        is_stopped(&h)?,
        "Служба не остановилась; новый обход не запущен"
    );
    Ok(())
}

pub(crate) fn stop_zapret(root: &Path, name: &str) -> Result<()> {
    let Some(handle) = open(
        name,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    )?
    else {
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = query_handle(&handle)?;
        if status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0 {
            return Ok(());
        }
        if ![
            SERVICE_STOP_PENDING,
            SERVICE_START_PENDING,
            SERVICE_PAUSE_PENDING,
            SERVICE_CONTINUE_PENDING,
        ]
        .contains(&status.dwCurrentState)
        {
            let current = info_handle_named(root, &handle, name)?;
            ensure_zapret_engine(&current)?;
            if !request_stop(&handle, true)? {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            if wait_stopped(&handle, deadline)? {
                return Ok(());
            }
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let current = info_handle_named(root, &handle, name)?;
    if current.state == SERVICE_STOPPED && current.pid == 0 {
        return Ok(());
    }
    ensure_zapret_engine(&current)?;
    let identity = current
        .identity
        .as_ref()
        .with_context(|| format!("Служба {name} не подтвердила остановку"))?;
    // A forced stop can trigger the SCM's recovery after 5 or 30 seconds.
    crate::terminate_owned(identity)?;
    let recovery = Instant::now() + Duration::from_secs(32);
    while Instant::now() < recovery {
        let status = query_handle(&handle)?;
        if [SERVICE_RUNNING, SERVICE_PAUSED].contains(&status.dwCurrentState) {
            ensure_zapret_engine(&info_handle_named(root, &handle, name)?)?;
            request_stop(&handle, true)?;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    ensure!(
        is_stopped(&handle)?,
        "Служба {name} не остановилась или перезапускается"
    );
    Ok(())
}

fn ensure_zapret_engine(service: &ServiceInfo) -> Result<()> {
    // The SCM name and process name are discovery hints. Verify the configured
    // image against the exact service process before sending any stop control.
    let args = argv(&service.binary)?;
    let image = Path::new(&args[0]);
    ensure!(
        service.service_type == SERVICE_WIN32_OWN_PROCESS && zapret_image(image),
        "Служба {} не распознана как служба zapret",
        service.name
    );
    ensure!(
        service.identity.as_ref().is_some_and(|identity| {
            service.pid != 0
                && identity.pid == service.pid
                && identity.created_filetime != 0
                && same_path(&identity.executable, image)
        }),
        "Не удалось подтвердить процесс службы {}",
        service.name
    );
    Ok(())
}

fn request_stop(handle: &ServiceHandle, allow_pending: bool) -> Result<bool> {
    unsafe {
        let mut status = zeroed();
        if ControlService(handle.0, SERVICE_CONTROL_STOP, &mut status) == 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_SERVICE_NOT_ACTIVE) => {}
                Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL) if allow_pending => return Ok(false),
                _ => return Err(error).context("Stop service"),
            }
        }
    }
    Ok(true)
}

fn is_stopped(handle: &ServiceHandle) -> Result<bool> {
    let status = query_handle(handle)?;
    Ok(status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0)
}

fn wait_stopped(handle: &ServiceHandle, deadline: Instant) -> Result<bool> {
    while !is_stopped(handle)? {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(true)
}
pub(crate) fn set_binary(root: &Path, binary: &str) -> Result<()> {
    let h = open(
        SERVICE_NAME,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    )?
    .context("Service is not installed")?;
    ensure_owned(&info_handle(root, &h)?)?;
    let c = wide(binary)?;
    ensure!(
        unsafe {
            ChangeServiceConfigW(
                h.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                c.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } != 0,
        "Update service command: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        info_handle(root, &h)?.binary == binary,
        "Service command did not match the owned launch recipe"
    );
    Ok(())
}
/// Change only the command/start policy used by the next SCM launch. The
/// caller separately verifies that the current process lifetime did not change.
pub(crate) fn configure_future(root: &Path, binary: &str, start_type: u32) -> Result<()> {
    ensure!(
        [SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED].contains(&start_type),
        "Недопустимый режим автозапуска службы"
    );
    ensure!(
        argv(binary)?
            .first()
            .is_some_and(|image| same_path(Path::new(image), &root.join("bin/winws2.exe"))),
        "Команда службы принадлежит другой папке"
    );
    crate::package::require_protected(root)?;
    let Some(handle) = open(
        SERVICE_NAME,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
    )?
    else {
        return create_with_start_type(root, binary, start_type);
    };
    ensure_owned(&info_handle(root, &handle)?)?;
    let command = wide(binary)?;
    ensure!(
        unsafe {
            ChangeServiceConfigW(
                handle.0,
                SERVICE_NO_CHANGE,
                start_type,
                SERVICE_NO_CHANGE,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } != 0,
        "Не удалось изменить автозапуск службы: {}",
        std::io::Error::last_os_error()
    );
    let after = info_handle(root, &handle)?;
    ensure_owned(&after)?;
    ensure!(
        after.binary == binary && after.start_type == start_type,
        "Новый режим автозапуска службы не подтверждён"
    );
    Ok(())
}
pub(crate) fn start(root: &Path, binary: &str) -> Result<()> {
    start_named(root, SERVICE_NAME, binary)
}
pub(crate) fn start_legacy(root: &Path, binary: &str) -> Result<()> {
    start_named(root, LEGACY_SERVICE_NAME, binary)
}
fn start_named(root: &Path, name: &str, binary: &str) -> Result<()> {
    let h = open(
        name,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    )?
    .context("Service missing")?;
    let s = info_handle(root, &h)?;
    ensure_owned(&s)?;
    ensure!(s.binary == binary, "Service command changed before startup");
    ensure!(
        unsafe { StartServiceW(h.0, 0, null()) } != 0,
        "Start service: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub(crate) fn create(root: &Path, binary: &str) -> Result<()> {
    create_with_start_type(root, binary, SERVICE_AUTO_START)
}
pub(crate) fn create_for_migration(root: &Path, binary: &str) -> Result<()> {
    create_with_start_type(root, binary, SERVICE_DEMAND_START)
}
fn create_with_start_type(root: &Path, binary: &str, start_type: u32) -> Result<()> {
    crate::package::require_protected(root)?;
    ensure!(
        assert_owned(root)?.is_none(),
        "Service is already installed"
    );
    unsafe {
        let manager =
            ServiceHandle::new(OpenSCManagerW(null(), null(), SC_MANAGER_CREATE_SERVICE))?;
        let n = wide(SERVICE_NAME)?;
        let d = wide("zapret-rust - обход DPI")?;
        let b = wide(binary)?;
        let h = ServiceHandle::new(CreateServiceW(
            manager.0,
            n.as_ptr(),
            d.as_ptr(),
            SERVICE_CHANGE_CONFIG
                | SERVICE_QUERY_CONFIG
                | SERVICE_QUERY_STATUS
                | SERVICE_START
                | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_NORMAL,
            b.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        ))?;
        let mut description = wide("Обход DPI для NBA 2K27, Discord и YouTube (zapret2 / winws2)")?;
        let desc = SERVICE_DESCRIPTIONW {
            lpDescription: description.as_mut_ptr(),
        };
        ensure!(
            ChangeServiceConfig2W(
                h.0,
                SERVICE_CONFIG_DESCRIPTION,
                (&desc as *const SERVICE_DESCRIPTIONW).cast()
            ) != 0,
            "Set service description: {}",
            std::io::Error::last_os_error()
        );
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 30000,
            },
        ];
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86400,
            lpRebootMsg: null_mut(),
            lpCommand: null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        ensure!(
            ChangeServiceConfig2W(
                h.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                (&failure as *const SERVICE_FAILURE_ACTIONSW).cast()
            ) != 0,
            "Set service recovery: {}",
            std::io::Error::last_os_error()
        );
    }
    ensure!(
        info(root)?.is_some_and(|s| s.binary == binary && s.owned),
        "Installed service command mismatch"
    );
    Ok(())
}
pub(crate) fn remove(root: &Path) -> Result<()> {
    remove_named(root, SERVICE_NAME)
}
pub(crate) fn remove_legacy(root: &Path) -> Result<()> {
    remove_named(root, LEGACY_SERVICE_NAME)
}
fn remove_named(root: &Path, name: &str) -> Result<()> {
    stop_named(root, name)?;
    delete_stopped_named(root, name)
}
pub(crate) fn remove_stopped(root: &Path) -> Result<()> {
    delete_stopped_named(root, SERVICE_NAME)
}
fn delete_stopped_named(root: &Path, name: &str) -> Result<()> {
    let Some(h) = open(name, DELETE | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)? else {
        return Ok(());
    };
    let current = info_handle_named(root, &h, name)?;
    ensure_owned(&current)?;
    ensure!(
        current.state == SERVICE_STOPPED && current.pid == 0,
        "Служба запущена; удаление остановленной регистрации отменено"
    );
    ensure!(
        unsafe { DeleteService(h.0) } != 0,
        "Delete service: {}",
        std::io::Error::last_os_error()
    );
    drop(h);
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if info_named(root, name)?.is_none() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("Прежняя служба ещё удаляется")
}
pub(crate) fn start_type(root: &Path, value: u32) -> Result<()> {
    ensure!(
        [SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED].contains(&value),
        "Unsupported migrated service start type"
    );
    let handle = open(
        SERVICE_NAME,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
    )?
    .context("Migrated service disappeared")?;
    ensure_owned(&info_handle(root, &handle)?)?;
    ensure!(
        unsafe {
            ChangeServiceConfigW(
                handle.0,
                SERVICE_NO_CHANGE,
                value,
                SERVICE_NO_CHANGE,
                null(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } != 0,
        "Set migrated service start type: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        info_handle(root, &handle)?.start_type == value,
        "Migrated service start type changed"
    );
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
enum DriverRemoval {
    Absent,
    Requested,
    Pending,
}

fn driver_removal_error(error: anyhow::Error) -> Result<DriverRemoval> {
    match error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
    {
        Some(code) if code == ERROR_SERVICE_MARKED_FOR_DELETE as i32 => Ok(DriverRemoval::Pending),
        Some(code) if code == ERROR_SERVICE_DOES_NOT_EXIST as i32 => Ok(DriverRemoval::Absent),
        _ => Err(error),
    }
}

fn remove_driver_with<H>(
    opened: Result<Option<H>>,
    request: impl FnOnce(&H) -> std::io::Result<()>,
) -> Result<DriverRemoval> {
    let handle = match opened {
        Ok(Some(handle)) => handle,
        Ok(None) => return Ok(DriverRemoval::Absent),
        Err(error) => return driver_removal_error(error),
    };
    // Deletion is asynchronous. Repeating a request can return 1072; closing
    // our handle remains necessary for Windows to finish the pending deletion.
    // https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-deleteservice
    match request(&handle) {
        Ok(()) => Ok(DriverRemoval::Requested),
        Err(error) => driver_removal_error(error.into()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DriverImageAction {
    Keep,
    Remove,
}

fn driver_image_action(root: &Path, image: &Path, remove_all: bool) -> Result<DriverImageAction> {
    let exists = image
        .try_exists()
        .context("Проверка файла зарегистрированного драйвера")?;
    let expected = root.join("bin/WinDivert64.sys");
    if exists && !same_path(image, &expected) {
        // WinDivert is shared system-wide. A test snapshot may have loaded the
        // identical pinned driver before the installed package starts. Reuse it
        // without claiming ownership or deleting another directory's service.
        ensure!(
            zapret_core::sha256_file(image)? == zapret_core::sha256_file(&expected)?,
            "Драйвер из другой папки отличается от версии в этом пакете"
        );
        return Ok(DriverImageAction::Keep);
    }
    Ok(if !remove_all && exists {
        DriverImageAction::Keep
    } else {
        DriverImageAction::Remove
    })
}

pub(crate) fn driver(root: &Path, remove_all: bool) -> Result<serde_json::Value> {
    let foreign = crate::system::processes()?
        .into_iter()
        .filter(|p| ["winws", "winws2", "goodbyedpi"].contains(&p.name.to_lowercase().as_str()))
        .filter(|p| {
            p.identity
                .as_ref()
                .is_none_or(|p| !same_path(&p.executable, &root.join("bin/winws2.exe")))
        })
        .collect::<Vec<_>>();
    ensure!(
        foreign.is_empty(),
        "Другой обход использует общий драйвер; изменение WinDivert отменено"
    );
    let mut removed = Vec::new();
    let mut pending_deletion = Vec::new();
    let mut reused_compatible = Vec::new();
    for name in ["WinDivert", "WinDivert14"] {
        let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
        let Some(image) = reg_string(HKEY_LOCAL_MACHINE, &key, "ImagePath")? else {
            continue;
        };
        let image = image.trim_matches('"').trim_start_matches(r"\??\");
        if driver_image_action(root, Path::new(image), remove_all)? == DriverImageAction::Keep {
            if !same_path(Path::new(image), &root.join("bin/WinDivert64.sys")) {
                reused_compatible.push(name);
            }
            continue;
        }
        let state = remove_driver_with(
            open(name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS),
            |h| unsafe {
                let mut s = zeroed();
                ControlService(h.0, SERVICE_CONTROL_STOP, &mut s);
                if DeleteService(h.0) != 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            },
        )
        .context("Delete stale WinDivert service")?;
        match state {
            DriverRemoval::Requested => removed.push(name),
            DriverRemoval::Pending => pending_deletion.push(name),
            DriverRemoval::Absent => {}
        }
    }
    Ok(
        json!({"removed":removed,"pending_deletion":pending_deletion,"reused_compatible":reused_compatible}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_stop_discovers_registered_zapret_and_custom_engine_services() {
        let engines = [ProcessRow {
            pid: 42,
            name: "winws2".into(),
            identity: None,
        }];
        let row = |name: &str, state, pid| ServiceRow {
            name: name.into(),
            display_name: String::new(),
            state,
            pid,
        };
        assert!(is_active_zapret_service(
            &row("ZAPRET2-BYPASS", SERVICE_START_PENDING, 0),
            &engines
        ));
        assert!(is_active_zapret_service(
            &row(LEGACY_SERVICE_NAME, SERVICE_RUNNING, 23),
            &engines
        ));
        assert!(is_active_zapret_service(
            &row("custom", SERVICE_RUNNING, 42),
            &engines
        ));
        assert!(!is_active_zapret_service(
            &row("custom", SERVICE_RUNNING, 43),
            &engines
        ));
        assert!(!is_active_zapret_service(
            &row(SERVICE_NAME, SERVICE_STOPPED, 0),
            &engines
        ));
    }

    #[test]
    fn global_stop_accepts_another_installation_and_checks_the_real_service_image() {
        let mut service = ServiceInfo {
            name: SERVICE_NAME.into(),
            state: SERVICE_RUNNING,
            pid: 42,
            owned: false,
            ownership_known: true,
            binary: r#""C:\old zapret\bin\WINWS2.EXE" --example"#.into(),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
            identity: Some(ProcessIdentity {
                pid: 42,
                created_filetime: 100,
                executable: r"\\?\C:\old zapret\bin\winws2.exe".into(),
            }),
        };
        assert!(ensure_owned(&service).is_err());
        assert!(ensure_zapret_engine(&service).is_ok());
        service.identity.as_mut().unwrap().pid = 43;
        assert!(ensure_zapret_engine(&service).is_err());
        service.identity.as_mut().unwrap().pid = 42;
        service.identity.as_mut().unwrap().executable = r"C:\unrelated\winws2.exe".into();
        assert!(ensure_zapret_engine(&service).is_err());
        service.binary = r"C:\unrelated\winws2.exe --example".into();
        service.service_type = SERVICE_WIN32_SHARE_PROCESS;
        assert!(ensure_zapret_engine(&service).is_err());
        service.service_type = SERVICE_WIN32_OWN_PROCESS;
        service.binary = r"C:\Windows\System32\cmd.exe /c winws2.exe".into();
        assert!(ensure_zapret_engine(&service).is_err());
    }
    #[test]
    fn moved_service_keeps_its_policy_and_does_not_claim_an_unrelated_or_unknown_process() {
        let previous = Path::new("C:/old");
        let root = Path::new("C:/moved package");
        let mut service = ServiceInfo {
            name: SERVICE_NAME.into(),
            state: SERVICE_STOPPED,
            pid: 0,
            owned: false,
            ownership_known: true,
            binary: "\"C:/old/bin/winws2.exe\" \"--lua-init=@C:/old/lua/lib.lua\"".into(),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
            identity: None,
        };
        let binary = relocated_binary(root, previous, &service).unwrap().unwrap();
        let args = argv(&binary).unwrap();
        assert!(same_path(Path::new(&args[0]), &root.join("bin/winws2.exe")));
        assert!(args[1].contains("C:/moved package/lua/lib.lua"));
        assert_eq!(service.start_type, SERVICE_AUTO_START);
        service.state = SERVICE_RUNNING;
        service.pid = 42;
        assert!(relocated_binary(root, previous, &service).is_err());
        service.identity = Some(ProcessIdentity {
            pid: 42,
            created_filetime: 100,
            executable: root.join("bin/winws2.exe"),
        });
        assert!(relocated_binary(root, previous, &service).is_ok());
        service.identity.as_mut().unwrap().executable = "C:/unrelated/winws2.exe".into();
        assert!(relocated_binary(root, previous, &service).is_err());
        service.state = SERVICE_STOPPED;
        service.pid = 0;
        service.account = "custom user".into();
        assert!(relocated_binary(root, previous, &service).is_err());
        service.account = "LocalSystem".into();
        service.binary = "C:/another/bin/winws2.exe".into();
        assert!(relocated_binary(root, previous, &service).is_err());
    }
    #[test]
    fn a_matching_driver_left_in_a_selection_snapshot_can_be_reused_without_deleting_it() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = tempfile::Builder::new()
            .prefix("zapret-rust-native-run-")
            .tempdir()
            .unwrap();
        for directory in [root.path(), snapshot.path()] {
            std::fs::create_dir(directory.join("bin")).unwrap();
            std::fs::write(
                directory.join("bin/WinDivert64.sys"),
                b"same trusted driver release",
            )
            .unwrap();
        }
        let image = snapshot.path().join("bin/WinDivert64.sys");
        for remove_all in [false, true] {
            assert_eq!(
                driver_image_action(root.path(), &image, remove_all).unwrap(),
                DriverImageAction::Keep
            );
            assert!(image.is_file());
        }
        std::fs::write(&image, b"different driver release").unwrap();
        assert!(driver_image_action(root.path(), &image, false).is_err());
        assert!(driver_image_action(root.path(), &image, true).is_err());
    }

    #[test]
    fn driver_cleanup_preserves_owned_and_missing_image_behavior() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("bin")).unwrap();
        let image = root.path().join("bin/WinDivert64.sys");
        std::fs::write(&image, b"driver").unwrap();
        assert_eq!(
            driver_image_action(root.path(), &image, false).unwrap(),
            DriverImageAction::Keep
        );
        assert_eq!(
            driver_image_action(root.path(), &image, true).unwrap(),
            DriverImageAction::Remove
        );
        let gone = root.path().join("old-copy/WinDivert64.sys");
        for remove_all in [false, true] {
            assert_eq!(
                driver_image_action(root.path(), &gone, remove_all).unwrap(),
                DriverImageAction::Remove
            );
        }
    }

    #[test]
    fn repeated_driver_deletion_succeeds_and_closes_the_service_handle() {
        use std::cell::Cell;
        struct TestHandle<'a>(&'a Cell<bool>);
        impl Drop for TestHandle<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        for (code, expected) in [
            (None, DriverRemoval::Requested),
            (
                Some(ERROR_SERVICE_MARKED_FOR_DELETE),
                DriverRemoval::Pending,
            ),
            (Some(ERROR_SERVICE_DOES_NOT_EXIST), DriverRemoval::Absent),
        ] {
            let closed = Cell::new(false);
            let calls = Cell::new(0);
            let result = remove_driver_with(Ok(Some(TestHandle(&closed))), |_| {
                calls.set(calls.get() + 1);
                match code {
                    Some(code) => Err(std::io::Error::from_raw_os_error(code as i32)),
                    None => Ok(()),
                }
            });
            assert!(closed.get(), "service handle must close before returning");
            assert_eq!(calls.get(), 1);
            assert_eq!(result.unwrap(), expected);
        }
    }

    #[test]
    fn pending_driver_before_open_does_not_repeat_the_delete_request() {
        let result = remove_driver_with::<()>(
            Err(std::io::Error::from_raw_os_error(ERROR_SERVICE_MARKED_FOR_DELETE as i32).into()),
            |_| panic!("driver already pending deletion must not be opened/deleted again"),
        );
        assert_eq!(result.unwrap(), DriverRemoval::Pending);
    }

    #[test]
    fn absent_driver_cleanup_is_a_noop() {
        let result = remove_driver_with::<()>(Ok(None), |_| panic!("no driver handle to delete"));
        assert_eq!(result.unwrap(), DriverRemoval::Absent);
    }

    #[test]
    fn driver_cleanup_keeps_real_access_and_handle_errors() {
        for code in [ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE] {
            let opened = remove_driver_with::<()>(
                Err(std::io::Error::from_raw_os_error(code as i32).into()),
                |_| panic!("delete after a failed open"),
            )
            .unwrap_err();
            assert_eq!(
                opened
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(code as i32)
            );
            let deleted = remove_driver_with(Ok(Some(())), |_| {
                Err(std::io::Error::from_raw_os_error(code as i32))
            })
            .unwrap_err();
            assert_eq!(
                deleted
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(code as i32)
            );
        }
    }

    #[test]
    fn long_service_command_uses_fallback_only_for_rpc_size_failures() {
        let mut configuration = Configuration {
            binary: "x".repeat(26180),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
        };
        for error in [
            ERROR_INSUFFICIENT_BUFFER as i32,
            RPC_X_BAD_STUB_DATA,
            RPC_S_INVALID_BOUND,
        ] {
            assert!(oversized_configuration(error, &configuration));
        }
        assert!(!oversized_configuration(
            ERROR_ACCESS_DENIED as i32,
            &configuration
        ));
        assert!(!oversized_configuration(
            ERROR_INVALID_HANDLE as i32,
            &configuration
        ));
        configuration.binary = "я".repeat(4095);
        assert!(!oversized_configuration(
            RPC_X_BAD_STUB_DATA,
            &configuration
        ));
        configuration.binary.push('я');
        assert!(oversized_configuration(RPC_X_BAD_STUB_DATA, &configuration));
        assert!(registry_configuration("unrelated-service").is_err());
    }

    #[test]
    fn normalized_service_status_distinguishes_absent_installed_and_unknown() {
        let absent = status_value(Ok(None));
        assert_eq!(absent["exists"], false);
        assert_eq!(absent["installed"], false);
        assert_eq!(absent["known"], true);
        let unknown = status_value(Err(anyhow::anyhow!("fixture denied")));
        assert_eq!(unknown["exists"], Value::Null);
        assert_eq!(unknown["installed"], Value::Null);
        assert_eq!(unknown["known"], false);
        assert_eq!(unknown["ownership_known"], false);
        let installed = status_value(Ok(Some(ServiceInfo {
            name: SERVICE_NAME.into(),
            state: SERVICE_STOPPED,
            pid: 0,
            owned: true,
            ownership_known: true,
            binary: "fixture".into(),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
            identity: None,
        })));
        assert_eq!(installed["exists"], true);
        assert_eq!(installed["installed"], true);
        assert_eq!(installed["running"], false);
    }
    #[test]
    fn active_service_requires_a_live_exact_engine_identity() {
        let engine = Path::new("C:/fixture/bin/winws2.exe");
        let binary = "\"C:/fixture/bin/winws2.exe\" --intercept=0";
        let identity = ProcessIdentity {
            pid: 42,
            created_filetime: 100,
            executable: engine.into(),
        };
        assert_eq!(
            ownership(engine, binary, SERVICE_STOPPED, 0, None),
            (true, true)
        );
        for state in [
            SERVICE_START_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_RUNNING,
            SERVICE_PAUSED,
        ] {
            assert_eq!(ownership(engine, binary, state, 42, None), (false, false));
            assert_eq!(
                ownership(engine, binary, state, 42, Some(&identity)),
                (true, true)
            );
            assert_eq!(
                ownership(engine, binary, state, 43, Some(&identity)),
                (false, false)
            );
        }
        let foreign = ProcessIdentity {
            executable: "C:/another/bin/winws2.exe".into(),
            ..identity
        };
        assert_eq!(
            ownership(engine, binary, SERVICE_RUNNING, 42, Some(&foreign)),
            (false, true)
        );
        assert_eq!(
            ownership(engine, "\"C:/other/winws2.exe\"", SERVICE_STOPPED, 0, None),
            (false, true)
        );
    }

    #[test]
    fn engine_control_ignores_only_a_confirmed_stopped_registration_from_another_folder() {
        let mut service = ServiceInfo {
            name: SERVICE_NAME.into(),
            state: SERVICE_STOPPED,
            pid: 0,
            owned: false,
            ownership_known: true,
            binary: r#""C:\old zapret\bin\winws2.exe" --intercept=0"#.into(),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
            identity: None,
        };
        assert!(ensure_owned(&service).is_err());
        assert!(!engine_service_owned(&service).unwrap());

        service.pid = 42;
        assert!(engine_service_owned(&service).is_err());
        service.state = SERVICE_RUNNING;
        assert!(engine_service_owned(&service).is_err());
        service.state = SERVICE_STOPPED;
        service.pid = 0;
        service.ownership_known = false;
        assert!(engine_service_owned(&service).is_err());

        service.owned = true;
        service.ownership_known = true;
        assert!(engine_service_owned(&service).unwrap());
    }
}
