use crate::com::{Apartment, Dispatch, Object, StringValue, check};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::{Mutex, mpsc},
    time::Duration,
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, S_FALSE, S_OK, SCHED_E_TASK_NOT_RUNNING},
        System::{
            Com::{CLSCTX_INPROC_SERVER, CoCreateInstance},
            Variant::{VARIANT, VT_BSTR},
        },
    },
    core::{BSTR, GUID, HRESULT},
};

const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(15);
const TASK_STATE_DISABLED: i32 = 1;
const TASK_STATE_READY: i32 = 3;
const MAX_ACTIVE_QUERIES: usize = 4;
static ACTIVE_QUERIES: Mutex<usize> = Mutex::new(0);
pub(crate) const TASK_NOT_FOUND: HRESULT = (0x8007_0000 | ERROR_FILE_NOT_FOUND) as HRESULT;
const TASK_CREATE: i32 = 2;
const TASK_UPDATE: i32 = 4;
#[cfg(test)]
const TASK_VALIDATE_ONLY: i32 = 1;
const TASK_LOGON_INTERACTIVE_TOKEN: i32 = 3;
const TASK_LOGON_GROUP: i32 = 4;
const TASK_LOGON_SERVICE_ACCOUNT: i32 = 5;
const TASK_LOGON_S4U: i32 = 2;
const MAX_XML_CHARS: usize = 4 * 1024 * 1024;

// Vtable prefixes from taskschd.h. The service receives the current token and
// the null server name selects the local scheduler.
#[repr(C)]
struct TaskService {
    base: Dispatch,
    get_folder: unsafe extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    get_running_tasks: usize,
    new_task: usize,
    connect: unsafe extern "system" fn(*mut c_void, VARIANT, VARIANT, VARIANT, VARIANT) -> HRESULT,
}
#[repr(C)]
struct TaskFolder {
    base: Dispatch,
    before_get_task: [usize; 6],
    get_task: unsafe extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    get_tasks: usize,
    delete_task: unsafe extern "system" fn(*mut c_void, BSTR, i32) -> HRESULT,
    register_task: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        VARIANT,
        VARIANT,
        i32,
        VARIANT,
        *mut *mut c_void,
    ) -> HRESULT,
}
#[repr(C)]
struct RegisteredTask {
    base: Dispatch,
    before_get_state: [usize; 2],
    get_state: unsafe extern "system" fn(*mut c_void, *mut i32) -> HRESULT,
    before_run: [usize; 2],
    run: unsafe extern "system" fn(*mut c_void, VARIANT, *mut *mut c_void) -> HRESULT,
    before_get_xml: [usize; 7],
    get_xml: unsafe extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT,
    before_stop: [usize; 2],
    stop: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
}

pub(crate) enum TaskQuery {
    Registered(String),
    LookupError(HRESULT),
}

/// The API can register a task and still return a warning. Carry the actual
/// definition back so a caller can roll back only the registration it made.
pub(crate) struct Registration {
    pub(crate) xml: String,
    result: HRESULT,
}

impl Registration {
    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            self.result == S_OK,
            "Планировщик зарегистрировал задачу с предупреждением: HRESULT 0x{:08X}",
            self.result as u32
        );
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub(crate) enum Action {
    Run,
    Stop,
    Delete,
}

struct QuerySlot;

impl Drop for QuerySlot {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_QUERIES.lock() {
            *active -= 1;
        }
    }
}

pub(crate) fn query(name: &str) -> Result<TaskQuery> {
    // A timed-out COM call may still be unwinding. Limit concurrent queries
    // so repeated status requests cannot accumulate stuck worker threads.
    let mut active = ACTIVE_QUERIES
        .lock()
        .map_err(|_| anyhow::anyhow!("Task Scheduler query counter is unavailable"))?;
    ensure!(
        *active < MAX_ACTIVE_QUERIES,
        "Task Scheduler queries are busy"
    );
    *active += 1;
    drop(active);
    let slot = QuerySlot;
    let name = name.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("task-scheduler-query".into())
        .spawn(move || {
            let result = query_local(&name);
            drop(slot);
            let _ = send.send(result);
        })
        .context("Start Task Scheduler query worker")?;
    receive
        .recv_timeout(QUERY_TIMEOUT)
        .context("Task Scheduler query incomplete")?
}

fn query_local(name: &str) -> Result<TaskQuery> {
    let _apartment = Apartment::enter("Task Scheduler COM apartment")?;
    let folder = root_folder()?;
    let name = StringValue::allocate(name)?;
    match registered_task(&folder, &name)? {
        Ok(task) => Ok(TaskQuery::Registered(task_xml(&task)?)),
        Err(error) => Ok(TaskQuery::LookupError(error)),
    }
}

fn root_folder() -> Result<Object> {
    const CLSID_TASK_SCHEDULER: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
    const IID_TASK_SERVICE: GUID = GUID::from_u128(0x2faba4c7_4da9_4013_9697_20cc3fd40f85);
    let folder_name = StringValue::allocate("\\")?;

    // Each returned interface is released in the apartment that acquired it.
    unsafe {
        let mut raw = null_mut();
        check(
            CoCreateInstance(
                &CLSID_TASK_SCHEDULER,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_TASK_SERVICE,
                &mut raw,
            ),
            "Create Task Scheduler service interface",
        )?;
        let service = Object::new(raw)?;
        let table = service.table::<TaskService>();
        let empty = VARIANT::default();
        check(
            (table.connect)(service.0, empty, empty, empty, empty),
            "Connect to the local Task Scheduler",
        )?;
        raw = null_mut();
        check(
            (table.get_folder)(service.0, folder_name.0, &mut raw),
            "Open the root task folder",
        )?;
        Object::new(raw)
    }
}

fn registered_task(folder: &Object, name: &StringValue) -> Result<Result<Object, HRESULT>> {
    let mut raw = null_mut();
    let result = unsafe { (folder.table::<TaskFolder>().get_task)(folder.0, name.0, &mut raw) };
    if result < 0 {
        return Ok(Err(result));
    }
    Ok(Ok(Object::new(raw)?))
}

fn task_xml(task: &Object) -> Result<String> {
    let mut xml = StringValue(null());
    check(
        unsafe { (task.table::<RegisteredTask>().get_xml)(task.0, &mut xml.0) },
        "Read task XML",
    )?;
    xml.read(MAX_XML_CHARS)
}

fn owned_registration(folder: &Object, name: &StringValue, expected_xml: &str) -> Result<Object> {
    let task = registered_task(folder, name)?.map_err(|error| {
        anyhow::anyhow!("Task lookup before change: HRESULT 0x{:08X}", error as u32)
    })?;
    ensure!(
        task_xml(&task)? == expected_xml,
        "Определение задачи изменилось во время операции"
    );
    Ok(task)
}

/// Register the XML with the same account and logon mode it declares. A task
/// that requires a saved password cannot be recreated from its XML.
fn registration_principal(xml: &str) -> Result<(String, i32)> {
    fn field<'a>(principal: roxmltree::Node<'a, '_>, tag: &str) -> Option<&'a str> {
        principal
            .children()
            .find(|node| node.has_tag_name(tag))?
            .text()
            .map(str::trim)
    }
    let doc = roxmltree::Document::parse(xml)?;
    let principals = doc
        .root_element()
        .children()
        .find(|node| node.has_tag_name("Principals"))
        .context("Task XML has no Principals")?;
    let mut entries = principals
        .children()
        .filter(|node| node.has_tag_name("Principal"));
    let principal = entries.next().context("Task XML has no Principal")?;
    ensure!(entries.next().is_none(), "Task XML has multiple principals");
    let user = field(principal, "UserId").filter(|user| !user.is_empty());
    let group = field(principal, "GroupId").filter(|group| !group.is_empty());
    let logon = field(principal, "LogonType");
    let (account, mode) = match (user, group, logon) {
        (Some(user), None, None | Some("ServiceAccount" | "InteractiveToken"))
            if service_account(user) =>
        {
            (user, TASK_LOGON_SERVICE_ACCOUNT)
        }
        (Some(user), None, Some("InteractiveToken")) => (user, TASK_LOGON_INTERACTIVE_TOKEN),
        (Some(user), None, Some("S4U")) => (user, TASK_LOGON_S4U),
        (None, Some(group), None | Some("Group")) => (group, TASK_LOGON_GROUP),
        _ => anyhow::bail!("Невозможно восстановить учётную запись задачи из XML"),
    };
    Ok((account.to_owned(), mode))
}

fn service_account(user: &str) -> bool {
    [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "SYSTEM",
        r"NT AUTHORITY\SYSTEM",
        "LOCAL SERVICE",
        r"NT AUTHORITY\LOCAL SERVICE",
        "NETWORK SERVICE",
        r"NT AUTHORITY\NETWORK SERVICE",
    ]
    .iter()
    .any(|account| account.eq_ignore_ascii_case(user))
}

fn register_xml(
    folder: &Object,
    name: &StringValue,
    xml: &str,
    flags: i32,
) -> Result<(Option<Object>, HRESULT)> {
    let (account, logon) = registration_principal(xml)?;
    let account = StringValue::allocate(&account)?;
    let xml = StringValue::allocate(xml)?;
    let mut user = VARIANT::default();
    user.Anonymous.Anonymous.vt = VT_BSTR;
    user.Anonymous.Anonymous.Anonymous.bstrVal = account.0;
    // The BSTR is borrowed by the input VARIANT until RegisterTask returns.
    let empty = VARIANT::default();
    let mut raw = null_mut();
    let result = unsafe {
        (folder.table::<TaskFolder>().register_task)(
            folder.0, name.0, xml.0, flags, user, empty, logon, empty, &mut raw,
        )
    };
    let task = Object::new(raw).ok();
    check(result, "Регистрация задачи")?;
    Ok((task, result))
}

pub(crate) fn register(name: &str, xml: &str, previous_xml: Option<&str>) -> Result<Registration> {
    let _apartment = Apartment::enter("Task Scheduler COM apartment")?;
    let folder = root_folder()?;
    let name = StringValue::allocate(name)?;
    // TASK_CREATE refuses same-name tasks created since the initial lookup.
    let existing = previous_xml
        .map(|expected| owned_registration(&folder, &name, expected))
        .transpose()?;
    let flags = if existing.is_some() {
        TASK_UPDATE
    } else {
        TASK_CREATE
    };
    let (task, result) = register_xml(&folder, &name, xml, flags)?;
    let task = task.context("Task Scheduler returned no registration")?;
    Ok(Registration {
        xml: task_xml(&task)?,
        result,
    })
}

fn task_state(task: &Object) -> Result<i32> {
    let mut state = 0;
    check(
        unsafe { (task.table::<RegisteredTask>().get_state)(task.0, &mut state) },
        "Read task execution state",
    )?;
    Ok(state)
}

pub(crate) fn action(name: &str, previous_xml: &str, action: Action) -> Result<()> {
    let _apartment = Apartment::enter("Task Scheduler COM apartment")?;
    let folder = root_folder()?;
    let name = StringValue::allocate(name)?;
    let task = owned_registration(&folder, &name, previous_xml)?;
    let table = unsafe { task.table::<RegisteredTask>() };
    match action {
        Action::Run => {
            let mut raw = null_mut();
            let result = unsafe { (table.run)(task.0, VARIANT::default(), &mut raw) };
            let _instance = Object::new(raw).ok();
            ensure!(
                result == S_OK,
                "Запуск задачи не подтверждён: HRESULT 0x{:08X}",
                result as u32
            );
        }
        Action::Stop => {
            let result = unsafe { (table.stop)(task.0, 0) };
            ensure!(
                matches!(result, S_OK | S_FALSE | SCHED_E_TASK_NOT_RUNNING),
                "Остановка задачи не подтверждена: HRESULT 0x{:08X}",
                result as u32
            );
            let deadline = std::time::Instant::now() + STOP_TIMEOUT;
            loop {
                if matches!(task_state(&task)?, TASK_STATE_READY | TASK_STATE_DISABLED) {
                    break;
                }
                ensure!(
                    matches!(result, S_OK | SCHED_E_TASK_NOT_RUNNING)
                        && std::time::Instant::now() < deadline,
                    "Остановка задачи не подтверждена: HRESULT 0x{:08X}",
                    result as u32
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Action::Delete => {
            let result = unsafe { (folder.table::<TaskFolder>().delete_task)(folder.0, name.0, 0) };
            if result != TASK_NOT_FOUND {
                check(result, "Удаление задачи")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, time::Instant};

    fn fixture_task_name(directory: &std::path::Path) -> String {
        format!(
            "zapret fixture {}",
            directory.file_name().unwrap().to_string_lossy()
        )
    }

    #[test]
    fn local_scheduler_queries_an_absent_task_without_registering_it() {
        let directory = tempfile::tempdir().unwrap();
        let name = fixture_task_name(directory.path());
        let result = query(&name).unwrap();
        assert!(matches!(result, TaskQuery::LookupError(TASK_NOT_FOUND)));
    }

    #[test]
    fn scheduler_accepts_generated_xml_and_leaves_fixture_unregistered() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("bin")).unwrap();
        fs::write(
            root.join("bin/zapret-rust.exe"),
            b"unused validation fixture",
        )
        .unwrap();
        fs::write(
            root.join("bin/zapret-rust-worker.exe"),
            b"unused GUI validation fixture",
        )
        .unwrap();
        let name = fixture_task_name(root);
        let _apartment = Apartment::enter("Task Scheduler validation test").unwrap();
        let folder = root_folder().unwrap();
        let task_name = StringValue::allocate(&name).unwrap();
        for kind in ["autotune", "watch", "notify", "telegram"] {
            let xml = crate::tasks::specification(root, &json!({"kind":kind})).unwrap();
            let (account, mode) = registration_principal(&xml).unwrap();
            if ["autotune", "watch"].contains(&kind) {
                assert_eq!(account, "S-1-5-18");
                assert_eq!(mode, TASK_LOGON_SERVICE_ACCOUNT);
            } else {
                assert_eq!(account, crate::control::current_sid().unwrap());
                assert_eq!(mode, TASK_LOGON_INTERACTIVE_TOKEN);
            }
            let (_, result) = register_xml(&folder, &task_name, &xml, TASK_VALIDATE_ONLY)
                .unwrap_or_else(|error| panic!("{kind}: {error:#}"));
            assert_eq!(result, S_OK, "{kind}");
            assert!(matches!(
                registered_task(&folder, &task_name).unwrap(),
                Err(TASK_NOT_FOUND)
            ));
        }
    }

    // Opt-in. The fixture uses only a uniquely named current-user task with an
    // innocuous Windows command and removes that exact registration on failure.
    #[test]
    #[ignore = "creates and runs a disposable current-user Task Scheduler fixture"]
    fn scheduler_fixture_create_update_run_stop_delete() {
        const TASK_STATE_RUNNING: i32 = 4;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let name = fixture_task_name(root);
        let _apartment = Apartment::enter("Task Scheduler lifecycle test").unwrap();
        let folder = root_folder().unwrap();
        let task_name = StringValue::allocate(&name).unwrap();
        let sid = crate::control::current_sid().unwrap();
        let executable = crate::system::system_exe("ping.exe").unwrap();
        let path = executable
            .to_string_lossy()
            .replace('&', "&amp;")
            .replace('<', "&lt;");
        let xml = format!(
            r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal id="Author"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT45S</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>{path}</Command><Arguments>-n 40 127.0.0.1</Arguments></Exec></Actions></Task>"#,
        );
        struct Cleanup<'a> {
            folder: &'a Object,
            name: &'a StringValue,
            action: &'a str,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let Ok(Ok(task)) = registered_task(self.folder, self.name) else {
                    return;
                };
                let Ok(xml) = task_xml(&task) else { return };
                if !xml.contains(self.action) {
                    return;
                }
                unsafe {
                    (task.table::<RegisteredTask>().stop)(task.0, 0);
                    (self.folder.table::<TaskFolder>().delete_task)(self.folder.0, self.name.0, 0);
                }
            }
        }
        // Mark this exact definition in the task XML to make fixture cleanup ownership explicit.
        let identifier = format!("{name} test-only");
        let xml = xml.replacen("<Principals>", &format!("<RegistrationInfo><Description>{identifier}</Description></RegistrationInfo><Principals>"), 1);
        assert!(matches!(
            query(&name).unwrap(),
            TaskQuery::LookupError(TASK_NOT_FOUND)
        ));
        let _cleanup = Cleanup {
            folder: &folder,
            name: &task_name,
            action: &identifier,
        };
        register(&name, &xml, None).unwrap().verify().unwrap();
        assert!(register(&name, &xml, None).is_err());
        let snapshot =
            task_xml(&registered_task(&folder, &task_name).unwrap().ok().unwrap()).unwrap();
        assert!(action(&name, "incompatible XML", Action::Stop).is_err());
        assert!(action(&name, "incompatible XML", Action::Delete).is_err());
        assert!(register(&name, &xml, Some("incompatible XML")).is_err());
        let disabled = xml.replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
        register(&name, &disabled, Some(&snapshot)).unwrap();
        let task = registered_task(&folder, &task_name).unwrap().ok().unwrap();
        let disabled_xml = task_xml(&task).unwrap();
        assert_eq!(task_state(&task).unwrap(), TASK_STATE_DISABLED);
        assert!(action(&name, &disabled_xml, Action::Run).is_err());
        register(&name, &xml, Some(&disabled_xml)).unwrap();
        let task = registered_task(&folder, &task_name).unwrap().ok().unwrap();
        let enabled_xml = task_xml(&task).unwrap();
        action(&name, &enabled_xml, Action::Run).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while task_state(&task).unwrap() != TASK_STATE_RUNNING {
            assert!(Instant::now() < deadline, "Disposable task did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        action(&name, &enabled_xml, Action::Stop).unwrap();
        action(&name, &enabled_xml, Action::Stop).unwrap();
        action(&name, &enabled_xml, Action::Delete).unwrap();
        assert!(matches!(
            query(&name).unwrap(),
            TaskQuery::LookupError(TASK_NOT_FOUND)
        ));
    }
}
