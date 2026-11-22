//! Exact-owned migrations retain old registrations until their replacements are verified.
use crate::{
    ControlGuard,
    service::{self, ServiceInfo},
    storage::{atomic_write, no_reparse, read_limited},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Services::*;

fn journal_path(root: &Path) -> PathBuf {
    root.join("runtime/legacy-migration/service.json")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    state: String,
    root: PathBuf,
    binary: String,
    start_type: u32,
    was_running: bool,
    created_replacement: bool,
}
fn journal(root: &Path) -> Result<Option<Journal>> {
    let path = journal_path(root);
    no_reparse(&path)?;
    if !path.exists() {
        return Ok(None);
    }
    ensure!(
        crate::trusted_path(&path)? && crate::trusted_path(path.parent().unwrap())?,
        "Legacy migration journal is untrusted"
    );
    let record: Journal = serde_json::from_slice(&read_limited(&path, 65536)?)?;
    ensure!(
        record.schema == 1
            && ["Prepared", "Committed"].contains(&record.state.as_str())
            && crate::process::same_path(&record.root, root)
            && [SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED]
                .contains(&record.start_type),
        "Legacy migration journal context changed"
    );
    let command = service::argv(&record.binary)?;
    ensure!(
        !command.is_empty()
            && crate::process::same_path(Path::new(&command[0]), &root.join("bin/winws2.exe")),
        "Legacy migration journal points outside this package"
    );
    Ok(Some(record))
}
fn save(root: &Path, record: &Journal) -> Result<()> {
    let path = journal_path(root);
    no_reparse(&path)?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    crate::protect_path(path.parent().unwrap())?;
    if path.exists() {
        ensure!(
            crate::trusted_path(&path)?,
            "Existing migration journal is untrusted"
        );
    }
    atomic_write(&path, &serde_json::to_vec(record)?)?;
    crate::protect_path(&path)
}
pub(crate) fn ensure_clear(root: &Path) -> Result<()> {
    ensure!(
        service::legacy_info(root)?.is_none()
            && !crate::tasks::legacy_present()?
            && journal(root)?.is_none_or(|record| record.state == "Committed"),
        "Обнаружены прежние регистрации zapret-rust. Выполните service migrate / task migrate перед управлением обходом"
    );
    Ok(())
}
pub(crate) fn status(root: &Path, args: &Value) -> Result<Value> {
    let service = service::status_value(service::legacy_info(root));
    let task = match crate::tasks::legacy_present() {
        Ok(false) => {
            json!({"known":true,"exists":false,"owned":false,"name":crate::tasks::LEGACY_AUTOTUNE})
        }
        Ok(true) => crate::tasks::legacy_status(root, args).unwrap_or_else(
            |error| json!({"known":false,"exists":true,"owned":false,"error":format!("{error:#}")}),
        ),
        Err(error) => {
            json!({"known":false,"exists":null,"owned":false,"error":format!("{error:#}")})
        }
    };
    let migration = journal(root);
    let error = migration.as_ref().err().map(ToString::to_string);
    let pending = migration
        .ok()
        .flatten()
        .is_some_and(|record| record.state == "Prepared");
    let required = service["exists"] == true || task["exists"] == true || pending;
    Ok(
        json!({"known":service["known"]==true && task["known"]!=false && error.is_none(),
        "migration_required":required,"service":service,"task":task,"pending":pending,"journal_error":error}),
    )
}
fn check_service(old: &ServiceInfo, replacement: Option<&ServiceInfo>) -> Result<()> {
    migration_service_type(old)?;
    ensure!(
        old.owned && old.ownership_known,
        "Прежняя служба не принадлежит этой папке; перенос отменён"
    );
    ensure!(
        [SERVICE_STOPPED, SERVICE_RUNNING].contains(&old.state),
        "Прежняя служба меняет состояние; повторите перенос"
    );
    ensure!(
        [SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED].contains(&old.start_type),
        "Unsupported legacy service start type"
    );
    if let Some(replacement) = replacement {
        migration_service_type(replacement)?;
        ensure!(
            replacement.owned && replacement.ownership_known && replacement.binary == old.binary,
            "Новая служба уже имеет другую команду или владельца; прежняя сохранена"
        );
        ensure!(
            old.state == SERVICE_STOPPED || replacement.state == SERVICE_STOPPED,
            "Обе службы уже работают; перенос требует отдельной диагностики"
        );
    }
    Ok(())
}
fn migration_service_type(service: &ServiceInfo) -> Result<()> {
    ensure!(
        service.service_type == SERVICE_WIN32_OWN_PROCESS
            && (service.account.eq_ignore_ascii_case("LocalSystem")
                || service.account.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")),
        "Legacy migration supports the package's own-process LocalSystem service only; custom account/configuration retained"
    );
    Ok(())
}
fn confirm_replacement(root: &Path, binary: &str, running: bool) -> Result<()> {
    let command = service::argv(binary)?;
    let end = Instant::now() + Duration::from_secs(5);
    let mut since = None;
    let mut previous = None;
    loop {
        let service = service::assert_owned(root)?.context("Migrated service disappeared")?;
        ensure!(service.binary == binary, "Migrated service command changed");
        if !running {
            ensure!(
                service.state == SERVICE_STOPPED,
                "Migrated service unexpectedly started"
            );
            return Ok(());
        }
        if service.state == SERVICE_RUNNING {
            if let Some(identity) = service.identity {
                let owned = crate::system::owned(root)?;
                ensure!(
                    owned == vec![identity.clone()],
                    "Replacement did not become the single owned engine"
                );
                let actual = crate::process::process_arguments(&identity)?;
                ensure!(
                    actual.len() == command.len()
                        && crate::process::same_path(Path::new(&actual[0]), Path::new(&command[0]))
                        && actual[1..] == command[1..],
                    "Migrated process command differs from its confirmed recipe"
                );
                if previous.as_ref() == Some(&identity) {
                    if since.is_some_and(|start: Instant| {
                        start.elapsed() >= Duration::from_millis(1200)
                    }) {
                        return Ok(());
                    }
                } else {
                    previous = Some(identity);
                    since = Some(Instant::now());
                }
            }
        }
        ensure!(
            Instant::now() < end,
            "Migrated service did not confirm stable startup"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
pub(crate) fn migrate_service(root: &Path, args: &Value) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, "legacy-service-migrate")?;
    crate::launch::allowed_base(root, args)?;
    crate::system::owned(root)?;
    let old = service::legacy_info(root)?;
    let replacement = service::info(root)?;
    let prior = journal(root)?.filter(|record| record.state == "Prepared");
    let mut record = match (old.as_ref(), prior) {
        (None, None) => return Ok(json!({"migrated":false,"reason":"LegacyServiceAbsent"})),
        (Some(old), None) => {
            check_service(old, replacement.as_ref())?;
            Journal {
                schema: 1,
                state: "Prepared".into(),
                root: root.into(),
                binary: old.binary.clone(),
                start_type: old.start_type,
                was_running: old.state == SERVICE_RUNNING,
                created_replacement: replacement.is_none(),
            }
        }
        (old, Some(record)) => {
            if let Some(old) = old {
                migration_service_type(old)?;
                ensure!(
                    old.owned && old.ownership_known && old.binary == record.binary,
                    "Прежняя служба изменилась после прерывания переноса"
                );
            }
            if let Some(replacement) = replacement.as_ref() {
                migration_service_type(replacement)?;
                ensure!(
                    replacement.owned
                        && replacement.ownership_known
                        && replacement.binary == record.binary,
                    "Новая служба изменилась после прерывания переноса"
                );
            }
            record
        }
    };
    let command = service::argv(&record.binary)?;
    crate::validate_engine_args(root, &command[1..])?;
    crate::package::require_protected(root)?;
    save(root, &record)?;
    let result = (|| -> Result<()> {
        if replacement.is_none() {
            service::create_for_migration(root, &record.binary)?;
        }
        crate::launch::allowed_base(root, args)?;
        if old.is_some() {
            service::stop_legacy(root)?;
        }
        if record.was_running
            && service::info(root)?.is_some_and(|service| service.state == SERVICE_STOPPED)
        {
            service::start(root, &record.binary)?;
        }
        confirm_replacement(root, &record.binary, record.was_running)?;
        // The new service is demand-start until old deletion. The prepared journal makes
        // a crash after deletion recoverable without two automatic engines at next boot.
        if old.is_some() {
            service::remove_legacy(root)?;
        }
        service::start_type(root, record.start_type)?;
        record.state = "Committed".into();
        save(root, &record)?;
        Ok(())
    })();
    if let Err(error) = result {
        if let Ok(Some(old)) = service::legacy_info(root) {
            if old.owned && old.binary == record.binary {
                if record.created_replacement
                    && service::info(root)
                        .ok()
                        .flatten()
                        .is_some_and(|service| service.owned && service.binary == record.binary)
                {
                    let _ = service::remove(root);
                }
                if record.was_running && old.state == SERVICE_STOPPED {
                    if let Err(restore) = service::start_legacy(root, &record.binary) {
                        return Err(error.context(format!(
                            "Old service retained but restart failed: {restore:#}"
                        )));
                    }
                }
            }
        }
        return Err(error.context("Migration journal retained; repeat service migrate to resume"));
    }
    Ok(
        json!({"migrated":true,"service":service::status_value(service::info(root)),"journal":journal_path(root)}),
    )
}
pub(crate) fn migrate_task(root: &Path, args: &Value) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, "legacy-task-migrate")?;
    crate::launch::allowed_base(root, args)?;
    if !crate::tasks::legacy_present()? {
        return Ok(json!({"migrated":false,"reason":"LegacyTaskAbsent"}));
    }
    let old = crate::tasks::legacy_status(root, args)?;
    ensure!(
        old["exists"] == true && old["owned"] == true,
        "Прежняя задача не принадлежит этой папке; перенос отменён"
    );
    let mut arguments = args.clone();
    arguments["kind"] = json!("autotune");
    let current = crate::tasks::status(root, &arguments)?;
    ensure!(
        current["exists"] == false || current["owned"] == true,
        "Новая задача принадлежит другой установке; прежняя сохранена"
    );
    let backup = root.join("runtime/legacy-migration/autotune-before.xml");
    std::fs::create_dir_all(backup.parent().unwrap())?;
    crate::protect_path(backup.parent().unwrap())?;
    if backup.exists() {
        ensure!(
            crate::trusted_path(&backup)?,
            "Legacy task backup is untrusted"
        );
    }
    atomic_write(
        &backup,
        old["xml"]
            .as_str()
            .context("Legacy task XML missing")?
            .as_bytes(),
    )?;
    crate::protect_path(&backup)?;
    let installed = crate::tasks::install(root, &arguments)?;
    if let Err(error) = crate::tasks::remove_legacy(root, &arguments, &old) {
        if current["exists"] == false && crate::tasks::legacy_present().ok() == Some(true) {
            let _ = crate::tasks::action_checked(
                root,
                &arguments,
                &installed,
                crate::tasks::Action::Delete,
            );
        }
        return Err(error.context("Old task retained; replacement rollback attempted"));
    }
    Ok(json!({"migrated":true,"task":crate::tasks::status(root, &arguments)?,"backup":backup}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service(owned: bool, binary: &str) -> ServiceInfo {
        ServiceInfo {
            name: service::LEGACY_SERVICE_NAME.into(),
            state: SERVICE_STOPPED,
            pid: 0,
            owned,
            ownership_known: true,
            binary: binary.into(),
            start_type: SERVICE_AUTO_START,
            service_type: SERVICE_WIN32_OWN_PROCESS,
            account: "LocalSystem".into(),
            identity: None,
        }
    }
    #[test]
    fn legacy_migration_refuses_foreign_or_conflicting_replacements_before_actions() {
        let binary = "\"C:/fixture/bin/winws2.exe\" --intercept=0";
        let old = service(true, binary);
        check_service(&old, None).unwrap();
        assert!(check_service(&service(false, binary), None).is_err());
        assert!(check_service(&old, Some(&service(true, "other command"))).is_err());
        let mut unknown = old.clone();
        unknown.ownership_known = false;
        assert!(check_service(&unknown, None).is_err());
        let mut both = old.clone();
        both.state = SERVICE_RUNNING;
        assert!(check_service(&both, Some(&both)).is_err());
        let mut custom = old;
        custom.account = "CustomUser".into();
        assert!(check_service(&custom, None).is_err());
    }
}
