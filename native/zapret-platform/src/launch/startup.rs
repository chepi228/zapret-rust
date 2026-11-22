use super::{Recipe, allowed};
use crate::{
    ControlGuard, ProcessIdentity,
    service::{self, ServiceInfo},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use windows_sys::Win32::System::Services::{
    SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_RUNNING, SERVICE_STOPPED,
};

#[derive(Clone)]
struct State {
    service: Option<ServiceInfo>,
    processes: Vec<ProcessIdentity>,
}

impl State {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.processes.len() <= 1,
            "Обнаружено несколько процессов обхода"
        );
        if let Some(service) = &self.service {
            ensure!(
                service.owned && service.ownership_known,
                "Владелец службы не подтверждён; автозапуск не изменён"
            );
            match service.state {
                SERVICE_STOPPED => ensure!(
                    service.pid == 0 && service.identity.is_none(),
                    "Остановка службы не подтверждена"
                ),
                SERVICE_RUNNING => ensure!(
                    self.processes.len() == 1
                        && service.identity.as_ref() == self.processes.first()
                        && self.processes[0].pid == service.pid,
                    "Работа службы не подтверждена"
                ),
                _ => anyhow::bail!("Служба меняет состояние; повторите изменение автозапуска"),
            }
        }
        Ok(())
    }
    fn preserves(&self, before: &Self) -> bool {
        self.processes == before.processes
            && match (&before.service, &self.service) {
                (Some(before), Some(after)) => {
                    before.state == after.state
                        && before.pid == after.pid
                        && before.identity == after.identity
                }
                (None, Some(after)) => {
                    after.state == SERVICE_STOPPED && after.pid == 0 && after.identity.is_none()
                }
                (None, None) => true,
                (Some(_), None) => false,
            }
    }
}

trait Driver {
    fn state(&mut self) -> Result<State>;
    fn prepare(&mut self) -> Result<()>;
    fn configure(&mut self, enabled: bool) -> Result<()>;
    fn restore(&mut self, before: &State) -> Result<()>;
    fn watch(&mut self) -> Result<()>;
}

fn set_with(driver: &mut impl Driver, enabled: bool) -> Result<Value> {
    let before = driver.state()?;
    before.validate()?;
    if enabled {
        driver.prepare()?;
    }
    let mut attempted = false;
    let operation = (|| -> Result<State> {
        if enabled || before.service.is_some() {
            attempted = true;
            driver.configure(enabled)?;
        }
        let after = driver.state()?;
        after.validate()?;
        ensure!(
            after.preserves(&before),
            "Состояние работающего обхода изменилось при настройке автозапуска"
        );
        ensure!(
            if enabled {
                after
                    .service
                    .as_ref()
                    .is_some_and(|service| service.start_type == SERVICE_AUTO_START)
            } else {
                after
                    .service
                    .as_ref()
                    .is_none_or(|service| service.start_type == SERVICE_DEMAND_START)
            },
            "Новый режим автозапуска не подтверждён"
        );
        Ok(after)
    })();
    let after = match operation {
        Ok(after) => after,
        Err(error) => {
            if attempted {
                if let Err(restore) = driver.restore(&before) {
                    return Err(error.context(format!(
                        "Не удалось вернуть прежний режим автозапуска: {restore:#}"
                    )));
                }
            }
            return Err(error);
        }
    };
    let watch_error = if enabled {
        driver.watch().err().map(|error| format!("{error:#}"))
    } else {
        None
    };
    let running = !after.processes.is_empty();
    Ok(
        json!({"enabled":enabled,"known":true,"ownership_known":true,"running":running,
        "processes":after.processes,"service":service::status_value(Ok(after.service)),
        "watch_task_error":watch_error}),
    )
}

struct Native<'a> {
    root: &'a Path,
    args: &'a Value,
    recipe: Option<Recipe>,
}
impl Driver for Native<'_> {
    fn state(&mut self) -> Result<State> {
        Ok(State {
            service: service::assert_owned(self.root)?,
            processes: crate::system::owned(self.root)?,
        })
    }
    fn prepare(&mut self) -> Result<()> {
        crate::package::require_protected(self.root)?;
        let settings = zapret_core::read_settings(self.root)?;
        let network = crate::system::network(self.root)?;
        let key = network["key"]
            .as_str()
            .filter(|key| key.len() == 64)
            .map(str::to_owned);
        let recipe = Recipe::capture(self.root, &settings, key)?;
        recipe.dry()?;
        recipe.current()?;
        self.recipe = Some(recipe);
        Ok(())
    }
    fn configure(&mut self, enabled: bool) -> Result<()> {
        allowed(self.root, self.args)?;
        let binary = if enabled {
            let recipe = self
                .recipe
                .as_ref()
                .context("Не подготовлена команда автозапуска")?;
            recipe.current()?;
            recipe.binary()
        } else {
            service::assert_owned(self.root)?
                .context("Служба исчезла перед изменением автозапуска")?
                .binary
        };
        service::configure_future(
            self.root,
            &binary,
            if enabled {
                SERVICE_AUTO_START
            } else {
                SERVICE_DEMAND_START
            },
        )
    }
    fn restore(&mut self, before: &State) -> Result<()> {
        match &before.service {
            Some(before) => service::configure_future(self.root, &before.binary, before.start_type),
            None => service::remove_stopped(self.root),
        }
    }
    fn watch(&mut self) -> Result<()> {
        crate::tasks::install(self.root, &json!({"kind":"watch"}))?;
        Ok(())
    }
}

pub(crate) fn autostart(root: &Path, args: &Value) -> Result<Value> {
    let enabled = args["enabled"]
        .as_bool()
        .context("Нужно указать режим автозапуска")?;
    let _guard = ControlGuard::acquire(root, "service-autostart")?;
    allowed(root, args)?;
    set_with(
        &mut Native {
            root,
            args,
            recipe: None,
        },
        enabled,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            created_filetime: 101,
            executable: r"C:\fixture\bin\winws2.exe".into(),
        }
    }
    fn service(running: bool, start_type: u32) -> ServiceInfo {
        ServiceInfo {
            name: "zapret2-bypass".into(),
            state: if running {
                SERVICE_RUNNING
            } else {
                SERVICE_STOPPED
            },
            pid: if running { 42 } else { 0 },
            owned: true,
            ownership_known: true,
            binary: "original command".into(),
            start_type,
            service_type: 16,
            account: "LocalSystem".into(),
            identity: running.then(identity),
        }
    }
    struct Fake {
        current: State,
        original: State,
        calls: Vec<&'static str>,
        failed: bool,
        change_process: bool,
        wrong_policy: bool,
    }
    impl Fake {
        fn new(service: Option<ServiceInfo>, running: bool) -> Self {
            let state = State {
                service,
                processes: if running { vec![identity()] } else { vec![] },
            };
            Self {
                current: state.clone(),
                original: state,
                calls: vec![],
                failed: false,
                change_process: false,
                wrong_policy: false,
            }
        }
    }
    impl Driver for Fake {
        fn state(&mut self) -> Result<State> {
            Ok(self.current.clone())
        }
        fn prepare(&mut self) -> Result<()> {
            self.calls.push("prepare");
            Ok(())
        }
        fn configure(&mut self, enabled: bool) -> Result<()> {
            self.calls.push("configure");
            let service = self
                .current
                .service
                .get_or_insert_with(|| service(false, SERVICE_DEMAND_START));
            service.start_type = if enabled && !self.wrong_policy {
                SERVICE_AUTO_START
            } else {
                SERVICE_DEMAND_START
            };
            if self.change_process {
                self.current.processes.clear();
            }
            ensure!(!self.failed, "fixture change failed");
            Ok(())
        }
        fn restore(&mut self, before: &State) -> Result<()> {
            self.calls.push("restore");
            self.current = before.clone();
            Ok(())
        }
        fn watch(&mut self) -> Result<()> {
            self.calls.push("watch");
            Ok(())
        }
    }
    #[test]
    fn enabling_a_stopped_bypass_registers_future_startup_without_running_it() {
        let mut driver = Fake::new(None, false);
        let result = set_with(&mut driver, true).unwrap();
        assert_eq!(result["enabled"], true);
        assert_eq!(result["running"], false);
        assert_eq!(result["service"]["state"], SERVICE_STOPPED);
        assert_eq!(driver.calls, vec!["prepare", "configure", "watch"]);
    }
    #[test]
    fn both_autostart_directions_preserve_the_exact_running_process() {
        for enabled in [false, true] {
            let mut driver = Fake::new(
                Some(service(
                    true,
                    if enabled {
                        SERVICE_DEMAND_START
                    } else {
                        SERVICE_AUTO_START
                    },
                )),
                true,
            );
            let result = set_with(&mut driver, enabled).unwrap();
            assert_eq!(result["running"], true);
            assert_eq!(driver.current.processes, driver.original.processes);
            assert_eq!(
                driver.current.service.as_ref().unwrap().identity,
                Some(identity())
            );
            assert!(!driver.calls.contains(&"restore"));
        }
        let mut standalone = Fake::new(None, true);
        set_with(&mut standalone, true).unwrap();
        assert_eq!(standalone.current.processes, vec![identity()]);
        assert_eq!(standalone.current.service.unwrap().state, SERVICE_STOPPED);
    }
    #[test]
    fn failed_or_unconfirmed_policy_changes_restore_the_previous_configuration() {
        for failure in ["configure", "policy", "process"] {
            let mut driver = Fake::new(Some(service(false, SERVICE_DEMAND_START)), false);
            driver.failed = failure == "configure";
            driver.wrong_policy = failure == "policy";
            driver.change_process = failure == "process";
            if failure == "process" {
                driver.current.processes = vec![identity()];
                driver.original = driver.current.clone();
            }
            assert!(set_with(&mut driver, true).is_err(), "{failure}");
            assert_eq!(driver.calls.last(), Some(&"restore"));
            assert_eq!(
                driver.current.service.unwrap().start_type,
                SERVICE_DEMAND_START
            );
            assert_eq!(driver.current.processes, driver.original.processes);
        }
    }
    #[test]
    fn an_absent_disabled_service_is_a_noop_and_foreign_state_is_rejected() {
        let mut absent = Fake::new(None, false);
        set_with(&mut absent, false).unwrap();
        assert!(absent.calls.is_empty());
        let mut foreign = Fake::new(Some(service(false, SERVICE_AUTO_START)), false);
        foreign.current.service.as_mut().unwrap().owned = false;
        assert!(set_with(&mut foreign, false).is_err());
        assert!(foreign.calls.is_empty());
    }
}
