use crate::{
    ControlGuard, OwnedChild, ProcessIdentity, RunOptions,
    process::same_path,
    storage::{Pins, atomic_write, hash, no_reparse, read_limited},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zapret_core::{ComposeOptions, Settings};
mod startup;
pub(crate) use startup::autostart;

pub(crate) fn allowed(root: &Path, args: &Value) -> Result<()> {
    allowed_base(root, args)?;
    crate::legacy::ensure_clear(root)
}
pub(crate) fn allowed_base(root: &Path, args: &Value) -> Result<()> {
    no_reparse(root)?;
    if !args["allow_pending_update"].as_bool().unwrap_or(false) {
        let dir = root.join("runtime/update");
        if dir.exists() {
            no_reparse(&dir)?;
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.len() != 32 || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let path = entry.path().join("journal.json");
                if !path.exists() {
                    continue;
                }
                ensure!(
                    crate::trusted_path(&dir)?
                        && crate::trusted_path(&entry.path())?
                        && crate::trusted_path(&path)?,
                    "Untrusted update journal; control deferred"
                );
                let state: Value = serde_json::from_slice(&read_limited(&path, 1024 * 1024)?)?;
                let status = state["State"]
                    .as_str()
                    .or(state["state"].as_str())
                    .unwrap_or("");
                ensure!(
                    !["Prepared", "Applying", "prepared", "applying"].contains(&status),
                    "Обновление прервано. Восстановите файлы перед управлением обходом."
                );
            }
        }
    }
    let games = crate::system::games(root)?;
    ensure!(
        games.is_empty() || args["game_approved"].as_bool().unwrap_or(false),
        "Действие отложено: запущена игра ({}). Закройте игру и повторите запуск.",
        games
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Input {
    name: String,
    sha256: String,
    length: u64,
}
struct Recipe {
    root: PathBuf,
    settings: Settings,
    args: Vec<String>,
    catalog: Vec<String>,
    inputs_hash: String,
    config_hash: String,
    _pins: Pins,
}
fn catalog(root: &Path) -> Result<Vec<String>> {
    let mut names = zapret_core::score_input_files(root)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    names.extend(["tools/targets.txt", "tools/dpi-suite.json"].map(String::from));
    for dir in ["bin", "strategies", "windivert", "tools"] {
        for f in std::fs::read_dir(root.join(dir))? {
            let f = f?;
            no_reparse(&f.path())?;
            if f.file_type()?.is_file()
                && (dir != "tools"
                    || f.path()
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("ps1")))
            {
                let name = format!("{dir}/{}", f.file_name().to_string_lossy());
                if !zapret_core::is_native_build_artifact(&name) {
                    names.insert(name);
                }
            }
        }
    }
    for name in [
        "test-rank.txt",
        "test-cover.txt",
        "tested-strategies.txt",
        "ipset-any.txt",
    ] {
        if root.join("runtime").join(name).is_file() {
            names.insert(format!("runtime/{name}"));
        }
    }
    ensure!(
        !names.is_empty() && names.len() <= 2048,
        "Launch input catalog exceeds its budget"
    );
    Ok(names.into_iter().collect())
}
impl Recipe {
    fn capture(root: &Path, settings: &Settings, network_key: Option<String>) -> Result<Self> {
        Self::capture_with_controller(root, settings, network_key, &std::env::current_exe()?)
    }

    fn capture_with_controller(
        root: &Path,
        settings: &Settings,
        network_key: Option<String>,
        controller: &Path,
    ) -> Result<Self> {
        no_reparse(root)?;
        let manifest = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
        let bad = zapret_core::verify_integrity(root, &manifest)?;
        ensure!(
            bad.is_empty(),
            "Повреждены файлы движка: {}",
            bad.join(", ")
        );
        zapret_core::prepare_runtime(root, settings)?;
        let catalog = catalog(root)?;
        let mut pins = Pins::new();
        pins.directory(root)?;
        let mut dirs = BTreeSet::new();
        let mut inputs = Vec::new();
        let mut total = 0u64;
        for name in &catalog {
            let p = root.join(name);
            if let Some(parent) = p.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        for p in dirs {
            pins.directory(&p)?;
        }
        for name in &catalog {
            let path = crate::storage::relative(root, name)
                .with_context(|| format!("Invalid launch input: {name}"))?;
            let bytes = pins.file(&path)?;
            total += bytes.len() as u64;
            ensure!(total <= 64 * 1024 * 1024, "Launch inputs exceed 64 MiB");
            inputs.push(Input {
                name: name.clone(),
                sha256: hash(&bytes),
                length: bytes.len() as u64,
            });
        }
        // Revalidate pinned upstream bytes after immutable leases close the capture race.
        ensure!(
            inputs
                .iter()
                .any(|i| i.name == "tools/upstream.txt" && i.sha256 == manifest.content_hash),
            "Manifest changed while acquiring launch inputs"
        );
        for (name, expected) in &manifest.hashes {
            ensure!(
                inputs
                    .iter()
                    .any(|i| i.name == *name && i.sha256.eq_ignore_ascii_case(expected)),
                "Leased engine input differs from its pinned release: {name}"
            );
        }
        // Own adapter/module pins are checked again while their input leases
        // prevent a write or rename between integrity validation and execution.
        zapret_core::verify_ring(root)?;
        // Composition is evaluated from bytes leased against writes and rename.
        let controller_hash = crate::storage::file_hash(controller)?;
        let options = ComposeOptions {
            network_key,
            native_identity: Some(controller_hash.clone()),
            ..Default::default()
        };
        let args = zapret_core::checked_command_line(
            root,
            &zapret_core::compose(root, settings, &options)?,
        )?;
        let static_inputs = inputs
            .iter()
            .filter(|x| !x.name.starts_with("runtime/"))
            .collect::<Vec<_>>();
        let inputs_hash = hash(
            format!(
                "native-launch-inputs-v1\n{}\n{controller_hash}",
                serde_json::to_string(&static_inputs)?
            )
            .as_bytes(),
        );
        let config_hash = hash(
            format!(
                "native-launch-config-v1\n{inputs_hash}\n{}",
                serde_json::to_string(&(root.join("bin/winws2.exe"), root.join("bin"), &args))?
            )
            .as_bytes(),
        );
        let recipe = Self {
            root: root.into(),
            settings: settings.clone(),
            args,
            catalog,
            inputs_hash,
            config_hash,
            _pins: pins,
        };
        recipe.current()?;
        Ok(recipe)
    }
    fn current(&self) -> Result<()> {
        ensure!(
            catalog(&self.root)? == self.catalog,
            "Launch input catalog changed; repeat the operation"
        );
        Ok(())
    }
    fn binary(&self) -> String {
        format!(
            "\"{}\" {}",
            self.root.join("bin/winws2.exe").display(),
            zapret_core::windows_command_line(&self.args)
        )
    }
    fn dry(&self) -> Result<Value> {
        crate::validate_engine_args(&self.root, &self.args)
    }
}

/// Prepare and validate the installed recipe without opening WinDivert.
pub fn validate_launch(root: &Path) -> Result<Value> {
    let settings = zapret_core::read_settings(root)?;
    Recipe::capture_with_controller(root, &settings, None, &root.join("bin/zapret-rust.exe"))?.dry()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmed {
    schema: u32,
    root: PathBuf,
    version: String,
    inputs_hash: String,
    config_hash: String,
    settings: BTreeMap<String, String>,
}
fn confirmation(root: &Path) -> PathBuf {
    root.join("runtime/launch-state/confirmed-native.json")
}
const ENGINE_SETTINGS: [&str; 7] = [
    "alt", "auto", "game", "ipset", "gametcp", "gameudp", "autolist",
];
fn engine_settings(settings: &Settings) -> BTreeMap<String, String> {
    ENGINE_SETTINGS
        .into_iter()
        .chain(
            settings
                .get("game")
                .eq_ignore_ascii_case("selected")
                .then_some("gameapps"),
        )
        .map(|k| (k.into(), settings.get(k).into()))
        .collect()
}
fn save_confirmed(recipe: &Recipe) -> Result<()> {
    recipe.current()?;
    let path = confirmation(&recipe.root);
    let dir = path.parent().unwrap();
    no_reparse(dir)?;
    std::fs::create_dir_all(dir)?;
    crate::protect_path(dir)?;
    if path.exists() {
        ensure!(
            crate::trusted_path(&path)?,
            "Untrusted previous launch confirmation"
        );
    }
    let record = Confirmed {
        schema: 1,
        root: recipe.root.clone(),
        version: zapret_core::PACKAGE_VERSION.into(),
        inputs_hash: recipe.inputs_hash.clone(),
        config_hash: recipe.config_hash.clone(),
        settings: engine_settings(&recipe.settings),
    };
    let data = serde_json::to_vec(&record)?;
    ensure!(data.len() <= 16384, "Confirmation exceeds budget");
    atomic_write(&path, &data)?;
    crate::protect_path(&path)?;
    Ok(())
}
fn read_confirmed(root: &Path) -> Result<Option<Confirmed>> {
    let path = confirmation(root);
    if !path.exists() {
        return Ok(None);
    }
    ensure!(
        crate::trusted_path(path.parent().unwrap())? && crate::trusted_path(&path)?,
        "Untrusted launch confirmation"
    );
    let record: Confirmed = serde_json::from_slice(&read_limited(&path, 16384)?)?;
    ensure!(
        record.schema == 1
            && same_path(&record.root, root)
            && record.version == zapret_core::PACKAGE_VERSION
            && record.inputs_hash.len() == 64
            && record.config_hash.len() == 64,
        "Launch confirmation context changed"
    );
    ensure!(
        ENGINE_SETTINGS
            .iter()
            .all(|k| record.settings.contains_key(*k)),
        "Incomplete confirmed engine settings"
    );
    let mut checked = zapret_core::read_settings(root)?;
    for (k, v) in &record.settings {
        ensure!(
            ENGINE_SETTINGS.contains(&k.as_str())
                || (k == "gameapps" && record.settings["game"].eq_ignore_ascii_case("selected")),
            "Unknown confirmed setting"
        );
        checked.set(k, v)?;
    }
    Ok(Some(record))
}
fn stable(recipe: &Recipe, mut child: Option<&mut OwnedChild>) -> Result<ProcessIdentity> {
    let start = Instant::now();
    let mut since = None;
    let mut current = None;
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(c) = child.as_deref_mut() {
            if !c.is_running()? {
                bail!("Owned engine exited before startup confirmation");
            }
        }
        let p = crate::system::owned(&recipe.root)?;
        if p.len() == 1 {
            let identity = p[0].clone();
            if current.as_ref() != Some(&identity) {
                current = Some(identity);
                since = Some(Instant::now());
            } else if since.is_some_and(|s| s.elapsed() >= Duration::from_millis(1200)) {
                recipe.current()?;
                return Ok(p[0].clone());
            }
        } else {
            current = None;
            since = None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("Не удалось подтвердить стабильный запуск winws2")
}
fn spawn_engine(recipe: &Recipe) -> Result<OwnedChild> {
    let options = RunOptions {
        cwd: Some(recipe.root.join("bin")),
        timeout: Duration::from_secs(24 * 3600),
        ..Default::default()
    };
    let arguments = recipe.args.iter().map(OsString::from).collect::<Vec<_>>();
    OwnedChild::spawn_background(
        &recipe.root.join("bin/winws2.exe"),
        &arguments,
        &options,
        &recipe.root.join("runtime/engine.log"),
    )
}
fn activate(
    recipe: &Recipe,
    args: &Value,
    install: bool,
    replacement_started: &mut bool,
) -> Result<Value> {
    allowed(&recipe.root, args)?;
    recipe.current()?;
    recipe.dry()?;
    allowed(&recipe.root, args)?;
    recipe.current()?;
    stop_core(&recipe.root, false)?;
    *replacement_started = true;
    crate::service::driver(&recipe.root, false)?;
    crate::network_settings::enable_timestamps(&recipe.root, args)?;
    let service = crate::service::engine_service(&recipe.root)?;
    let binary = recipe.binary();
    let mut child = None;
    if install && service.is_none() {
        crate::service::create(&recipe.root, &binary)?;
    }
    if install || service.is_some() {
        crate::service::set_binary(&recipe.root, &binary)?;
        if install {
            crate::service::start_type(
                &recipe.root,
                windows_sys::Win32::System::Services::SERVICE_AUTO_START,
            )?;
        }
        allowed(&recipe.root, args)?;
        recipe.current()?;
        crate::service::start(&recipe.root, &binary)?;
    } else {
        child = Some(spawn_engine(recipe)?);
    }
    let mut retries = 0;
    let identity = loop {
        match stable(recipe, child.as_mut()) {
            Ok(id) => break id,
            Err(e) => {
                if let Some(c) = child.as_mut() {
                    let _ = c.terminate();
                }
                if child.is_some() && retries == 0 && crate::system::owned(&recipe.root)?.is_empty()
                {
                    allowed(&recipe.root, args)?;
                    recipe.current()?;
                    child = Some(spawn_engine(recipe)?);
                    retries += 1;
                    continue;
                }
                if install && service.is_none() {
                    let _ = crate::service::remove(&recipe.root);
                }
                return Err(e);
            }
        }
    };
    if install || service.is_some() {
        let state = crate::service::assert_owned(&recipe.root)?
            .context("Service disappeared after startup")?;
        ensure!(
            state.binary == binary && state.identity.as_ref() == Some(&identity),
            "Service launch identity changed"
        );
    }
    let actual = crate::process::process_arguments(&identity)?;
    ensure!(
        actual.len() == recipe.args.len() + 1
            && crate::process::same_path(
                Path::new(&actual[0]),
                &recipe.root.join("bin/winws2.exe")
            )
            && actual[1..] == recipe.args,
        "Started engine arguments differ from owned launch recipe"
    );
    let state = json!({"schema":1,"identity":identity,"inputs_hash":recipe.inputs_hash,"config_hash":recipe.config_hash,"settings":engine_settings(&recipe.settings),"arguments":recipe.args});
    atomic_write(
        &recipe.root.join("runtime/native-engine.json"),
        &serde_json::to_vec(&state)?,
    )?;
    atomic_write(
        &recipe.root.join("runtime/args-active.txt"),
        format!("{}\r\n", recipe.args.join("\r\n")).as_bytes(),
    )?;
    if let Some(c) = child {
        c.detach()?;
    }
    let warning = save_confirmed(recipe).err().map(|e| e.to_string());
    let _ = crate::maintenance::priority(
        &recipe.root,
        &json!({"enabled":true,"game_approved":args["game_approved"]}),
    );
    let manual = recipe.root.join("runtime/manual-stop.txt");
    if manual.exists() {
        no_reparse(&manual)?;
        std::fs::remove_file(manual)?;
    }
    let watcher = (|| -> Result<ProcessIdentity> {
        let executable = crate::tasks::executable(&recipe.root, args)?;
        let a = [
            OsString::from("--root"),
            recipe.root.as_os_str().into(),
            "watch".into(),
        ];
        let options = RunOptions {
            cwd: Some(recipe.root.clone()),
            timeout: Duration::from_secs(24 * 3600),
            ..Default::default()
        };
        OwnedChild::spawn_background(
            &executable,
            &a,
            &options,
            &recipe.root.join("runtime/network-watch-native.log"),
        )?
        .detach()
    })();
    let watcher_error = watcher.as_ref().err().map(ToString::to_string);
    let watcher = watcher.ok();
    let watch_task_error = if install || service.is_some() {
        crate::tasks::install(&recipe.root, &json!({"kind":"watch"}))
            .err()
            .map(|e| e.to_string())
    } else {
        None
    };
    let post_start = post_start_with(&recipe.settings, |action| match action {
        "gamepins" => {
            let mut options = args.clone();
            options["expected_engine"] = serde_json::to_value(&identity)?;
            crate::gamepins::update(&recipe.root, &options)
        }
        "telegram" => {
            let state = crate::telegram::start(&recipe.root, args)?;
            Ok(
                json!({"running":state["running"],"current":state["current"],
                    "port":state["port"],"component_tag":state["component_tag"]}),
            )
        }
        _ => anyhow::bail!("Unsupported post-start action: {action}"),
    });
    ensure!(
        crate::process_identity(identity.pid).ok().as_ref() == Some(&identity),
        "Owned engine exited while completing startup actions"
    );
    Ok(
        json!({"running":true,"processes":[identity],"restored":false,"confirmation_warning":warning,"inputs_hash":recipe.inputs_hash,"config_hash":recipe.config_hash,"watcher":watcher,"watcher_error":watcher_error,"watch_task_error":watch_task_error,"post_start":post_start}),
    )
}
fn post_start_with(settings: &Settings, mut action: impl FnMut(&str) -> Result<Value>) -> Value {
    let mut result = serde_json::Map::new();
    for name in ["gamepins", "telegram"] {
        let enabled = settings.get(name) == "on";
        let state = if enabled {
            match action(name) {
                Ok(value) => json!({"enabled":true,"ok":true,"result":value}),
                Err(error) => json!({"enabled":true,"ok":false,"error":format!("{error:#}")}),
            }
        } else {
            json!({"enabled":false})
        };
        result.insert(name.into(), state);
    }
    Value::Object(result)
}
fn stop_core(root: &Path, unload: bool) -> Result<()> {
    crate::system::owned(root)?;
    if crate::service::engine_service(root)?.is_some() {
        crate::service::stop(root)?;
    }
    for p in crate::system::owned(root)? {
        crate::terminate_owned(&p)?;
    }
    ensure!(
        crate::system::owned(root)?.is_empty(),
        "Предыдущий обход не удалось остановить"
    );
    ensure!(
        crate::service::engine_service(root)?.is_none_or(|s| {
            s.state == windows_sys::Win32::System::Services::SERVICE_STOPPED && s.pid == 0
        }),
        "Служба ещё работает"
    );
    if unload {
        crate::service::driver(root, true)?;
    }
    Ok(())
}

pub(crate) fn stop(root: &Path, args: &Value) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, "stop")?;
    allowed(root, args)?;
    stop_core(root, args["unload"].as_bool().unwrap_or(false))?;
    atomic_write(&root.join("runtime/manual-stop.txt"), b"manual\r\n")?;
    Ok(json!({"running":false,"processes":[]}))
}

pub(crate) fn stop_all(root: &Path, args: &Value) -> Result<Value> {
    ensure!(
        crate::is_admin()?,
        "Для остановки zapret нужны права администратора"
    );
    let _guard = ControlGuard::acquire(root, "stop-all")?;
    allowed_base(root, args)?;

    let engines = crate::system::zapret_processes()?;
    let mut failures = Vec::new();
    for service in crate::service::active_zapret_services(&engines)? {
        if let Err(error) = crate::service::stop_zapret(root, &service.name) {
            failures.push(format!("{}: {error:#}", service.name));
        }
    }
    stop_standalone_zapret(&mut failures)?;

    let remaining = crate::system::zapret_processes()?;
    let active_services = crate::service::active_zapret_services(&remaining)?;
    for service in active_services {
        failures.push(format!("{} ещё работает", service.name));
    }
    for engine in remaining {
        failures.push(format!("{} (PID {}) ещё работает", engine.name, engine.pid));
    }
    ensure!(
        failures.is_empty(),
        "Не удалось подтвердить остановку всех экземпляров zapret. {}",
        failures.join(". ")
    );
    atomic_write(&root.join("runtime/manual-stop.txt"), b"manual\r\n")?;
    let driver = match crate::service::driver(root, true) {
        Ok(result) => result,
        Err(error) => json!({"warning":format!("{error:#}")}),
    };
    Ok(json!({"running":false,"processes":[],"scope":"system","driver":driver}))
}

fn stop_standalone_zapret(failures: &mut Vec<String>) -> Result<()> {
    let engines = crate::system::zapret_processes()?;
    let service_pids: BTreeSet<_> = crate::service::snapshot()?
        .into_iter()
        .filter(|service| service.pid != 0)
        .map(|service| service.pid)
        .collect();
    for engine in engines {
        if service_pids.contains(&engine.pid) {
            continue;
        }
        let Some(identity) = engine.identity.filter(|identity| {
            identity.pid == engine.pid && crate::system::zapret_image(&identity.executable)
        }) else {
            continue;
        };
        if let Err(error) = crate::terminate_owned(&identity) {
            failures.push(format!("{} (PID {}): {error:#}", engine.name, engine.pid));
        }
    }
    Ok(())
}

pub(crate) fn start(root: &Path, args: &Value, install: bool) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, if install { "service-install" } else { "start" })?;
    allowed(root, args)?;
    crate::relocation::recover(root)?;
    if install {
        crate::service::assert_owned(root)?;
    } else {
        crate::service::engine_service(root)?;
    }
    crate::system::owned(root)?;
    crate::package::require_protected(root)?;
    if let Some(mut update) = zapret_core::RingUpdate::load(root)? {
        // An explicit start/restart authorizes replacing the stopped engine.
        // Never rename a mapped engine: its Windows identity would move too.
        stop_core(root, false)?;
        let attempt = update
            .apply()
            .and_then(|()| start_prepared(root, args, install))
            .and_then(|mut value| {
                update.commit()?;
                value["ring_update"] = json!("Applied");
                Ok(value)
            });
        return match attempt {
            Ok(value) => Ok(value),
            Err(error) => {
                stop_core(root, false).context("Stop failed Rust ring attempt")?;
                update
                    .rollback(true)
                    .context("Restore previous engine and Lua files")?;
                let mut restored = start_prepared(root, args, install).context(format!(
                    "Rust ring update failed ({error:#}); previous startup failed too"
                ))?;
                restored["restored"] = json!(true);
                restored["ring_update"] = json!("Rejected");
                restored["failed_attempt"] = json!(format!("{error:#}"));
                Ok(restored)
            }
        };
    }
    start_prepared(root, args, install)
}
fn start_prepared(root: &Path, args: &Value, install: bool) -> Result<Value> {
    let current = zapret_core::read_settings(root)?;
    let network = crate::system::network(root)?;
    let network_key = network["key"]
        .as_str()
        .filter(|s| s.len() == 64)
        .map(String::from);
    let recipe = Recipe::capture(root, &current, network_key.clone())?;
    let before_settings = current.values.clone();
    let desired_hash = recipe.config_hash.clone();
    let mut replacement_started = false;
    let result = activate(&recipe, args, install, &mut replacement_started);
    drop(recipe);
    match result {
        Ok(v) => Ok(v),
        Err(original) => {
            // Restore only after replacement actually stopped the prior configuration.
            if !replacement_started || !crate::system::games(root)?.is_empty() {
                return Err(original);
            }
            if let Err(cleanup) = stop_core(root, false) {
                return Err(original.context(format!("Failed attempt cleanup: {cleanup}")));
            }
            let Some(confirmed) = read_confirmed(root).unwrap_or(None) else {
                return Err(original);
            };
            if confirmed.config_hash == desired_hash
                || zapret_core::read_settings(root)?.values != before_settings
            {
                return Err(original);
            }
            let mut restored = current.clone();
            for (k, v) in confirmed.settings {
                restored.set(&k, &v)?;
            }
            let fallback = Recipe::capture(root, &restored, network_key)?;
            if fallback.inputs_hash != confirmed.inputs_hash
                || fallback.config_hash != confirmed.config_hash
            {
                return Err(original);
            }
            let mut outcome = activate(&fallback, args, false, &mut false)?;
            if zapret_core::read_settings(root)?.values == before_settings {
                zapret_core::save_settings(root, &restored)?;
            }
            outcome["restored"] = json!(true);
            outcome["failed_attempt"] = json!(original.to_string());
            Ok(outcome)
        }
    }
}
pub(crate) fn remove_service(root: &Path, args: &Value) -> Result<Value> {
    let _guard = ControlGuard::acquire(root, "service-remove")?;
    allowed(root, args)?;
    crate::system::owned(root)?;
    crate::service::remove(root)?;
    stop_core(root, true)?;
    Ok(json!({"removed":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmation_preserves_selected_games_and_the_legacy_record_shape() {
        let mut settings = Settings::default();
        settings.set("gameapps", "A Game.exe|NBA2K27.exe").unwrap();
        let old = engine_settings(&settings);
        assert_eq!(old.len(), 7);
        assert!(!old.contains_key("gameapps"));
        settings.set("game", "selected").unwrap();
        let selected = engine_settings(&settings);
        settings.set("gameapps", "Other.exe").unwrap();
        for (k, v) in &selected {
            settings.set(k, v).unwrap();
        }
        assert_eq!(settings.get("gameapps"), "a game|nba2k27");
        assert_eq!(engine_settings(&settings), selected);
    }
    fn inventory_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for directory in [
            "bin",
            "lua",
            "lists",
            "fake",
            "strategies",
            "tools",
            "windivert",
        ] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
        }
        std::fs::write(root.path().join("bin/winws2.exe"), b"engine fixture").unwrap();
        std::fs::write(
            root.path().join("bin/zapret-rust.exe"),
            b"controller fixture",
        )
        .unwrap();
        std::fs::write(
            root.path().join("strategies/alt12.txt"),
            b"strategy fixture",
        )
        .unwrap();
        root
    }

    #[test]
    fn launch_inventory_excludes_old_and_staged_native_build_images() {
        let root = inventory_fixture();
        for name in [
            ".native-build-0123456789abcdef0123456789abcdef.tmp",
            ".native-build-5213a59bc04e4b968837e406296e4edf.tmp.old",
            ".native-build-563c5dc414554c00907148b13c77efe3.tmp.old",
        ] {
            std::fs::write(root.path().join("bin").join(name), b"unused controller").unwrap();
        }
        let names = catalog(root.path()).unwrap();
        for name in &names {
            crate::storage::relative(root.path(), name)
                .unwrap_or_else(|error| panic!("Launch input {name}: {error:#}"));
        }
        let expected: BTreeSet<_> = [
            "CHECKSUMS.txt",
            "bin/winws2.exe",
            "bin/zapret-rust.exe",
            "strategies/alt12.txt",
            "tools/dpi-suite.json",
            "tools/targets.txt",
            "tools/upstream.txt",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(names.into_iter().collect::<BTreeSet<_>>(), expected);
    }

    #[test]
    fn unknown_dot_files_are_not_mistaken_for_native_build_artifacts() {
        let root = inventory_fixture();
        let unknown = "bin/.native-build-not-a-guid.tmp.old";
        std::fs::write(root.path().join(unknown), b"unknown input").unwrap();
        assert!(catalog(root.path()).unwrap().contains(&unknown.to_owned()));
        assert!(crate::storage::relative(root.path(), unknown).is_err());
        for invalid in ["bin/../outside", "bin/name:stream", "bin/CON.txt"] {
            assert!(crate::storage::relative(root.path(), invalid).is_err());
        }
    }

    #[test]
    fn confirmed_start_honors_gamepins_and_telegram_settings_and_keeps_hook_errors_separate() {
        let mut settings = Settings::default();
        settings.set("gamepins", "off").unwrap();
        settings.set("telegram", "off").unwrap();
        let disabled = post_start_with(&settings, |_| panic!("disabled hooks must not run"));
        assert_eq!(disabled["gamepins"]["enabled"], false);
        settings.set("gamepins", "on").unwrap();
        settings.set("telegram", "on").unwrap();
        let mut calls = Vec::new();
        let result = post_start_with(&settings, |name| {
            calls.push(name.to_owned());
            if name == "gamepins" {
                anyhow::bail!("fixture probe unavailable");
            }
            Ok(json!({"running":true}))
        });
        assert_eq!(calls, vec!["gamepins", "telegram"]);
        assert_eq!(result["gamepins"]["ok"], false);
        assert_eq!(result["telegram"]["ok"], true);
    }
}
