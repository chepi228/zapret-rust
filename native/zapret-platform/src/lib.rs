//! Native Windows control plane. Importing this crate has no side effects.
mod certificates;
mod com;
mod control;
mod dns_cache;
mod engine;
mod gamepins;
mod hosts;
mod launch;
mod legacy;
mod maintenance;
mod metrics;
mod network_events;
mod network_settings;
mod package;
mod process;
mod profiles;
mod relocation;
mod scheduler;
mod service;
mod storage;
mod system;
mod tasks;
mod telegram;
mod tracking;
mod uninstall;
mod wifi;
mod wmi;
pub use control::ControlGuard;
pub use dns_cache::{ForwardDnsCache, forward_dns_cache};
pub use engine::{validate_capture_filter, validate_engine_args};
pub use hosts::{
    DISCORD_MEDIA_GROUP, DISCORD_MEDIA_HOST, reference_entries as hosts_reference_entries,
};
pub use launch::validate_launch;
pub use maintenance::is_admin;
pub use metrics::ProcessMetrics;
pub use network_events::NetworkEvents;
pub use process::{
    OwnedChild, ProcessIdentity, RunOptions, RunOutput, process_identity, run_owned,
    terminate_owned,
};
pub use system::configured_proxy_server;
/// Entry point for the exact-owned hidden Telegram child.
pub fn run_telegram_core(path: &std::path::Path, expected_hash: &str) -> anyhow::Result<()> {
    telegram::run_core(path, expected_hash)
}
pub fn protect_path(path: &std::path::Path) -> anyhow::Result<()> {
    control::protect(path)
}
/// Published executables and package files remain readable before UAC elevation.
pub fn protect_readable_path(path: &std::path::Path) -> anyhow::Result<()> {
    control::protect_readable(path)
}
pub fn trusted_path(path: &std::path::Path) -> anyhow::Result<bool> {
    control::trusted(path)
}
/// System-wide QPC milliseconds use the same monotonic origin in every process.
pub fn monotonic_ms() -> anyhow::Result<f64> {
    use anyhow::ensure;
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut frequency = 0;
    let mut counter = 0;
    ensure!(
        unsafe { QueryPerformanceFrequency(&mut frequency) } != 0 && frequency > 0,
        "Monotonic performance-counter frequency is unavailable"
    );
    ensure!(
        unsafe { QueryPerformanceCounter(&mut counter) } != 0,
        "Monotonic performance counter is unavailable"
    );
    let milliseconds = counter as f64 * 1000.0 / frequency as f64;
    ensure!(milliseconds.is_finite(), "Monotonic clock value is invalid");
    Ok(milliseconds)
}
pub(crate) fn time_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        / 100
        + 116444736000000000
}
pub fn command(
    root: &std::path::Path,
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    match name {
        "status" => {
            let observation = system::engine_observation(root, system::processes()?);
            let processes = observation.processes;
            let unidentified = observation.unidentified;
            let service = service::status_value(service::info(root));
            let service_running = service["owned"] == true
                && service["state"]
                    .as_u64()
                    .is_some_and(|s| (2..=7).contains(&s));
            let known = unidentified.is_empty()
                && service["known"] != false
                && service["ownership_known"] != false;
            Ok(
                json!({"known":known,"ownership_known":known,"running":!processes.is_empty()||service_running,"processes":processes,"service":service,"unidentified_engine_processes":unidentified,"version":zapret_core::PACKAGE_VERSION}),
            )
        }
        "start" | "restart" => launch::start(root, args, false),
        "control-check" => {
            launch::allowed(root, args)?;
            Ok(json!({"allowed":true}))
        }
        "stop" => launch::stop(root, args),
        "stop-all" => launch::stop_all(root, args),
        "service-status" => Ok(service::status_value(service::info(root))),
        "service-install" => launch::start(root, args, true),
        "service-remove" => launch::remove_service(root, args),
        "service-autostart" => launch::autostart(root, args),
        "legacy-status" => legacy::status(root, args),
        "service-migrate" => legacy::migrate_service(root, args),
        "task-migrate" => legacy::migrate_task(root, args),
        "legacy-migrate" => {
            let service = legacy::migrate_service(root, args)?;
            let task = legacy::migrate_task(root, args)?;
            Ok(json!({"service":service,"task":task}))
        }
        "task-status" => tasks::status(root, args),
        "task-configure" => tasks::configure(root, args),
        "task-spec" => Ok(json!({"xml":tasks::specification(root,args)?})),
        "task-install" => {
            let _guard = ControlGuard::acquire(root, "task-install")?;
            launch::allowed(root, args)?;
            tasks::install(root, args)
        }
        "task-remove" => {
            let _guard = ControlGuard::acquire(root, "task-remove")?;
            launch::allowed(root, args)?;
            tasks::action(root, args, tasks::Action::Delete)
        }
        "telegram-status" => telegram::status(root),
        "telegram-media" => telegram::media_check(root),
        "telegram-start" => telegram::start(root, args),
        "telegram-stop" => telegram::stop(root, args),
        "telegram-run" => telegram::run(root),
        "admin" => Ok(json!({"is_admin":is_admin()?})),
        "elevate" => maintenance::elevate(root, args),
        "notify" => maintenance::notify(args),
        "priority" => maintenance::priority(root, args),
        "prefer-ipv4" => maintenance::prefer_ipv4(root, args),
        "network-settings-worker" => network_settings::worker(root, args),
        "tcp-timestamps-status" => network_settings::timestamps_status(root),
        "conflicts" => maintenance::conflicts(root),
        "discord-cache" => maintenance::discord_cache(root, args),
        "uninstall" => uninstall::run(root, args),
        "processes" => Ok(json!(system::processes()?)),
        "services" => Ok(json!(service::snapshot()?)),
        "process-metrics" => metrics::metrics(args),
        "games" => Ok(json!(system::games(root)?)),
        "adapters" => system::adapters(),
        "wifi-events" => wifi::events(args),
        "network" | "network-context" => {
            system::network_snapshot(root, args["identity_only"] == true)
        }
        "proxy" => system::proxy(),
        "certificates" => certificates::inspect(),
        "protect-package" | "unprotect-package" | "unblock-package" => {
            package::dispatch(root, name)
        }
        "tcp-connections" => system::tcp_connections(),
        "track" | "track-replay" | "voice-capture" | "trace-guard" => {
            tracking::dispatch(root, name, args)
        }
        "hosts-status" => hosts::status(root, args),
        "hosts-set" => hosts::set(root, args),
        "gamepins-status" => gamepins::status(root, args),
        "gamepins-probe" => gamepins::probe(root, args),
        "gamepins-update" => gamepins::update(root, args),
        "telegram-config" => telegram::configure(root, args),
        "telegram-open-link" => telegram::open_link(args),
        _ => anyhow::bail!("Unsupported Windows platform command: {name}"),
    }
}
#[cfg(test)]
mod clock_tests {
    #[test]
    fn qpc_milliseconds_are_finite_and_nondecreasing() {
        let mut previous = super::monotonic_ms().unwrap();
        assert!(previous.is_finite());
        for _ in 0..64 {
            let current = super::monotonic_ms().unwrap();
            assert!(current >= previous);
            previous = current;
        }
    }
}
