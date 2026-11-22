use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zapret_platform::{OwnedChild, RunOptions, process_identity, run_owned, terminate_owned};

fn image() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zapret-worker"))
}
fn fixture() -> tempfile::TempDir {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path().join("пакет & пробел");
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::copy(image(), root.join("bin/zapret-rust-worker.exe")).unwrap();
    let source = folder.path().join("fixture.rs");
    fs::write(&source, include_bytes!("fixtures/child.rs")).unwrap();
    let rustc = std::env::var_os("RUSTC")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .or_else(|| {
            std::env::var_os("PATH").and_then(|v| {
                std::env::split_paths(&v)
                    .map(|p| p.join("rustc.exe"))
                    .find(|p| p.is_file())
            })
        })
        .expect("test requires the Rust compiler used by Cargo");
    let output = root.join("bin/zapret-rust.exe");
    let mut arguments = vec![
        "--edition=2024".into(),
        "--crate-name".into(),
        "gui_fixture".into(),
        source.into_os_string(),
        "-o".into(),
        output.into_os_string(),
    ];
    if cfg!(target_env = "gnu") {
        arguments.extend([
            "-C".into(),
            "linker-flavor=ld.lld".into(),
            "-C".into(),
            "linker=rust-lld".into(),
        ]);
    }
    let result = run_owned(
        &rustc,
        &arguments,
        &RunOptions {
            timeout: Duration::from_secs(30),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.exit_code,
        0,
        "compiler {}: {} {}",
        rustc.display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    folder
}
fn args(root: &Path) -> Vec<OsString> {
    vec![
        "--root".into(),
        root.as_os_str().into(),
        "notify".into(),
        "--watch".into(),
    ]
}

#[test]
fn gui_image_has_no_console_and_requires_an_explicit_background_command() {
    let bytes = fs::read(image()).unwrap();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(
        u16::from_le_bytes(bytes[pe + 24 + 68..pe + 24 + 70].try_into().unwrap()),
        2
    );
    let result = run_owned(&image(), &["--self-check".into()], &RunOptions::default()).unwrap();
    assert_eq!(result.exit_code, 0);
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["console_window"], false);
    let rejected = run_owned(&image(), &[], &RunOptions::default()).unwrap();
    assert_eq!(rejected.exit_code, 1);
}
#[test]
fn gui_host_rejects_another_gui_image_as_its_controller() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("bin")).unwrap();
    fs::copy(image(), temporary.path().join("bin/zapret-rust.exe")).unwrap();
    fs::copy(image(), temporary.path().join("bin/zapret-rust-worker.exe")).unwrap();
    let result = run_owned(
        &temporary.path().join("bin/zapret-rust-worker.exe"),
        &args(temporary.path()),
        &RunOptions::default(),
    )
    .unwrap();
    assert_eq!(result.exit_code, 1);
    assert!(String::from_utf8_lossy(&result.stderr).contains("console controller"));
}
#[test]
fn gui_host_preserves_unicode_arguments_exit_code_and_hidden_child_output() {
    let folder = fixture();
    let root = folder.path().join("пакет & пробел");
    let result = run_owned(
        &root.join("bin/zapret-rust-worker.exe"),
        &args(&root),
        &RunOptions::default(),
    )
    .unwrap();
    assert_eq!(result.exit_code, 17);
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("console=false"), "{stdout}");
    assert!(
        stdout.contains("пакет & пробел")
            && stdout.contains("arg=notify\n")
            && stdout.contains("arg=--watch\n"),
        "{stdout}"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("fixture stderr"));
}
fn waiting_host(root: &Path, ready: &Path) -> OwnedChild {
    OwnedChild::spawn(
        &root.join("bin/zapret-rust-worker.exe"),
        &args(root),
        &RunOptions {
            timeout: Duration::from_secs(15),
            env: [
                (
                    OsString::from("ZAPRET_GUI_FIXTURE_WAIT"),
                    OsString::from("1"),
                ),
                (
                    OsString::from("ZAPRET_GUI_FIXTURE_READY"),
                    ready.as_os_str().into(),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    )
    .unwrap()
}
fn ready_identity(ready: &Path) -> zapret_platform::ProcessIdentity {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(ready) {
            if let Ok(pid) = text.parse() {
                return process_identity(pid).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("GUI fixture did not become ready")
}
#[test]
fn terminating_only_the_host_closes_its_job_without_killing_another_host() {
    let folder = fixture();
    let root = folder.path().join("пакет & пробел");
    let first_ready = folder.path().join("first.ready");
    let other_ready = folder.path().join("other.ready");
    let first = waiting_host(&root, &first_ready);
    let mut other = waiting_host(&root, &other_ready);
    let child = ready_identity(&first_ready);
    let unrelated = ready_identity(&other_ready);
    assert!(terminate_owned(first.identity()).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && process_identity(child.pid).is_ok_and(|actual| actual == child)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    // Keep the test's outer job alive: only termination of the GUI host must
    // close its inner job and clean up the hidden controller.
    assert!(!process_identity(child.pid).is_ok_and(|actual| actual == child));
    assert_eq!(process_identity(unrelated.pid).unwrap(), unrelated);
    assert!(other.is_running().unwrap());
    first.finish().unwrap();
    other.terminate().unwrap();
}
