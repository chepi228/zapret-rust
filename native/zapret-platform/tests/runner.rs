use std::{
    ffi::OsString,
    io::{Read, Write},
    time::{Duration, Instant},
};
use zapret_platform::{OwnedChild, RunOptions, process_identity, run_owned, terminate_owned};

fn options(mode: &str) -> RunOptions {
    let mut o = RunOptions::default();
    o.env.insert("ZAPRET_PLATFORM_FIXTURE".into(), mode.into());
    o.timeout = Duration::from_secs(8);
    o
}
fn args() -> Vec<OsString> {
    ["--exact", "fixture_child", "--ignored", "--nocapture"]
        .into_iter()
        .map(Into::into)
        .collect()
}

#[test]
fn capture_stdin_stdout_stderr_and_exit() {
    let mut o = options("echo");
    o.stdin = Some(b"hello from stdin".to_vec());
    let r = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(!r.timed_out);
    assert_eq!(r.exit_code, 0);
    assert!(String::from_utf8_lossy(&r.stdout).contains("hello from stdin"));
    assert!(String::from_utf8_lossy(&r.stderr).contains("fixture stderr"));
}

#[test]
fn desktop_child_drops_split_admin_rights_and_preserves_owned_io() {
    use windows_sys::Win32::{Foundation::CloseHandle, Security::*, System::Threading::*};
    let mut raw = std::ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
        0
    );
    let mut kind = 0i32;
    let mut bytes = 0;
    let queried = unsafe {
        GetTokenInformation(
            raw,
            TokenElevationType,
            (&mut kind as *mut i32).cast(),
            4,
            &mut bytes,
        )
    };
    unsafe {
        CloseHandle(raw);
    }
    assert_ne!(queried, 0);
    let expected_elevated = zapret_platform::is_admin().unwrap() && kind != TokenElevationTypeFull;
    let mut o = options("desktop-token");
    o.desktop_user = true;
    o.stdin = Some(b"owned desktop input".to_vec());
    let result = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert_eq!(
        result.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!result.timed_out);
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(
        text.contains(&format!("child_elevated={expected_elevated}")),
        "parent_token_type={kind}; child stdout: {text}; stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(text.contains("owned desktop input"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("owned desktop stderr"));
}
#[test]
fn hard_timeout_reaps_descendants_and_does_not_kill_unrelated_process() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("descendant.json");
    let unrelated = OwnedChild::spawn(
        &std::env::current_exe().unwrap(),
        &args(),
        &options("sleep"),
    )
    .unwrap();
    let other = unrelated.identity().clone();
    let mut o = options("tree");
    o.timeout = Duration::from_millis(1500);
    o.env
        .insert("ZAPRET_PLATFORM_MARKER".into(), marker.as_os_str().into());
    let start = Instant::now();
    let r = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(r.timed_out);
    assert!(start.elapsed() < Duration::from_secs(6));
    let descendant: zapret_platform::ProcessIdentity =
        serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
    assert!(process_identity(descendant.pid).is_err());
    assert_eq!(process_identity(other.pid).unwrap(), other);
    drop(unrelated);
    assert!(process_identity(other.pid).is_err());
}
#[test]
fn refuses_pid_reuse_and_wrong_executable() {
    let child = OwnedChild::spawn(
        &std::env::current_exe().unwrap(),
        &args(),
        &options("sleep"),
    )
    .unwrap();
    let mut wrong = child.identity().clone();
    wrong.created_filetime += 1;
    assert!(!terminate_owned(&wrong).unwrap());
    wrong = child.identity().clone();
    wrong.executable = std::path::PathBuf::from("C:/Windows/not-the-child.exe");
    assert!(!terminate_owned(&wrong).unwrap());
    assert_eq!(
        &process_identity(child.identity().pid).unwrap(),
        child.identity()
    );
}

#[test]
fn process_identity_keeps_long_unicode_image_paths() {
    let directory = tempfile::tempdir().unwrap();
    let nested = (0..4).fold(directory.path().to_owned(), |path, _| {
        path.join("каталог".repeat(12))
    });
    std::fs::create_dir_all(&nested).unwrap();
    let binary = nested.join("процесс.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let binary = binary.canonicalize().unwrap();
    let child = OwnedChild::spawn(&binary, &args(), &options("sleep")).unwrap();
    let identity = process_identity(child.identity().pid).unwrap();
    assert_eq!(identity.executable.canonicalize().unwrap(), binary);
}
#[test]
fn bounded_output_drains_both_pipes_without_deadlock() {
    let mut o = options("flood");
    o.max_output_bytes = 32768;
    let r = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(!r.timed_out);
    assert!(r.output_truncated);
    assert!(r.stdout.len() + r.stderr.len() <= 32768);
}
#[test]
fn blocked_stdin_writer_obeys_hard_timeout() {
    let mut o = options("sleep");
    o.timeout = Duration::from_millis(300);
    o.stdin = Some(vec![b'x'; 16 * 1024 * 1024]);
    let start = Instant::now();
    let result = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(result.timed_out);
    assert!(start.elapsed() < Duration::from_secs(5));
}
#[test]
fn global_control_is_recursive_and_excludes_another_process() {
    let dir = tempfile::tempdir().unwrap();
    let outer = zapret_platform::ControlGuard::acquire(dir.path(), "test outer").unwrap();
    let inner = zapret_platform::ControlGuard::acquire(dir.path(), "test inner").unwrap();
    let mut o = options("control");
    o.env
        .insert("ZAPRET_PLATFORM_ROOT".into(), dir.path().as_os_str().into());
    let result = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(String::from_utf8_lossy(&result.stdout).contains("control_acquired=false"));
    drop(inner);
    drop(outer);
    let result = run_owned(&std::env::current_exe().unwrap(), &args(), &o).unwrap();
    assert!(String::from_utf8_lossy(&result.stdout).contains("control_acquired=true"));
}
#[test]
fn loaded_image_atomic_replacement_keeps_the_running_process_and_a_valid_target() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("loaded-fixture.exe");
    let staged = directory.path().join("staged-fixture.exe");
    let original = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(&target, &original).unwrap();
    let mut replacement = original.clone();
    replacement.extend_from_slice(b"ZAPRET-TEMP-REPLACEMENT-FIXTURE");
    std::fs::write(&staged, &replacement).unwrap();
    let mut child = OwnedChild::spawn(&target, &args(), &options("sleep")).unwrap();
    let identity = child.identity().clone();
    let replaced = zapret_core::atomic_replace_file(&staged, &target);
    match &replaced {
        Ok(()) => {
            eprintln!("loaded_image_replacement=supported");
            assert_eq!(std::fs::read(&target).unwrap(), replacement);
            assert!(!staged.exists());
        }
        Err(error) => {
            eprintln!("loaded_image_replacement=unavailable: {error:#}");
            assert_eq!(std::fs::read(&target).unwrap(), original);
            assert_eq!(std::fs::read(&staged).unwrap(), replacement);
        }
    }
    assert!(child.is_running().unwrap());
    assert_eq!(process_identity(identity.pid).unwrap(), identity);
    child.terminate().unwrap();
    if replaced.is_ok() {
        let result = run_owned(&target, &args(), &options("echo")).unwrap();
        assert!(!result.timed_out);
        assert_eq!(result.exit_code, 0);
    }
}
#[test]
#[ignore]
fn fixture_child() {
    match std::env::var("ZAPRET_PLATFORM_FIXTURE").as_deref() {
        Ok("desktop-token") => {
            use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::*};
            let own_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId()) };
            assert!(
                !own_process.is_null(),
                "A desktop child must be able to open its own process: {}",
                std::io::Error::last_os_error()
            );
            unsafe {
                CloseHandle(own_process);
            }
            let mut own_token = std::ptr::null_mut();
            assert_ne!(
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        windows_sys::Win32::Security::TOKEN_ALL_ACCESS,
                        &mut own_token,
                    )
                },
                0,
                "A desktop child must be able to manage its own primary token: {}",
                std::io::Error::last_os_error()
            );
            unsafe {
                CloseHandle(own_token);
            }
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap();
            println!("child_elevated={}", zapret_platform::is_admin().unwrap());
            println!("{input}");
            eprintln!("owned desktop stderr");
        }
        Ok("echo") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            print!("{s}");
            eprintln!("fixture stderr");
        }
        Ok("flood") => {
            for _ in 0..128 {
                std::io::stdout().write_all(&[b'o'; 8192]).unwrap();
                std::io::stderr().write_all(&[b'e'; 8192]).unwrap();
            }
        }
        Ok("tree") => {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(args())
                .env("ZAPRET_PLATFORM_FIXTURE", "sleep")
                .spawn()
                .unwrap();
            let id = process_identity(child.id()).unwrap();
            std::fs::write(
                std::env::var_os("ZAPRET_PLATFORM_MARKER").unwrap(),
                serde_json::to_vec(&id).unwrap(),
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(120));
            child.wait().unwrap();
        }
        Ok("control") => {
            let root = std::path::PathBuf::from(std::env::var_os("ZAPRET_PLATFORM_ROOT").unwrap());
            let acquired = zapret_platform::ControlGuard::acquire(&root, "fixture");
            println!("control_acquired={}", acquired.is_ok());
        }
        Ok("sleep") => std::thread::sleep(Duration::from_secs(120)),
        _ => panic!("explicit fixture mode required"),
    }
}
