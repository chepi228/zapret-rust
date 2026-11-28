use anyhow::Result;
use std::{
    env,
    ffi::OsString,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    process, ptr, thread,
    time::Duration,
};
use windows_sys::Win32::System::Threading::{
    OpenSemaphoreW, ReleaseSemaphore, SEMAPHORE_MODIFY_STATE,
};
use zapret_platform::{OwnedChild, RunOptions};

const BEHAVIOR: &str = "ZAPRET_TEST_TRIAL_CHILD";

pub(super) fn spawn(behavior: &str, mut options: RunOptions) -> Result<OwnedChild> {
    options.env.insert(BEHAVIOR.into(), behavior.into());
    let args = ["--ignored", "--exact", "selection::trial_fixture::child"].map(OsString::from);
    OwnedChild::spawn(&env::current_exe()?, &args, &options)
}

pub(super) fn post(handle: &OwnedHandle) -> io::Result<()> {
    if unsafe { ReleaseSemaphore(handle.as_raw_handle(), 1, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[test]
#[ignore = "spawned by selection tests as a child process"]
fn child() {
    let Ok(behavior) = env::var(BEHAVIOR) else {
        return;
    };
    match behavior.as_str() {
        "exit-19" => process::exit(19),
        "exit-before-ready" => {
            // Stay alive past the two-second grace period for legacy engines.
            thread::sleep(Duration::from_millis(2300));
            process::exit(3);
        }
        "ready" => {
            let name = env::var("ZAPRET_TRIAL_STARTUP").unwrap();
            let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
            let raw = unsafe { OpenSemaphoreW(SEMAPHORE_MODIFY_STATE, 0, wide.as_ptr()) };
            assert!(!raw.is_null(), "{}", io::Error::last_os_error());
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            post(&handle).unwrap();
            loop {
                thread::park();
            }
        }
        _ => panic!("unknown trial fixture behavior: {behavior}"),
    }
}
