//! Optional startup notifications for the selector's exact child process.
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::System::Threading::{
    OpenSemaphoreW, ReleaseSemaphore, SEMAPHORE_MODIFY_STATE,
};

static STARTUP: Mutex<Option<OwnedHandle>> = Mutex::new(None);

fn valid_name(name: &str) -> bool {
    name.strip_prefix("Local\\zapret-trial-")
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

#[unsafe(no_mangle)]
extern "C" fn zapret_trial_starting() {
    let Ok(name) = std::env::var("ZAPRET_TRIAL_STARTUP") else {
        return;
    };
    if !valid_name(&name) {
        return;
    }
    // Only this engine may acknowledge the launch. Do not pass the name to
    // child programs started by its configuration. Called at Windows CRT entry.
    unsafe { std::env::remove_var("ZAPRET_TRIAL_STARTUP") };
    let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    let raw = unsafe { OpenSemaphoreW(SEMAPHORE_MODIFY_STATE, 0, wide.as_ptr()) };
    if raw.is_null() {
        return;
    }
    // Open before the sandbox. A reconnect must not emit another startup signal.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    if let Ok(mut slot) = STARTUP.lock() {
        if unsafe { ReleaseSemaphore(handle.as_raw_handle(), 1, ptr::null_mut()) } != 0 {
            *slot = Some(handle);
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_trial_ready() {
    if let Some(handle) = STARTUP.lock().ok().and_then(|mut slot| slot.take()) {
        unsafe { ReleaseSemaphore(handle.as_raw_handle(), 1, ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::valid_name;

    #[test]
    fn only_local_trial_semaphores_are_opened() {
        let token = "d2255371e15c743a8510ad6f2a7384f3";
        assert!(valid_name(&format!("Local\\zapret-trial-{token}")));
        for name in [
            format!("Global\\zapret-trial-{token}"),
            format!("Local\\another-event-{token}"),
            format!("Local\\zapret-trial-{token}0"),
            "Local\\zapret-trial-short".into(),
        ] {
            assert!(!valid_name(&name));
        }
    }
}
