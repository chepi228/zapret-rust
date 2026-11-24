use crate::interrupt;
use anyhow::{Result, ensure};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError, SetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateSemaphoreW, WaitForSingleObject},
};
use zapret_platform::{OwnedChild, RunOptions};

pub(super) struct Signal(OwnedHandle);

impl Signal {
    pub(super) fn for_child(options: &mut RunOptions) -> Option<Self> {
        // Never propagate another launch's rendezvous, even if setup fails.
        let key = "ZAPRET_TRIAL_STARTUP";
        options.env.insert(key.into(), "".into());
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).ok()?;
        let name = format!("Local\\zapret-trial-{:032x}", u128::from_be_bytes(bytes));
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            SetLastError(0);
            CreateSemaphoreW(ptr::null(), 0, 2, wide.as_ptr())
        };
        if raw.is_null() {
            return None;
        }
        let collision = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if collision {
            return None;
        }
        options.env.insert(key.into(), name.into());
        Some(Self(handle))
    }

    fn notified(&self, interval: Duration) -> Result<bool> {
        let status =
            unsafe { WaitForSingleObject(self.0.as_raw_handle(), interval.as_millis() as u32) };
        ensure!(
            matches!(status, WAIT_OBJECT_0 | WAIT_TIMEOUT),
            "Trial startup wait: {}",
            std::io::Error::last_os_error()
        );
        Ok(status == WAIT_OBJECT_0)
    }
}

pub(super) fn wait(child: &mut OwnedChild, signal: Option<&Signal>) -> Result<bool> {
    let started = Instant::now();
    let mut announced = false;
    loop {
        interrupt::check()?;
        if !child.is_running()? {
            return Ok(false);
        }
        // Older engines never announce the protocol. Keep their original grace
        // period. An engine that announced must positively finish initialization.
        let limit = Duration::from_secs(if announced { 15 } else { 2 });
        let interval = limit
            .saturating_sub(started.elapsed())
            .min(Duration::from_millis(50));
        if let Some(signal) = signal {
            if signal.notified(interval)? {
                if announced {
                    interrupt::check()?;
                    return child.is_running();
                }
                announced = true;
                continue;
            }
        } else {
            child.wait_for_exit(interval)?;
        }
        if started.elapsed() >= limit {
            if announced {
                eprintln!("Движок не подтвердил готовность за {} с.", limit.as_secs());
                child.terminate()?;
                return Ok(false);
            }
            return child.is_running();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, path::PathBuf};

    fn fixture(script: &str) -> Result<bool> {
        let mut options = RunOptions::default();
        let signal = Signal::for_child(&mut options).expect("create a private test semaphore");
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let args = ["-NoProfile", "-NonInteractive", "-Command", script].map(OsString::from);
        let mut child = OwnedChild::spawn(&shell, &args, &options)?;
        // Start the trial in the announced state. PowerShell startup on CI can
        // exceed the legacy engine grace period before the script executes.
        let posted = unsafe {
            windows_sys::Win32::System::Threading::ReleaseSemaphore(
                signal.0.as_raw_handle(),
                1,
                ptr::null_mut(),
            )
        };
        ensure!(posted != 0, "Could not announce fixture initialization");
        wait(&mut child, Some(&signal))
    }

    #[test]
    fn initialization_alone_does_not_start_measurements() {
        assert!(!fixture("Start-Sleep -Milliseconds 2300; exit 3").unwrap());
        assert!(fixture(
            "$s=[Threading.Semaphore]::OpenExisting($env:ZAPRET_TRIAL_STARTUP); $null=$s.Release(); Start-Sleep -Seconds 20"
        ).unwrap());
    }
}
