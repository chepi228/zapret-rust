use crate::{
    ProcessIdentity,
    process::{Handle, identity_handle, same_path},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    mem::{size_of, zeroed},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{ProcessStatus::*, Threading::*},
};
pub(crate) fn metrics(args: &Value) -> Result<Value> {
    let identity: ProcessIdentity = serde_json::from_value(args["identity"].clone())?;
    ProcessMetrics::open(identity)?.sample()
}

pub struct ProcessMetrics {
    handle: Handle,
    identity: ProcessIdentity,
}

impl ProcessMetrics {
    pub fn open(identity: ProcessIdentity) -> Result<Self> {
        let handle = Handle::new(unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
                0,
                identity.pid,
            )
        })?;
        let actual = identity_handle(handle.0, identity.pid)?;
        ensure!(
            actual.created_filetime == identity.created_filetime
                && same_path(&actual.executable, &identity.executable),
            "Process metrics identity changed"
        );
        Ok(Self { handle, identity })
    }

    pub fn is_running(&self) -> Result<bool> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(std::io::Error::last_os_error().into()),
        }
    }

    /// Final CPU accounting remains available through this exact process handle
    /// after exit. It does not represent a new live resource sample.
    pub fn cpu_total_ms(&self) -> Result<f64> {
        let mut created: FILETIME = unsafe { zeroed() };
        let mut exited = unsafe { zeroed() };
        let mut kernel = unsafe { zeroed() };
        let mut user = unsafe { zeroed() };
        ensure!(
            unsafe {
                GetProcessTimes(
                    self.handle.0,
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            } != 0,
            "Process CPU accounting: {}",
            std::io::Error::last_os_error()
        );
        let ticks = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
        ensure!(
            ticks(created) == self.identity.created_filetime,
            "Process metrics creation time changed"
        );
        Ok((ticks(kernel) + ticks(user)) as f64 / 10000.0)
    }

    pub fn sample(&self) -> Result<Value> {
        let identity = &self.identity;
        let handle = &self.handle;
        let started = Instant::now();
        ensure!(self.is_running()?, "Process metrics process exited");
        let mut created: FILETIME = unsafe { zeroed() };
        let mut exited = unsafe { zeroed() };
        let mut kernel = unsafe { zeroed() };
        let mut user = unsafe { zeroed() };
        ensure!(
            unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }
                != 0,
            "Process times: {}",
            std::io::Error::last_os_error()
        );
        let mut memory: PROCESS_MEMORY_COUNTERS_EX = unsafe { zeroed() };
        memory.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        ensure!(
            unsafe {
                K32GetProcessMemoryInfo(
                    handle.0,
                    (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
                    size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
                )
            } != 0,
            "Process memory: {}",
            std::io::Error::last_os_error()
        );
        let ticks = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
        ensure!(
            ticks(created) == identity.created_filetime,
            "Process metrics creation time changed"
        );
        ensure!(
            self.is_running()?,
            "Process metrics process exited during sampling"
        );
        Ok(
            json!({"ready":true,"status":"Ready","pid":identity.pid,"created_filetime":identity.created_filetime,"identity":identity,"cpu_total_ms":(ticks(kernel)+ticks(user)) as f64/10000.0,"private_bytes":memory.PrivateUsage,"working_set_bytes":memory.WorkingSetSize,"peak_working_set_bytes":memory.PeakWorkingSetSize,"observed_ms":crate::time_filetime()/10000,"read_duration_ms":started.elapsed().as_secs_f64()*1000.0}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnedChild, RunOptions};
    use std::{path::PathBuf, time::Duration};

    #[test]
    fn observer_pins_lifetime_rejects_stale_identity_and_retains_final_cpu() {
        let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/ping.exe");
        let mut child = OwnedChild::spawn(
            &exe,
            &["-n".into(), "20".into(), "127.0.0.1".into()],
            &RunOptions {
                timeout: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .unwrap();
        let identity = child.identity().clone();
        let observer = ProcessMetrics::open(identity.clone()).unwrap();
        let mut stale = identity;
        stale.created_filetime += 1;
        assert!(ProcessMetrics::open(stale).is_err());
        assert_eq!(observer.sample().unwrap()["ready"], true);
        child.terminate().unwrap();
        assert!(!observer.is_running().unwrap());
        assert!(observer.sample().is_err());
        assert!(observer.cpu_total_ms().unwrap() >= 0.);
    }
}
