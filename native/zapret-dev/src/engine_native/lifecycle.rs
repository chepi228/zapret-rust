use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    System::{JobObjects::*, Threading::*},
};

struct Handles {
    job: HANDLE,
    process: HANDLE,
    thread: HANDLE,
}
impl Drop for Handles {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.job);
            if !self.thread.is_null() {
                CloseHandle(self.thread);
            }
            if !self.process.is_null() {
                CloseHandle(self.process);
            }
        }
    }
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Keep a private kill-on-close job while testing parent exit and its child.
/// Both cases use the explicit no-driver engine selftest.
pub(crate) fn run(bin: &Path, temporary: &Path) -> Result<usize> {
    for daemon in [false, true] {
        let root = temporary.join(if daemon { "daemon" } else { "no-stdio" });
        let relative = root.join("relative-subdir");
        fs::create_dir_all(&relative)?;
        let writable = root.join("writable");
        let marker = writable.join("complete.txt");
        let executable = bin.join("winws2.exe");
        let mut args = vec![
            executable.to_str().context("Engine fixture path encoding")?.to_owned(),
            "--intercept=0".into(),
            "--chdir=relative-subdir".into(),
            format!("--writable={}", writable.display()),
            "--lua-init=timer_set('lifecycle',function() local f=assert(io.open(os.getenv('WRITABLE')..'/complete.txt','wb'));assert(f:write('completed'));assert(f:close());os.exit(0) end,100,true)".into(),
        ];
        if daemon {
            args.push("--daemon".into());
        }
        let mut command: Vec<_> = zapret_core::windows_command_line(&args)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let image = wide(executable.as_os_str());
        let directory = wide(root.as_os_str());
        let mut environment = BTreeMap::new();
        for (key, value) in std::env::vars_os().chain([
            (
                OsString::from("__COMPAT_LAYER"),
                OsString::from("RunAsInvoker"),
            ),
            (OsString::from("ZAPRET_RING_SELFTEST"), OsString::from("1")),
        ]) {
            environment.insert(key.to_string_lossy().to_uppercase(), (key, value));
        }
        let mut block = Vec::new();
        for (_, (mut key, value)) in environment {
            key.push("=");
            key.push(value);
            block.extend(wide(&key));
        }
        block.push(0);
        unsafe {
            let job = CreateJobObjectW(null(), null());
            ensure!(
                !job.is_null(),
                "Create lifecycle fixture job: {}",
                std::io::Error::last_os_error()
            );
            let mut handles = Handles {
                job,
                process: null_mut(),
                thread: null_mut(),
            };
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ensure!(
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
                ) != 0,
                "Configure lifecycle fixture job"
            );
            let mut startup: STARTUPINFOW = zeroed();
            startup.cb = size_of::<STARTUPINFOW>() as u32;
            startup.dwFlags = STARTF_USESTDHANDLES;
            // Deliberately absent handles reproduce a service's initial stdio.
            let mut process: PROCESS_INFORMATION = zeroed();
            ensure!(
                CreateProcessW(
                    image.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    0,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    block.as_ptr().cast(),
                    directory.as_ptr(),
                    &startup,
                    &mut process
                ) != 0,
                "Start lifecycle fixture: {}",
                std::io::Error::last_os_error()
            );
            handles.process = process.hProcess;
            handles.thread = process.hThread;
            if AssignProcessToJobObject(job, process.hProcess) == 0 {
                let error = std::io::Error::last_os_error();
                TerminateProcess(process.hProcess, 1);
                anyhow::bail!("Own lifecycle fixture: {error}");
            }
            ensure!(
                ResumeThread(process.hThread) != u32::MAX,
                "Resume lifecycle fixture"
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
                ensure!(
                    QueryInformationJobObject(
                        job,
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut()
                    ) != 0,
                    "Observe owned lifecycle fixture"
                );
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "Lifecycle fixture timed out (daemon {daemon})"
                );
                thread::sleep(Duration::from_millis(10));
            }
            ensure!(
                WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0,
                "Lifecycle parent did not exit"
            );
            let mut code = 0;
            ensure!(
                GetExitCodeProcess(process.hProcess, &mut code) != 0 && code == 0,
                "Lifecycle parent exit {code} (daemon {daemon})"
            );
            ensure!(
                fs::read(&marker)
                    .with_context(|| format!("Lifecycle marker missing (daemon {daemon})"))?
                    == b"completed",
                "Lifecycle fixture marker differs"
            );
        }
        println!("ok native lifecycle with absent stdio, daemon {daemon}");
    }
    Ok(2)
}
