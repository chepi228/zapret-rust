use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::Write,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReadFile},
    System::{
        JobObjects::*,
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::*,
    },
    UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId},
};

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub timeout: Duration,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<OsString, OsString>,
    pub max_output_bytes: usize,
    pub stdin: Option<Vec<u8>>,
    /// Run desktop applications in the ordinary interactive user's context.
    pub desktop_user: bool,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            cwd: None,
            env: BTreeMap::new(),
            max_output_bytes: 8 * 1024 * 1024,
            stdin: None,
            desktop_user: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub created_filetime: u64,
    pub executable: PathBuf,
}
#[derive(Debug)]
pub struct RunOutput {
    pub identity: ProcessIdentity,
    pub exit_code: u32,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
}
pub(crate) struct Handle(pub HANDLE);
impl Handle {
    pub(crate) fn new(h: HANDLE) -> Result<Self> {
        ensure!(
            !h.is_null() && h != INVALID_HANDLE_VALUE,
            "Windows handle: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(h))
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct DesktopParent {
    process: Handle,
    handles: Vec<HANDLE>,
    security: Vec<usize>,
    token_security: Vec<usize>,
}
impl Drop for DesktopParent {
    fn drop(&mut self) {
        for remote in self.handles.drain(..) {
            let mut local = null_mut();
            unsafe {
                DuplicateHandle(
                    self.process.0,
                    remote,
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                );
                if !local.is_null() {
                    CloseHandle(local);
                }
            }
        }
    }
}

fn desktop_object_security(handle: HANDLE) -> Result<Vec<usize>> {
    unsafe {
        let information = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        let mut needed = 0;
        GetKernelObjectSecurity(handle, information, null_mut(), 0, &mut needed);
        ensure!(
            needed > 0 && needed <= 65536,
            "Desktop object security size is unavailable"
        );
        let mut security = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        ensure!(
            GetKernelObjectSecurity(
                handle,
                information,
                security.as_mut_ptr().cast(),
                (security.len() * size_of::<usize>()) as u32,
                &mut needed,
            ) != 0,
            "Read desktop object security: {}",
            std::io::Error::last_os_error()
        );
        Ok(security)
    }
}

fn desktop_parent(inherited: &[HANDLE]) -> Result<Option<DesktopParent>> {
    unsafe {
        let mut raw = null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) != 0,
            "Open desktop caller token: {}",
            std::io::Error::last_os_error()
        );
        let caller = Handle::new(raw)?;
        let mut kind = 0i32;
        let mut bytes = 0;
        ensure!(
            GetTokenInformation(
                caller.0,
                TokenElevationType,
                (&mut kind as *mut i32).cast(),
                size_of::<i32>() as u32,
                &mut bytes
            ) != 0,
            "Query desktop token type: {}",
            std::io::Error::last_os_error()
        );
        // Normal/default tokens already match the caller's desktop context.
        if kind != TokenElevationTypeFull {
            return Ok(None);
        }
        // Launch through the interactive parent instead of duplicating UAC
        // tokens, which need privileges a split-token administrator may lack.
        // https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
        let window = GetShellWindow();
        ensure!(
            !window.is_null(),
            "Interactive desktop shell is unavailable"
        );
        let mut shell_pid = 0;
        GetWindowThreadProcessId(window, &mut shell_pid);
        let process = Handle::new(OpenProcess(
            PROCESS_CREATE_PROCESS
                | PROCESS_DUP_HANDLE
                | PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_READ_CONTROL,
            0,
            shell_pid,
        ))?;
        let mut shell_token = null_mut();
        ensure!(
            OpenProcessToken(process.0, TOKEN_READ, &mut shell_token) != 0,
            "Open desktop shell token: {}",
            std::io::Error::last_os_error()
        );
        let shell_token = Handle::new(shell_token)?;
        let mut caller_session = 0u32;
        let mut shell_session = 0u32;
        ensure!(
            GetTokenInformation(
                caller.0,
                TokenSessionId,
                (&mut caller_session as *mut u32).cast(),
                4,
                &mut bytes
            ) != 0
                && GetTokenInformation(
                    shell_token.0,
                    TokenSessionId,
                    (&mut shell_session as *mut u32).cast(),
                    4,
                    &mut bytes
                ) != 0
                && caller_session == shell_session,
            "Desktop shell belongs to a different session"
        );
        let mut elevation: TOKEN_ELEVATION = zeroed();
        ensure!(
            GetTokenInformation(
                shell_token.0,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut bytes
            ) != 0
                && elevation.TokenIsElevated == 0,
            "Interactive desktop is not running with ordinary user rights"
        );
        // A limited token alone is insufficient: the default process/thread
        // security descriptors still come from the elevated creator. That
        // prevents browser workers from opening their own broker process.
        // Copy the desktop parent's DACL and integrity label for these new
        // objects; do not alter the shell or the caller's security settings.
        let security = desktop_object_security(process.0)?;
        let token_security = desktop_object_security(shell_token.0)?;
        let mut parent = DesktopParent {
            process,
            handles: Vec::new(),
            security,
            token_security,
        };
        for handle in inherited {
            let mut remote = null_mut();
            ensure!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    *handle,
                    parent.process.0,
                    &mut remote,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS
                ) != 0,
                "Duplicate desktop child IO handle: {}",
                std::io::Error::last_os_error()
            );
            parent.handles.push(remote);
        }
        Ok(Some(parent))
    }
}
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Result<Vec<u16>> {
    let mut b: Vec<u16> = s.as_ref().encode_wide().collect();
    ensure!(!b.contains(&0), "NUL in Windows argument");
    b.push(0);
    Ok(b)
}
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    path_key(a) == path_key(b)
}
pub(crate) fn path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_lowercase()
}
/// Inspect the command line through the same live identity used by the caller.
pub(crate) fn process_arguments(expected: &ProcessIdentity) -> Result<Vec<String>> {
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }
    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    unsafe {
        let handle = Handle::new(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            expected.pid,
        ))?;
        let actual = identity_handle(handle.0, expected.pid)?;
        ensure!(
            actual.created_filetime == expected.created_filetime
                && same_path(&actual.executable, &expected.executable),
            "Process identity changed before command inspection"
        );
        let mut needed = 0;
        NtQueryInformationProcess(
            handle.0,
            ProcessCommandLineInformation,
            null_mut(),
            0,
            &mut needed,
        );
        ensure!(
            needed >= size_of::<UnicodeString>() as u32 && needed <= 131072,
            "Process command line size unavailable"
        );
        let mut memory =
            vec![0usize; (needed as usize + size_of::<usize>() - 1) / size_of::<usize>()];
        ensure!(
            NtQueryInformationProcess(
                handle.0,
                ProcessCommandLineInformation,
                memory.as_mut_ptr().cast(),
                needed,
                &mut needed
            ) >= 0,
            "Native process command line query failed"
        );
        let value = &*memory.as_ptr().cast::<UnicodeString>();
        let begin = memory.as_ptr() as usize;
        let end = begin + memory.len() * size_of::<usize>();
        let pointer = value.buffer as usize;
        ensure!(
            value.length % 2 == 0
                && pointer >= begin
                && pointer
                    .checked_add(value.length as usize)
                    .is_some_and(|p| p <= end),
            "Process command line buffer is invalid"
        );
        let text = String::from_utf16(std::slice::from_raw_parts(
            value.buffer,
            value.length as usize / 2,
        ))?;
        crate::service::argv(&text)
    }
}
pub fn quote_arg(value: &OsStr) -> OsString {
    let input: Vec<u16> = value.encode_wide().collect();
    if !input.is_empty()
        && !input
            .iter()
            .any(|c| [9, 10, 11, 12, 13, 32, 34].contains(c))
    {
        return value.into();
    }
    let mut out = vec![34];
    let mut slashes = 0;
    for c in input {
        if c == 92 {
            slashes += 1;
            continue;
        }
        if c == 34 {
            out.extend(std::iter::repeat_n(92, slashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat_n(92, slashes));
        }
        out.push(c);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n(92, slashes * 2));
    out.push(34);
    OsString::from_wide(&out)
}
pub(crate) fn command_line(exe: &Path, args: &[OsString]) -> Result<Vec<u16>> {
    let mut c = quote_arg(exe.as_os_str());
    for arg in args {
        c.push(" ");
        c.push(quote_arg(arg));
    }
    let c = wide(c)?;
    ensure!(
        c.len() <= 32767,
        "Windows command line exceeds 32767 UTF-16 units"
    );
    Ok(c)
}
fn pipe() -> Result<(Handle, Handle)> {
    unsafe {
        let mut r = null_mut();
        let mut w = null_mut();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        ensure!(
            CreatePipe(&mut r, &mut w, &sa, 0) != 0,
            "CreatePipe: {}",
            std::io::Error::last_os_error()
        );
        Ok((Handle(r), Handle(w)))
    }
}
fn no_inherit(h: &Handle) -> Result<()> {
    ensure!(
        unsafe { SetHandleInformation(h.0, HANDLE_FLAG_INHERIT, 0) } != 0,
        "SetHandleInformation: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub(crate) fn identity_handle(h: HANDLE, pid: u32) -> Result<ProcessIdentity> {
    unsafe {
        ensure!(
            WaitForSingleObject(h, 0) == WAIT_TIMEOUT,
            "Process {pid} has exited"
        );
        let mut created: FILETIME = zeroed();
        let mut exited = zeroed();
        let mut kernel = zeroed();
        let mut user = zeroed();
        ensure!(
            GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) != 0,
            "GetProcessTimes: {}",
            std::io::Error::last_os_error()
        );
        Ok(ProcessIdentity {
            pid,
            created_filetime: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
            executable: process_image(h)?,
        })
    }
}

fn process_image(handle: HANDLE) -> Result<PathBuf> {
    fn query(handle: HANDLE, image: &mut [u16]) -> std::io::Result<PathBuf> {
        let mut len = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(OsString::from_wide(&image[..len as usize]).into())
    }

    let mut image = [0; MAX_PATH as usize];
    let mut result = query(handle, &mut image);
    if result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32))
    {
        result = query(handle, &mut vec![0; 32768]);
    }
    result.map_err(|error| anyhow::anyhow!("QueryFullProcessImageName: {error}"))
}
struct AttributeList {
    memory: Vec<usize>,
}
impl AttributeList {
    fn handles(handles: &[HANDLE], parent: Option<&HANDLE>) -> Result<Self> {
        unsafe {
            let mut bytes = 0;
            let count = if parent.is_some() { 2 } else { 1 };
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
            ensure!(bytes > 0, "Attribute list size unavailable");
            let mut list = Self {
                memory: vec![0; (bytes + size_of::<usize>() - 1) / size_of::<usize>()],
            };
            ensure!(
                InitializeProcThreadAttributeList(list.ptr(), count, 0, &mut bytes) != 0,
                "InitializeProcThreadAttributeList: {}",
                std::io::Error::last_os_error()
            );
            ensure!(
                UpdateProcThreadAttribute(
                    list.ptr(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    std::mem::size_of_val(handles),
                    null_mut(),
                    null()
                ) != 0,
                "UpdateProcThreadAttribute: {}",
                std::io::Error::last_os_error()
            );
            if let Some(parent) = parent {
                ensure!(
                    UpdateProcThreadAttribute(
                        list.ptr(),
                        0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                        (parent as *const HANDLE).cast(),
                        size_of::<HANDLE>(),
                        null_mut(),
                        null()
                    ) != 0,
                    "Set desktop parent attribute: {}",
                    std::io::Error::last_os_error()
                );
            }
            Ok(list)
        }
    }
    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.memory.as_mut_ptr().cast()
    }
}
impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.ptr());
        }
    }
}
/// A suspended-created process assigned to an exact owned job before it can spawn children.
/// Dropping the owner closes a kill-on-close job, including all descendants.
pub struct OwnedChild {
    job: Handle,
    process: Handle,
    identity: ProcessIdentity,
    out: Handle,
    err: Handle,
    writer: Option<JoinHandle<std::io::Result<()>>>,
    started: Instant,
    timeout: Duration,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    max_output: usize,
    truncated: bool,
    timed_out: bool,
    terminated: bool,
}
impl OwnedChild {
    pub fn spawn(executable: &Path, args: &[OsString], options: &RunOptions) -> Result<Self> {
        Self::spawn_named(executable, args, options, None)
    }
    pub(crate) fn spawn_named(
        executable: &Path,
        args: &[OsString],
        options: &RunOptions,
        job_name: Option<&str>,
    ) -> Result<Self> {
        Self::spawn_redirect(executable, args, options, job_name, None)
    }
    pub(crate) fn spawn_background(
        executable: &Path,
        args: &[OsString],
        options: &RunOptions,
        log: &Path,
    ) -> Result<Self> {
        Self::spawn_redirect(executable, args, options, None, Some(log))
    }
    pub(crate) fn spawn_redirect(
        executable: &Path,
        args: &[OsString],
        options: &RunOptions,
        job_name: Option<&str>,
        log: Option<&Path>,
    ) -> Result<Self> {
        unsafe {
            ensure!(
                executable.is_absolute(),
                "Owned executable must have an absolute path"
            );
            ensure!(
                !options.timeout.is_zero() && options.timeout <= Duration::from_secs(24 * 3600),
                "Invalid subprocess deadline"
            );
            ensure!(
                options.max_output_bytes <= 64 * 1024 * 1024,
                "Output capture budget exceeds 64 MiB"
            );
            // Keep the caller's absolute Win32 spelling for the loader and argv[0].
            // canonicalize adds a verbatim prefix which breaks .NET Framework
            // configuration (including Windows PowerShell initialization).
            // The loaded image is still checked against its canonical identity
            // before the suspended process is allowed to execute.
            let mut cmd = command_line(executable, args)?;
            let image = wide(executable)?;
            let executable =
                std::fs::canonicalize(executable).context("Resolve owned executable")?;
            let cwd = options.cwd.as_ref().map(wide).transpose()?;
            let name = job_name.map(wide).transpose()?;
            let job = Handle::new(CreateJobObjectW(
                null(),
                name.as_ref().map_or(null(), |x| x.as_ptr()),
            ))?;
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ensure!(
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
                ) != 0,
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            );
            let (out, out_write) = pipe()?;
            let (err, err_write) = pipe()?;
            let (input, input_write) = pipe()?;
            no_inherit(&out)?;
            no_inherit(&err)?;
            no_inherit(&input_write)?;
            let log_file = log
                .map(|path| -> Result<File> {
                    crate::storage::no_reparse(path)?;
                    if let Some(p) = path.parent() {
                        std::fs::create_dir_all(p)?;
                    }
                    let f = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                        .open(path)?;
                    ensure!(
                        SetHandleInformation(
                            f.as_raw_handle(),
                            HANDLE_FLAG_INHERIT,
                            HANDLE_FLAG_INHERIT
                        ) != 0,
                        "Log handle inheritance: {}",
                        std::io::Error::last_os_error()
                    );
                    Ok(f)
                })
                .transpose()?;
            let log_handle = log_file.as_ref().map(|f| f.as_raw_handle());
            let inherited = if let Some(h) = log_handle {
                vec![input.0, h]
            } else {
                vec![input.0, out_write.0, err_write.0]
            };
            let desktop = if options.desktop_user {
                desktop_parent(&inherited)?
            } else {
                None
            };
            let inherited = desktop
                .as_ref()
                .map_or(inherited.as_slice(), |parent| parent.handles.as_slice());
            let mut attrs = AttributeList::handles(
                inherited,
                desktop.as_ref().map(|parent| &parent.process.0),
            )?;
            let mut si: STARTUPINFOEXW = zeroed();
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = inherited[0];
            si.StartupInfo.hStdOutput = inherited[1];
            si.StartupInfo.hStdError = if log_handle.is_some() {
                inherited[1]
            } else {
                inherited[2]
            };
            si.lpAttributeList = attrs.ptr();
            let mut env: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
            for (k, v) in std::env::vars_os().chain(options.env.clone()) {
                ensure!(
                    !k.as_os_str().encode_wide().any(|x| x == 0),
                    "Invalid environment key"
                );
                env.insert(k.to_string_lossy().to_uppercase(), (k, v));
            }
            let mut block = Vec::new();
            for (_, (k, v)) in env {
                let mut item = k;
                item.push("=");
                item.push(v);
                block.extend(wide(item)?);
            }
            block.push(0);
            let mut pi: PROCESS_INFORMATION = zeroed();
            let flags = CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT;
            let desktop_security = desktop.as_ref().map(|parent| SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: parent.security.as_ptr().cast_mut().cast(),
                bInheritHandle: 0,
            });
            let security = desktop_security
                .as_ref()
                .map_or(null(), |attributes| attributes);
            let created = CreateProcessW(
                image.as_ptr(),
                cmd.as_mut_ptr(),
                security,
                security,
                1,
                flags,
                block.as_ptr().cast(),
                cwd.as_ref().map_or(null(), |x| x.as_ptr()),
                &si.StartupInfo,
                &mut pi,
            );
            ensure!(
                created != 0,
                "CreateProcess: {}",
                std::io::Error::last_os_error()
            );
            let process = Handle(pi.hProcess);
            let thread = Handle(pi.hThread);
            if AssignProcessToJobObject(job.0, process.0) == 0 {
                let e = std::io::Error::last_os_error();
                TerminateProcess(process.0, 1);
                WaitForSingleObject(process.0, 5000);
                bail!("AssignProcessToJobObject: {e}");
            }
            if let Some(parent) = &desktop {
                // The duplicate primary token is also a newly created kernel
                // object. Give only this child's token the desktop token's
                // normal permissions so it can create restricted worker tokens.
                let mut token = null_mut();
                ensure!(
                    OpenProcessToken(process.0, TOKEN_ALL_ACCESS, &mut token) != 0,
                    "Open new desktop token: {}",
                    std::io::Error::last_os_error()
                );
                let token = Handle::new(token)?;
                ensure!(
                    SetKernelObjectSecurity(
                        token.0,
                        DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                        parent.token_security.as_ptr().cast_mut().cast(),
                    ) != 0,
                    "Set new desktop token security: {}",
                    std::io::Error::last_os_error()
                );
            }
            let identity = identity_handle(process.0, pi.dwProcessId)?;
            ensure!(
                same_path(&identity.executable, &executable),
                "Created process executable identity mismatch"
            );
            if ResumeThread(thread.0) == u32::MAX {
                bail!("ResumeThread: {}", std::io::Error::last_os_error());
            }
            drop(input);
            drop(out_write);
            drop(err_write);
            let writer = if let Some(bytes) = options.stdin.clone() {
                let raw = input_write.0 as usize;
                std::mem::forget(input_write);
                Some(std::thread::spawn(move || {
                    let mut f = File::from_raw_handle(raw as *mut _);
                    f.write_all(&bytes)
                }))
            } else {
                drop(input_write);
                None
            };
            Ok(Self {
                job,
                process,
                identity,
                out,
                err,
                writer,
                started: Instant::now(),
                timeout: options.timeout,
                stdout: Vec::new(),
                stderr: Vec::new(),
                max_output: options.max_output_bytes,
                truncated: false,
                timed_out: false,
                terminated: false,
            })
        }
    }
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }
    /// Keep an explicitly long-lived helper in its owned kill-on-close job.
    /// Finite commands must use `finish` with their configured deadline.
    pub fn supervise(mut self) -> Result<RunOutput> {
        self.timeout = Duration::MAX;
        self.finish()
    }
    fn pump(&mut self) -> Result<()> {
        for stdout in [true, false] {
            for _ in 0..32 {
                let h = if stdout { self.out.0 } else { self.err.0 };
                let mut available = 0;
                let ok = unsafe {
                    PeekNamedPipe(h, null_mut(), 0, null_mut(), &mut available, null_mut())
                };
                if ok == 0 {
                    let e = std::io::Error::last_os_error();
                    if matches!(e.raw_os_error(), Some(109 | 232)) {
                        break;
                    }
                    return Err(e.into());
                }
                if available == 0 {
                    break;
                }
                let mut buf = [0u8; 8192];
                let mut n = 0;
                ensure!(
                    unsafe {
                        ReadFile(
                            h,
                            buf.as_mut_ptr(),
                            available.min(buf.len() as u32),
                            &mut n,
                            null_mut(),
                        )
                    } != 0,
                    "ReadFile pipe: {}",
                    std::io::Error::last_os_error()
                );
                let room = self
                    .max_output
                    .saturating_sub(self.stdout.len() + self.stderr.len());
                let take = room.min(n as usize);
                if stdout {
                    self.stdout.extend_from_slice(&buf[..take]);
                } else {
                    self.stderr.extend_from_slice(&buf[..take]);
                }
                if take < n as usize {
                    self.truncated = true;
                }
            }
        }
        Ok(())
    }
    pub fn is_running(&mut self) -> Result<bool> {
        self.pump()?;
        let state = unsafe { WaitForSingleObject(self.process.0, 0) };
        ensure!(
            state != WAIT_FAILED,
            "WaitForSingleObject: {}",
            std::io::Error::last_os_error()
        );
        if state == WAIT_OBJECT_0 {
            return Ok(false);
        }
        if self.started.elapsed() >= self.timeout {
            self.timed_out = true;
            self.terminate()?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Wait for the root process or the next polling interval, whichever comes first.
    /// Call is_running afterwards to drain its pipes and enforce the deadline.
    pub fn wait_for_exit(&self, interval: Duration) -> Result<()> {
        let remaining = self.timeout.saturating_sub(self.started.elapsed());
        let milliseconds = interval
            .min(remaining)
            .as_millis()
            .min(u128::from(u32::MAX - 1));
        let status = unsafe { WaitForSingleObject(self.process.0, milliseconds as u32) };
        ensure!(
            matches!(status, WAIT_OBJECT_0 | WAIT_TIMEOUT),
            "Wait for owned process: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }

    pub fn terminate(&mut self) -> Result<()> {
        if !self.terminated {
            ensure!(
                unsafe { TerminateJobObject(self.job.0, 1) } != 0,
                "TerminateJobObject: {}",
                std::io::Error::last_os_error()
            );
            self.terminated = true;
            ensure!(
                unsafe { WaitForSingleObject(self.process.0, 5000) } == WAIT_OBJECT_0,
                "Owned process did not exit after job termination"
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
                ensure!(
                    unsafe {
                        QueryInformationJobObject(
                            self.job.0,
                            JobObjectBasicAccountingInformation,
                            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                            null_mut(),
                        )
                    } != 0,
                    "Query terminated job: {}",
                    std::io::Error::last_os_error()
                );
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "Owned descendants did not exit after job termination"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<RunOutput> {
        while self.is_running()? {
            self.wait_for_exit(Duration::from_millis(5))?;
        }
        // A parent may exit while descendants retain pipe handles. End the owned job first.
        self.terminate()?;
        for _ in 0..64 {
            let before = self.stdout.len() + self.stderr.len();
            self.pump()?;
            if self.stdout.len() + self.stderr.len() == before {
                break;
            }
        }
        if let Some(w) = self.writer.take() {
            let result = w
                .join()
                .map_err(|_| anyhow::anyhow!("stdin writer panicked"))?;
            if let Err(e) = result {
                if !matches!(e.raw_os_error(), Some(109 | 232)) {
                    return Err(e.into());
                }
            }
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(self.process.0, &mut code) } != 0,
            "GetExitCodeProcess: {}",
            std::io::Error::last_os_error()
        );
        Ok(RunOutput {
            identity: self.identity.clone(),
            exit_code: code,
            timed_out: self.timed_out,
            stdout: std::mem::take(&mut self.stdout),
            stderr: std::mem::take(&mut self.stderr),
            output_truncated: self.truncated,
        })
    }
    /// Keep a confirmed long-lived engine running after its startup controller exits.
    /// The caller must first persist the validated identity; finite jobs never use this.
    pub(crate) fn detach(mut self) -> Result<ProcessIdentity> {
        unsafe {
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            ensure!(
                SetInformationJobObject(
                    self.job.0,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
                ) != 0,
                "Detach confirmed engine job: {}",
                std::io::Error::last_os_error()
            );
        }
        self.terminated = true;
        Ok(self.identity.clone())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.terminated {
            let _ = self.terminate();
        }
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
    }
}
pub fn run_owned(executable: &Path, args: &[OsString], options: &RunOptions) -> Result<RunOutput> {
    OwnedChild::spawn(executable, args, options)?.finish()
}
pub fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    let h = Handle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    })?;
    identity_handle(h.0, pid)
}
pub fn terminate_owned(expected: &ProcessIdentity) -> Result<bool> {
    unsafe {
        let raw = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            expected.pid,
        );
        if raw.is_null() {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(87) {
                return Ok(false);
            }
            return Err(e.into());
        }
        let h = Handle(raw);
        let Ok(actual) = identity_handle(h.0, expected.pid) else {
            return Ok(false);
        };
        if actual.created_filetime != expected.created_filetime
            || !same_path(&actual.executable, &expected.executable)
        {
            return Ok(false);
        }
        ensure!(
            TerminateProcess(h.0, 1) != 0,
            "TerminateProcess: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            WaitForSingleObject(h.0, 5000) == WAIT_OBJECT_0,
            "Owned process did not exit"
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Compatibility check for the optional PowerShell/curl benchmark"]
    fn owned_windows_powershell_initializes_dotnet_configuration() {
        let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0");
        let output = run_owned(
            &system.join("powershell.exe"),
            &[
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                "[System.Net.ServicePointManager]::SecurityProtocol; 'initialized'".into(),
            ],
            &RunOptions {
                env: BTreeMap::from([(
                    "PSModulePath".into(),
                    system.join("Modules").into_os_string(),
                )]),
                timeout: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            output.exit_code,
            0,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("initialized"));
    }
}
