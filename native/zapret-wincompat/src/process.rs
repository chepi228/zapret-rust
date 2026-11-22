//! Win32 startup and daemon re-execution for the native engine.

use crate::engine_bootstrap::ucrt::configure_standard_stream;
use crate::files::{
    WinResult, buffer, current_directory_wide, executable_path_wide, last_error, utf8, win32_ok,
};
use std::{
    ffi::{c_char, c_int},
    mem::size_of,
    ptr::null,
    slice,
    sync::OnceLock,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_PATH_NOT_FOUND,
        FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Globalization::{CP_UTF8, CSTR_EQUAL, CompareStringOrdinal},
    Networking::WinSock::{WSACleanup, WSADATA, WSAStartup},
    System::{
        Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleOutputCP,
        },
        Environment::{GetCommandLineW, GetEnvironmentVariableW, SetEnvironmentVariableW},
        Threading::{
            CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CreateProcessW, GetCurrentProcess,
            GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_INFORMATION,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            QueryFullProcessImageNameW, STARTUPINFOW, WaitForSingleObject,
        },
    },
};

// The NUL-terminated Win32 environment variable is shared by parent and child.
const DAEMON_MARKER: *const u16 = windows_sys::w!("ZAPRET_NATIVE_DAEMON_PARENT");

struct Startup {
    initial_directory: Vec<u16>,
    daemon_child: bool,
}

static STARTUP: OnceLock<Startup> = OnceLock::new();

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn creation_time(process: HANDLE) -> WinResult<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    win32_ok(unsafe {
        GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user)
    })?;
    Ok(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
}

fn is_parent_image(process: HANDLE) -> WinResult<bool> {
    let image = executable_path_wide()?;
    let mut parent = buffer::<u16>(32_768)?;
    let mut len = parent.len() as u32;
    win32_ok(unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, parent.as_mut_ptr(), &mut len)
    })?;
    Ok(unsafe {
        CompareStringOrdinal(
            image.as_ptr(),
            (image.len() - 1) as i32,
            parent.as_ptr(),
            len as i32,
            1,
        )
    } == CSTR_EQUAL)
}

fn daemon_parent_finished() -> WinResult<bool> {
    let mut raw = [0u16; 80];
    let len = unsafe { GetEnvironmentVariableW(DAEMON_MARKER, raw.as_mut_ptr(), raw.len() as u32) }
        as usize;
    if len == 0 {
        return Ok(false);
    }
    if len >= raw.len() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let id = String::from_utf16(&raw[..len]).map_err(|_| ERROR_INVALID_PARAMETER)?;
    let (pid, ticks) = id.split_once(':').ok_or(ERROR_INVALID_PARAMETER)?;
    let pid = pid
        .parse::<u32>()
        .ok()
        .filter(|&value| value != 0)
        .ok_or(ERROR_INVALID_PARAMETER)?;
    let ticks = u64::from_str_radix(ticks, 16)
        .ok()
        .filter(|&value| value != 0)
        .ok_or(ERROR_INVALID_PARAMETER)?;
    unsafe { SetEnvironmentVariableW(DAEMON_MARKER, null()) };

    let handle = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if handle.is_null() {
        // The parent may have exited before the child got a handle.
        return if last_error() == ERROR_INVALID_PARAMETER {
            Ok(true)
        } else {
            Err(ERROR_INVALID_PARAMETER)
        };
    }
    let parent = ProcessHandle(handle);
    if creation_time(parent.0).ok() != Some(ticks) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if unsafe { WaitForSingleObject(parent.0, 0) } == WAIT_OBJECT_0 {
        return Ok(true);
    }

    // Image lookup can fail if the parent exits while the query is in progress.
    let timeout = if is_parent_image(parent.0).unwrap_or(false) {
        30_000
    } else {
        0
    };
    if unsafe { WaitForSingleObject(parent.0, timeout) } == WAIT_OBJECT_0 {
        Ok(true)
    } else {
        Err(ERROR_INVALID_PARAMETER)
    }
}

fn spawn_daemon(startup: &Startup) -> WinResult<()> {
    let image = executable_path_wide()?;
    let command = unsafe { GetCommandLineW() };
    if command.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    // GetCommandLineW returns a process-owned NUL-terminated string.
    let mut len = 0;
    unsafe {
        while *command.add(len) != 0 {
            len += 1;
        }
    }
    let mut args = buffer::<u16>(len + 1)?;
    args.copy_from_slice(unsafe { slice::from_raw_parts(command, len + 1) });

    let ticks = creation_time(unsafe { GetCurrentProcess() })?;
    let identity = format!("{}:{ticks:016x}", unsafe { GetCurrentProcessId() });
    let mut marker = [0u16; 80];
    for (unit, digit) in marker.iter_mut().zip(identity.bytes()) {
        *unit = u16::from(digit);
    }
    win32_ok(unsafe { SetEnvironmentVariableW(DAEMON_MARKER, marker.as_ptr()) })?;
    let attributes = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..STARTUPINFOW::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    let spawned = win32_ok(unsafe {
        CreateProcessW(
            image.as_ptr(),
            args.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
            null(),
            startup.initial_directory.as_ptr(),
            &attributes,
            &mut process,
        )
    });
    unsafe { SetEnvironmentVariableW(DAEMON_MARKER, null()) };
    spawned?;
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(())
}

struct Winsock;

impl Winsock {
    fn initialize() -> Result<Self, c_int> {
        let mut data = WSADATA::default();
        let error = unsafe { WSAStartup(0x0202, &mut data) };
        if error == 0 { Ok(Self) } else { Err(error) }
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe { WSACleanup() };
    }
}

type EngineMain = unsafe extern "C-unwind" fn(c_int, *mut *mut c_char) -> c_int;

/// # Safety
/// The UCRT startup supplies argc valid NUL-terminated UTF-16 arguments. The
/// engine borrows the translated argv through its main call.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_native_start(
    argc: c_int,
    wide_argv: *const *const u16,
    engine: EngineMain,
) -> c_int {
    let run = || {
        let initial_directory =
            current_directory_wide().map_err(|_| ERROR_PATH_NOT_FOUND as c_int)?;
        if initial_directory.len() > 32_768 || argc <= 0 || wide_argv.is_null() {
            return Err(ERROR_INVALID_PARAMETER as c_int);
        }
        let daemon_child = daemon_parent_finished().map_err(|error| error as c_int)?;
        if STARTUP
            .set(Startup {
                initial_directory,
                daemon_child,
            })
            .is_err()
        {
            return Err(ERROR_INVALID_PARAMETER as c_int);
        }
        let wide_argv = unsafe { slice::from_raw_parts(wide_argv, argc as usize) };
        let mut arguments = Vec::new();
        arguments
            .try_reserve_exact(wide_argv.len())
            .map_err(|_| ERROR_NOT_ENOUGH_MEMORY as c_int)?;
        let mut argv =
            buffer::<*mut c_char>(wide_argv.len() + 1).map_err(|error| error as c_int)?;
        for (&source, slot) in wide_argv.iter().zip(&mut argv) {
            let mut utf8 = unsafe { utf8(source) }.map_err(|error| error as c_int)?;
            *slot = utf8.as_mut_ptr().cast();
            arguments.push(utf8);
        }
        for (index, stdio) in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
            .into_iter()
            .enumerate()
        {
            let handle = unsafe { GetStdHandle(stdio) };
            let use_null = daemon_child || handle.is_null() || handle == INVALID_HANDLE_VALUE;
            unsafe { configure_standard_stream(index as c_int, use_null) }?;
        }
        unsafe { SetConsoleOutputCP(CP_UTF8) };
        let _winsock = Winsock::initialize()?;
        Ok(unsafe { engine(argc, argv.as_mut_ptr()) })
    };
    run().unwrap_or_else(|error| error)
}

/// Keep the engine's UCRT exit so buffered engine output is flushed.
#[unsafe(no_mangle)]
extern "C" fn daemonize() {
    let status = match STARTUP.get() {
        Some(startup) if startup.daemon_child => return,
        Some(startup) => spawn_daemon(startup).map_or(20, |()| 0),
        None => 20,
    };
    unsafe { libc::exit(status) };
}
