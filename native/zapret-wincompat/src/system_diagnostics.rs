//! Native system identity and synchronized Unicode event-log ownership.
use crate::engine_bootstrap::ucrt::_errno;
use std::{
    ffi::{CStr, c_char},
    fmt::{self, Write},
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::OutputDebugStringW,
        EventLog::{DeregisterEventSource, RegisterEventSourceW, ReportEventW},
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        SystemInformation::{
            GetNativeSystemInfo, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
            PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
        },
        WindowsProgramming::GetComputerNameW,
    },
};

#[repr(C)]
struct Identity {
    system: [u8; 65],
    node: [u8; 256],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
}
const _: () = assert!(size_of::<Identity>() == 516);

impl Identity {
    const fn empty() -> Self {
        Self {
            system: [0; 65],
            node: [0; 256],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
        }
    }
}
type QueryVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
#[repr(C)]
struct IdentityOps {
    version: QueryVersion,
    name: unsafe extern "system" fn(*mut u16, *mut u32) -> i32,
    architecture: unsafe extern "system" fn(*mut SYSTEM_INFO),
}
unsafe extern "system" fn native_version(version: *mut OSVERSIONINFOW) -> i32 {
    const NTDLL: &[u16] = &[110, 116, 100, 108, 108, 46, 100, 108, 108, 0];
    let module = unsafe { GetModuleHandleW(NTDLL.as_ptr()) };
    if module.is_null() {
        return -1;
    }
    let Some(query) = (unsafe { GetProcAddress(module, c"RtlGetVersion".as_ptr().cast()) }) else {
        return -1;
    };
    let query: QueryVersion = unsafe { std::mem::transmute(query) };
    unsafe { query(version) }
}
const NATIVE_IDENTITY: IdentityOps = IdentityOps {
    version: native_version,
    name: GetComputerNameW,
    architecture: GetNativeSystemInfo,
};

struct Text<'a> {
    bytes: &'a mut [u8],
    length: usize,
}
impl fmt::Write for Text<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
        if end >= self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.length..end].copy_from_slice(value.as_bytes());
        self.bytes[end] = 0;
        self.length = end;
        Ok(())
    }
}
fn text(output: &mut [u8], arguments: fmt::Arguments<'_>) -> Result<(), i32> {
    Text {
        bytes: output,
        length: 0,
    }
    .write_fmt(arguments)
    .map_err(|_| libc::EIO)
}
unsafe fn identity(ops: &IdentityOps) -> Result<Identity, i32> {
    let mut result = Identity::empty();
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    if unsafe { (ops.version)(&mut version) } < 0 {
        return Err(libc::EIO);
    }
    let mut name = [0u16; 256];
    let mut length = name.len() as u32;
    if unsafe { (ops.name)(name.as_mut_ptr(), &mut length) } == 0 || length as usize >= name.len() {
        return Err(libc::EIO);
    }
    let node = String::from_utf16(&name[..length as usize]).map_err(|_| libc::EIO)?;
    let mut system = SYSTEM_INFO::default();
    unsafe { (ops.architecture)(&mut system) };
    let machine = match unsafe { system.Anonymous.Anonymous.wProcessorArchitecture } {
        PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
        PROCESSOR_ARCHITECTURE_ARM64 => "aarch64",
        _ => "x86",
    };
    text(&mut result.system, format_args!("Windows_NT"))?;
    text(
        &mut result.release,
        format_args!("{}.{}", version.dwMajorVersion, version.dwMinorVersion),
    )?;
    text(
        &mut result.version,
        format_args!("build {}", version.dwBuildNumber),
    )?;
    text(&mut result.node, format_args!("{node}"))?;
    text(&mut result.machine, format_args!("{machine}"))?;
    Ok(result)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_system_uname(output: *mut Identity, ops: *const IdentityOps) -> i32 {
    if output.is_null() {
        return libc::EINVAL;
    }
    unsafe { output.write(Identity::empty()) };
    let ops = if ops.is_null() {
        &NATIVE_IDENTITY
    } else {
        unsafe { &*ops }
    };
    match unsafe { identity(ops) } {
        Ok(result) => {
            unsafe { output.write(result) };
            0
        }
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn uname(output: *mut Identity) -> i32 {
    let error = unsafe { zapret_system_uname(output, ptr::null()) };
    if error == 0 {
        0
    } else {
        unsafe { _errno().write(error) };
        -1
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct EventOps {
    register: unsafe extern "C" fn(*const u16) -> HANDLE,
    report: unsafe extern "C" fn(HANDLE, u16, *const u16) -> i32,
    release: unsafe extern "C" fn(HANDLE) -> i32,
    debug: unsafe extern "C" fn(*const u16),
}
unsafe extern "C" fn native_register(name: *const u16) -> HANDLE {
    unsafe { RegisterEventSourceW(ptr::null(), name) }
}
unsafe extern "C" fn native_report(handle: HANDLE, kind: u16, message: *const u16) -> i32 {
    unsafe {
        ReportEventW(
            handle,
            kind,
            0,
            0,
            ptr::null_mut(),
            1,
            0,
            &message,
            ptr::null(),
        )
    }
}
unsafe extern "C" fn native_release(handle: HANDLE) -> i32 {
    unsafe { DeregisterEventSource(handle) }
}
unsafe extern "C" fn native_debug(message: *const u16) {
    unsafe { OutputDebugStringW(message) }
}
const NATIVE_EVENTS: EventOps = EventOps {
    register: native_register,
    report: native_report,
    release: native_release,
    debug: native_debug,
};
struct Log {
    handle: usize,
    ops: EventOps,
}
static LOG: Mutex<Log> = Mutex::new(Log {
    handle: 0,
    ops: NATIVE_EVENTS,
});

unsafe fn c_bytes<'a>(input: *const c_char) -> &'a [u8] {
    if input.is_null() {
        &[]
    } else {
        unsafe { CStr::from_ptr(input) }.to_bytes()
    }
}

fn wide(bytes: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(bytes)
        .encode_utf16()
        .chain(Some(0))
        .collect()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_system_openlog(name: *const c_char, ops: *const EventOps) -> bool {
    let name = wide(unsafe { c_bytes(name) });
    let ops = if ops.is_null() {
        NATIVE_EVENTS
    } else {
        unsafe { ops.read() }
    };
    let mut log = LOG.lock().unwrap_or_else(|error| error.into_inner());
    if log.handle != 0 {
        unsafe { (log.ops.release)(log.handle as HANDLE) };
    }
    log.ops = ops;
    log.handle = unsafe { (ops.register)(name.as_ptr()) } as usize;
    log.handle != 0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openlog(name: *const c_char, _options: i32, _facility: i32) {
    unsafe { zapret_system_openlog(name, ptr::null()) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_system_syslog(priority: i32, message: *const c_char) {
    // The previous variadic bridge used an 8192-byte buffer including the NUL.
    let bytes = unsafe { c_bytes(message) };
    let message = wide(&bytes[..bytes.len().min(8191)]);
    let log = LOG.lock().unwrap_or_else(|error| error.into_inner());
    unsafe { (log.ops.debug)(message.as_ptr()) };
    if log.handle != 0 {
        let kind = if priority <= 3 { 1 } else { 4 };
        unsafe { (log.ops.report)(log.handle as HANDLE, kind, message.as_ptr()) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn closelog() {
    zapret_system_closelog();
}
#[unsafe(no_mangle)]
extern "C" fn zapret_system_closelog() {
    let mut log = LOG.lock().unwrap_or_else(|error| error.into_inner());
    if log.handle != 0 {
        unsafe { (log.ops.release)(log.handle as HANDLE) };
        log.handle = 0;
    }
}
