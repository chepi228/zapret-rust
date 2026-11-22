//! Owned Job limits and a single published process-sandbox transition.
use std::{
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BUSY, ERROR_GEN_FAILURE, ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER,
        GetLastError, HANDLE,
    },
    Security::SECURITY_ATTRIBUTES,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
            JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
            JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
            JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
            JobObjectBasicLimitInformation, JobObjectBasicUIRestrictions, SetInformationJobObject,
        },
        Threading::GetCurrentProcess,
    },
};
#[repr(C)]
struct JobOps {
    create: unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, *const u16) -> HANDLE,
    set: unsafe extern "system" fn(HANDLE, i32, *const c_void, u32) -> i32,
    assign: unsafe extern "system" fn(HANDLE, HANDLE) -> i32,
    process: unsafe extern "system" fn() -> HANDLE,
    close: unsafe extern "system" fn(HANDLE) -> i32,
    error: unsafe extern "system" fn() -> u32,
}
const JOB: JobOps = JobOps {
    create: CreateJobObjectW,
    set: SetInformationJobObject,
    assign: AssignProcessToJobObject,
    process: GetCurrentProcess,
    close: CloseHandle,
    error: GetLastError,
};
const UI: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
fn failure(ops: &JobOps) -> u32 {
    match unsafe { (ops.error)() } {
        0 => ERROR_GEN_FAILURE,
        value => value,
    }
}
struct Job<'a> {
    handle: HANDLE,
    ops: &'a JobOps,
}
impl Drop for Job<'_> {
    fn drop(&mut self) {
        unsafe { (self.ops.close)(self.handle) };
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_job(input: *const JobOps) -> u32 {
    let ops = if input.is_null() {
        &JOB
    } else {
        unsafe { &*input }
    };
    let handle = unsafe { (ops.create)(ptr::null(), ptr::null()) };
    if handle.is_null() {
        return failure(ops);
    }
    let job = Job { handle, ops };
    let limit = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        ActiveProcessLimit: 1,
        ..Default::default()
    };
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: UI,
    };
    if unsafe {
        (ops.set)(
            job.handle,
            JobObjectBasicLimitInformation,
            ptr::addr_of!(limit).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        )
    } == 0
        || unsafe {
            (ops.set)(
                job.handle,
                JobObjectBasicUIRestrictions,
                ptr::addr_of!(ui).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        } == 0
        || unsafe { (ops.assign)(job.handle, (ops.process)()) } == 0
    {
        return failure(ops);
    }
    0
}
type Step = unsafe extern "C" fn(*const c_void) -> u32;
#[repr(C)]
struct SandboxOps {
    remove: Step,
    label: Step,
    low: Step,
    job: Step,
}
unsafe extern "C" fn remove(_: *const c_void) -> u32 {
    crate::security_token::remove_privileges()
}
unsafe extern "C" fn low(_: *const c_void) -> u32 {
    crate::security_token::low_integrity()
}
unsafe extern "C" fn device(_: *const c_void) -> u32 {
    crate::security_label::label_device()
}
unsafe extern "C" fn job(_: *const c_void) -> u32 {
    unsafe { zapret_security_job(ptr::null()) }
}
const SANDBOX: SandboxOps = SandboxOps {
    remove,
    label: device,
    low,
    job,
};
static STATE: AtomicU32 = AtomicU32::new(0);
struct Transition<'a> {
    state: &'a AtomicU32,
    ready: bool,
}
impl Drop for Transition<'_> {
    fn drop(&mut self) {
        self.state
            .store(if self.ready { 2 } else { 0 }, Ordering::Release);
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_sandbox(
    present: Option<unsafe extern "C" fn() -> bool>,
    state: *mut u32,
    input: *const SandboxOps,
) -> u32 {
    let Some(present) = present else {
        return ERROR_INVALID_PARAMETER;
    };
    let state = if state.is_null() {
        &STATE
    } else {
        if !state.cast::<AtomicU32>().is_aligned() {
            return ERROR_INVALID_PARAMETER;
        }
        // Engine-owned aligned storage, accessed atomically for its full lifetime.
        unsafe { AtomicU32::from_ptr(state) }
    };
    match state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
        Ok(_) => {}
        Err(2) => return 0,
        Err(1) => return ERROR_BUSY,
        Err(_) => return ERROR_INVALID_DATA,
    }
    let mut transition = Transition {
        state,
        ready: false,
    };
    let ops = if input.is_null() {
        &SANDBOX
    } else {
        unsafe { &*input }
    };
    let error = unsafe { (ops.remove)(ptr::null()) };
    if error != 0 {
        return error;
    }
    if unsafe { present() } {
        let error = unsafe { (ops.label)(ptr::null()) };
        if error != 0 {
            return error;
        }
    }
    let error = unsafe { (ops.low)(ptr::null()) };
    if error != 0 {
        return error;
    }
    let error = unsafe { (ops.job)(ptr::null()) };
    if error != 0 {
        return error;
    }
    transition.ready = true;
    0
}
