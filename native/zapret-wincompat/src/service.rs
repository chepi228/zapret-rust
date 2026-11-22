//! Engine service callbacks share one synchronized status and one dispatch.
use std::{
    ffi::{c_char, c_int},
    ptr,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::{
    Win32::System::Services::{
        LPHANDLER_FUNCTION, RegisterServiceCtrlHandlerW, SERVICE_ACCEPT_SHUTDOWN,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
        SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        StartServiceCtrlDispatcherW,
    },
    core::{BOOL, PCWSTR},
};

type Entry = unsafe extern "C-unwind" fn(c_int, *mut *mut c_char) -> c_int;
type Quit = unsafe extern "C" fn();

#[repr(C)]
#[derive(Clone, Copy)]
struct Ops {
    dispatch: unsafe extern "system" fn(*const SERVICE_TABLE_ENTRYW) -> BOOL,
    register: unsafe extern "system" fn(PCWSTR, LPHANDLER_FUNCTION) -> SERVICE_STATUS_HANDLE,
    status: unsafe extern "system" fn(SERVICE_STATUS_HANDLE, *const SERVICE_STATUS) -> BOOL,
}
unsafe extern "system" fn publish_native(
    handle: SERVICE_STATUS_HANDLE,
    status: *const SERVICE_STATUS,
) -> BOOL {
    let snapshot = unsafe { status.read() };
    unsafe { SetServiceStatus(handle, &snapshot) }
}

const NATIVE: Ops = Ops {
    dispatch: StartServiceCtrlDispatcherW,
    register: RegisterServiceCtrlHandlerW,
    status: publish_native,
};

#[derive(Clone, Copy)]
struct Context {
    argc: c_int,
    argv: usize,
    entry: Entry,
    quit: Quit,
    ops: Ops,
}

struct State {
    context: Option<Context>,
    handle: usize,
    stopping: bool,
    status: SERVICE_STATUS,
}
static BUSY: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<State> = Mutex::new(State {
    context: None,
    handle: 0,
    stopping: false,
    status: SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 0,
    },
});
const NAME: PCWSTR = windows_sys::core::w!("winws2");

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl State {
    fn publish(&self) {
        if let Some(context) = self.context.filter(|_| self.handle != 0) {
            // Publish under the same lock that changes the status, so a late
            // RUNNING snapshot cannot overtake a stop notification.
            unsafe { (context.ops.status)(self.handle as SERVICE_STATUS_HANDLE, &self.status) };
        }
    }
}

unsafe extern "system" fn control(request: u32) {
    let mut state = state();
    let Some(context) = state.context else {
        return;
    };
    if matches!(request, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN)
        && state.status.dwCurrentState != SERVICE_STOPPED
    {
        state.stopping = true;
        state.status.dwCurrentState = SERVICE_STOP_PENDING;
        state.status.dwControlsAccepted = 0;
        unsafe { (context.quit)() };
    }
    state.publish();
}

unsafe extern "system" fn main(_argc: u32, _argv: *mut *mut u16) {
    let Some(context) = state().context else {
        return;
    };
    let handle = unsafe { (context.ops.register)(NAME, Some(control)) };
    if handle.is_null() {
        return;
    }
    let run = {
        let mut state = state();
        state.handle = handle as usize;
        let run = !state.stopping;
        state.status.dwCurrentState = if run {
            SERVICE_RUNNING
        } else {
            SERVICE_STOP_PENDING
        };
        state.status.dwControlsAccepted = if run {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        };
        state.publish();
        run
    };
    let result = if run {
        unsafe { (context.entry)(context.argc, context.argv as *mut *mut c_char) }
    } else {
        0
    };
    let mut state = state();
    state.status.dwWin32ExitCode = result as u32;
    state.status.dwCurrentState = SERVICE_STOPPED;
    state.status.dwControlsAccepted = 0;
    state.status.dwCheckPoint = 0;
    state.publish();
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_engine_service_run(
    argc: c_int,
    argv: *mut *mut c_char,
    entry: Entry,
    quit: Quit,
    ops: &Ops,
) -> bool {
    if BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // The registered service callback re-enters the ordinary engine main.
        return false;
    }
    {
        let mut state = state();
        state.context = Some(Context {
            argc,
            argv: argv as usize,
            entry,
            quit,
            ops: *ops,
        });
        state.handle = 0;
        state.stopping = false;
        state.status.dwCurrentState = SERVICE_START_PENDING;
        state.status.dwControlsAccepted = 0;
        state.status.dwWin32ExitCode = 0;
        state.status.dwCheckPoint = 1;
    }
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: NAME.cast_mut(),
            lpServiceProc: Some(main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    let dispatched = unsafe { (ops.dispatch)(table.as_ptr()) } != 0;
    {
        let mut state = state();
        state.context = None;
        state.handle = 0;
    }
    BUSY.store(false, Ordering::Release);
    dispatched
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_native_service_dispatch(
    argc: c_int,
    argv: *mut *mut c_char,
    entry: Entry,
    quit: Quit,
) -> bool {
    unsafe { zapret_engine_service_run(argc, argv, entry, quit, &NATIVE) }
}
