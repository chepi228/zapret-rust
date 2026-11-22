//! Console dispatch and Lua shutdown ownership outside packet processing.
use crate::logging::LogSink;
use std::{
    ffi::{c_char, c_void},
    sync::{
        Mutex, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
};

type Quit = unsafe extern "C" fn(i32);
type Signal = unsafe extern "C" fn(i32);
type Console = unsafe extern "system" fn(u32) -> i32;
type Install = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct Ops {
    console: unsafe extern "system" fn(Option<Console>, i32) -> i32,
    signal: unsafe extern "C" fn(i32, Signal) -> usize,
}

static QUIT: OnceLock<Quit> = OnceLock::new();

unsafe extern "C" fn signal(event: i32) {
    if let Some(quit) = QUIT.get() {
        unsafe { quit(event) };
    }
}

unsafe extern "system" fn console(event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    if matches!(
        event,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    ) {
        unsafe { signal(libc::SIGINT) };
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_console_register(
    quit: Quit,
    ops: *const Ops,
    error: LogSink,
) -> bool {
    QUIT.get_or_init(|| quit);
    let ops = unsafe { &*ops };
    let interrupt = unsafe { (ops.signal)(libc::SIGINT, signal) };
    let terminate = unsafe { (ops.signal)(libc::SIGTERM, signal) };
    let console = unsafe { (ops.console)(Some(console), 1) };
    let registered = interrupt != usize::MAX && terminate != usize::MAX && console != 0;
    if !registered {
        unsafe { error(c"could not register every console shutdown handler\n".as_ptr()) };
    }
    registered
}

#[repr(C)]
struct ShutdownMessage {
    text: *const c_char,
    length: usize,
}

// Called by the console or CRT signal handler. Only the first signal publishes
// a message. The caller performs native I/O and enters Lua after this returns.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_console_claim_shutdown(
    quit: *mut AtomicI32,
    event: i32,
    output: *mut ShutdownMessage,
) -> bool {
    if unsafe { (*quit).swap(1, Ordering::AcqRel) } != 0 {
        return false;
    }
    let text = if event == libc::SIGTERM {
        c"TERM received !\n"
    } else {
        c"INT received !\n"
    };
    unsafe {
        output.write(ShutdownMessage {
            text: text.as_ptr(),
            length: text.to_bytes().len(),
        });
    }
    true
}

struct Vm {
    // The C owner publishes a live VM and detaches it before cleanup or free.
    address: usize,
    install: Install,
    interrupted: bool,
}
static VM: Mutex<Option<Vm>> = Mutex::new(None);
static REQUESTED: AtomicBool = AtomicBool::new(false);

fn install_interrupt() {
    // A CRT signal can interrupt publication on the same thread. Never wait
    // here; publication retries after unlocking, and detachment needs no hook.
    let mut state = match VM.try_lock() {
        Ok(state) => state,
        Err(TryLockError::Poisoned(error)) => error.into_inner(),
        Err(TryLockError::WouldBlock) => return,
    };
    if let Some(vm) = state.as_mut().filter(|vm| !vm.interrupted) {
        vm.interrupted = true;
        // The C adapter only installs a hook. It cannot raise a Lua error.
        unsafe { (vm.install)(vm.address as *mut c_void) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_publish(address: *mut c_void, install: Install) {
    *VM.lock().unwrap_or_else(|error| error.into_inner()) = Some(Vm {
        address: address as usize,
        install,
        interrupted: false,
    });
    // Read after unlocking so a signal that could not acquire the lock cannot
    // lose its request between publication and the next Lua instruction.
    if REQUESTED.load(Ordering::Acquire) {
        install_interrupt();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_detach(address: *mut c_void) -> bool {
    let mut state = VM.lock().unwrap_or_else(|error| error.into_inner());
    if state
        .as_ref()
        .is_some_and(|vm| vm.address == address as usize)
    {
        *state = None;
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_vm_request_quit() {
    REQUESTED.store(true, Ordering::Release);
    install_interrupt();
}
