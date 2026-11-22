//! Own the driver's startup lock, receive handle pair and diagnostics.
use crate::logging::LogSink;
use std::{
    ffi::c_char,
    ptr::{self, NonNull},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_GEN_FAILURE, ERROR_INVALID_IMAGE_HASH,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, SetLastError, WAIT_ABANDONED, WAIT_FAILED,
        WAIT_OBJECT_0,
    },
    System::Threading::{CreateMutexA, INFINITE, ReleaseMutex, WaitForSingleObject},
};

type Close = unsafe extern "C" fn(HANDLE);

#[repr(C)]
struct Ops {
    open: unsafe extern "C" fn(*const c_char) -> HANDLE,
    close: Close,
    receive_event: unsafe extern "C" fn() -> HANDLE,
}

struct DriverLock {
    handle: HANDLE,
    owned: bool,
}

impl DriverLock {
    unsafe fn acquire(name: *const c_char) -> Result<Self, u32> {
        let handle = unsafe { CreateMutexA(ptr::null(), 1, name.cast()) };
        let error = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(error);
        }
        let mut lock = Self {
            handle,
            owned: error != ERROR_ALREADY_EXISTS,
        };
        if !lock.owned {
            match unsafe { WaitForSingleObject(handle, INFINITE) } {
                WAIT_OBJECT_0 | WAIT_ABANDONED => lock.owned = true,
                WAIT_FAILED => return Err(unsafe { GetLastError() }),
                _ => return Err(ERROR_GEN_FAILURE),
            }
        }
        Ok(lock)
    }
}

impl Drop for DriverLock {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                ReleaseMutex(self.handle);
            }
            CloseHandle(self.handle);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_deactivate(
    filter: *mut HANDLE,
    event: *mut HANDLE,
    close: Close,
) {
    let old_filter = unsafe { filter.replace(ptr::null_mut()) };
    if !old_filter.is_null() {
        unsafe { close(old_filter) };
    }
    let old_event = unsafe { event.replace(ptr::null_mut()) };
    if !old_event.is_null() {
        unsafe { CloseHandle(old_event) };
    }
}

// Return 0 on success, 1 if the driver could not be opened, and 2 if its
// receive event could not be created. Publish the handles only as a pair.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_activate(
    filter: *mut HANDLE,
    event: *mut HANDLE,
    error: *mut u32,
    condition: *const c_char,
    mutex_name: *const c_char,
    ops: &Ops,
) -> u32 {
    unsafe { zapret_divert_deactivate(filter, event, ops.close) };
    let lock = match unsafe { DriverLock::acquire(mutex_name) } {
        Ok(lock) => lock,
        Err(code) => {
            unsafe {
                error.write(code);
                SetLastError(code)
            };
            return 1;
        }
    };
    let driver = unsafe { (ops.open)(condition) };
    let code = unsafe { GetLastError() };
    drop(lock);
    unsafe {
        error.write(code);
        SetLastError(code)
    };
    if driver.is_null() || driver == INVALID_HANDLE_VALUE {
        return 1;
    }
    let receive = unsafe { (ops.receive_event)() };
    if receive.is_null() {
        let code = unsafe { GetLastError() };
        unsafe {
            (ops.close)(driver);
            error.write(code);
            SetLastError(code);
        }
        return 2;
    }
    unsafe {
        filter.write(driver);
        event.write(receive)
    };
    0
}

#[repr(C)]
struct Diagnostics {
    message: unsafe extern "C" fn(u32) -> *mut c_char,
    log: LogSink,
    release: unsafe extern "C" fn(*mut c_char),
}

unsafe fn report_open_failure(
    error: *const u32,
    message: unsafe extern "C" fn(u32) -> *mut c_char,
    release: unsafe extern "C" fn(*mut c_char),
    mut write: impl FnMut(Option<NonNull<c_char>>),
) {
    if let Some(message) = NonNull::new(unsafe { message(error.read()) }) {
        write(Some(message));
        unsafe { release(message.as_ptr()) };
    }
    // Logging and LocalFree run before the second observation, as before.
    if unsafe { error.read() } == ERROR_INVALID_IMAGE_HASH {
        write(None);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_divert_open_report(
    status: u32,
    error: *const u32,
    ops: &Diagnostics,
) -> bool {
    if status == 1 {
        unsafe {
            report_open_failure(error, ops.message, ops.release, |message| match message {
                Some(message) => {
                    (ops.log)(
                        c"windivert: error opening filter: %s".as_ptr(),
                        message.as_ptr(),
                    );
                }
                None => {
                    (ops.log)(
                        c"windivert: try to disable secure boot and install OS patches\n".as_ptr(),
                    );
                }
            })
        };
    }
    status == 0
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static TRACE: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        static ERROR: Cell<u32> = const { Cell::new(0) };
    }

    fn record(value: u32) {
        TRACE.with(|trace| trace.borrow_mut().push(value));
    }
    unsafe extern "C" fn message(code: u32) -> *mut c_char {
        record(code);
        c"diagnostic text".as_ptr().cast_mut()
    }
    unsafe extern "C" fn release(_text: *mut c_char) {
        record(2000);
        ERROR.set(ERROR_INVALID_IMAGE_HASH);
    }

    #[test]
    fn report_releases_the_message_before_observing_the_image_hash_status() {
        TRACE.with(|trace| trace.borrow_mut().clear());
        ERROR.with(|error| {
            error.set(77);
            unsafe {
                report_open_failure(error.as_ptr(), message, release, |message| {
                    record(if message.is_some() { 1000 } else { 1001 });
                });
            }
        });
        TRACE.with(|trace| assert_eq!(*trace.borrow(), [77, 1000, 2000, 1001]));
    }
}
