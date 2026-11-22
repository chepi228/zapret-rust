//! Wait for a single overlapped receive before returning its storage to the engine.
mod handles;
mod send;
use crate::engine_loop::{
    BATCH, Batch, ERROR_INVALID_DATA, OVERSIZE, RECEIVE_ERROR, SHUTDOWN, TimerOps,
};
use crate::logging::LogSink;
use core::ffi::c_void;
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_NO_DATA, GetLastError, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{ResetEvent, WaitForSingleObject},
    },
};

const ADDRESS_SIZE: u32 = 80;
const MAX_POLL_DELAY_MS: u32 = 50;

#[repr(C)]
struct ReceiveOps {
    timers: &'static TimerOps,
    poll: extern "C" fn() -> u32,
    submit: unsafe extern "C" fn(
        HANDLE,
        *mut u8,
        u32,
        *mut u32,
        *mut c_void,
        *mut u32,
        *mut OVERLAPPED,
    ) -> u32,
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_win_receive(
    ops: &ReceiveOps,
    handle: HANDLE,
    event: HANDLE,
    data: *mut u8,
    addresses: *mut c_void,
    batch: &mut Batch,
    deadline: &mut u64,
) -> u32 {
    let status = (ops.poll)();
    if status != BATCH {
        return status;
    }

    let mut delay = 0;
    let timers = ops.timers;
    if (timers.active)() {
        if *deadline == 0 || (timers.dirty)() {
            *deadline = (timers.next)();
        }
        let now = (timers.now)();
        delay = deadline.saturating_sub(now);
        if delay == 0 {
            *deadline = (timers.run)(now);
            delay = deadline.saturating_sub((timers.now)());
        }
    } else {
        *deadline = 0;
    }

    let Ok(capacity) = u32::try_from(batch.length) else {
        return receive_error(batch, ERROR_INVALID_DATA);
    };
    let Some(mut address_bytes) = batch.count.checked_mul(ADDRESS_SIZE) else {
        return receive_error(batch, ERROR_INVALID_DATA);
    };
    let mut received = 0;
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };
    // The previous receive is complete before this call. Clear any signal it
    // left in the event, including a synchronous completion.
    if unsafe { ResetEvent(event) } == 0 {
        return receive_error(batch, unsafe { GetLastError() });
    }
    let error = unsafe {
        (ops.submit)(
            handle,
            data,
            capacity,
            &raw mut received,
            addresses,
            &raw mut address_bytes,
            &raw mut overlapped,
        )
    };
    if error == ERROR_IO_PENDING {
        // The operation may still write to the capture buffer, address array,
        // byte counts and OVERLAPPED. Their storage remains live until drain.
        let mut pending = PendingReceive {
            handle,
            event,
            overlapped: &raw mut overlapped,
        };
        loop {
            let interval = if (timers.active)() {
                delay.min(u64::from(MAX_POLL_DELAY_MS)) as u32
            } else {
                MAX_POLL_DELAY_MS
            };
            match unsafe { WaitForSingleObject(pending.event, interval) } {
                WAIT_OBJECT_0 => match pending.complete() {
                    Ok(length) => {
                        received = length;
                        break;
                    }
                    Err(error) => return receive_error(batch, error),
                },
                WAIT_TIMEOUT => {
                    let status = (ops.poll)();
                    if status != BATCH {
                        return status;
                    }
                    if (timers.active)() {
                        let now = (timers.now)();
                        delay = deadline.saturating_sub(now);
                        if delay == 0 {
                            *deadline = (timers.run)(now);
                            delay = deadline.saturating_sub((timers.now)());
                        }
                    }
                }
                _ => return receive_error(batch, unsafe { GetLastError() }),
            }
        }
    } else if error != 0 {
        return receive_error(batch, error);
    }
    if received > capacity
        || address_bytes > batch.count * ADDRESS_SIZE
        || address_bytes % ADDRESS_SIZE != 0
    {
        return receive_error(batch, ERROR_INVALID_DATA);
    }
    batch.length = received as usize;
    batch.count = address_bytes / ADDRESS_SIZE;
    BATCH
}

fn receive_error(batch: &mut Batch, error: u32) -> u32 {
    batch.error = error;
    match error {
        ERROR_INSUFFICIENT_BUFFER => OVERSIZE,
        ERROR_NO_DATA => SHUTDOWN,
        _ => RECEIVE_ERROR,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_win_receive_report(
    status: u32,
    io_error: i32,
    shutdown: i32,
    log: LogSink,
) -> u32 {
    let error = match status {
        RECEIVE_ERROR => io_error,
        SHUTDOWN => shutdown,
        _ => return status,
    };
    unsafe { log(c"windivert: recv failed. errno %d\n".as_ptr(), error) };
    status
}

struct PendingReceive {
    handle: HANDLE,
    event: HANDLE,
    overlapped: *mut OVERLAPPED,
}

impl PendingReceive {
    fn complete(&mut self) -> Result<u32, u32> {
        let mut length = 0;
        if unsafe { GetOverlappedResult(self.handle, self.overlapped, &mut length, 0) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        self.overlapped = core::ptr::null_mut();
        Ok(length)
    }
}

impl Drop for PendingReceive {
    fn drop(&mut self) {
        if !self.overlapped.is_null() {
            let mut length = 0;
            // Completion can race with cancellation. Wait in either case.
            unsafe {
                CancelIoEx(self.handle, self.overlapped);
                GetOverlappedResult(self.handle, self.overlapped, &mut length, 1);
            }
        }
    }
}
