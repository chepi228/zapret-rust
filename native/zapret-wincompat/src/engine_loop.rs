//! Scheduling and packet dispatch for the native Windows engine.
#[cfg(windows)]
mod diagnostics;

use crate::packet_policy::{VERDICT_MASK, VERDICT_MODIFY, VERDICT_PASS};
use std::{collections::TryReserveError, ffi::c_void};

const RECEIVE_CAPACITY: usize = 196_608;
const MODIFY_CAPACITY: usize = 65_536;
const IDLE_POLL_MS: u64 = 50;
const ADDRESS_CAPACITY: u32 = 128;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub(super) const ERROR_INVALID_DATA: u32 = 13;
pub(super) const BATCH: u32 = 0;
pub(super) const OVERSIZE: u32 = 1;
pub(super) const RECONNECT: u32 = 2;
pub(super) const QUIT: u32 = 3;
#[cfg(windows)]
pub(super) const RECEIVE_ERROR: u32 = 4;
#[cfg(windows)]
pub(super) const SHUTDOWN: u32 = 5;

#[repr(C)]
pub(super) struct TimerOps {
    pub(super) active: extern "C" fn() -> bool,
    pub(super) dirty: extern "C" fn() -> bool,
    pub(super) next: extern "C" fn() -> u64,
    pub(super) now: extern "C" fn() -> u64,
    pub(super) run: extern "C-unwind" fn(u64) -> u64,
}

#[unsafe(no_mangle)]
extern "C-unwind" fn zapret_idle_loop(
    timers: &TimerOps,
    quitting: extern "C" fn() -> bool,
    sleep_ms: extern "C" fn(u64),
    prepare: extern "C-unwind" fn(),
    report: extern "C" fn(bool),
) {
    if !(timers.active)() {
        return;
    }
    report(false);
    let mut deadline = (timers.next)();
    while (timers.active)() {
        if quitting() {
            report(true);
            break;
        }
        let delay = deadline.saturating_sub((timers.now)());
        if delay != 0 {
            // Long timer intervals must not postpone a shutdown request.
            sleep_ms(delay.min(IDLE_POLL_MS));
            if quitting() {
                report(true);
                break;
            }
            if (timers.now)() < deadline {
                continue;
            }
        }
        prepare();
        deadline = (timers.run)(0);
    }
}

#[repr(C)]
pub(super) struct Batch {
    pub(super) length: usize,
    pub(super) count: u32,
    pub(super) error: u32,
}

#[repr(u32)]
enum Event {
    NetworkWaiting,
    NetworkPresent,
    NetworkLost,
    Quit,
    NoInterceptQuit,
    Oversize,
    InvalidBatch,
    InvalidIpv4,
    InvalidIpv6,
    Pass,
    Modify,
    Drop,
    SendFailed,
    InvalidModification,
}

#[repr(C)]
struct CaptureOps {
    register_signals: extern "C" fn(),
    network_ready: extern "C" fn() -> bool,
    quitting: extern "C" fn() -> bool,
    sleep_ms: extern "C" fn(u64),
    activate: unsafe extern "C-unwind" fn(*mut u32) -> bool,
    deactivate: extern "C" fn(),
    idle: extern "C-unwind" fn(),
    prepare: extern "C-unwind" fn(),
    receive: unsafe extern "C-unwind" fn(*mut c_void, *mut u8, *mut Batch, *mut u64) -> u32,
    ipv6: unsafe extern "C" fn(*const c_void, u32) -> bool,
    process: unsafe extern "C-unwind" fn(
        *const c_void,
        u32,
        u32,
        *const u8,
        usize,
        *mut u8,
        *mut usize,
    ) -> u8,
    send: unsafe extern "C" fn(*const c_void, u32, *const u8, usize) -> bool,
    report: extern "C" fn(u32, u32, usize, usize),
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_capture_loop(
    ops: &CaptureOps,
    addresses: *mut c_void,
    intercept: bool,
) -> u32 {
    let (Ok(mut packets), Ok(mut modified)) = (buffer(RECEIVE_CAPACITY), buffer(MODIFY_CAPACITY))
    else {
        return ERROR_NOT_ENOUGH_MEMORY;
    };
    let report = ops.report;
    (ops.register_signals)();
    loop {
        if !(ops.network_ready)() {
            report(Event::NetworkWaiting as u32, 0, 0, 0);
            loop {
                if (ops.quitting)() {
                    report(Event::Quit as u32, 0, 0, 0);
                    return 0;
                }
                (ops.sleep_ms)(500);
                if (ops.network_ready)() {
                    break;
                }
            }
            report(Event::NetworkPresent as u32, 0, 0, 0);
        }
        let mut error = 0;
        // The adapter initializes the existing filter, sandbox and Lua state.
        if !unsafe { (ops.activate)(&mut error) } {
            return error;
        }
        if !intercept {
            (ops.idle)();
            report(Event::NoInterceptQuit as u32, 0, 0, 0);
            return 0;
        }

        let mut deadline = 0;
        let mut id = 0;
        loop {
            let mut batch = Batch {
                length: packets.len(),
                count: ADDRESS_CAPACITY,
                error: 0,
            };
            // The adapter owns the matching address records. All overlapped
            // writes finish before it returns, so the byte buffer can be reused.
            match unsafe {
                (ops.receive)(addresses, packets.as_mut_ptr(), &mut batch, &mut deadline)
            } {
                BATCH => {}
                OVERSIZE => {
                    report(Event::Oversize as u32, 0, 0, 0);
                    continue;
                }
                RECONNECT => {
                    report(Event::NetworkLost as u32, 0, 0, 0);
                    (ops.deactivate)();
                    break;
                }
                QUIT => {
                    report(Event::Quit as u32, 0, 0, 0);
                    return 0;
                }
                _ => return batch.error,
            }
            (ops.prepare)();
            let Some(data) = packets.get_mut(..batch.length) else {
                report(
                    Event::InvalidBatch as u32,
                    0,
                    batch.length,
                    batch.count as usize,
                );
                return ERROR_INVALID_DATA;
            };
            if batch.count > ADDRESS_CAPACITY {
                report(
                    Event::InvalidBatch as u32,
                    0,
                    batch.length,
                    batch.count as usize,
                );
                return ERROR_INVALID_DATA;
            }
            // The successful receive initialized exactly batch.count addresses.
            unsafe {
                dispatch(ops, addresses, data, batch.count, &mut modified, &mut id);
            }
        }
    }
}

fn buffer(length: usize) -> Result<Vec<u8>, TryReserveError> {
    let mut data = Vec::new();
    data.try_reserve_exact(length)?;
    data.resize(length, 0);
    Ok(data)
}

unsafe fn dispatch(
    ops: &CaptureOps,
    addresses: *const c_void,
    mut data: &mut [u8],
    count: u32,
    modified: &mut [u8],
    id: &mut u32,
) {
    let report = ops.report;
    for index in 0..count {
        let ipv6 = unsafe { (ops.ipv6)(addresses, index) };
        let Some((packet, rest)) = split_packet(data, ipv6) else {
            let event = if ipv6 {
                Event::InvalidIpv6
            } else {
                Event::InvalidIpv4
            };
            report(event as u32, *id, 0, 0);
            break;
        };
        let mut length = modified.len();
        let verdict = unsafe {
            (ops.process)(
                addresses,
                index,
                *id,
                // The Windows handler can repair the original checksum
                // in place before returning a pass verdict.
                packet.as_mut_ptr(),
                packet.len(),
                modified.as_mut_ptr(),
                &mut length,
            )
        };
        let outbound: Option<&[u8]> = match verdict & VERDICT_MASK {
            VERDICT_PASS => {
                report(Event::Pass as u32, *id, packet.len(), 0);
                Some(packet)
            }
            VERDICT_MODIFY => match modified.get(..length) {
                Some(bytes) => {
                    report(Event::Modify as u32, *id, packet.len(), length);
                    Some(bytes)
                }
                None => {
                    report(Event::InvalidModification as u32, *id, packet.len(), length);
                    None
                }
            },
            _ => {
                report(Event::Drop as u32, *id, packet.len(), 0);
                None
            }
        };
        if let Some(bytes) = outbound {
            if !unsafe { (ops.send)(addresses, index, bytes.as_ptr(), bytes.len()) } {
                report(Event::SendFailed as u32, *id, bytes.len(), 0);
            }
        }
        data = rest;
        *id = id.wrapping_add(1);
    }
}

fn split_packet(data: &mut [u8], ipv6: bool) -> Option<(&mut [u8], &mut [u8])> {
    let (header, field) = if ipv6 { (40, 4) } else { (20, 2) };
    if data.len() < header {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([data[field], data[field + 1]]));
    let length = if ipv6 { header + declared } else { declared };
    data.split_at_mut_checked(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct IdleState {
        active: bool,
        now: u64,
        deadline: u64,
        quitting: bool,
        cancel_during_sleep: bool,
        waits: Vec<u64>,
        reports: Vec<bool>,
        prepared: usize,
        fired: usize,
    }

    thread_local! {
        static IDLE: RefCell<IdleState> = RefCell::default();
    }
    extern "C" fn active() -> bool {
        IDLE.with_borrow(|state| state.active)
    }
    extern "C" fn dirty() -> bool {
        false
    }
    extern "C" fn next() -> u64 {
        IDLE.with_borrow(|state| state.deadline)
    }
    extern "C" fn now() -> u64 {
        IDLE.with_borrow(|state| state.now)
    }
    extern "C-unwind" fn run(_: u64) -> u64 {
        IDLE.with_borrow_mut(|state| {
            assert!(state.now >= state.deadline);
            state.fired += 1;
            state.active = false;
        });
        0
    }
    extern "C" fn quitting() -> bool {
        IDLE.with_borrow(|state| state.quitting)
    }
    extern "C" fn sleep(delay: u64) {
        IDLE.with_borrow_mut(|state| {
            state.now += delay;
            state.waits.push(delay);
            state.quitting = state.cancel_during_sleep;
        });
    }
    extern "C-unwind" fn prepare() {
        IDLE.with_borrow_mut(|state| state.prepared += 1);
    }
    extern "C" fn report(quit: bool) {
        IDLE.with_borrow_mut(|state| state.reports.push(quit));
    }

    fn idle() {
        zapret_idle_loop(
            &TimerOps {
                active,
                dirty,
                next,
                now,
                run,
            },
            quitting,
            sleep,
            prepare,
            report,
        );
    }

    #[test]
    fn distant_idle_timer_does_not_delay_a_quit_request() {
        IDLE.set(IdleState {
            active: true,
            deadline: 60_000,
            cancel_during_sleep: true,
            ..IdleState::default()
        });
        idle();
        IDLE.with_borrow(|state| {
            assert_eq!(state.waits, [50]);
            assert_eq!(state.reports, [false, true]);
            assert_eq!(state.prepared, 0);
            assert_eq!(state.fired, 0);
        });
    }

    #[test]
    fn bounded_idle_wait_fires_once_at_the_actual_deadline() {
        IDLE.set(IdleState {
            active: true,
            deadline: 125,
            ..IdleState::default()
        });
        idle();
        IDLE.with_borrow(|state| {
            assert_eq!(state.waits, [50, 50, 25]);
            assert_eq!(state.now, 125);
            assert_eq!(state.prepared, 1);
            assert_eq!(state.fired, 1);
        });
    }
}
