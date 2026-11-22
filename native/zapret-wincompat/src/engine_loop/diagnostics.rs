//! Capture loop diagnostics with native variadic argument types.
use super::Event;
use crate::native_logging_entry::LogSink;
use std::mem;

#[unsafe(no_mangle)]
extern "C" fn zapret_capture_idle_report(quitting: bool, debug: LogSink, console: LogSink) {
    unsafe {
        if quitting {
            console(c"quit requested\n".as_ptr());
        } else {
            debug(c"processing timers\n".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_capture_loop_report(
    event: u32,
    id: u32,
    length: usize,
    other: usize,
    debug: LogSink,
    error: LogSink,
    console: LogSink,
) {
    if event > Event::InvalidModification as u32 {
        return;
    }
    // Event has consecutive u32 discriminants starting at zero.
    let event = unsafe { mem::transmute::<u32, Event>(event) };
    unsafe {
        match event {
            Event::NetworkWaiting => {
                console(c"logical network is not present. waiting it to appear.\n".as_ptr())
            }
            Event::NetworkPresent => console(c"logical network now present\n".as_ptr()),
            Event::NetworkLost => {
                console(c"\nlogical network disappeared. deinitializing windivert.\n".as_ptr())
            }
            Event::Quit => debug(c"quit requested\n".as_ptr()),
            Event::NoInterceptQuit => debug(c"no intercept quit\n".as_ptr()),
            Event::Oversize => debug(c"windivert: ignoring too large packet\n".as_ptr()),
            Event::InvalidBatch => error(
                c"windivert: invalid batch (%zu bytes, %zu addresses)\n".as_ptr(),
                length,
                other,
            ),
            Event::InvalidIpv4 => error(c"invalid ipv4 packet\n".as_ptr()),
            Event::InvalidIpv6 => error(c"invalid ipv6 packet\n".as_ptr()),
            Event::Pass => debug(c"packet: id=%u reinject unmodified\n".as_ptr(), id),
            Event::Modify => debug(
                c"packet: id=%u reinject modified len %zu => %zu\n".as_ptr(),
                id,
                length,
                other,
            ),
            Event::Drop => debug(c"packet: id=%u drop\n".as_ptr(), id),
            Event::SendFailed => {
                error(c"windivert: reinject of packet id=%u failed\n".as_ptr(), id)
            }
            Event::InvalidModification => error(
                c"windivert: packet id=%u invalid modified length %zu\n".as_ptr(),
                id,
                other,
            ),
        };
    }
}
