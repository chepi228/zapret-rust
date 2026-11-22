//! Deliver automatic hostlist records through the native log and append sinks.
use super::{Context, Event, config, connection};
use crate::{
    native_logging_entry::LogSink,
    profile_config::{profile_name, profile_number},
    protocol::l7proto_str,
};
use std::{
    ffi::{c_char, c_int},
    mem,
};

#[repr(C)]
struct Sinks {
    debug: LogSink,
    error: LogSink,
    hostlist_append: LogSink,
    perror: unsafe extern "C" fn(*const c_char) -> c_int,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_autolist_report(
    event: u32,
    ctx: *const Context,
    a: u64,
    b: u64,
    d: u64,
    e: u64,
    sinks: &Sinks,
) {
    if event > Event::IncomingLimit as u32 {
        return;
    }
    // Event has consecutive u32 discriminants starting at zero.
    let event = unsafe { mem::transmute::<u32, Event>(event) };
    let (a, b, d, e) = (a as u32, b as u32, d as u32, e as u32);
    let &Sinks {
        debug,
        error,
        hostlist_append,
        perror,
    } = sinks;
    unsafe {
        // Capture the profile identity once. Native output can precede a second read
        // of the profile fields, host, endpoint and connection's current profile.
        let profile = (*ctx).profile;
        let number = || profile_number(profile);
        let name = || {
            let name = profile_name(profile);
            if name.is_null() {
                c"noname".as_ptr()
            } else {
                name
            }
        };
        let hostname = || (*ctx).hostname;
        let filename = || (*(*config(profile)).automatic).filename;
        let tracked_number = || profile_number((*connection((*ctx).track)).profile);
        let prefix = || {
            (
                hostname(),
                name(),
                (*ctx).client_text,
                l7proto_str((*ctx).l7),
            )
        };
        match event {
            Event::ResetCounter => {
                debug(c"auto hostlist (profile %u (%s)) : %s : fail counter reset. website is working.\n".as_ptr(),
                    number(), name(), hostname());
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : fail counter reset. website is working.".as_ptr(),
                    host, number(), name, client, proto)
            }
            Event::OutsideSequence => debug(
                c"retrans : tcp seq %u not within range %u-%u. stop tracking.\n".as_ptr(),
                a, b, d,
            ),
            Event::RetransThreshold => debug(c"retrans threshold reached : %u/%u\n".as_ptr(), a, b),
            Event::SendReset => {
                let name = (*ctx).interface;
                let name = if name.is_null() { c"".as_ptr() } else { name };
                debug(c"sending RST to retransmitter. ifname=%s\n".as_ptr(), name)
            }
            Event::RetransCounter => debug(c"retrans counter : %u/%u\n".as_ptr(), a, b),
            Event::CounterAllocationFailed => error(c"HostFailPoolAdd: out of memory\n".as_ptr()),
            Event::FailureCounter => {
                let (a, b) = (a as c_int, b as c_int);
                debug(c"auto hostlist (profile %u (%s)) : %s : fail counter %d/%d\n".as_ptr(),
                    number(), name(), hostname(), a, b);
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : fail counter %d/%d".as_ptr(),
                    host, number(), name, client, proto, a, b)
            }
            Event::FailureThreshold => debug(
                c"auto hostlist (profile %u (%s)) : fail threshold reached. about to add %s to auto hostlist\n".as_ptr(),
                number(), name(), hostname(),
            ),
            Event::RecheckHost => debug(
                c"auto hostlist (profile %u (%s)) : rechecking %s to avoid duplicates\n".as_ptr(),
                number(), name(), hostname(),
            ),
            Event::AddHost => {
                debug(c"auto hostlist (profile %u) : adding %s to %s\n".as_ptr(), number(), hostname(), filename());
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : adding to %s".as_ptr(),
                    host, number(), name, client, proto, filename())
            }
            Event::SkipHost => {
                debug(c"auto hostlist (profile %u) : NOT adding %s\n".as_ptr(), number(), hostname());
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : NOT adding, duplicate detected".as_ptr(),
                    host, number(), name, client, proto)
            }
            Event::HostAllocationFailed => error(c"StrPoolAddStr out of memory\n".as_ptr()),
            Event::AppendFailed => perror(c"write to auto hostlist".as_ptr()),
            Event::StampFailed => perror(c"file_mod_signature".as_ptr()),
            Event::RetransFailure => {
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : retrans threshold reached".as_ptr(),
                    host, number(), name, client, proto)
            }
            Event::UdpSuccess => debug(c"udp_in %u > %u\n".as_ptr(), a, b),
            Event::UdpFailure => {
                debug(c"udp_in %u <= %u, udp_out %u >= %u\n".as_ptr(), a, b, d, e);
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : udp_in %u<=%u udp_out %u>=%u".as_ptr(),
                    host, number(), name, client, proto, a, b, d, e)
            }
            Event::IncomingReset => {
                debug(c"incoming RST detected for hostname %s rseq %u\n".as_ptr(), hostname(), a);
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : rseq %u : incoming RST".as_ptr(),
                    host, tracked_number(), name, client, proto, a)
            }
            Event::IncomingHttp => debug(c"incoming HTTP reply detected for hostname %s rseq %u\n".as_ptr(), hostname(), a),
            Event::RedirectOther => {
                debug(c"redirect to another domain detected. possibly DPI redirect.\n".as_ptr());
                let (host, name, client, proto) = prefix();
                hostlist_append(c"%s : profile %u (%s) : client %s : proto %s : rseq %u : redirect to another domain".as_ptr(),
                    host, tracked_number(), name, client, proto, a)
            }
            Event::RedirectLocal => debug(c"local or in-domain redirect detected. it's not a DPI redirect.\n".as_ptr()),
            Event::IncomingLimit => debug(c"incoming rseq %u > %u\n".as_ptr(), a, b),
        };
    }
}
