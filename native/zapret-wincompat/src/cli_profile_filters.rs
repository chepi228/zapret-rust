//! Startup filter decisions and publication of each Lua rule's packet context.
use crate::{logging::LogSink, packet_policy::Range};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

#[repr(C)]
struct Target {
    value: *mut c_void,
    explicit: *mut bool,
    extra: *mut bool,
    payload: *const u64,
    incoming: *const Range,
    outgoing: *const Range,
}
#[repr(C)]
struct RulePrefix {
    name: *const c_char,
    payload: u64,
    incoming: Range,
    outgoing: Range,
}
type ParseCollection = unsafe extern "C" fn(*const c_char, *mut c_void) -> bool;
type ParseMask = unsafe extern "C" fn(*const c_char, *mut u64) -> bool;
#[repr(C)]
struct Ops {
    versions: Option<unsafe extern "C" fn(*const c_char, *mut bool, *mut bool) -> bool>,
    ports: Option<ParseCollection>,
    icmp: Option<ParseCollection>,
    ip_protocol: Option<ParseCollection>,
    protocols: Option<ParseMask>,
    payloads: Option<ParseMask>,
    range: Option<unsafe extern "C" fn(*const c_char, *mut Range) -> bool>,
    append: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut RulePrefix>,
}
fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_profile_filter(
    kind: u32,
    text: *const c_char,
    target: *const Target,
    ops: *const Ops,
) -> u32 {
    if kind > 11 || !aligned(target) || !aligned(ops) {
        return 1;
    }
    let target = unsafe { &*target };
    let ops = unsafe { &*ops };
    if target.value.is_null() || (text.is_null() && !matches!(kind, 6 | 7)) {
        return 1;
    }
    if kind == 11 {
        if !aligned(target.value.cast::<*mut c_void>())
            || !aligned(target.payload)
            || !aligned(target.incoming)
            || !aligned(target.outgoing)
        {
            return 1;
        }
        let Some(append) = ops.append else {
            return 1;
        };
        let rule = unsafe { append(target.value, text) };
        if rule.is_null() {
            return 3;
        }
        // The C parser has completed and published a valid owned function node.
        unsafe {
            (*rule).payload = target.payload.read();
            ptr::copy(target.incoming, ptr::addr_of_mut!((*rule).incoming), 1);
            ptr::copy(target.outgoing, ptr::addr_of_mut!((*rule).outgoing), 1);
        }
        return 0;
    }
    let success = match kind {
        0 => {
            let Some(parse) = ops.versions else {
                return 1;
            };
            if !aligned(target.value.cast::<bool>())
                || !aligned(target.extra)
                || !aligned(target.explicit)
            {
                return 1;
            }
            // The parser adds versions across repeated --filter-l3 arguments.
            let (mut ipv4, mut ipv6) =
                unsafe { (target.value.cast::<bool>().read(), target.extra.read()) };
            if !unsafe { parse(text, &mut ipv4, &mut ipv6) } {
                false
            } else {
                unsafe {
                    target.value.cast::<bool>().write(ipv4);
                    target.extra.write(ipv6);
                    target.explicit.write(true)
                };
                true
            }
        }
        1..=4 => {
            let parser = match kind {
                1 | 2 => ops.ports,
                3 => ops.icmp,
                _ => ops.ip_protocol,
            };
            let Some(parse) = parser else {
                return 1;
            };
            if !aligned(target.value.cast::<*mut c_void>()) {
                return 1;
            }
            unsafe { parse(text, target.value) }
        }
        5..=8 => {
            let parser = if kind == 5 {
                ops.protocols
            } else {
                ops.payloads
            };
            let Some(parse) = parser else {
                return 1;
            };
            if !aligned(target.value.cast::<u64>()) || (kind == 5 && !aligned(target.explicit)) {
                return 1;
            }
            let mut value = 0u64;
            if !text.is_null() && !unsafe { parse(text, &mut value) } {
                false
            } else {
                unsafe {
                    target.value.cast::<u64>().write(value);
                    if kind == 5 {
                        target.explicit.write(true)
                    }
                };
                true
            }
        }
        9 | 10 => {
            let Some(parse) = ops.range else {
                return 1;
            };
            if !aligned(target.value.cast::<Range>()) {
                return 1;
            }
            // All fields are initialized by a successful parser. Padding is not inspected.
            let mut value = std::mem::MaybeUninit::<Range>::uninit();
            if !unsafe { parse(text, value.as_mut_ptr()) } {
                false
            } else {
                unsafe { ptr::copy_nonoverlapping(value.as_ptr(), target.value.cast(), 1) };
                true
            }
        }
        _ => unreachable!(),
    };
    if success { 0 } else { 2 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cli_profile_filter_report(
    kind: u32,
    status: u32,
    text: *const c_char,
    error: LogSink,
) -> c_int {
    if status == 0 {
        return 1;
    }
    if status == 1 {
        unsafe { error(c"invalid profile filter storage\n".as_ptr()) };
        return -1;
    }
    if kind == 0 {
        unsafe { error(c"bad value for --filter-l3\n".as_ptr()) };
        return -1;
    }
    let format = match kind {
        1 | 2 => c"Invalid port filter : %s\n",
        3 => c"Invalid icmp filter : %s\n",
        4 => c"Invalid ip protocol filter : %s\n",
        5 => c"Invalid l7 filter : %s\n",
        6 | 8 => c"Invalid payload filter : %s\n",
        7 => c"Invalid l7 protocol list : %s\n",
        9 | 10 => c"invalid packet range value : %s\n",
        _ => c"invalid lua function call : %s\n",
    };
    let argument = if text.is_null() { c"".as_ptr() } else { text };
    unsafe { error(format.as_ptr(), argument) };
    -1
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(size_of::<Target>() == 48);
    assert!(size_of::<Ops>() == 64);
    assert!(size_of::<Range>() == 20);
    assert!(size_of::<RulePrefix>() == 56);
    assert!(std::mem::offset_of!(RulePrefix, incoming) == 16);
    assert!(std::mem::offset_of!(RulePrefix, outgoing) == 36);
};
