//! Render TLS diagnostics while reading each field at its original observation.
use crate::{logging::LogSink, protocol::tls::TLSVersionStr};
use std::{ffi::c_char, ptr};

struct Flow {
    phase: u32,
    record: bool,
    server: bool,
    data: *const u8,
    length: usize,
    cursor: *const u8,
    remaining: usize,
    advance: usize,
}

impl Flow {
    fn new(data: *const u8, length: usize, record: bool) -> Self {
        Self {
            phase: 0,
            record,
            server: false,
            data,
            length,
            cursor: ptr::null(),
            remaining: 0,
            advance: 0,
        }
    }
}

struct Feedback {
    extension: *const u8,
    length: usize,
    debug: bool,
    server: bool,
    found: bool,
}

impl Default for Feedback {
    fn default() -> Self {
        Self {
            extension: ptr::null(),
            length: 0,
            debug: false,
            server: false,
            found: false,
        }
    }
}

#[derive(Default)]
struct View {
    version: u16,
    text: [u8; 32],
}
unsafe fn word(p: *const u8) -> u16 {
    u16::from_be_bytes(unsafe { [*p, *p.add(1)] })
}
fn after_versions(flow: &Flow) -> u32 {
    if flow.server { 14 } else { 9 }
}
unsafe fn version(flow: &mut Flow, view: &mut View) -> u32 {
    if flow.remaining == 0 {
        return after_versions(flow);
    }
    view.version = unsafe { word(flow.cursor) };
    7
}
unsafe fn alpn(flow: &mut Flow, view: &mut View) -> u32 {
    if flow.remaining == 0 {
        return 12;
    }
    let length = unsafe { *flow.cursor } as usize;
    flow.cursor = unsafe { flow.cursor.add(1) };
    flow.remaining -= 1;
    if length > flow.remaining {
        return 12;
    }
    let copied = length.min(31);
    unsafe { std::ptr::copy_nonoverlapping(flow.cursor, view.text.as_mut_ptr(), copied) };
    view.text[copied] = 0;
    flow.advance = length;
    10
}
unsafe fn step(flow: &mut Flow, value: &Feedback, view: &mut View) -> u32 {
    let next = match flow.phase {
        0 => 1,
        1 => {
            if !value.debug {
                14
            } else if flow.record {
                if flow.length < 11 {
                    14
                } else {
                    view.version = unsafe { word(flow.data.add(1)) };
                    2
                }
            } else if flow.length < 6 {
                14
            } else {
                4
            }
        }
        2 => {
            let length = 5 + unsafe { word(flow.data.add(3)) } as usize;
            flow.length = flow.length.min(length) - 5;
            flow.data = unsafe { flow.data.add(5) };
            3
        }
        3 => {
            if value.debug && flow.length >= 6 {
                4
            } else {
                14
            }
        }
        4 => {
            flow.server = value.server;
            view.version = unsafe { word(flow.data.add(4)) };
            5
        }
        5 => 6,
        6 => {
            if !value.found {
                8
            } else if value.length == 0 {
                after_versions(flow)
            } else {
                flow.cursor = value.extension;
                if flow.server {
                    flow.remaining = 2;
                    unsafe { version(flow, view) }
                } else {
                    let length = unsafe { *value.extension } as usize;
                    if length < value.length {
                        flow.cursor = unsafe { value.extension.add(1) };
                        flow.remaining = length & !1;
                        unsafe { version(flow, view) }
                    } else {
                        after_versions(flow)
                    }
                }
            }
        }
        7 => {
            flow.cursor = unsafe { flow.cursor.add(2) };
            flow.remaining -= 2;
            unsafe { version(flow, view) }
        }
        8 => after_versions(flow),
        9 => {
            if !value.found {
                11
            } else if value.length < 2 {
                12
            } else {
                let length = unsafe { word(value.extension) } as usize;
                if length > value.length - 2 {
                    12
                } else {
                    flow.cursor = unsafe { value.extension.add(2) };
                    flow.remaining = length;
                    unsafe { alpn(flow, view) }
                }
            }
        }
        10 => {
            flow.cursor = unsafe { flow.cursor.add(flow.advance) };
            flow.remaining -= flow.advance;
            unsafe { alpn(flow, view) }
        }
        11 => 12,
        12 => {
            let text: &[u8] = if value.found {
                b"present\0"
            } else {
                b"not present\0"
            };
            view.text[..text.len()].copy_from_slice(text);
            13
        }
        13 | 14 => 14,
        _ => 15,
    };
    flow.phase = next;
    next
}

type FindExtension =
    unsafe extern "C" fn(*const u8, usize, u16, *mut *const u8, *mut usize, bool) -> bool;

#[repr(C)]
struct Ops {
    server_hello: unsafe extern "C" fn(*const u8, usize, bool) -> bool,
    find_extension: FindExtension,
    debug: LogSink,
    error: LogSink,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_tls_debug(
    record: bool,
    data: *const u8,
    length: usize,
    debug_enabled: *const bool,
    ops: &Ops,
) {
    let mut flow = Flow::new(data, length, record);
    let mut value = Feedback::default();
    let mut view = View::default();
    let log = ops.debug;
    unsafe {
        loop {
            match step(&mut flow, &value, &mut view) {
                1 | 3 => value.debug = debug_enabled.read(),
                2 => {
                    log(
                        c"TLS record layer version : %s\n".as_ptr(),
                        TLSVersionStr(view.version),
                    );
                }
                4 => value.server = (ops.server_hello)(flow.data, flow.length, true),
                5 => {
                    log(
                        c"TLS handshake version : %s\n".as_ptr(),
                        TLSVersionStr(view.version),
                    );
                }
                action @ (6 | 9) => {
                    let extension = if action == 6 { 43 } else { 16 };
                    value.found = (ops.find_extension)(
                        flow.data,
                        flow.length,
                        extension,
                        &mut value.extension,
                        &mut value.length,
                        false,
                    );
                }
                7 => {
                    log(
                        c"TLS supported versions ext : %s\n".as_ptr(),
                        TLSVersionStr(view.version),
                    );
                }
                8 => {
                    log(c"TLS supported versions ext : not present\n".as_ptr());
                }
                10 => {
                    log(
                        c"TLS ALPN ext : %s\n".as_ptr(),
                        view.text.as_ptr().cast::<c_char>(),
                    );
                }
                11 => {
                    log(c"TLS ALPN ext : not present\n".as_ptr());
                }
                12 => {
                    value.found = (ops.find_extension)(
                        flow.data,
                        flow.length,
                        65037,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        false,
                    );
                }
                13 => {
                    log(
                        c"TLS ECH ext : %s\n".as_ptr(),
                        view.text.as_ptr().cast::<c_char>(),
                    );
                }
                14 => return,
                _ => {
                    (ops.error)(c"invalid TLS diagnostic cursor\n".as_ptr());
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow(data: &[u8], record: bool) -> Flow {
        Flow::new(data.as_ptr(), data.len(), record)
    }
    fn value() -> Feedback {
        Feedback {
            debug: true,
            ..Feedback::default()
        }
    }
    #[test]
    fn debug_off_skips_even_unreadable_input() {
        let mut f = flow(&[], false);
        f.data = std::ptr::null();
        f.length = usize::MAX;
        let mut v = value();
        v.debug = false;
        let mut out = View {
            version: 0,
            text: [0; 32],
        };
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 1);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 14);
    }
    #[test]
    fn version_words_remain_borrowed_until_their_individual_log() {
        let mut f = flow(&[1, 0, 0, 0, 3, 3], false);
        let mut v = value();
        let mut out = View {
            version: 0,
            text: [0; 32],
        };
        for want in [1, 4, 5, 6] {
            assert_eq!(unsafe { step(&mut f, &v, &mut out) }, want);
        }
        let mut versions = [4, 3, 4, 3, 3];
        v.extension = versions.as_ptr();
        v.length = 5;
        v.found = true;
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 7);
        assert_eq!(out.version, 0x304);
        versions[4] = 2;
        assert_eq!(versions[4], 2);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 7);
        assert_eq!(out.version, 0x302);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 9);
        let alpn = [0, 5, 2, b'h', b'2', 1, b'x'];
        v.extension = alpn.as_ptr();
        v.length = alpn.len();
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 10);
        assert_eq!(&out.text[..3], b"h2\0");
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 10);
        assert_eq!(&out.text[..2], b"x\0");
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 12);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 13);
        assert_eq!(&out.text[..8], b"present\0");
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 14);
    }
    #[test]
    fn record_is_clamped_only_after_record_log_then_debug_is_observed_again() {
        let mut f = flow(&[22, 3, 1, 0, 1, 1, 0, 0, 0, 3, 3, 0], true);
        let mut v = value();
        let mut out = View {
            version: 0,
            text: [0; 32],
        };
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 1);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 2);
        assert_eq!(out.version, 0x301);
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 3);
        assert_eq!(f.length, 1);
        v.debug = false;
        assert_eq!(unsafe { step(&mut f, &v, &mut out) }, 14);
    }
}
