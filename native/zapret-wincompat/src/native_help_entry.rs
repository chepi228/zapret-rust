//! Bounded assembly of the native Windows help text.
use crate::{
    logging::LogSink,
    protocol::{l7payload_str, l7proto_str},
};
use std::ffi::{c_char, c_int};

#[path = "native_help_catalog.rs"]
mod catalog;

const DEFAULTS: [u32; 13] = [60, 300, 60, 60, 7200, 60, 3, 60, 3, 32768, 4096, 4, 1];
type Lookup = unsafe extern "C" fn(u32) -> *const c_char;

#[repr(C)]
struct HelpNames {
    payload: Lookup,
    protocol: Lookup,
}

const NAMES: HelpNames = HelpNames {
    payload: l7payload_str,
    protocol: l7proto_str,
};

unsafe fn help_names(buffer: &mut [u8], lookup: Lookup, count: u32) {
    let mut used = 0;
    let limit = buffer.len() - 1;
    for index in 0..count {
        // Look up every name in order, including those that no longer fit.
        let name = unsafe { lookup(index) };
        if index != 0 && used < limit {
            buffer[used] = b' ';
            used += 1;
        }
        for offset in 0..limit - used {
            let byte = unsafe { name.add(offset).read() } as u8;
            if byte == 0 {
                break;
            }
            buffer[used] = byte;
            used += 1;
        }
    }
    buffer[used] = 0;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_help(names: *const HelpNames, print: LogSink) -> c_int {
    let names = unsafe { names.as_ref() }.unwrap_or(&NAMES);
    let mut payloads = [0; 1024];
    let mut protocols = [0; 512];
    let d = DEFAULTS;
    unsafe {
        help_names(&mut payloads, names.payload, 31);
        help_names(&mut protocols, names.protocol, 16);
        print(
            catalog::FORMAT.as_ptr(),
            d[0],
            d[1],
            d[2],
            d[3],
            d[4],
            d[5],
            protocols.as_ptr().cast::<c_char>(),
            d[6] as c_int,
            d[7] as c_int,
            d[8] as c_int,
            d[9],
            d[10],
            d[11],
            d[12],
            payloads.as_ptr().cast::<c_char>(),
        );
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    unsafe extern "C" fn names_with_empty(index: u32) -> *const c_char {
        [c"a", c"", c"c"][index as usize].as_ptr()
    }

    #[test]
    fn label_order_and_separators_include_empty_names() {
        let mut buffer = [0; 16];
        unsafe { help_names(&mut buffer, names_with_empty, 3) };
        assert_eq!(CStr::from_bytes_until_nul(&buffer), Ok(c"a  c"));
    }

    unsafe extern "C" fn long_name(_: u32) -> *const c_char {
        static INPUT: [u8; 2001] = [b'x'; 2001];
        INPUT.as_ptr().cast()
    }

    #[test]
    fn long_names_are_bounded_and_null_terminated() {
        let mut payloads = [0; 1024];
        let mut protocols = [0; 512];
        unsafe {
            help_names(&mut payloads, long_name, 31);
            help_names(&mut protocols, long_name, 16);
        }
        assert_eq!(payloads[1022..], [b'x', 0]);
        assert_eq!(protocols[510..], [b'x', 0]);
    }
}
