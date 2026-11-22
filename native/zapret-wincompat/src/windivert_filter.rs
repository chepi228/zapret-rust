//! Bounded formatting of the existing WinDivert capture filter.
#[cfg(windows)]
mod startup;
use crate::filters::{ANY, SKIP, icmp_filter, ip_filter, port_filter};
use std::{
    ffi::{CStr, c_char},
    fmt::{self, Write},
    mem::MaybeUninit,
    ptr, slice,
};

const IPV4: u32 = 1;
const IPV6: u32 = 2;
const EMPTY_TCP: u32 = 4;
const EXCLUDE_LAN: u32 = 8;
const EXCLUDE_LOOPBACK: u32 = 16;
const CONTROL_TCP: &str = "(tcp.Syn or tcp.Rst or tcp.Fin)";
const NONEMPTY_TCP: &str = "(!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0)";
const HTTP_REDIRECT: &str = concat!(
    "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31",
    " and tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30",
    " and (tcp.Payload[11]==0x32 or tcp.Payload[11]==0x37)"
);

struct Buffer<'a> {
    bytes: &'a mut [MaybeUninit<u8>],
    end: usize,
}

impl Buffer<'_> {
    fn put(&mut self, value: &[u8]) -> fmt::Result {
        let end = self.end.checked_add(value.len()).ok_or(fmt::Error)?;
        if end >= self.bytes.len() {
            return Err(fmt::Error);
        }
        unsafe {
            ptr::copy_nonoverlapping(
                value.as_ptr(),
                self.bytes.as_mut_ptr().add(self.end).cast(),
                value.len(),
            );
        }
        self.end = end;
        Ok(())
    }

    fn separator(&mut self, seen: &mut bool) -> fmt::Result {
        if *seen {
            self.write_str(" or ")?;
        }
        *seen = true;
        Ok(())
    }
}

impl Write for Buffer<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.put(value.as_bytes())
    }
}

unsafe fn format_into(
    output: *mut c_char,
    size: usize,
    render: impl FnOnce(&mut Buffer<'_>) -> fmt::Result,
) -> bool {
    if output.is_null() || size == 0 || size > isize::MAX as usize {
        return false;
    }
    let bytes = unsafe { slice::from_raw_parts_mut(output.cast::<MaybeUninit<u8>>(), size) };
    let mut buffer = Buffer { bytes, end: 0 };
    let ok = render(&mut buffer).is_ok();
    buffer.bytes[if ok { buffer.end } else { 0 }].write(0);
    ok
}

unsafe fn text<'a>(value: *const c_char) -> &'a [u8] {
    if value.is_null() {
        &[]
    } else {
        unsafe { CStr::from_ptr(value) }.to_bytes()
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_ip_versions(
    option: *const c_char,
    ipv4: *mut bool,
    ipv6: *mut bool,
) -> bool {
    if option.is_null() {
        return true;
    }
    let mut found4 = false;
    let mut found6 = false;
    for part in unsafe { text(option) }.split(|&byte| byte == b',') {
        match part {
            b"ipv4" => found4 = true,
            b"ipv6" => found6 = true,
            _ => return false,
        }
    }
    unsafe {
        if found4 {
            ipv4.write(true);
        }
        if found6 {
            ipv6.write(true);
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_filter_clauses(
    option: *const c_char,
    kind: u32,
    protocol: *const c_char,
    field: *const c_char,
    output: *mut c_char,
    size: usize,
) -> bool {
    let options = (!option.is_null()).then(|| unsafe { text(option) });
    unsafe {
        format_into(output, size, |buffer| {
            let mut seen = false;
            let protocol = std::str::from_utf8(text(protocol)).map_err(|_| fmt::Error)?;
            let field = std::str::from_utf8(text(field)).map_err(|_| fmt::Error)?;
            buffer.write_char('(')?;
            for option in options
                .into_iter()
                .flat_map(|part| part.split(|&byte| byte == b','))
            {
                match kind {
                    0 => {
                        let filter = port_filter(option).ok_or(fmt::Error)?;
                        buffer.separator(&mut seen)?;
                        let (from, to) = (filter.from, filter.to);
                        if from == to {
                            let operator = if filter.negated { "!=" } else { "==" };
                            write!(buffer, "({protocol}.{field} {operator} {from})")?;
                        } else {
                            let (lower, join, upper) = if filter.negated {
                                ("<", "or", ">")
                            } else {
                                (">=", "and", "<=")
                            };
                            write!(
                                buffer,
                                "({protocol}.{field} {lower} {from} {join} {protocol}.{field} {upper} {to})"
                            )?;
                        }
                    }
                    1 => {
                        let filter = icmp_filter(option).ok_or(fmt::Error)?;
                        if filter.mode == SKIP {
                            continue;
                        }
                        buffer.separator(&mut seen)?;
                        let (kind, code) = (filter.kind, filter.code);
                        if filter.mode == ANY {
                            buffer.write_str("icmp or icmpv6")?;
                        } else if filter.code_valid {
                            write!(
                                buffer,
                                "icmp.Type=={kind} and icmp.Code=={code} or icmpv6.Type=={kind} and icmpv6.Code=={code}"
                            )?;
                        } else {
                            write!(buffer, "icmp.Type=={kind} or icmpv6.Type=={kind}")?;
                        }
                    }
                    2 => {
                        let filter = ip_filter(option).ok_or(fmt::Error)?;
                        if filter.mode == SKIP {
                            continue;
                        }
                        buffer.separator(&mut seen)?;
                        let protocol = filter.protocol;
                        if filter.mode == ANY {
                            buffer.write_str("ip or ipv6")?;
                        } else {
                            write!(
                                buffer,
                                "ip.Protocol=={protocol} or ipv6.NextHdr=={protocol}"
                            )?;
                        }
                    }
                    _ => return Err(fmt::Error),
                }
            }
            if !seen && kind != 0 {
                return Err(fmt::Error);
            }
            buffer.write_char(')')
        })
    }
}

#[repr(C)]
struct Part {
    value: *const c_char,
    next: *const Part,
}

#[repr(C)]
struct Filter {
    tcp_source_out: *const c_char,
    tcp_destination_out: *const c_char,
    tcp_source_in: *const c_char,
    tcp_destination_in: *const c_char,
    udp_source_in: *const c_char,
    udp_destination_out: *const c_char,
    icmp_out: *const c_char,
    icmp_in: *const c_char,
    ip_out: *const c_char,
    ip_in: *const c_char,
    raw: *const c_char,
    parts: *const Part,
    index: u32,
    sub_index: u32,
    flags: u32,
}

fn local_exclusions(buffer: &mut Buffer<'_>, address: &str, ipv4: bool, ipv6: bool) -> fmt::Result {
    if ipv4 && ipv6 {
        buffer.write_char('(')?;
    }
    if ipv4 {
        write!(
            buffer,
            "((ip.{address} < 10.0.0.0 or ip.{address} > 10.255.255.255) and (ip.{address} < 192.168.0.0 or ip.{address} > 192.168.255.255) and (ip.{address} < 172.16.0.0 or ip.{address} > 172.31.255.255) and (ip.{address} < 169.254.0.0 or ip.{address} > 169.254.255.255))"
        )?;
    }
    if ipv4 && ipv6 {
        buffer.write_str(" or ")?;
    }
    if ipv6 || !ipv4 {
        write!(
            buffer,
            "((ipv6.{address} < 2001::0 or ipv6.{address} >= 2001:1::0) and (ipv6.{address} < fc00::0 or ipv6.{address} >= fe00::0) and (ipv6.{address} < fe80::0 or ipv6.{address} >= fec0::0) and (ipv6.{address} < ff00::0 or ipv6.{address} >= ffff::0))"
        )?;
    }
    if ipv4 && ipv6 {
        buffer.write_char(')')?;
    }
    Ok(())
}

unsafe fn compile(filter: &Filter, buffer: &mut Buffer<'_>) -> fmt::Result {
    let ipv4 = filter.flags & IPV4 != 0;
    let ipv6 = filter.flags & IPV6 != 0;
    let tcp_out = unsafe { text(filter.tcp_destination_out) };
    let tcp_in = unsafe { text(filter.tcp_source_in) };
    let tcp = !tcp_out.is_empty() || !tcp_in.is_empty();
    buffer.write_str("!impostor")?;
    if filter.flags & EXCLUDE_LOOPBACK != 0 {
        buffer.write_str("\nand !loopback")?;
    }
    if filter.index != 0 {
        write!(
            buffer,
            "\nand ifIdx={} and subIfIdx={}",
            filter.index, filter.sub_index
        )?;
    }
    if ipv4 ^ ipv6 {
        buffer.write_str(if ipv4 { "\nand ip" } else { "\nand ipv6" })?;
    }
    if tcp && filter.flags & EMPTY_TCP == 0 {
        write!(buffer, "\nand {NONEMPTY_TCP}")?;
    }
    let raw = unsafe { text(filter.raw) };
    if !raw.is_empty() {
        buffer.write_str("\nand\n(\n")?;
        buffer.put(raw)?;
        buffer.write_str("\n)")?;
    }
    buffer.write_str("\nand\n(\n false")?;
    if tcp {
        write!(buffer, " or\n {HTTP_REDIRECT}")?;
    }
    let mut part = filter.parts;
    while let Some(node) = unsafe { part.as_ref() } {
        buffer.write_str(" or\n (\n")?;
        buffer.put(unsafe { text(node.value) })?;
        buffer.write_str("\n )")?;
        part = node.next;
    }
    for (spec, opposite_spec, direction, opposite) in [
        (tcp_out, filter.tcp_source_out, "outbound", "inbound"),
        (tcp_in, filter.tcp_destination_in, "inbound", "outbound"),
    ] {
        if !spec.is_empty() {
            write!(buffer, " or\n {direction} and ")?;
            buffer.put(spec)?;
            write!(buffer, " or\n {opposite} and {CONTROL_TCP} and ")?;
            buffer.put(unsafe { text(opposite_spec) })?;
        }
    }
    for (spec, direction) in [
        (filter.udp_destination_out, "outbound"),
        (filter.udp_source_in, "inbound"),
        (filter.icmp_in, "inbound"),
        (filter.icmp_out, "outbound"),
        (filter.ip_in, "inbound"),
        (filter.ip_out, "outbound"),
    ] {
        let spec = unsafe { text(spec) };
        if !spec.is_empty() {
            write!(buffer, " or\n {direction} and ")?;
            buffer.put(spec)?;
        }
    }
    buffer.write_str("\n)")?;
    if filter.flags & EXCLUDE_LAN != 0 {
        buffer.write_str("\nand\n(\n outbound and ")?;
        local_exclusions(buffer, "DstAddr", ipv4, ipv6)?;
        buffer.write_str("\n or\n inbound and ")?;
        local_exclusions(buffer, "SrcAddr", ipv4, ipv6)?;
        buffer.write_str("\n)\n")?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_build_windivert_filter(
    output: *mut c_char,
    size: usize,
    filter: &Filter,
) -> bool {
    unsafe { format_into(output, size, |buffer| compile(filter, buffer)) }
}
