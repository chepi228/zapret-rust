//! Resource-free schema and scalar extraction between C-owned Lua operations.
use super::*;
use std::ffi::{CStr, c_char, c_void};

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Conversion {
    Integer = 1,
    Exact32,
    Flow,
    Address,
    Checked,
}
struct Spec {
    name: &'static CStr,
    conversion: Conversion,
    required: bool,
}
impl Spec {
    const fn integer(name: &'static CStr, required: bool) -> Self {
        Self {
            name,
            conversion: Conversion::Integer,
            required,
        }
    }
    const fn special(name: &'static CStr, conversion: Conversion) -> Self {
        Self {
            name,
            conversion,
            required: false,
        }
    }
}
const IPV4: &[Spec] = &[
    Spec::integer(c"ip_tos", false),
    Spec::integer(c"ip_len", false),
    Spec::integer(c"ip_id", false),
    Spec::integer(c"ip_off", false),
    Spec::integer(c"ip_ttl", true),
    Spec::integer(c"ip_p", true),
    Spec::special(c"ip_src", Conversion::Address),
    Spec::special(c"ip_dst", Conversion::Address),
];
const IPV6: &[Spec] = &[
    Spec::special(c"ip6_flow", Conversion::Flow),
    Spec::integer(c"ip6_nxt", false),
    Spec::integer(c"ip6_hlim", false),
    Spec::special(c"ip6_src", Conversion::Address),
    Spec::special(c"ip6_dst", Conversion::Address),
    Spec::special(c"ip6_plen", Conversion::Checked),
];
const TCP: &[Spec] = &[
    Spec::integer(c"th_sport", true),
    Spec::integer(c"th_dport", true),
    Spec::special(c"th_seq", Conversion::Exact32),
    Spec::special(c"th_ack", Conversion::Exact32),
    Spec::integer(c"th_x2", false),
    Spec::integer(c"th_flags", true),
    Spec::integer(c"th_win", true),
    Spec::integer(c"th_sum", false),
    Spec::integer(c"th_urp", false),
];
const UDP: &[Spec] = &[
    Spec::integer(c"uh_sport", true),
    Spec::integer(c"uh_dport", true),
    Spec::integer(c"uh_ulen", false),
    Spec::integer(c"uh_sum", false),
];
const ICMP: &[Spec] = &[
    Spec::integer(c"icmp_type", true),
    Spec::integer(c"icmp_code", true),
    Spec::special(c"icmp_data", Conversion::Exact32),
    Spec::integer(c"icmp_cksum", false),
];
fn layout(kind: u32) -> Option<(usize, usize, &'static [Spec])> {
    Some(match kind {
        0 => (size_of::<Ipv4Fields>(), mem::align_of::<Ipv4Fields>(), IPV4),
        1 => (size_of::<Ipv6Fields>(), mem::align_of::<Ipv6Fields>(), IPV6),
        2 => (size_of::<TcpFields>(), mem::align_of::<TcpFields>(), TCP),
        3 => (size_of::<UdpFields>(), mem::align_of::<UdpFields>(), UDP),
        4 => (size_of::<IcmpFields>(), mem::align_of::<IcmpFields>(), ICMP),
        _ => return None,
    })
}
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}
fn target_valid(pointer: *const c_void, alignment: usize) -> bool {
    !pointer.is_null() && pointer.addr() & (alignment - 1) == 0
}

#[repr(C)]
struct Cursor {
    target: *mut c_void,
    index: u32,
    kind: u32,
}
#[repr(C)]
struct Field {
    name: *const c_char,
    conversion: u32,
}
#[repr(C)]
struct Value {
    data: *const u8,
    length: usize,
    number: i64,
    tag: i32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_begin(
    kind: u32,
    target: *mut c_void,
    length: usize,
    cursor: *mut Cursor,
) -> bool {
    let Some((size, alignment, _)) = layout(kind) else {
        return false;
    };
    if length != size || !target_valid(target, alignment) || !aligned(cursor) {
        return false;
    }
    // C supplies exactly one writable serializer descriptor and a disjoint cursor.
    unsafe {
        target.cast::<u8>().write_bytes(0, size);
        cursor.write(Cursor {
            target,
            index: 0,
            kind,
        });
    }
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_next(cursor: *const Cursor, field: *mut Field) -> u32 {
    if !aligned(cursor) || !aligned(field) {
        return 2;
    }
    let cursor = unsafe { &*cursor };
    let Some((_, alignment, schema)) = layout(cursor.kind) else {
        return 2;
    };
    if !target_valid(cursor.target, alignment) {
        return 2;
    }
    if cursor.index as usize == schema.len() {
        return 0;
    }
    let Some(spec) = schema.get(cursor.index as usize) else {
        return 2;
    };
    // Static field names remain valid after Rust returns and C enters the VM.
    unsafe {
        field.write(Field {
            name: spec.name.as_ptr(),
            conversion: spec.conversion as u32,
        });
    }
    1
}
#[unsafe(no_mangle)]
extern "C" fn zapret_lua_header_field_error_format(status: u32) -> *const c_char {
    match status {
        3 => c"reconstruct_ip6hdr: ip6_plen wrong type",
        _ => c"invalid Lua header state",
    }
    .as_ptr()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_header_observe(cursor: *mut Cursor, value: *const Value) -> u32 {
    if !aligned(cursor) || !aligned(value) {
        return 2;
    }
    let cursor = unsafe { &mut *cursor };
    let value = unsafe { &*value };
    let Some((_, alignment, schema)) = layout(cursor.kind) else {
        return 2;
    };
    if !target_valid(cursor.target, alignment) {
        return 2;
    }
    let Some(spec) = schema.get(cursor.index as usize) else {
        return 2;
    };
    let address_length = if cursor.kind == 0 { 4 } else { 16 };
    match spec.conversion {
        Conversion::Integer if spec.required && value.tag != 3 => return 1,
        Conversion::Exact32 if value.tag != 3 => return 1,
        Conversion::Address
            if value.tag != 4 || value.length != address_length || value.data.is_null() =>
        {
            return 1;
        }
        Conversion::Checked if value.tag != 0 && value.tag != 3 => return 3,
        _ => {}
    }
    let number = value.number;
    // The descriptor stays C-owned between observations. Only the selected
    // initialized scalar is written, and address bytes are consumed before a VM call.
    macro_rules! set {
        ($ty:ty,$field:ident,$value:expr) => {
            unsafe { ptr::addr_of_mut!((*cursor.target.cast::<$ty>()).$field).write($value) }
        };
    }
    macro_rules! address {
        ($ty:ty,$field:ident) => {
            unsafe {
                ptr::copy(
                    value.data,
                    ptr::addr_of_mut!((*cursor.target.cast::<$ty>()).$field).cast::<u8>(),
                    address_length,
                )
            }
        };
    }
    match (cursor.kind, cursor.index) {
        (0, 0) => set!(Ipv4Fields, service, number as u8),
        (0, 1) => set!(Ipv4Fields, length, number as u16),
        (0, 2) => set!(Ipv4Fields, identification, number as u16),
        (0, 3) => set!(Ipv4Fields, fragment, number as u16),
        (0, 4) => set!(Ipv4Fields, hop_limit, number as u8),
        (0, 5) => set!(Ipv4Fields, protocol, number as u8),
        (0, 6) => address!(Ipv4Fields, source),
        (0, 7) => address!(Ipv4Fields, destination),
        (1, 0) => set!(
            Ipv6Fields,
            flow,
            if value.tag == 3 {
                number as u32
            } else {
                0x60000000
            }
        ),
        (1, 1) => set!(Ipv6Fields, next, number as u8),
        (1, 2) => set!(Ipv6Fields, hop_limit, number as u8),
        (1, 3) => address!(Ipv6Fields, source),
        (1, 4) => address!(Ipv6Fields, destination),
        (1, 5) => {
            if value.tag == 3 {
                set!(Ipv6Fields, payload_length, number as u16);
                set!(Ipv6Fields, has_payload_length, 1);
            }
        }
        (2, 0) => set!(TcpFields, source, number as u16),
        (2, 1) => set!(TcpFields, destination, number as u16),
        (2, 2) => set!(TcpFields, sequence, number as u32),
        (2, 3) => set!(TcpFields, acknowledgement, number as u32),
        (2, 4) => set!(TcpFields, reserved, number as u8),
        (2, 5) => set!(TcpFields, flags, number as u8),
        (2, 6) => set!(TcpFields, window, number as u16),
        (2, 7) => set!(TcpFields, checksum, number as u16),
        (2, 8) => set!(TcpFields, urgent, number as u16),
        (3, 0) => set!(UdpFields, source, number as u16),
        (3, 1) => set!(UdpFields, destination, number as u16),
        (3, 2) => set!(UdpFields, length, number as u16),
        (3, 3) => set!(UdpFields, checksum, number as u16),
        (4, 0) => set!(IcmpFields, kind, number as u8),
        (4, 1) => set!(IcmpFields, code, number as u8),
        (4, 2) => set!(IcmpFields, data, number as u32),
        (4, 3) => set!(IcmpFields, checksum, number as u16),
        _ => return 2,
    }
    cursor.index += 1;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CStr, mem::MaybeUninit};
    #[test]
    fn optional_numeric_strings_are_narrowed_but_required_fields_need_a_number() {
        let mut fields = MaybeUninit::<Ipv4Fields>::uninit();
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_begin(
                0,
                fields.as_mut_ptr().cast(),
                size_of::<Ipv4Fields>(),
                cursor.as_mut_ptr(),
            )
        });
        let mut cursor = unsafe { cursor.assume_init() };
        let mut field = MaybeUninit::<Field>::uninit();
        assert_eq!(
            unsafe { zapret_lua_header_next(&cursor, field.as_mut_ptr()) },
            1
        );
        assert_eq!(
            unsafe { CStr::from_ptr(field.assume_init_ref().name) },
            c"ip_tos"
        );
        let input = Value {
            number: 300,
            tag: 4,
            data: ptr::null(),
            length: 0,
        };
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &input) }, 0);
        assert_eq!(unsafe { fields.assume_init_ref() }.service, 44);
        cursor.index = 4;
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &input) }, 1);
        assert_eq!(cursor.index, 4);
        assert_eq!(unsafe { fields.assume_init_ref() }.hop_limit, 0);
    }
    #[test]
    fn ipv6_payload_presence_and_wrong_type_remain_distinct() {
        let mut fields = MaybeUninit::<Ipv6Fields>::uninit();
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_begin(
                1,
                fields.as_mut_ptr().cast(),
                size_of::<Ipv6Fields>(),
                cursor.as_mut_ptr(),
            )
        });
        let mut cursor = unsafe { cursor.assume_init() };
        cursor.index = 5;
        let mut value = Value {
            tag: 0,
            number: 65537,
            data: ptr::null(),
            length: 0,
        };
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 0);
        assert_eq!(unsafe { fields.assume_init_ref() }.has_payload_length, 0);
        cursor.index = 5;
        value.tag = 4;
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 3);
        assert_eq!(cursor.index, 5);
        value.tag = 3;
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 0);
        assert_eq!(unsafe { fields.assume_init_ref() }.payload_length, 1);
        assert_eq!(unsafe { fields.assume_init_ref() }.has_payload_length, 1);
    }
    #[test]
    fn addresses_require_exact_binary_string_width_before_copying() {
        let mut fields = MaybeUninit::<Ipv4Fields>::uninit();
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_begin(
                0,
                fields.as_mut_ptr().cast(),
                size_of::<Ipv4Fields>(),
                cursor.as_mut_ptr(),
            )
        });
        let mut cursor = unsafe { cursor.assume_init() };
        cursor.index = 6;
        let bytes = [0, 255, 17, 0];
        let mut value = Value {
            data: bytes.as_ptr(),
            length: 3,
            number: 0,
            tag: 4,
        };
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 1);
        assert_eq!(unsafe { fields.assume_init_ref() }.source, [0; 4]);
        value.length = 4;
        value.tag = 3;
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 1);
        value.tag = 4;
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 0);
        assert_eq!(unsafe { fields.assume_init_ref() }.source, bytes);
    }
    #[test]
    fn tcp_sequence_narrowing_and_ipv6_flow_defaults_retain_the_existing_contract() {
        let mut tcp = MaybeUninit::<TcpFields>::uninit();
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe {
            zapret_lua_header_begin(
                2,
                tcp.as_mut_ptr().cast(),
                size_of::<TcpFields>(),
                cursor.as_mut_ptr(),
            )
        });
        let mut cursor = unsafe { cursor.assume_init() };
        cursor.index = 2;
        let value = Value {
            number: -1,
            tag: 3,
            data: ptr::null(),
            length: 0,
        };
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &value) }, 0);
        assert_eq!(unsafe { tcp.assume_init_ref() }.sequence, u32::MAX);
        let mut ip6 = MaybeUninit::<Ipv6Fields>::uninit();
        assert!(unsafe {
            zapret_lua_header_begin(
                1,
                ip6.as_mut_ptr().cast(),
                size_of::<Ipv6Fields>(),
                &mut cursor,
            )
        });
        let text = Value {
            number: -1,
            tag: 4,
            ..value
        };
        assert_eq!(unsafe { zapret_lua_header_observe(&mut cursor, &text) }, 0);
        assert_eq!(unsafe { ip6.assume_init_ref() }.flow, 0x60000000);
    }
    #[test]
    fn field_names_keep_the_required_lookup_order_for_all_five_headers() {
        let expected: &[&[&CStr]] = &[
            &[
                c"ip_tos", c"ip_len", c"ip_id", c"ip_off", c"ip_ttl", c"ip_p", c"ip_src", c"ip_dst",
            ],
            &[
                c"ip6_flow",
                c"ip6_nxt",
                c"ip6_hlim",
                c"ip6_src",
                c"ip6_dst",
                c"ip6_plen",
            ],
            &[
                c"th_sport",
                c"th_dport",
                c"th_seq",
                c"th_ack",
                c"th_x2",
                c"th_flags",
                c"th_win",
                c"th_sum",
                c"th_urp",
            ],
            &[c"uh_sport", c"uh_dport", c"uh_ulen", c"uh_sum"],
            &[c"icmp_type", c"icmp_code", c"icmp_data", c"icmp_cksum"],
        ];
        #[repr(align(8))]
        struct Storage([u8; 64]);
        for (kind, names) in expected.iter().enumerate() {
            let mut bytes = Storage([0; 64]);
            let mut cursor = MaybeUninit::uninit();
            assert!(unsafe {
                zapret_lua_header_begin(
                    kind as u32,
                    bytes.0.as_mut_ptr().cast(),
                    layout(kind as u32).unwrap().0,
                    cursor.as_mut_ptr(),
                )
            });
            let mut cursor = unsafe { cursor.assume_init() };
            let mut field = MaybeUninit::<Field>::uninit();
            for (index, name) in names.iter().enumerate() {
                cursor.index = index as u32;
                assert_eq!(
                    unsafe { zapret_lua_header_next(&cursor, field.as_mut_ptr()) },
                    1
                );
                assert_eq!(
                    unsafe { CStr::from_ptr(field.assume_init_ref().name) },
                    *name
                );
            }
            cursor.index = names.len() as u32;
            assert_eq!(
                unsafe { zapret_lua_header_next(&cursor, field.as_mut_ptr()) },
                0
            );
        }
    }
    #[test]
    fn invalid_storage_does_not_initialize_a_mismatched_descriptor() {
        let mut fields = MaybeUninit::<TcpFields>::uninit();
        unsafe {
            fields
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0xa5, size_of::<TcpFields>())
        };
        let mut cursor = Cursor {
            target: ptr::null_mut(),
            index: 99,
            kind: 99,
        };
        assert!(!unsafe {
            zapret_lua_header_begin(
                2,
                fields.as_mut_ptr().cast(),
                size_of::<TcpFields>() - 1,
                &mut cursor,
            )
        });
        assert_eq!(cursor.index, 99);
        assert_eq!(unsafe { fields.as_ptr().cast::<u8>().read() }, 0xa5);
    }
}
