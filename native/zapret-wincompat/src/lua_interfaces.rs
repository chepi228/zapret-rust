//! Windows adapter queries and borrowed views between C-owned Lua operations.
use crate::address_prefix::{zapret_prefix_mask4, zapret_prefix_mask6};
use std::{
    ffi::{CStr, c_char, c_void},
    mem, ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH as Adapter, IP_ADAPTER_UNICAST_ADDRESS_LH as Address,
    },
    Networking::WinSock::AF_UNSPEC,
};

type AdapterQuery =
    unsafe extern "system" fn(u32, u32, *const c_void, *mut Adapter, *mut u32) -> u32;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_interfaces_read(
    adapters: *mut Adapter,
    size: *mut u32,
    query: AdapterQuery,
) -> bool {
    let flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
    let status = unsafe { query(u32::from(AF_UNSPEC), flags, ptr::null(), adapters, size) };
    // The probe reports the required allocation; the fill must succeed outright.
    status
        == if adapters.is_null() {
            ERROR_BUFFER_OVERFLOW
        } else {
            ERROR_SUCCESS
        }
}

#[repr(C)]
struct Cursor {
    adapter: *const Adapter,
    address: *const Address,
    index: i64,
    phase: u32,
    host_mask: u32,
}
#[repr(C)]
struct Field {
    name: *const c_char,
    data: *const u8,
    number: i64,
    length: usize,
    kind: u32,
    bytes: [u8; 16],
    label: [u8; 16],
}
const _: () = {
    let pointer = size_of::<usize>();
    let (field_size, adapter_size, physical, speed, connection, address) =
        if cfg!(target_pointer_width = "64") {
            (72, 448, 80, 184, 268, 16)
        } else {
            (56, 376, 44, 144, 212, 12)
        };
    assert!(size_of::<Cursor>() == 2 * pointer + 16);
    assert!(mem::offset_of!(Cursor, index) == 2 * pointer);
    assert!(size_of::<Field>() == field_size);
    assert!(mem::offset_of!(Field, bytes) == 3 * pointer + 12);
    assert!(size_of::<Adapter>() == adapter_size);
    assert!(mem::offset_of!(Adapter, Next) == 8);
    assert!(mem::offset_of!(Adapter, PhysicalAddress) == physical);
    assert!(mem::offset_of!(Adapter, TransmitLinkSpeed) == speed);
    assert!(mem::offset_of!(Adapter, ConnectionType) == connection);
    assert!(mem::offset_of!(Address, Address) == address);
};
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

// IP Helper can pack Win32 records on a pointer boundary even though the SDK
// types contain an eight-byte-aligned union. Observe individual fields without
// creating an aligned reference or eagerly reading fields used by later steps.
fn record_aligned<T>(pointer: *const T) -> bool {
    aligned(pointer.cast::<usize>())
}

macro_rules! read_field {
    ($record:expr, $($field:ident).+) => {
        (&raw const (*$record).$($field).+).read_unaligned()
    };
}

impl Field {
    fn new(kind: u32, name: Option<&CStr>) -> Self {
        Self {
            name: name.map_or(ptr::null(), CStr::as_ptr),
            data: ptr::null(),
            number: 0,
            length: 0,
            kind,
            bytes: [0; 16],
            label: [0; 16],
        }
    }
    fn integer(name: &CStr, value: i64) -> Self {
        Self {
            number: value,
            ..Self::new(4, Some(name))
        }
    }
    fn bytes(name: &CStr, value: &[u8]) -> Self {
        let mut result = Self::new(7, Some(name));
        result.bytes[..value.len()].copy_from_slice(value);
        result.length = value.len();
        result
    }
    unsafe fn address(address: *const Address) -> Self {
        let socket = unsafe { read_field!(address, Address.lpSockaddr) };
        let mut value = Self::new(7, Some(c"addr"));
        if !socket.is_null() {
            let family = unsafe { ptr::addr_of!((*socket).sa_family).read_unaligned() };
            let (offset, length) = match family {
                2 => (4, 4),
                23 => (8, 16),
                _ => (0, 0),
            };
            value.length = length;
            if length != 0 {
                unsafe {
                    ptr::copy_nonoverlapping(
                        socket.cast::<u8>().add(offset),
                        value.bytes.as_mut_ptr(),
                        length,
                    )
                };
            }
        }
        value
    }
    fn adapter(index: u32) -> Self {
        let mut value = Self::new(1, None);
        let mut digits = [0; 10];
        let mut number = index;
        let mut length = 0;
        loop {
            digits[length] = b'0' + (number % 10) as u8;
            length += 1;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        for (target, source) in value.label.iter_mut().zip(digits[..length].iter().rev()) {
            *target = *source;
        }
        value.label[length..length + 2].copy_from_slice(b".0");
        value
    }
}
impl Cursor {
    unsafe fn next(&mut self) -> Option<Field> {
        loop {
            if self.phase > 23 {
                return None;
            }
            if !self.adapter.is_null() && !record_aligned(self.adapter)
                || self.phase != 0 && self.adapter.is_null()
            {
                return None;
            }
            if (17..=22).contains(&self.phase) && !record_aligned(self.address) {
                return None;
            }
            let phase = self.phase;
            self.phase += 1;
            // Each borrowed descriptor is observed only in this Rust call. C may
            // allocate or invoke Lua after the resulting field has been returned.
            let adapter = (!self.adapter.is_null()).then_some(self.adapter);
            let value = match phase {
                0 => {
                    while !self.adapter.is_null() {
                        if !record_aligned(self.adapter) {
                            return None;
                        }
                        let adapter = self.adapter;
                        if unsafe {
                            !read_field!(adapter, FirstUnicastAddress).is_null()
                                && read_field!(adapter, OperStatus) == 1
                        } {
                            break;
                        }
                        self.adapter = unsafe { read_field!(adapter, Next) };
                    }
                    if self.adapter.is_null() {
                        self.phase = 24;
                        Field::new(0, None)
                    } else {
                        Field::adapter(unsafe {
                            read_field!(self.adapter, Anonymous1.Anonymous.IfIndex)
                        })
                    }
                }
                1 => {
                    let mut field = Field::new(2, Some(c"guid"));
                    field.data = unsafe { read_field!(adapter?, AdapterName) };
                    field
                }
                2 => {
                    let adapter = adapter?;
                    let length = unsafe { read_field!(adapter, PhysicalAddressLength) };
                    if length == 0 {
                        continue;
                    }
                    let mut field = Field::new(3, Some(c"phys"));
                    field.data = unsafe { (&raw const (*adapter).PhysicalAddress).cast() };
                    field.length = length as usize;
                    field
                }
                3 => Field::integer(c"index", unsafe {
                    read_field!(adapter?, Anonymous1.Anonymous.IfIndex)
                } as i64),
                4 => Field::integer(c"index6", unsafe { read_field!(adapter?, Ipv6IfIndex) }
                    as i64),
                5 => Field::integer(c"flags", unsafe { read_field!(adapter?, Anonymous2.Flags) }
                    as i64),
                6 => Field::integer(c"mtu", unsafe { read_field!(adapter?, Mtu) } as i64),
                7 => Field::integer(c"iftype", unsafe { read_field!(adapter?, IfType) } as i64),
                8 => Field::integer(c"speed_xmit", unsafe {
                    read_field!(adapter?, TransmitLinkSpeed)
                } as i64),
                9 => {
                    Field::integer(
                        c"speed_recv",
                        unsafe { read_field!(adapter?, ReceiveLinkSpeed) } as i64,
                    )
                }
                10 => Field::integer(c"metric4", unsafe { read_field!(adapter?, Ipv4Metric) }
                    as i64),
                11 => Field::integer(c"metric6", unsafe { read_field!(adapter?, Ipv6Metric) }
                    as i64),
                // The native C enum ABI promotes these as unsigned 32-bit
                // values, while windows-sys declares the same fields as i32.
                12 => Field::integer(
                    c"conntype",
                    unsafe { read_field!(adapter?, ConnectionType) } as u32 as i64,
                ),
                13 => Field::integer(c"tunneltype", unsafe { read_field!(adapter?, TunnelType) }
                    as u32 as i64),
                14 => Field::new(5, Some(c"addr")),
                15 | 16 => {
                    if phase == 15 {
                        self.address = unsafe { read_field!(adapter?, FirstUnicastAddress) };
                        self.index = 1;
                    }
                    if self.address.is_null() {
                        self.phase = 23;
                        Field::new(9, None)
                    } else if !record_aligned(self.address) {
                        return None;
                    } else {
                        self.phase = 17;
                        let mut field = Field::new(6, None);
                        field.number = self.index;
                        field
                    }
                }
                17 | 20 => unsafe { Field::address(self.address) },
                18 => {
                    let address = self.address;
                    let socket = unsafe { read_field!(address, Address.lpSockaddr) };
                    let family = if socket.is_null() {
                        0
                    } else {
                        unsafe { ptr::addr_of!((*socket).sa_family).read_unaligned() }
                    };
                    if family != 2 && family != 23 {
                        self.phase = 20;
                        continue;
                    }
                    let prefix = unsafe { read_field!(address, OnLinkPrefixLength) };
                    if family == 2 && prefix <= 32 {
                        self.host_mask = zapret_prefix_mask4(prefix as u32);
                        Field::bytes(c"netmask", &(!self.host_mask).to_ne_bytes())
                    } else if family == 23 && prefix <= 128 {
                        self.phase = 20;
                        let mask = zapret_prefix_mask6(128 - prefix as u32);
                        Field::bytes(c"netmask", unsafe { std::slice::from_raw_parts(mask, 16) })
                    } else {
                        self.phase = 20;
                        continue;
                    }
                }
                19 => {
                    let socket = unsafe { read_field!(self.address, Address.lpSockaddr) };
                    if socket.is_null() {
                        return None;
                    }
                    let address =
                        unsafe { socket.cast::<u8>().add(4).cast::<u32>().read_unaligned() };
                    Field::bytes(
                        c"broadcast",
                        &((!self.host_mask & address) | self.host_mask).to_ne_bytes(),
                    )
                }
                21 => Field::new(8, None),
                22 => {
                    self.address = unsafe { read_field!(self.address, Next) };
                    self.index = self.index.checked_add(1)?;
                    self.phase = 16;
                    continue;
                }
                23 => {
                    self.adapter = unsafe { read_field!(adapter?, Next) };
                    self.phase = 0;
                    continue;
                }
                _ => return None,
            };
            return Some(value);
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_interfaces_begin(
    head: *const Adapter,
    cursor: *mut Cursor,
) -> bool {
    if !aligned(cursor) || !head.is_null() && !record_aligned(head) {
        return false;
    }
    unsafe {
        cursor.write(Cursor {
            adapter: head,
            address: ptr::null(),
            index: 0,
            phase: 0,
            host_mask: 0,
        })
    };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_interfaces_next(cursor: *mut Cursor, field: *mut Field) -> bool {
    if !aligned(cursor) || !aligned(field) {
        return false;
    }
    let cursor = unsafe { &mut *cursor };
    let Some(value) = (unsafe { cursor.next() }) else {
        return false;
    };
    unsafe { field.write(value) };
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;
    #[test]
    fn down_and_empty_adapters_are_skipped_and_indices_keep_decimal_point_zero() {
        let mut empty = Adapter::default();
        let mut up = Adapter::default();
        let mut addr = Address::default();
        up.OperStatus = 1;
        up.FirstUnicastAddress = &mut addr;
        up.Anonymous1.Anonymous.IfIndex = u32::MAX;
        empty.Next = ptr::from_mut(&mut up);
        let mut cursor = MaybeUninit::uninit();
        let mut field = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_interfaces_begin(&empty, cursor.as_mut_ptr()) });
        let mut cursor = unsafe { cursor.assume_init() };
        assert!(unsafe { zapret_lua_interfaces_next(&mut cursor, field.as_mut_ptr()) });
        let field = unsafe { field.assume_init() };
        assert_eq!(field.kind, 1);
        assert_eq!(&field.label[..13], b"4294967295.0\0");
    }
    unsafe fn begin(adapter: *const Adapter) -> Cursor {
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_interfaces_begin(adapter, cursor.as_mut_ptr()) });
        unsafe { cursor.assume_init() }
    }
    unsafe fn next(cursor: &mut Cursor) -> Field {
        let mut field = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_interfaces_next(cursor, field.as_mut_ptr()) });
        unsafe { field.assume_init() }
    }
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn win32_ip_helper_records_can_be_four_byte_aligned() {
        #[repr(align(8))]
        struct Storage<const N: usize>([MaybeUninit<u8>; N]);

        let mut adapter_storage = Storage([MaybeUninit::uninit(); size_of::<Adapter>() + 4]);
        let mut address_storage = Storage([MaybeUninit::uninit(); size_of::<Address>() + 4]);
        let adapter = unsafe { adapter_storage.0.as_mut_ptr().add(4).cast::<Adapter>() };
        let address = unsafe { address_storage.0.as_mut_ptr().add(4).cast::<Address>() };
        assert!(!adapter.is_aligned() && !address.is_aligned());
        let speed = 0x1_0000_0000;
        unsafe {
            address.write_unaligned(Address::default());
            adapter.write_unaligned(Adapter {
                OperStatus: 1,
                FirstUnicastAddress: address,
                TransmitLinkSpeed: speed,
                ..Adapter::default()
            });
        }

        let mut cursor = unsafe { begin(adapter) };
        let mut seen_speed = false;
        let mut seen_address = false;
        loop {
            let field = unsafe { next(&mut cursor) };
            match field.kind {
                0 => break,
                4 if unsafe { CStr::from_ptr(field.name) } == c"speed_xmit" => {
                    assert_eq!(field.number, speed as i64);
                    seen_speed = true;
                }
                7 => seen_address = true,
                _ => {}
            }
        }
        assert!(seen_speed && seen_address);
    }
    #[test]
    fn all_scalar_fields_are_selected_in_the_original_order_and_speeds_keep_signed_bits() {
        let mut address = Address::default();
        let adapter = Adapter {
            OperStatus: 1,
            FirstUnicastAddress: &mut address,
            TransmitLinkSpeed: u64::MAX,
            ConnectionType: -1,
            TunnelType: i32::MIN,
            ..Adapter::default()
        };
        let mut cursor = unsafe { begin(&adapter) };
        assert_eq!(unsafe { next(&mut cursor) }.kind, 1);
        let mut names = Vec::new();
        while cursor.phase <= 14 {
            let field = unsafe { next(&mut cursor) };
            if !field.name.is_null() {
                names.push(unsafe { CStr::from_ptr(field.name) });
                if names.last() == Some(&c"speed_xmit") {
                    assert_eq!(field.number, -1);
                }
                if names.last() == Some(&c"conntype") {
                    assert_eq!(field.number, u32::MAX as i64);
                }
                if names.last() == Some(&c"tunneltype") {
                    assert_eq!(field.number, 1i64 << 31);
                }
            }
        }
        assert_eq!(
            names,
            vec![
                c"guid",
                c"index",
                c"index6",
                c"flags",
                c"mtu",
                c"iftype",
                c"speed_xmit",
                c"speed_recv",
                c"metric4",
                c"metric6",
                c"conntype",
                c"tunneltype",
                c"addr"
            ]
        );
    }
    #[test]
    fn ipv4_masks_and_broadcast_keep_the_existing_native_byte_convention() {
        use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
        for prefix in [0, 1, 24, 31, 32, 33] {
            let mut socket = SOCKADDR_IN {
                sin_family: 2,
                ..SOCKADDR_IN::default()
            };
            socket.sin_addr.S_un.S_addr = 0x070200c0;
            let mut address = Address {
                Address: windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS {
                    lpSockaddr: ptr::from_mut(&mut socket).cast(),
                    iSockaddrLength: 16,
                },
                OnLinkPrefixLength: prefix,
                ..Address::default()
            };
            let adapter = Adapter {
                OperStatus: 1,
                FirstUnicastAddress: &mut address,
                ..Adapter::default()
            };
            let mut cursor = unsafe { begin(&adapter) };
            let mut netmask = None;
            let mut broadcast = None;
            let mut duplicate = 0;
            loop {
                let f = unsafe { next(&mut cursor) };
                if f.kind == 0 {
                    break;
                }
                if f.kind == 7 {
                    match unsafe { CStr::from_ptr(f.name) } {
                        name if name == c"netmask" => netmask = Some(f.bytes),
                        name if name == c"broadcast" => broadcast = Some(f.bytes),
                        name if name == c"addr" => duplicate += 1,
                        _ => {}
                    }
                }
            }
            assert_eq!(duplicate, 2);
            if prefix > 32 {
                assert!(netmask.is_none() && broadcast.is_none());
            } else {
                let mask = zapret_prefix_mask4(prefix as u32);
                assert_eq!(&netmask.expect("netmask")[..4], &(!mask).to_ne_bytes());
                assert_eq!(
                    &broadcast.expect("broadcast")[..4],
                    &((!mask & 0x070200c0) | mask).to_ne_bytes()
                );
            }
        }
    }
    #[test]
    fn numeric_fields_are_read_after_the_preceding_vm_field_finishes() {
        let mut address = Address::default();
        let mut adapter = Adapter {
            OperStatus: 1,
            FirstUnicastAddress: &mut address,
            Mtu: 1500,
            ..Adapter::default()
        };
        let pointer = ptr::from_mut(&mut adapter);
        let mut cursor = unsafe { begin(&*pointer) };
        loop {
            let field = unsafe { next(&mut cursor) };
            if field.kind == 2 {
                unsafe {
                    (*pointer).Mtu = 1200;
                }
            }
            if field.kind == 4 && unsafe { CStr::from_ptr(field.name) } == c"mtu" {
                assert_eq!(field.number, 1200);
                break;
            }
        }
    }
    #[test]
    fn empty_views_finish_once_and_invalid_metadata_does_not_publish_a_field() {
        let mut cursor = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_interfaces_begin(ptr::null(), cursor.as_mut_ptr()) });
        let mut cursor = unsafe { cursor.assume_init() };
        assert_eq!(unsafe { next(&mut cursor) }.kind, 0);
        let mut field = Field::new(99, None);
        assert!(!unsafe { zapret_lua_interfaces_next(&mut cursor, &mut field) });
        assert_eq!(field.kind, 99);
        cursor.phase = 0;
        cursor.adapter = ptr::without_provenance(1);
        assert!(!unsafe { zapret_lua_interfaces_next(&mut cursor, &mut field) });
        assert_eq!(field.kind, 99);
    }
}
