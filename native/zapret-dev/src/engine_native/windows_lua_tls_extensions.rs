//! Parse and encode the structured TLS extension lists exposed to Lua.
use super::*;

#[derive(Clone, Copy)]
enum Shape {
    ServerName,
    Alpn,
    Words8,
    Words16,
    Bytes8,
    KeyShare,
    Transport16,
    TransportVarint,
}

impl Shape {
    fn for_type(vm: Stack, kind: c_int) -> Option<Self> {
        let top = vm.top();
        for (global, shape) in [
            (c"TLS_EXT_SERVER_NAME", Self::ServerName),
            (c"TLS_EXT_ALPN", Self::Alpn),
            (c"TLS_EXT_SUPPORTED_VERSIONS", Self::Words8),
            (c"TLS_EXT_COMPRESS_CERTIFICATE", Self::Words8),
            (c"TLS_EXT_SIGNATURE_ALGORITHMS", Self::Words16),
            (c"TLS_EXT_DELEGATED_CREDENTIALS", Self::Words16),
            (c"TLS_EXT_SUPPORTED_GROUPS", Self::Words16),
            (c"TLS_EXT_EC_POINT_FORMATS", Self::Bytes8),
            (c"TLS_EXT_PSK_KEY_EXCHANGE_MODES", Self::Bytes8),
            (c"TLS_EXT_KEY_SHARE", Self::KeyShare),
            (c"TLS_EXT_QUIC_TRANSPORT_PARAMETERS", Self::Transport16),
            (
                c"TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1",
                Self::TransportVarint,
            ),
        ] {
            let matched = vm.equal(kind, vm.field(GLOBALS, global));
            vm.reset(top);
            if matched {
                return Some(shape);
            }
        }
        None
    }

    fn length_bytes(self) -> usize {
        match self {
            Self::TransportVarint => 0,
            Self::Words8 | Self::Bytes8 => 1,
            _ => 2,
        }
    }
}

fn word(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[0], bytes[1]]) as usize
}

fn prefixed(bytes: &[u8], width: usize) -> Option<&[u8]> {
    let count = match width {
        0 => return Some(bytes),
        1 => usize::from(*bytes.first()?),
        _ => word(bytes.get(..2)?),
    };
    bytes.get(width..width + count)
}

fn push_transport_value(vm: Stack, key: c_int, data: &[u8]) -> c_int {
    let entry = vm.table(3);
    vm.assign(entry, c"type", key);
    put_name(vm, entry, c"TLS_HANDSHAKE_QUIC_TP_NAMES", key, false);
    put_bytes(vm, entry, c"data", data);
    entry
}

fn parse_pairs(vm: Stack, list: c_int, mut data: &[u8], shape: Shape) -> Option<()> {
    let header = match shape {
        Shape::ServerName => 3,
        Shape::Alpn => 1,
        _ => 4,
    };
    let start = vm.top();
    let mut index = 0;
    while data.len() >= header {
        let length = if header == 1 {
            usize::from(data[0])
        } else {
            word(&data[header - 2..header])
        };
        let bytes = data.get(header..header + length)?;
        let entry = match shape {
            Shape::ServerName => {
                let entry = vm.table(2);
                put_number(vm, entry, c"type", usize::from(data[0]));
                put_bytes(vm, entry, c"name", bytes);
                entry
            }
            Shape::Alpn => {
                vm.bytes(bytes);
                vm.top()
            }
            Shape::KeyShare => {
                let entry = vm.table(2);
                put_number(vm, entry, c"group", word(data));
                put_bytes(vm, entry, c"kex", bytes);
                entry
            }
            _ => {
                vm.integer(word(data) as isize);
                push_transport_value(vm, vm.top(), bytes)
            }
        };
        index += 1;
        vm.raw_array_put(list, index, entry);
        vm.reset(start);
        data = &data[header + length..];
    }
    Some(())
}

fn varint(vm: Stack, data: c_int, offset: usize) -> (c_int, c_int) {
    vm.integer(offset as isize + 1);
    let size = vm.call_global(c"quic_tvb", &[data, vm.top()], 2);
    (size - 1, size)
}

fn parse_transport_varints(vm: Stack, list: c_int, bytes: &[u8], source: c_int) -> Option<()> {
    let top = vm.top();
    let mut offset = 0usize;
    let mut index = 0;
    while bytes.len().checked_sub(offset)? >= 2 {
        let (kind, size) = varint(vm, source, offset);
        if !vm.truth(kind) {
            return None;
        }
        offset = offset.checked_add(vm.arithmetic_number(size) as usize)?;
        let (length, size) = varint(vm, source, offset);
        if vm.kind(length) != NUMBER {
            return None;
        }
        offset = offset.checked_add(vm.arithmetic_number(size) as usize)?;
        let end = offset.checked_add(vm.arithmetic_number(length) as usize)?;
        let value = push_transport_value(vm, kind, bytes.get(offset..end)?);
        index += 1;
        vm.raw_array_put(list, index, value);
        vm.reset(top);
        offset = end;
    }
    Some(())
}

pub(super) unsafe extern "C-unwind" fn dissect_ext(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 46) };
    vm.pad_arguments(1);
    vm.nil();
    vm.set(1, c"dis");
    let kind = vm.field(1, c"type");
    let Some(shape) = Shape::for_type(vm, kind) else {
        return 0;
    };
    let source = vm.field(1, c"data");
    if vm.kind(source) != STRING {
        vm.reset(1);
        return call_original(vm);
    }
    let (data, size) = vm.text(source);
    let Some(bytes) = prefixed(
        unsafe { slice::from_raw_parts(data, size) },
        shape.length_bytes(),
    ) else {
        return 0;
    };
    let dissect = vm.table(1);
    let list = vm.table(0);
    let complete = match shape {
        Shape::Words8 | Shape::Words16 => {
            for (index, bytes) in bytes.chunks_exact(2).enumerate() {
                vm.integer(word(bytes) as isize);
                vm.raw_array_put(list, index as c_int + 1, vm.top());
                vm.reset(list);
            }
            true
        }
        Shape::Bytes8 => {
            for (index, &byte) in bytes.iter().enumerate() {
                vm.integer(isize::from(byte));
                vm.raw_array_put(list, index as c_int + 1, vm.top());
                vm.reset(list);
            }
            true
        }
        Shape::TransportVarint => parse_transport_varints(vm, list, bytes, source).is_some(),
        _ => parse_pairs(vm, list, bytes, shape).is_some(),
    };
    if complete {
        vm.assign(dissect, c"list", list);
        vm.assign(1, c"dis", dissect);
    }
    0
}

pub(super) fn pack_size(vm: Stack, method: &CStr, size: usize) -> c_int {
    let top = vm.top();
    vm.integer(size as isize);
    vm.call_global(method, &[top + 1], 1);
    vm.replace(top + 1);
    top + 1
}

unsafe extern "C-unwind" fn pack_sni(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    let mut kind = vm.field(1, c"type");
    if !vm.truth(kind) {
        vm.integer(0);
        kind = vm.top();
    }
    let code = vm.call_global(c"bu8", &[kind], 1);
    let name = vm.field(1, c"name");
    pack_size(vm, c"bu16", vm.length(name));
    vm.replace(code + 1);
    vm.field(1, c"name");
    vm.concat(3);
    1
}

unsafe extern "C-unwind" fn pack_alpn(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    pack_size(vm, c"bu8", vm.length(1));
    vm.push(1);
    vm.concat(2);
    1
}

fn pack_keyed(vm: Stack, method: &CStr, key: &CStr, body: &CStr) -> c_int {
    let code = vm.call_global(method, &[vm.field(1, key)], 1);
    let data = vm.field(1, body);
    pack_size(vm, method, vm.length(data));
    vm.replace(code + 1);
    vm.field(1, body);
    vm.concat(3);
    1
}

unsafe extern "C-unwind" fn pack_share(lua: *mut LuaState) -> c_int {
    pack_keyed(unsafe { Stack::enter(lua, 12) }, c"bu16", c"group", c"kex")
}

unsafe extern "C-unwind" fn pack_transport16(lua: *mut LuaState) -> c_int {
    pack_keyed(unsafe { Stack::enter(lua, 12) }, c"bu16", c"type", c"data")
}

unsafe extern "C-unwind" fn pack_transport_varint(lua: *mut LuaState) -> c_int {
    pack_keyed(
        unsafe { Stack::enter(lua, 12) },
        c"bquic_tvb",
        c"type",
        c"data",
    )
}

pub(super) unsafe extern "C-unwind" fn reconstruct_ext(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 24) };
    vm.pad_arguments(1);
    let dissect = vm.field(1, c"dis");
    if vm.truth(dissect) {
        if let Some(shape) = Shape::for_type(vm, vm.field(1, c"type")) {
            let list = vm.field(dissect, c"list");
            match shape {
                Shape::Words8 | Shape::Words16 => {
                    vm.field(GLOBALS, c"bu16");
                }
                Shape::Bytes8 => {
                    vm.field(GLOBALS, c"bu8");
                }
                Shape::ServerName => vm.closure(pack_sni, 0),
                Shape::Alpn => vm.closure(pack_alpn, 0),
                Shape::KeyShare => vm.closure(pack_share, 0),
                Shape::Transport16 => vm.closure(pack_transport16, 0),
                Shape::TransportVarint => vm.closure(pack_transport_varint, 0),
            }
            vm.call_global(c"barray", &[list, vm.top()], 1);
            vm.set(1, c"data");
            let prefix = shape.length_bytes();
            if prefix != 0 {
                let data = vm.field(1, c"data");
                pack_size(
                    vm,
                    if prefix == 1 { c"bu8" } else { c"bu16" },
                    vm.length(data),
                );
                vm.field(1, c"data");
                vm.concat(2);
                vm.set(1, c"data");
            }
        } else {
            vm.nil();
            vm.set(1, c"data");
        }
    }
    vm.boolean(vm.kind(vm.field(1, c"data")) == STRING);
    1
}
