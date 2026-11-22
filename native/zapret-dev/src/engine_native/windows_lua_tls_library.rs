//! Lua-facing TLS codecs with the bundled library's record and table shapes.
use super::*;

#[path = "windows_lua_tls_extensions.rs"]
mod extensions;
#[path = "windows_lua_tls_handshake.rs"]
mod handshake;
#[path = "windows_lua_tls_records.rs"]
mod records;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"bquic_tvb", bquic_tvb),
    (c"is_tls_handshake", is_tls_handshake),
    (c"is_tls_handshake_type_hello", is_tls_handshake_type_hello),
    (c"is_tls_hello", is_tls_hello),
    (c"is_tls_record", is_tls_record),
    (c"quic_tvb", quic_tvb),
    (c"tls_client_hello_mod", handshake::client_hello_mod),
    (c"tls_dissect", records::dissect),
    (c"tls_dissect_ext", extensions::dissect_ext),
    (c"tls_dissect_handshake", handshake::dissect_handshake),
    (c"tls_handshake_data_len", tls_handshake_data_len),
    (c"tls_handshake_full", tls_handshake_full),
    (c"tls_handshake_len", tls_handshake_len),
    (c"tls_handshake_type", tls_handshake_type),
    (c"tls_reconstruct", records::reconstruct),
    (c"tls_reconstruct_ext", extensions::reconstruct_ext),
    (
        c"tls_reconstruct_handshake",
        handshake::reconstruct_handshake,
    ),
    (c"tls_record_data_len", tls_record_data_len),
    (c"tls_record_full", tls_record_full),
    (c"tls_record_type", tls_record_type),
];

fn default_offset(vm: Stack) {
    if !vm.truth(2) {
        vm.integer(1);
        vm.replace(2);
    }
}

fn push_integer_at(vm: Stack, accessor: &CStr, data: c_int, offset: f64) -> c_int {
    vm.push_number(offset);
    vm.call_global(accessor, &[data, vm.top()], 1)
}

fn put_number(vm: Stack, table: c_int, field: &CStr, value: usize) {
    vm.integer(value as isize);
    vm.set(table, field);
}

fn put_bytes(vm: Stack, table: c_int, field: &CStr, bytes: &[u8]) {
    vm.bytes(bytes);
    vm.set(table, field);
}

fn put_name(vm: Stack, entry: c_int, database: &CStr, key: c_int, stringify: bool) {
    let top = vm.top();
    let name = vm.item(vm.field(GLOBALS, database), key);
    if stringify {
        vm.call_global(c"tostring", &[name], 1);
        vm.set(entry, c"name");
    } else {
        vm.assign(entry, c"name", name);
    }
    vm.reset(top);
}

fn is_client_or_server(vm: Stack, kind: c_int) -> bool {
    vm.equal(kind, vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_CLIENT"))
        || vm.equal(kind, vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_SERVER"))
}

fn valid_version(vm: Stack, value: c_int) -> bool {
    let low = vm.field(GLOBALS, c"TLS_VER_SSL30");
    let high = vm.field(GLOBALS, c"TLS_VER_TLS12");
    vm.less_equal(low, value) && vm.less_equal(value, high)
}

fn bytes_remaining(vm: Stack, data: c_int, offset: c_int) -> f64 {
    vm.length(data) as f64 - vm.arithmetic_number(offset) + 1.0
}

fn tail_number_reader(vm: Stack, method: &CStr, delta: f64) -> c_int {
    vm.pad_arguments(2);
    default_offset(vm);
    vm.push_number(vm.arithmetic_number(2) + delta);
    vm.tail_global(method, &[1, vm.top()])
}

unsafe extern "C-unwind" fn tls_record_data_len(lua: *mut LuaState) -> c_int {
    tail_number_reader(unsafe { Stack::enter(lua, 7) }, c"u16", 3.0)
}

unsafe extern "C-unwind" fn tls_handshake_data_len(lua: *mut LuaState) -> c_int {
    tail_number_reader(unsafe { Stack::enter(lua, 7) }, c"u24", 1.0)
}

unsafe extern "C-unwind" fn tls_record_type(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(2);
    default_offset(vm);
    vm.tail_global(c"u8", &[1, 2])
}

unsafe extern "C-unwind" fn tls_handshake_type(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(2);
    vm.tail_global(c"u8", &[1, 2])
}

fn fits(vm: Stack, read: &CStr, header: f64) -> c_int {
    vm.pad_arguments(2);
    default_offset(vm);
    let length = vm.call_global(read, &[1, 2], 1);
    vm.push_number(bytes_remaining(vm, 1, 2) - header);
    vm.boolean(vm.less_equal(length, vm.top()));
    1
}

unsafe extern "C-unwind" fn tls_record_full(lua: *mut LuaState) -> c_int {
    fits(unsafe { Stack::enter(lua, 9) }, c"tls_record_data_len", 5.0)
}

unsafe extern "C-unwind" fn tls_handshake_full(lua: *mut LuaState) -> c_int {
    fits(
        unsafe { Stack::enter(lua, 9) },
        c"tls_handshake_data_len",
        4.0,
    )
}

unsafe extern "C-unwind" fn tls_handshake_len(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 7) };
    vm.pad_arguments(2);
    let length = vm.call_global(c"tls_handshake_data_len", &[1, 2], 1);
    vm.push_number(vm.arithmetic_number(length) + 4.0);
    1
}

unsafe extern "C-unwind" fn is_tls_record(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 16) };
    vm.pad_arguments(4);
    if vm.truth(1) {
        default_offset(vm);
        if bytes_remaining(vm, 1, 2) >= 5.0
            && (!vm.truth(3) || vm.equal(3, vm.call_global(c"tls_record_type", &[1, 2], 1)))
        {
            let version = push_integer_at(vm, c"u16", 1, vm.arithmetic_number(2) + 1.0);
            if valid_version(vm, version) {
                if vm.truth(4) {
                    vm.push(4);
                } else {
                    vm.call_global(c"tls_record_full", &[1, 2], 1);
                }
                return 1;
            }
        }
    }
    vm.boolean(false);
    1
}

unsafe extern "C-unwind" fn is_tls_handshake_type_hello(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 9) };
    vm.pad_arguments(2);
    vm.boolean(
        vm.truth(1) && is_client_or_server(vm, vm.call_global(c"tls_handshake_type", &[1, 2], 1)),
    );
    1
}

fn check_handshake(vm: Stack) -> bool {
    if !vm.truth(1) {
        return false;
    }
    default_offset(vm);
    if bytes_remaining(vm, 1, 2) < 4.0 {
        return false;
    }
    let kind = vm.call_global(c"tls_handshake_type", &[1, 2], 1);
    if (vm.truth(3) && !vm.equal(3, kind))
        || !vm.truth(vm.item(vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_NAMES"), kind))
    {
        return false;
    }
    !is_client_or_server(vm, kind)
        || (bytes_remaining(vm, 1, 2) >= 6.0
            && valid_version(
                vm,
                push_integer_at(vm, c"u16", 1, vm.arithmetic_number(2) + 4.0),
            ))
}

unsafe extern "C-unwind" fn is_tls_handshake(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(4);
    if !check_handshake(vm) {
        vm.boolean(false);
    } else if vm.truth(4) {
        vm.push(4);
    } else {
        vm.call_global(c"tls_handshake_full", &[1, 2], 1);
    }
    1
}

unsafe extern "C-unwind" fn is_tls_hello(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(3);
    let client = vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_CLIENT");
    if !vm.truth(vm.call_global(c"is_tls_handshake", &[1, 2, client, 3], 1)) {
        let server = vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_SERVER");
        vm.call_global(c"is_tls_handshake", &[1, 2, server, 3], 1);
    }
    1
}

unsafe extern "C-unwind" fn quic_tvb(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 9) };
    let offset = if vm.truth(2) && vm.kind(2) == NUMBER {
        vm.number(2)
    } else {
        1.0
    };
    if vm.kind(1) != STRING
        || (vm.truth(2) && vm.kind(2) != NUMBER)
        || !offset.is_finite()
        || offset < 1.0
        || offset != (offset as usize) as f64
    {
        return call_original(vm);
    }
    let (data, length) = vm.text(1);
    let bytes = unsafe { slice::from_raw_parts(data, length) };
    let Some(tail) = bytes.get(offset as usize - 1..) else {
        return 0;
    };
    let Some(&first) = tail.first() else { return 0 };
    let width = 1usize << (first >> 6);
    let Some(encoded) = tail.get(..width) else {
        return 0;
    };
    let mut value = u64::from(first & 63);
    for &byte in &encoded[1..] {
        value = (value << 8) | u64::from(byte);
    }
    if value >= (1 << 53) && vm.kind(vm.path(GLOBALS, &[c"math", c"type"])) == NIL {
        vm.bytes(encoded);
    } else {
        vm.push_number(value as f64);
    }
    vm.integer(width as isize);
    2
}

unsafe extern "C-unwind" fn bquic_tvb(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 16) };
    if vm.kind(1) == STRING {
        vm.push(1);
        return 1;
    }
    if vm.kind(1) != NUMBER {
        return call_original(vm);
    }
    let value = vm.number(1);
    if value < 64.0 {
        vm.tail_global(c"bu8", &[1])
    } else if value < 16384.0 {
        vm.push_number(value + 16384.0);
        vm.tail_global(c"bu16", &[vm.top()])
    } else if value < 1073741824.0 {
        vm.push_number(value + 2147483648.0);
        vm.tail_global(c"bu32", &[vm.top()])
    } else if value < 4611686018427387904.0 {
        const TWO32: f64 = 4294967296.0;
        vm.push_number(TWO32);
        let high = vm.call_global(c"divint", &[1, vm.top()], 1);
        vm.push_number(vm.arithmetic_number(high) + 3221225472.0);
        vm.call_global(c"bu32", &[vm.top()], 1);
        let encoded = vm.top();
        vm.push_number(value % TWO32);
        vm.call_global(c"bu32", &[vm.top()], 1);
        vm.replace(encoded + 1);
        vm.concat(2);
        1
    } else {
        0
    }
}
