//! TLS record assembly and handshake reassembly for the Lua rule API.
use super::{extensions::pack_size, *};

fn at_offset(vm: Stack, function: &CStr, offset: f64) -> c_int {
    push_integer_at(vm, function, 1, offset)
}

fn valid_at(vm: Stack, function: &CStr, offset: f64) -> bool {
    let top = vm.top();
    vm.push_number(offset);
    let offset = vm.top();
    vm.nil();
    let valid = vm.truth(vm.call_global(function, &[1, offset, offset + 1, 3], 1));
    vm.reset(top);
    valid
}

#[derive(Clone, Copy)]
struct Record {
    offset: f64,
    length: c_int,
    kind: c_int,
    encrypted: bool,
    continuation: Option<c_int>,
}

fn data_in_record(vm: Stack, offset: f64, length: c_int) -> c_int {
    let length = vm.arithmetic_number(length);
    vm.substring(1, offset + 5.0, Some(offset + 4.0 + length))
}

fn add_record(vm: Stack, records: c_int, header: Record) -> c_int {
    let item = vm.table(8);
    vm.assign(item, c"type", header.kind);
    put_name(vm, item, c"TLS_RECORD_TYPE_NAMES", header.kind, true);
    vm.assign(item, c"len", header.length);
    at_offset(vm, c"u16", header.offset + 1.0);
    vm.set(item, c"ver");
    vm.boolean(header.encrypted);
    vm.set(item, c"encrypted");
    data_in_record(vm, header.offset, header.length);
    vm.set(item, c"data");
    if let Some(handshake_type) = header.continuation {
        vm.assign(item, c"htype", handshake_type);
        vm.boolean(true);
        vm.set(item, c"not_first");
    }
    vm.raw_array_put(records, vm.length(records) as c_int + 1, item);
    item
}

fn add_handshake(vm: Stack, handshakes: c_int, kind: c_int, input: c_int) -> c_int {
    let handshake = vm.table(4);
    vm.assign(handshake, c"type", kind);
    put_name(vm, handshake, c"TLS_HANDSHAKE_TYPE_NAMES", kind, false);
    vm.assign(handshake, c"data", input);
    vm.set_item(handshakes, kind, handshake);
    handshake
}

fn collect_handshake(
    vm: Stack,
    records: c_int,
    mut record: Record,
    hello: c_int,
    handshake_type: c_int,
) -> Option<(f64, bool)> {
    let goal = at_offset(vm, c"tls_handshake_len", record.offset + 5.0);
    let base = vm.top();
    // The length slot must remain rooted as the current record changes.
    let length_slot = vm.top() + 1;
    vm.push(record.length);
    record.length = length_slot;
    loop {
        vm.field(hello, c"data");
        data_in_record(vm, record.offset, record.length);
        vm.concat(2);
        vm.set(hello, c"data");
        let next = record.offset + 5.0 + vm.arithmetic_number(record.length);
        let size = vm.length(vm.field(hello, c"data"));
        vm.integer(size as isize);
        if vm.less_equal(goal, vm.top()) {
            vm.reset(base);
            return Some((next, false));
        }
        if !valid_at(vm, c"is_tls_record", next)
            || !vm.equal(at_offset(vm, c"tls_record_type", next), record.kind)
        {
            vm.reset(base);
            return vm.truth(3).then_some((next, true));
        }
        vm.reset(length_slot);
        record.offset = next;
        at_offset(vm, c"tls_record_data_len", next);
        vm.replace(length_slot);
        record.continuation = Some(handshake_type);
        record.encrypted = false;
        add_record(vm, records, record);
        vm.reset(length_slot);
    }
}

fn dissect_hellos(vm: Stack, handshakes: c_int) {
    let top = vm.top();
    let cursor = vm.call_global(c"pairs", &[handshakes], 3);
    while let Some(handshake) = vm.next_pair(cursor) {
        if is_client_or_server(vm, vm.field(handshake, c"type")) {
            vm.call_global(c"tls_dissect_handshake", &[handshake, 3], 0);
        }
        vm.reset(cursor);
    }
    vm.reset(top);
}

pub(super) unsafe extern "C-unwind" fn dissect(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 80) };
    vm.pad_arguments(3);
    default_offset(vm);
    let output = vm.table(2);
    let records = vm.table(0);
    let handshakes = vm.table(0);
    let mut offset = vm.arithmetic_number(2);
    let mut encrypted = false;
    let mut has_record = false;
    let mut has_handshake = false;
    while valid_at(vm, c"is_tls_record", offset) {
        if !has_record {
            has_record = true;
            vm.assign(output, c"rec", records);
        }
        let length = at_offset(vm, c"tls_record_data_len", offset);
        let kind = at_offset(vm, c"tls_record_type", offset);
        let record = Record {
            offset,
            length,
            kind,
            encrypted,
            continuation: None,
        };
        let item = add_record(vm, records, record);
        if vm.equal(
            kind,
            vm.field(GLOBALS, c"TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC"),
        ) {
            encrypted = true;
        } else if !encrypted && vm.equal(kind, vm.field(GLOBALS, c"TLS_RECORD_TYPE_HANDSHAKE")) {
            if vm.length(1) as f64 - offset + 1.0 < 9.0 {
                if !vm.truth(3) {
                    return 0;
                }
                break;
            }
            let handshake_type = at_offset(vm, c"tls_handshake_type", offset + 5.0);
            vm.assign(item, c"htype", handshake_type);
            if !has_handshake {
                has_handshake = true;
                vm.assign(output, c"handshake", handshakes);
            }
            vm.bytes(b"");
            let hello = add_handshake(vm, handshakes, handshake_type, vm.top());
            let Some((next, partial)) =
                collect_handshake(vm, records, record, hello, handshake_type)
            else {
                return 0;
            };
            if partial {
                break;
            }
            offset = next;
            vm.reset(handshakes);
            continue;
        }
        offset += 5.0 + vm.arithmetic_number(length);
        vm.reset(handshakes);
    }
    vm.reset(handshakes);
    if has_handshake {
        dissect_hellos(vm, handshakes);
    } else if !has_record && valid_at(vm, c"is_tls_handshake", vm.arithmetic_number(2)) {
        let kind = vm.call_global(c"tls_handshake_type", &[1, 2], 1);
        let bytes = vm.substring(1, vm.arithmetic_number(2), Some(vm.length(1) as f64));
        let hello = add_handshake(vm, handshakes, kind, bytes);
        vm.assign(output, c"handshake", handshakes);
        vm.call_global(c"tls_dissect_handshake", &[hello, 3], 0);
        has_handshake = true;
    }
    if has_record || has_handshake {
        vm.push(output)
    } else {
        vm.nil()
    }
    1
}

fn record_handshake(vm: Stack, record: c_int, handshakes: c_int) -> Option<(c_int, c_int, c_int)> {
    let kind = vm.field(GLOBALS, c"TLS_RECORD_TYPE_HANDSHAKE");
    if !vm.equal(vm.field(record, c"type"), kind) || vm.truth(vm.field(record, c"encrypted")) {
        return None;
    }
    let key = vm.field(record, c"htype");
    if !vm.truth(key) || !vm.truth(handshakes) {
        return None;
    }
    let handshake = vm.item(handshakes, key);
    if !vm.truth(handshake) {
        return None;
    }
    let data = vm.field(handshake, c"data");
    vm.truth(data).then_some((kind, key, data))
}

fn contiguous_end(
    vm: Stack,
    records: c_int,
    index: usize,
    kind: c_int,
    handshake_type: c_int,
) -> usize {
    let top = vm.top();
    let mut end = index;
    while end < vm.length(records) {
        let record = vm.array_item(records, end + 1);
        let matches = vm.equal(vm.field(record, c"type"), kind)
            && !vm.truth(vm.field(record, c"encrypted"))
            && vm.equal(vm.field(record, c"htype"), handshake_type);
        vm.reset(top);
        if !matches {
            break;
        }
        end += 1;
    }
    end
}

fn write_chunks(vm: Stack, records: c_int, first: usize, end: usize, data: c_int) {
    let top = vm.top();
    let mut offset = 1.0;
    for index in first..=end {
        let target = vm.array_item(records, index);
        let remaining = vm.length(data) as f64 - offset + 1.0;
        let size = if index == end {
            remaining
        } else {
            vm.push_number(remaining);
            let difference = vm.top();
            let old_size = vm.field(target, c"len");
            if vm.less(difference, old_size) {
                remaining
            } else {
                vm.arithmetic_number(old_size)
            }
        };
        vm.substring(data, offset, Some(offset + size - 1.0));
        vm.set(target, c"data");
        vm.push_number(size);
        vm.set(target, c"len");
        offset += size;
        vm.reset(top);
    }
}

unsafe extern "C-unwind" fn pack_record(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 16) };
    let size = vm.length(vm.field(1, c"data"));
    if size == 0 {
        vm.bytes(b"");
        return 1;
    }
    let kind = vm.field(1, c"type");
    let encoded = vm.call_global(c"bu8", &[kind], 1);
    vm.call_global(c"bu16", &[vm.field(1, c"ver")], 1);
    vm.replace(encoded + 1);
    pack_size(vm, c"bu16", vm.length(vm.field(1, c"data")));
    vm.replace(encoded + 2);
    vm.field(1, c"data");
    vm.concat(4);
    1
}

pub(super) unsafe extern "C-unwind" fn reconstruct(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 45) };
    vm.pad_arguments(1);
    let handshakes = vm.field(1, c"handshake");
    if vm.truth(handshakes) {
        let cursor = vm.call_global(c"pairs", &[handshakes], 3);
        while let Some(handshake) = vm.next_pair(cursor) {
            if !vm.truth(vm.call_global(c"tls_reconstruct_handshake", &[handshake], 1)) {
                vm.nil();
                return 1;
            }
            vm.reset(cursor);
        }
        vm.reset(handshakes);
    }
    let records = vm.field(1, c"rec");
    if vm.truth(records) {
        let mut index = 1;
        while index <= vm.length(records) {
            let record = vm.array_item(records, index);
            if let Some((kind, handshake_type, data)) = record_handshake(vm, record, handshakes) {
                vm.nil();
                vm.set(record, c"data");
                let end = contiguous_end(vm, records, index, kind, handshake_type);
                write_chunks(vm, records, index, end, data);
                index = end + 1;
            } else {
                index += 1;
            }
            if !vm.truth(vm.field(record, c"data")) {
                vm.nil();
                return 1;
            }
            vm.reset(records);
        }
        vm.closure(pack_record, 0);
        vm.call_global(c"barray", &[records, vm.top()], 1);
        return 1;
    }
    if vm.truth(handshakes) {
        let key = vm.call_global(c"next", &[handshakes], 1);
        if vm.kind(key) != NIL {
            vm.field(vm.item(handshakes, key), c"data");
            return 1;
        }
    }
    vm.nil();
    1
}
