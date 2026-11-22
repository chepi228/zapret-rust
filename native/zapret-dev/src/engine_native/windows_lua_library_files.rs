//! The bundled Lua file helpers use the VM's I/O and stream objects.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"is_gzip_file", is_gzip_file),
    (c"gunzip_file", gunzip_file),
    (c"gzip_file", gzip_file),
    (c"readfile", readfile),
    (c"z_readfile", z_readfile),
    (c"writefile", writefile),
];

fn file_error(vm: Stack, prefix: &[u8], cause: c_int) {
    vm.field(GLOBALS, c"error");
    vm.bytes(prefix);
    vm.push(cause);
    vm.concat(2);
    vm.call(1, 0);
}

fn open(vm: Stack, mode: &[u8], error_prefix: &[u8]) -> Option<c_int> {
    let io = vm.field(GLOBALS, c"io");
    vm.field(io, c"open");
    vm.push(1);
    vm.bytes(mode);
    vm.call(2, 2);
    let file = vm.top() - 1;
    if vm.truth(file) {
        Some(file)
    } else {
        file_error(vm, error_prefix, file + 1);
        None
    }
}

unsafe extern "C-unwind" fn is_gzip_file(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    let Some(file) = open(vm, b"rb", b"is_gzip_file: ") else {
        return 0;
    };
    vm.integer(2);
    let header = vm.call_method(file, c"read", &[vm.top()], 1);
    vm.call_method(file, c"close", &[], 0);
    if vm.truth(header) {
        vm.bytes(b"\x1f\x8b");
        vm.boolean(vm.equal(header, -1));
    } else {
        vm.push(header);
    }
    1
}

unsafe extern "C-unwind" fn readfile(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    let Some(file) = open(vm, b"rb", b"readfile: ") else {
        return 0;
    };
    vm.bytes(b"*a");
    let error = vm.call_method(file, c"read", &[vm.top()], 2);
    vm.call_method(file, c"close", &[], 0);
    if vm.truth(error) {
        file_error(vm, b"readfile: ", error);
    }
    vm.push(error - 1);
    1
}

unsafe extern "C-unwind" fn writefile(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    let Some(file) = open(vm, b"wb", b"writefile: ") else {
        return 0;
    };
    let error = vm.call_method(file, c"write", &[2], 2);
    vm.call_method(file, c"close", &[], 0);
    if !vm.truth(error - 1) {
        file_error(vm, b"writefile: ", error);
    }
    0
}

fn default_number(vm: Stack, index: c_int, default: f64, coerce: bool) -> Option<f64> {
    if !vm.truth(index) {
        Some(default)
    } else if vm.kind(index) == NUMBER || (coerce && vm.numeric(index)) {
        Some(vm.number(index))
    } else {
        None
    }
}

fn finish(vm: Stack, file: c_int, stream: c_int, end: &CStr) {
    vm.call_method(file, c"close", &[], 0);
    vm.call_global(end, &[stream], 0);
}

unsafe extern "C-unwind" fn gunzip_file(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    let Some(ratio) = default_number(vm, 2, 4.0, true) else {
        return call_original(vm);
    };
    vm.pad_arguments(3);
    let Some(file) = open(vm, b"rb", b"gunzip_file: ") else {
        return 0;
    };
    if !vm.truth(3) {
        vm.integer(16_384);
        vm.replace(3);
    }
    vm.bytes(b"");
    let decompressed = vm.top();
    let stream = vm.call_global(c"gunzip_init", &[], 1);
    if !vm.truth(stream) {
        return vm.error(c"gunzip_file: stream init error");
    }
    loop {
        let read_error = vm.call_method(file, c"read", &[3], 2);
        let compressed = read_error - 1;
        if !vm.truth(compressed) {
            finish(vm, file, stream, c"gunzip_end");
            if vm.truth(read_error) {
                file_error(vm, b"gunzip_file: file read error : ", read_error);
            }
            vm.nil();
            return 1;
        }
        vm.push_number(vm.length(compressed) as f64 * ratio);
        let eof = vm.call_global(c"gunzip_inflate", &[stream, compressed, vm.top()], 2);
        let block = eof - 1;
        if !vm.truth(block) {
            finish(vm, file, stream, c"gunzip_end");
            vm.nil();
            return 1;
        }
        vm.push(decompressed);
        vm.push(block);
        vm.concat(2);
        vm.replace(decompressed);
        let complete = vm.truth(eof);
        vm.reset(stream);
        if complete {
            finish(vm, file, stream, c"gunzip_end");
            vm.push(decompressed);
            return 1;
        }
    }
}

unsafe extern "C-unwind" fn gzip_file(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    let Some(ratio) = default_number(vm, 3, 2.0, true) else {
        return call_original(vm);
    };
    let Some(block_limit) = default_number(vm, 6, 16_384.0, false) else {
        return call_original(vm);
    };
    if vm.kind(2) != STRING {
        return call_original(vm);
    }
    vm.pad_arguments(6);
    let Some(file) = open(vm, b"wb", b"gzip_file: ") else {
        return 0;
    };
    vm.nil();
    let stream = vm.call_global(c"gzip_init", &[vm.top(), 4, 5], 1);
    if !vm.truth(stream) {
        return vm.error(c"gzip_file: stream init error");
    }
    let data_size = vm.length(2) as f64;
    let mut offset = 1.0;
    loop {
        let remaining = data_size - offset + 1.0;
        let block_size = if remaining > block_limit {
            block_limit
        } else {
            remaining
        };
        let string = vm.field(GLOBALS, c"string");
        vm.field(string, c"sub");
        vm.push(2);
        vm.push_number(offset);
        vm.push_number(offset + block_size - 1.0);
        vm.call(3, 1);
        let block = vm.top();
        vm.push_number(block_size / ratio);
        let eof = vm.call_global(c"gzip_deflate", &[stream, block, vm.top()], 2);
        let compressed = eof - 1;
        if !vm.truth(compressed) {
            finish(vm, file, stream, c"gzip_end");
            vm.nil();
            return 1;
        }
        vm.call_method(file, c"write", &[compressed], 0);
        offset += block_size;
        let complete = vm.truth(eof);
        vm.reset(stream);
        if complete {
            finish(vm, file, stream, c"gzip_end");
            return 0;
        }
    }
}

unsafe extern "C-unwind" fn z_readfile(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(2);
    let gzip = vm.call_global(c"is_gzip_file", &[1], 1);
    if vm.truth(gzip) {
        let output = vm.call_global(c"gunzip_file", &[1, 2], 1);
        if vm.truth(output) {
            return 1;
        }
    }
    vm.call_global(c"readfile", &[1], 1);
    1
}
