//! TLS ClientHello and ServerHello dissection and reconstruction for Lua rules.
use super::{extensions::pack_size, *};

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let (head, tail) = bytes.split_at_checked(count)?;
    *bytes = tail;
    Some(head)
}

fn length(bytes: &mut &[u8], width: usize) -> Option<usize> {
    let next = take(bytes, width)?;
    Some(if width == 1 {
        usize::from(next[0])
    } else {
        u16::from_be_bytes([next[0], next[1]]) as usize
    })
}

fn numbers(vm: Stack, table: c_int, field: &CStr, bytes: &[u8], width: usize) {
    let top = vm.top();
    let list = vm.table(0);
    for (index, part) in bytes.chunks_exact(width).enumerate() {
        let number = if width == 1 {
            u16::from(part[0])
        } else {
            u16::from_be_bytes([part[0], part[1]])
        };
        vm.integer(number as isize);
        vm.raw_array_put(list, index as c_int + 1, vm.top());
        vm.reset(list);
    }
    vm.assign(table, field, list);
    vm.reset(top);
}

fn dissect_hello_fields(
    vm: Stack,
    out: c_int,
    rest: &mut &[u8],
    cipher_list: bool,
    compression_list: bool,
) -> Option<()> {
    put_bytes(vm, out, c"random", take(rest, 32)?);
    let len = length(rest, 1)?;
    put_bytes(vm, out, c"session_id", take(rest, len)?);
    if rest.len() < 2 {
        return None;
    }
    if cipher_list {
        let len = length(rest, 2)?;
        numbers(vm, out, c"cipher_suites", take(rest, len)?, 2);
    } else {
        put_number(vm, out, c"cipher_suite", length(rest, 2)?);
    }
    if compression_list {
        let len = length(rest, 1)?;
        numbers(vm, out, c"compression_methods", take(rest, len)?, 1);
    } else {
        put_number(vm, out, c"compression_method", length(rest, 1)?);
    }
    Some(())
}

fn dissect_hello_extensions(vm: Stack, out: c_int, mut data: &[u8], partial: bool) -> bool {
    let list = vm.table(0);
    vm.assign(out, c"ext", list);
    let mut index = 0;
    while data.len() >= 4 {
        let kind = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let Some(body) = data.get(4..4 + len) else {
            return partial;
        };
        let ext = vm.table(3);
        put_number(vm, ext, c"type", usize::from(kind));
        let typ = vm.field(ext, c"type");
        put_name(vm, ext, c"TLS_HELLO_EXT_NAMES", typ, true);
        put_bytes(vm, ext, c"data", body);
        index += 1;
        vm.raw_array_put(list, index, ext);
        vm.call_global(c"tls_dissect_ext", &[ext], 0);
        vm.reset(list);
        data = &data[4 + len..];
    }
    true
}

fn undecoded(vm: Stack, allow_partial: bool) -> c_int {
    if !allow_partial || !vm.truth(2) {
        vm.nil();
        vm.set(1, c"dis");
    }
    if allow_partial {
        vm.push(2);
    } else {
        vm.boolean(false);
    }
    1
}

pub(super) unsafe extern "C-unwind" fn dissect_handshake(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 42) };
    vm.pad_arguments(2);
    vm.nil();
    vm.set(1, c"dis");
    let source = vm.field(1, c"data");
    vm.integer(1);
    let first = vm.top();
    if !vm.truth(vm.call_global(c"is_tls_hello", &[source, first, 2], 1)) {
        vm.boolean(false);
        return 1;
    }
    if vm.kind(source) != STRING {
        vm.reset(2);
        return call_original(vm);
    }
    let (bytes, size) = vm.text(source);
    let data = unsafe { slice::from_raw_parts(bytes, size) };
    let max = vm.call_global(c"tls_handshake_len", &[source, first], 1);
    let max = vm.arithmetic_number(max) as usize;
    if max > size && !vm.truth(2) {
        vm.boolean(false);
        return 1;
    }
    let kind = vm.call_global(c"tls_handshake_type", &[source, first], 1);
    let version = push_integer_at(vm, c"u16", source, 5.0);
    let out = vm.table(8);
    vm.assign(out, c"type", kind);
    vm.assign(out, c"ver", version);
    put_name(vm, out, c"TLS_HANDSHAKE_TYPE_NAMES", kind, true);
    vm.assign(1, c"dis", out);

    let mut rest = data.get(6..max.min(size)).unwrap_or_default();
    let cipher_list = vm.equal(kind, vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_CLIENT"));
    vm.integer(1);
    let compression_list = vm.equal(kind, vm.top());
    if dissect_hello_fields(vm, out, &mut rest, cipher_list, compression_list).is_none() {
        return undecoded(vm, true);
    }
    let Some(declared) = length(&mut rest, 2) else {
        return undecoded(vm, true);
    };
    let partial = vm.truth(2);
    if (declared > rest.len() && !partial)
        || !dissect_hello_extensions(vm, out, &rest[..declared.min(rest.len())], partial)
    {
        return undecoded(vm, false);
    }
    vm.boolean(true);
    1
}

struct Pieces {
    table: c_int,
    count: c_int,
}

impl Pieces {
    fn new(vm: Stack) -> Self {
        Self {
            table: vm.table(0),
            count: 0,
        }
    }

    fn push(&mut self, vm: Stack, value: c_int) {
        self.count += 1;
        vm.raw_array_put(self.table, self.count, value);
    }

    fn field(&mut self, vm: Stack, table: c_int, name: &CStr, fallback: Option<&CStr>) {
        let top = vm.top();
        let mut value = vm.field(table, name);
        if !vm.truth(value)
            && let Some(fallback) = fallback
        {
            value = vm.field(GLOBALS, fallback);
        }
        self.push(vm, value);
        vm.reset(top);
    }

    fn encoded(&mut self, vm: Stack, method: &CStr, value: c_int) {
        let top = vm.top();
        self.push(vm, vm.call_global(method, &[value], 1));
        vm.reset(top);
    }

    fn encode_length(&mut self, vm: Stack, method: &CStr, size: usize) {
        let top = vm.top();
        self.push(vm, pack_size(vm, method, size));
        vm.reset(top);
    }

    fn concat(self, vm: Stack) -> c_int {
        vm.table_operation(c"concat", &[self.table], 1)
    }
}

fn pack_options(vm: Stack, header: &mut Pieces, hello: c_int, option: &CStr, width: usize) {
    let top = vm.top();
    let list = vm.field(hello, option);
    let packer = if width == 1 { c"bu8" } else { c"bu16" };
    let length = if vm.truth(list) { vm.length(list) } else { 0 };
    header.encode_length(vm, packer, width * length);
    if vm.truth(list) {
        let packer = vm.field(GLOBALS, packer);
        let data = vm.call_global(c"barray", &[list, packer], 1);
        if vm.truth(data) {
            header.push(vm, data);
        }
    }
    vm.reset(top);
}

fn make_hello_header(vm: Stack, hello: c_int, client: bool) -> c_int {
    let mut header = Pieces::new(vm);
    let top = vm.top();
    let mut version = vm.field(hello, c"ver");
    if !vm.truth(version) {
        version = vm.field(GLOBALS, c"TLS_VER_TLS12");
    }
    header.encoded(vm, c"bu16", version);
    let mut random = vm.field(hello, c"random");
    if vm.truth(random) && vm.length(random) == 32 {
        random = vm.field(hello, c"random");
    } else {
        vm.integer(32);
        random = vm.call_global(c"brandom", &[vm.top()], 1);
    }
    header.push(vm, random);
    let session = vm.field(hello, c"session_id");
    header.encode_length(
        vm,
        c"bu8",
        if vm.truth(session) {
            vm.length(session)
        } else {
            0
        },
    );
    let session = vm.field(hello, c"session_id");
    if vm.truth(session) {
        header.push(vm, session);
    }
    vm.reset(top);
    if client {
        pack_options(vm, &mut header, hello, c"cipher_suites", 2);
        pack_options(vm, &mut header, hello, c"compression_methods", 1);
    } else {
        header.encoded(vm, c"bu16", vm.field(hello, c"cipher_suite"));
        header.encoded(vm, c"bu8", vm.field(hello, c"compression_method"));
        vm.reset(top);
    }
    header.concat(vm)
}

fn make_extensions(vm: Stack, extensions: c_int) -> Option<c_int> {
    let mut parts = Pieces::new(vm);
    let top = vm.top();
    for index in 1..=vm.length(extensions) {
        let ext = vm.array_item(extensions, index);
        if !vm.truth(vm.call_global(c"tls_reconstruct_ext", &[ext], 1)) {
            return None;
        }
        parts.encoded(vm, c"bu16", vm.field(ext, c"type"));
        parts.encode_length(vm, c"bu16", vm.length(vm.field(ext, c"data")));
        parts.field(vm, ext, c"data", None);
        vm.reset(top);
    }
    Some(parts.concat(vm))
}

pub(super) unsafe extern "C-unwind" fn reconstruct_handshake(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 70) };
    vm.pad_arguments(1);
    let hello = vm.field(1, c"dis");
    if vm.truth(hello) {
        let kind = vm.field(hello, c"type");
        if is_client_or_server(vm, kind) {
            vm.nil();
            vm.set(1, c"data");
            let client = vm.equal(kind, vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_CLIENT"));
            let header = make_hello_header(vm, hello, client);
            let list = vm.field(hello, c"ext");
            let mut parts = Pieces::new(vm);
            if vm.truth(list) {
                let Some(exts) = make_extensions(vm, list) else {
                    vm.nil();
                    return 1;
                };
                let length = vm.length(exts);
                parts.encoded(vm, c"bu8", vm.field(1, c"type"));
                parts.encode_length(vm, c"bu24", vm.length(header) + 2 + length);
                parts.push(vm, header);
                parts.encode_length(vm, c"bu16", length);
                parts.push(vm, exts);
            } else {
                parts.encoded(vm, c"bu8", vm.field(1, c"type"));
                parts.encode_length(vm, c"bu24", vm.length(header));
                parts.push(vm, header);
            }
            parts.concat(vm);
            vm.set(1, c"data");
        }
    }
    vm.boolean(vm.kind(vm.field(1, c"data")) == STRING);
    1
}

fn sni_extension(vm: Stack, hello: c_int) -> (c_int, c_int) {
    let mut extensions = vm.field(hello, c"ext");
    let kind = vm.field(GLOBALS, c"TLS_EXT_SERVER_NAME");
    let index = if vm.truth(extensions) {
        vm.bytes(b"type");
        vm.call_global(c"array_field_search", &[extensions, vm.top(), kind], 1)
    } else {
        extensions = vm.table(0);
        vm.assign(hello, c"ext", extensions);
        vm.nil();
        vm.top()
    };
    if !vm.truth(index) {
        vm.log(b"tls_client_hello_mod: no SNI extension. adding", &[]);
        let extension = vm.table(2);
        vm.assign(extension, c"type", kind);
        let dissect = vm.table(1);
        vm.table(0);
        vm.set(dissect, c"list");
        vm.set(extension, c"dis");
        vm.integer(1);
        vm.replace(index);
        vm.table_operation(c"insert", &[extensions, index, extension], 0);
    }
    (extensions, index)
}

fn add_name(vm: Stack, names: c_int, name: c_int, first: bool) {
    let entry = vm.table(2);
    vm.assign(entry, c"name", name);
    vm.field(2, c"sni_snt_new");
    vm.set(entry, c"type");
    if first {
        vm.integer(1);
        vm.table_operation(c"insert", &[names, vm.top(), entry], 0);
    } else {
        vm.table_operation(c"insert", &[names, entry], 0);
    }
}

fn edit_sni(vm: Stack, hello: c_int) {
    let top = vm.top();
    if ![
        c"sni_snt",
        c"sni_del_ext",
        c"sni_del",
        c"sni_first",
        c"sni_last",
    ]
    .into_iter()
    .any(|field| {
        let set = vm.truth(vm.field(2, field));
        vm.reset(top);
        set
    }) {
        return;
    }
    let (extensions, index) = sni_extension(vm, hello);
    if vm.truth(vm.field(2, c"sni_del_ext")) {
        vm.table_operation(c"remove", &[extensions, index], 0);
        return;
    }
    let dissect = vm.field(vm.item(extensions, index), c"dis");
    if vm.truth(vm.field(2, c"sni_del")) {
        vm.table(0);
        vm.set(dissect, c"list");
    } else if vm.truth(vm.field(2, c"sni_snt")) {
        let names = vm.field(dissect, c"list");
        let cursor = vm.call_global(c"pairs", &[names], 3);
        while let Some(name) = vm.next_pair(cursor) {
            vm.field(2, c"sni_snt");
            vm.set(name, c"type");
            vm.reset(cursor);
        }
        vm.reset(names);
    }
    for (option, first) in [(c"sni_first", true), (c"sni_last", false)] {
        let name = vm.field(2, option);
        if vm.truth(name) {
            add_name(vm, vm.field(dissect, c"list"), name, first);
        }
    }
}

pub(super) unsafe extern "C-unwind" fn client_hello_mod(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 55) };
    vm.pad_arguments(2);
    let tls = vm.call_global(c"tls_dissect", &[1], 1);
    if !vm.truth(tls) {
        vm.log(b"tls_client_hello_mod: could not dissect tls", &[]);
        return 0;
    }
    let handshakes = vm.field(tls, c"handshake");
    let hello = if vm.truth(handshakes) {
        vm.item(handshakes, vm.field(GLOBALS, c"TLS_HANDSHAKE_TYPE_CLIENT"))
    } else {
        handshakes
    };
    let dissect = if vm.truth(hello) {
        vm.field(hello, c"dis")
    } else {
        hello
    };
    if !vm.truth(dissect) {
        vm.log(b"tls_client_hello_mod: handshake not dissected", &[]);
        return 0;
    }
    edit_sni(vm, dissect);
    let result = vm.call_global(c"tls_reconstruct", &[tls], 1);
    if !vm.truth(result) {
        vm.call_message(c"DLOG_ERR", b"tls_client_hello_mod: reconstruct error", &[]);
    }
    vm.push(result);
    1
}
