//! Lua-facing header policy and transport length accounting.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"find_tcp_option", find_tcp_option),
    (c"find_ip6_exthdr", find_ip6_exthdr),
    (c"parse_tcp_flags", parse_tcp_flags),
    (c"parse_autottl", parse_autottl),
    (c"autottl", autottl),
    (c"apply_fooling", apply_fooling),
    (c"l3_base_len", l3_base_len),
    (c"l4_base_len", l4_base_len),
    (c"l3_extra_len", l3_extra_len),
    (c"l4_extra_len", l4_extra_len),
    (c"l3_len", l3_len),
    (c"l4_len", l4_len),
    (c"l3l4_extra_len", l3l4_extra_len),
    (c"l3l4_len", l3l4_len),
    (c"packet_len", packet_len),
];

fn find_header(vm: Stack, field: &CStr) -> c_int {
    vm.pad_arguments(2);
    if vm.truth(1) {
        vm.call_global(c"ipairs", &[1], 3);
        let cursor = vm.top();
        loop {
            vm.push(cursor - 2);
            vm.push(cursor - 1);
            vm.push(cursor);
            vm.call(2, 2);
            let key = vm.top() - 1;
            if vm.kind(key) == NIL {
                break;
            }
            if vm.equal(vm.field(key + 1, field), 2) {
                vm.push(key);
                return 1;
            }
            vm.push(key);
            vm.replace(cursor);
            vm.reset(cursor);
        }
    }
    vm.nil();
    1
}

unsafe extern "C-unwind" fn find_tcp_option(lua: *mut LuaState) -> c_int {
    find_header(unsafe { Stack::enter(lua, 18) }, c"kind")
}

unsafe extern "C-unwind" fn find_ip6_exthdr(lua: *mut LuaState) -> c_int {
    find_header(unsafe { Stack::enter(lua, 18) }, c"type")
}

unsafe extern "C-unwind" fn parse_tcp_flags(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(1);
    let flags = vm.table(9);
    for (key, global) in [
        (c"FIN", c"TH_FIN"),
        (c"SYN", c"TH_SYN"),
        (c"RST", c"TH_RST"),
        (c"PSH", c"TH_PUSH"),
        (c"PUSH", c"TH_PUSH"),
        (c"ACK", c"TH_ACK"),
        (c"URG", c"TH_URG"),
        (c"ECE", c"TH_ECE"),
        (c"CWR", c"TH_CWR"),
    ] {
        vm.field(GLOBALS, global);
        vm.set(flags, key);
    }
    vm.integer(0);
    let combined = vm.top();
    vm.path(GLOBALS, &[c"string", c"upper"]);
    vm.push(1);
    vm.call(1, 1);
    let upper = vm.top();
    vm.path(GLOBALS, &[c"string", c"gmatch"]);
    vm.push(upper);
    vm.bytes(b"[^,]+");
    vm.call(2, 3);
    let cursor = vm.top();
    loop {
        vm.push(cursor - 2);
        vm.push(cursor - 1);
        vm.push(cursor);
        vm.call(2, 1);
        let token = vm.top();
        if vm.kind(token) == NIL {
            break;
        }
        let value = vm.item(flags, token);
        if vm.truth(value) {
            vm.call_global(c"bitor", &[combined, value], 1);
            vm.replace(combined);
        } else {
            vm.call_message(c"error", b"tcp flag '", &[(token, b"' is invalid")]);
        }
        vm.push(token);
        vm.replace(cursor);
        vm.reset(cursor);
    }
    vm.push(combined);
    1
}

unsafe extern "C-unwind" fn parse_autottl(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    vm.pad_arguments(1);
    if !vm.truth(1) {
        vm.nil();
        return 1;
    }
    vm.path(GLOBALS, &[c"string", c"match"]);
    vm.push(1);
    vm.bytes(b"([-+]?%d+),(%d+)-(%d+)");
    vm.call(2, 3);
    let last = vm.top();
    let min = vm.call_global(c"tonumber", &[last - 1], 1);
    let max = vm.call_global(c"tonumber", &[last], 1);
    let delta = vm.call_global(c"tonumber", &[last - 2], 1);
    if !vm.truth(delta) || vm.less(max, min) {
        vm.call_message(c"error", b"parse_autottl: invalid value '", &[(1, b"'")]);
    }
    let out = vm.table(3);
    vm.assign(out, c"delta", delta);
    vm.assign(out, c"min", min);
    vm.assign(out, c"max", max);
    1
}

unsafe extern "C-unwind" fn autottl(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    if vm.kind(1) != NUMBER {
        return call_original(vm);
    }
    vm.pad_arguments(2);
    let ttl = vm.number(1);
    let initial = if ttl > 223.0 {
        255.0
    } else if ttl <= 128.0 && ttl > 96.0 {
        128.0
    } else if ttl <= 64.0 && ttl > 32.0 {
        64.0
    } else {
        vm.nil();
        return 1;
    };
    let hops = initial - ttl;
    let delta = vm.field(2, c"delta");
    let delta_number = vm.arithmetic_number(delta);
    vm.push_number(hops + delta_number);
    let guess = vm.top();
    let min = vm.field(2, c"min");
    let result = if vm.less(guess, min) {
        min
    } else {
        let max = vm.field(2, c"max");
        if vm.less(max, guess) { max } else { guess }
    };
    vm.push_number(hops);
    let path = vm.top();
    vm.integer(0);
    let zero = vm.top();
    if (vm.less(delta, zero) && vm.less_equal(path, result))
        || (vm.less_equal(zero, delta) && vm.less(result, path))
    {
        vm.nil();
    } else {
        vm.push(result);
    }
    1
}

fn prepared_bytes(vm: Stack, hex: c_int, default: c_int) -> c_int {
    let bin = vm.call_global(c"parse_hex", &[hex], 1);
    if !vm.truth(bin) {
        vm.call_message(
            c"error",
            b"apply_fooling: invalid hex string '",
            &[(hex, b"'")],
        );
    }
    if vm.length(bin) > 0 { bin } else { default }
}

fn discovered_ttl(vm: Stack, requested: c_int) -> c_int {
    let track = vm.field(1, c"track");
    if !vm.truth(track) {
        return track;
    }
    let received = vm.field(track, c"incoming_ttl");
    if !vm.truth(received) {
        vm.log(
            b"apply_fooling: cannot apply autottl because incoming ttl unknown",
            &[],
        );
        vm.nil();
        return vm.top();
    }
    let state = vm.field(track, c"lua_state");
    let mut cache = vm.field(state, c"autottl_cache");
    if vm.kind(cache) != TABLE {
        cache = vm.table(0);
        vm.assign(state, c"autottl_cache", cache);
    }
    let instance = vm.field(1, c"func_instance");
    let mut record = vm.item(cache, instance);
    if vm.kind(record) != TABLE {
        record = vm.table(2);
        vm.set_item(cache, instance, record);
    }
    if !vm.truth(vm.field(record, c"autottl_found")) {
        let definition = vm.call_global(c"parse_autottl", &[requested], 1);
        if !vm.truth(definition) {
            vm.call_message(
                c"error",
                b"apply_fooling: invalid autottl value '",
                &[(requested, b"'")],
            );
        }
        vm.call_global(c"autottl", &[received, definition], 1);
        vm.set(record, c"autottl");
        let found = vm.field(record, c"autottl");
        if vm.truth(found) {
            vm.boolean(true);
            vm.set(record, c"autottl_found");
            vm.log(b"apply_fooling: discovered autottl ", &[(found, b"")]);
        } else {
            vm.log(b"apply_fooling: could not discover autottl", &[]);
        }
    } else {
        let ttl = vm.field(record, c"autottl");
        if vm.truth(ttl) {
            vm.log(b"apply_fooling: using cached autottl ", &[(ttl, b"")]);
        }
    }
    vm.field(record, c"autottl")
}

fn set_ttl(vm: Stack, header: c_int, opts: c_int, field: &CStr, arg: &CStr, discover: &CStr) {
    let top = vm.top();
    let fixed = vm.field(opts, arg);
    let requested = vm.field(opts, discover);
    let mut ttl = if vm.truth(requested) {
        discovered_ttl(vm, requested)
    } else {
        requested
    };
    if !vm.truth(ttl) && vm.truth(fixed) {
        ttl = vm.call_global(c"tonumber", &[fixed], 1);
        vm.integer(0);
        vm.integer(255);
        if !vm.truth(ttl) || vm.less(ttl, -2) || vm.less(-1, ttl) {
            vm.error(c"apply_fooling: ip_ttl and ip6_ttl require valid value");
            return;
        }
    }
    if vm.truth(ttl) {
        vm.assign(header, field, ttl);
    }
    vm.reset(top);
}

fn tcp_inc(vm: Stack, tcp: c_int, options: c_int, offset: &CStr, field: &CStr, message: &CStr) {
    let top = vm.top();
    let offset = vm.field(options, offset);
    if vm.truth(offset) {
        if !vm.truth(vm.call_global(c"tonumber", &[offset], 1)) {
            vm.error(message);
            return;
        }
        vm.call_global(c"u32add", &[vm.field(tcp, field), offset], 1);
        vm.set(tcp, field);
    }
    vm.reset(top);
}

fn tcp_option(vm: Stack, tcp: c_int, kind: &CStr) -> c_int {
    let options = vm.field(tcp, c"options");
    let kind = vm.field(GLOBALS, kind);
    vm.call_global(c"find_tcp_option", &[options, kind], 1)
}

fn remove_option(vm: Stack, options: c_int, index: c_int) {
    vm.path(GLOBALS, &[c"table", c"remove"]);
    vm.push(options);
    vm.push(index);
    vm.call(2, 0);
}

fn timestamp_offset(vm: Stack, tcp: c_int, offset: c_int) {
    if !vm.truth(vm.call_global(c"tonumber", &[offset], 1)) {
        vm.error(c"apply_fooling: tcp_ts requires increment parameter. there's no default value.");
        return;
    }
    let index = tcp_option(vm, tcp, c"TCP_KIND_TS");
    if vm.truth(index) {
        let option = vm.item(vm.field(tcp, c"options"), index);
        let data = vm.field(option, c"data");
        if vm.truth(data) && vm.length(data) == 8 {
            let value = vm.call_global(c"u32", &[data], 1);
            let new_value = vm.call_global(c"u32add", &[value, offset], 1);
            vm.call_global(c"bu32", &[new_value], 1);
            vm.substring(vm.field(option, c"data"), 5.0, None);
            // The data lookup is rooted beneath the substring result.
            vm.replace(vm.top() - 1);
            vm.concat(2);
            vm.set(option, c"data");
            return;
        }
    }
    vm.log(
        b"apply_fooling: timestamp tcp option not present or invalid",
        &[],
    );
}

fn tcp_md5(vm: Stack, tcp: c_int, value: c_int) {
    if vm.truth(tcp_option(vm, tcp, c"TCP_KIND_MD5")) {
        vm.log(b"apply_fooling: md5 option already present", &[]);
        return;
    }
    vm.path(GLOBALS, &[c"table", c"insert"]);
    vm.field(tcp, c"options");
    let option = vm.table(2);
    vm.field(GLOBALS, c"TCP_KIND_MD5");
    vm.set(option, c"kind");
    vm.integer(16);
    let random = vm.call_global(c"brandom", &[vm.top()], 1);
    vm.assign(option, c"data", prepared_bytes(vm, value, random));
    vm.reset(option);
    vm.call(2, 0);
}

fn modify_tcp(vm: Stack, tcp: c_int, options: c_int) {
    tcp_inc(
        vm,
        tcp,
        options,
        c"tcp_seq",
        c"th_seq",
        c"apply_fooling: tcp_seq requires increment parameter. there's no default value.",
    );
    tcp_inc(
        vm,
        tcp,
        options,
        c"tcp_ack",
        c"th_ack",
        c"apply_fooling: tcp_ack requires increment parameter. there's no default value.",
    );
    let top = vm.top();
    for (name, unset) in [(c"tcp_flags_unset", true), (c"tcp_flags_set", false)] {
        let requested = vm.field(options, name);
        if vm.truth(requested) {
            let flags = vm.field(tcp, c"th_flags");
            let bits = vm.call_global(c"parse_tcp_flags", &[requested], 1);
            if unset {
                let cleared = vm.call_global(c"bitnot", &[bits], 1);
                vm.call_global(c"bitand", &[flags, cleared], 1);
            } else {
                vm.call_global(c"bitor", &[flags, bits], 1);
            }
            vm.set(tcp, c"th_flags");
        }
        vm.reset(top);
    }
    if vm.truth(vm.field(options, c"tcp_nop_del")) {
        let options = vm.field(tcp, c"options");
        for index in (1..=vm.length(options)).rev() {
            let option = vm.array_item(options, index);
            let kind = vm.field(option, c"kind");
            if vm.equal(kind, vm.field(GLOBALS, c"TCP_KIND_NOOP")) {
                vm.integer(index as isize);
                remove_option(vm, options, vm.top());
            }
            vm.reset(options);
        }
    }
    vm.reset(top);
    let ts = vm.field(options, c"tcp_ts");
    if vm.truth(ts) {
        timestamp_offset(vm, tcp, ts);
    }
    vm.reset(top);
    let md5 = vm.field(options, c"tcp_md5");
    if vm.truth(md5) {
        tcp_md5(vm, tcp, md5);
    }
    vm.reset(top);
    if vm.truth(vm.field(options, c"tcp_ts_up")) {
        let index = tcp_option(vm, tcp, c"TCP_KIND_TS");
        vm.integer(1);
        if vm.truth(index) && vm.less(-1, index) {
            vm.path(GLOBALS, &[c"table", c"insert"]);
            let options = vm.field(tcp, c"options");
            vm.integer(1);
            vm.item(options, index);
            vm.call(3, 0);
            let options = vm.field(tcp, c"options");
            vm.push_number(vm.arithmetic_number(index) + 1.0);
            remove_option(vm, options, vm.top());
        }
    }
    vm.reset(top);
}

fn extend_ip6(vm: Stack, ip6: c_int, options: c_int) {
    let top = vm.top();
    for (name, kind, first) in [
        (c"ip6_hopbyhop", c"IPPROTO_HOPOPTS", true),
        (c"ip6_hopbyhop2", c"IPPROTO_HOPOPTS", true),
        (c"ip6_destopt", c"IPPROTO_DSTOPTS", false),
        (c"ip6_routing", c"IPPROTO_ROUTING", false),
        (c"ip6_destopt2", c"IPPROTO_DSTOPTS", false),
        (c"ip6_ah", c"IPPROTO_AH", false),
    ] {
        let hex = vm.field(options, name);
        if vm.truth(hex) {
            if name == c"ip6_ah" {
                vm.integer(4);
                let width = vm.top();
                vm.bytes(&[0; 2]);
                vm.call_global(c"brandom", &[width], 1);
                vm.concat(2);
            } else {
                vm.bytes(&[0; 6]);
            }
            let data = prepared_bytes(vm, hex, vm.top());
            if first {
                vm.integer(1)
            } else {
                vm.nil()
            }
            let index = vm.top();
            vm.call_global(
                c"insert_ip6_exthdr",
                &[ip6, index, vm.field(GLOBALS, kind), data],
                0,
            );
        }
        vm.reset(top);
    }
}

unsafe extern "C-unwind" fn apply_fooling(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 80) };
    vm.pad_arguments(3);
    let options = if vm.truth(3) { 3 } else { vm.field(1, c"arg") };
    let dis = if vm.truth(2) { 2 } else { vm.field(1, c"dis") };
    let tcp = vm.field(dis, c"tcp");
    if vm.truth(tcp) {
        modify_tcp(vm, tcp, options);
    }
    let ip6 = vm.field(dis, c"ip6");
    if vm.truth(ip6) {
        extend_ip6(vm, ip6, options);
    }
    let ip = vm.field(dis, c"ip");
    if vm.truth(ip) {
        set_ttl(vm, ip, options, c"ip_ttl", c"ip_ttl", c"ip_autottl");
    }
    let ip6 = vm.field(dis, c"ip6");
    if vm.truth(ip6) {
        set_ttl(vm, ip6, options, c"ip6_hlim", c"ip6_ttl", c"ip6_autottl");
    }
    let callback = vm.field(options, c"fool");
    if vm.truth(callback) && vm.length(callback) > 0 {
        let globals = vm.field(GLOBALS, c"_G");
        if vm.kind(vm.item(globals, callback)) == FUNCTION {
            vm.log(b"apply_fooling: calling '", &[(callback, b"'")]);
            vm.item(globals, vm.field(options, c"fool"));
            vm.push(dis);
            vm.push(options);
            vm.call(2, 0);
        } else {
            let name = vm.call_global(c"tostring", &[callback], 1);
            vm.call_message(
                c"error",
                b"apply_fooling: fool function '",
                &[(name, b"' does not exist")],
            );
        }
    }
    0
}

fn base_length(vm: Stack, choices: &[(&CStr, &CStr)]) -> c_int {
    vm.pad_arguments(1);
    for &(member, constant) in choices {
        if vm.truth(vm.field(1, member)) {
            vm.field(GLOBALS, constant);
            return 1;
        }
    }
    vm.integer(0);
    1
}

unsafe extern "C-unwind" fn l3_base_len(lua: *mut LuaState) -> c_int {
    base_length(
        unsafe { Stack::enter(lua, 8) },
        &[(c"ip", c"IP_BASE_LEN"), (c"ip6", c"IP6_BASE_LEN")],
    )
}

unsafe extern "C-unwind" fn l4_base_len(lua: *mut LuaState) -> c_int {
    base_length(
        unsafe { Stack::enter(lua, 8) },
        &[
            (c"tcp", c"TCP_BASE_LEN"),
            (c"udp", c"UDP_BASE_LEN"),
            (c"icmp", c"ICMP_BASE_LEN"),
        ],
    )
}

fn align_length(vm: Stack, size: usize, mask: &CStr) -> c_int {
    vm.integer(size as isize);
    vm.call_global(c"bitand", &[vm.top(), vm.field(GLOBALS, mask)], 1)
}

unsafe extern "C-unwind" fn l3_extra_len(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 26) };
    vm.pad_arguments(2);
    let ip = vm.field(1, c"ip");
    if vm.truth(ip) {
        let options = vm.field(ip, c"options");
        if vm.truth(options) {
            align_length(vm, vm.length(options) + 3, c"NOT3");
            return 1;
        }
    } else {
        let ip6 = vm.field(1, c"ip6");
        if vm.truth(ip6) {
            let headers = vm.field(ip6, c"exthdr");
            if vm.truth(headers) {
                let count = vm.length(headers);
                vm.integer(0);
                vm.integer(count as isize);
                let limit = if vm.truth(2)
                    && vm.less_equal(vm.top() - 1, 2)
                    && vm.less_equal(2, vm.top())
                {
                    vm.number(2) as usize
                } else {
                    count
                };
                let top = vm.top();
                let mut length = 0.0;
                for index in 1..=limit {
                    let header = vm.array_item(headers, index);
                    let kind = vm.field(header, c"type");
                    let auth = vm.equal(kind, vm.field(GLOBALS, c"IPPROTO_AH"));
                    let len = vm.length(vm.field(header, c"data"));
                    let aligned = if auth {
                        align_length(vm, len + 5, c"NOT3")
                    } else {
                        align_length(vm, len + 9, c"NOT7")
                    };
                    length += vm.arithmetic_number(aligned);
                    vm.reset(top);
                }
                vm.push_number(length);
                return 1;
            }
        }
    }
    vm.integer(0);
    1
}

unsafe extern "C-unwind" fn l4_extra_len(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 24) };
    vm.pad_arguments(1);
    let tcp = vm.field(1, c"tcp");
    if vm.truth(tcp) {
        let options = vm.field(tcp, c"options");
        if vm.truth(options) {
            let mut length = 0;
            for index in 1..=vm.length(options) {
                let option = vm.array_item(options, index);
                let kind = vm.field(option, c"kind");
                length += 1;
                if !vm.equal(kind, vm.field(GLOBALS, c"TCP_KIND_NOOP"))
                    && !vm.equal(kind, vm.field(GLOBALS, c"TCP_KIND_END"))
                {
                    length += 1;
                    let data = vm.field(option, c"data");
                    if vm.truth(data) {
                        length += vm.length(data);
                    }
                }
                vm.reset(options);
            }
            align_length(vm, length + 3, c"NOT3");
            return 1;
        }
    }
    vm.integer(0);
    1
}

fn sum_lengths(vm: Stack, first: &CStr, second: &CStr) -> c_int {
    vm.pad_arguments(1);
    let first = vm.call_global(first, &[1], 1);
    let second = vm.call_global(second, &[1], 1);
    vm.push_number(vm.arithmetic_number(first) + vm.arithmetic_number(second));
    1
}

unsafe extern "C-unwind" fn l3_len(lua: *mut LuaState) -> c_int {
    sum_lengths(
        unsafe { Stack::enter(lua, 10) },
        c"l3_base_len",
        c"l3_extra_len",
    )
}

unsafe extern "C-unwind" fn l4_len(lua: *mut LuaState) -> c_int {
    sum_lengths(
        unsafe { Stack::enter(lua, 10) },
        c"l4_base_len",
        c"l4_extra_len",
    )
}

unsafe extern "C-unwind" fn l3l4_extra_len(lua: *mut LuaState) -> c_int {
    sum_lengths(
        unsafe { Stack::enter(lua, 10) },
        c"l3_extra_len",
        c"l4_extra_len",
    )
}

unsafe extern "C-unwind" fn l3l4_len(lua: *mut LuaState) -> c_int {
    sum_lengths(unsafe { Stack::enter(lua, 10) }, c"l3_len", c"l4_len")
}

unsafe extern "C-unwind" fn packet_len(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    vm.pad_arguments(1);
    let headers = vm.call_global(c"l3l4_len", &[1], 1);
    let payload = vm.length(vm.field(1, c"payload"));
    vm.push_number(vm.arithmetic_number(headers) + payload as f64);
    1
}
