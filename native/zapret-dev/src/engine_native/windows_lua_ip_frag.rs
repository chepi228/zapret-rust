//! Update the extension chain and prepare the stock IPv4 and IPv6 fragments.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"insert_ip6_exthdr", insert_ip6_exthdr),
    (c"del_ip6_exthdr", del_ip6_exthdr),
    (c"fix_ip6_next", fix_ip6_next),
    (c"ipfrag2", ipfrag2),
];

fn extension_predecessor(vm: Stack, headers: c_int, position: c_int) -> (c_int, &'static CStr) {
    vm.integer(1);
    if vm.equal(position, -1) {
        (1, c"ip6_nxt")
    } else {
        vm.push_number(vm.arithmetic_number(position) - 1.0);
        (vm.item(headers, vm.top()), c"next")
    }
}

unsafe extern "C-unwind" fn insert_ip6_exthdr(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 24) };
    vm.pad_arguments(4);
    let mut headers = vm.field(1, c"exthdr");
    if !vm.truth(headers) {
        headers = vm.table(0);
        vm.assign(1, c"exthdr", headers);
    }
    vm.integer(vm.length(headers) as isize + 1);
    let end = vm.top();
    let position = if !vm.truth(2) {
        end
    } else {
        vm.integer(0);
        if vm.less(2, -1) || vm.less(end, 2) {
            vm.call_message(c"error", b"insert_ip6_exthdr: invalid index ", &[(2, b"")]);
        }
        2
    };
    let (previous, field) = extension_predecessor(vm, headers, position);
    let next = vm.field(previous, field);
    vm.assign(previous, field, 3);
    vm.path(GLOBALS, &[c"table", c"insert"]);
    vm.push(headers);
    vm.push(position);
    let entry = vm.table(3);
    vm.assign(entry, c"type", 3);
    vm.assign(entry, c"data", 4);
    vm.assign(entry, c"next", next);
    vm.call(3, 0);
    0
}

unsafe extern "C-unwind" fn del_ip6_exthdr(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(2);
    vm.integer(0);
    let low = vm.top();
    let headers = vm.field(1, c"exthdr");
    vm.integer(vm.length(headers) as isize);
    if vm.less_equal(2, low) || vm.less(-1, 2) {
        vm.call_message(
            c"error",
            b"delete_ip6_exthdr: nonexistent index ",
            &[(2, b"")],
        );
    }
    let next = vm.field(vm.item(headers, 2), c"next");
    let (previous, field) = extension_predecessor(vm, headers, 2);
    vm.assign(previous, field, next);
    vm.path(GLOBALS, &[c"table", c"remove"]);
    vm.push(headers);
    vm.push(2);
    vm.call(2, 0);
    0
}

unsafe extern "C-unwind" fn fix_ip6_next(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    vm.pad_arguments(2);
    let headers = vm.field(1, c"exthdr");
    let count = if vm.truth(headers) {
        vm.length(headers)
    } else {
        0
    };
    if count == 0 {
        if vm.truth(2) {
            vm.push(2)
        } else {
            vm.field(GLOBALS, c"IPPROTO_NONE");
        }
        vm.set(1, c"ip6_nxt");
        return 0;
    }
    for i in 1..=count {
        let header = vm.array_item(headers, i);
        if i == 1 {
            vm.field(header, c"type");
            vm.set(1, c"ip6_nxt");
        }
        if i == vm.length(headers) {
            if vm.truth(2) {
                vm.push(2)
            } else {
                vm.field(GLOBALS, c"IPPROTO_NONE");
            }
        } else {
            vm.field(vm.array_item(headers, i + 1), c"type");
        }
        vm.set(header, c"next");
        vm.reset(headers);
    }
    0
}

fn fragment_index(vm: Stack, headers: c_int) -> usize {
    if !vm.truth(headers) {
        return 1;
    }
    let dest = vm.field(GLOBALS, c"IPPROTO_DSTOPTS");
    let hop = vm.field(GLOBALS, c"IPPROTO_HOPOPTS");
    let route = vm.field(GLOBALS, c"IPPROTO_ROUTING");
    let count = vm.length(headers);
    let top = vm.top();
    let mut first_dest = 0;
    for i in 1..=count {
        let kind = vm.field(vm.array_item(headers, i), c"type");
        let matches = vm.equal(kind, dest);
        vm.reset(top);
        if matches {
            first_dest = i;
            break;
        }
    }
    for i in (1..=count).rev() {
        let kind = vm.field(vm.array_item(headers, i), c"type");
        let unfragmentable = vm.equal(kind, hop)
            || vm.equal(kind, route)
            || (i == first_dest && vm.equal(kind, dest));
        vm.reset(top);
        if unfragmentable {
            return i + 1;
        }
    }
    1
}

fn put_number(vm: Stack, table: c_int, field: &CStr, value: f64) {
    vm.push_number(value);
    vm.set(table, field);
}

fn random_id(vm: Stack, maximum: isize) -> c_int {
    vm.path(GLOBALS, &[c"math", c"random"]);
    vm.integer(1);
    vm.integer(maximum);
    vm.call(2, 1);
    vm.top()
}

fn overflow(vm: Stack, position: c_int) -> c_int {
    vm.log(
        b"ipfrag2: ip frag pos ",
        &[(position, b" exceeds packet length. ipfrag cancelled.")],
    );
    vm.nil();
    1
}

fn ipv4_fragments(
    vm: Stack,
    ip: c_int,
    position: c_int,
    offset: f64,
    l3: f64,
    len: f64,
) -> (c_int, c_int) {
    let existing = vm.field(ip, c"ip_id");
    vm.integer(0);
    let ident = if vm.equal(existing, -1) {
        let generated = random_id(vm, 0xFFFF);
        if vm.truth(generated) {
            generated
        } else {
            vm.field(ip, c"ip_id")
        }
    } else {
        existing
    };
    let first = vm.call_global(c"deepcopy", &[1], 1);
    let header = vm.field(first, c"ip");
    put_number(vm, header, c"ip_len", l3 + offset);
    vm.field(GLOBALS, c"IP_MF");
    vm.set(header, c"ip_off");
    vm.assign(header, c"ip_id", ident);
    let second = vm.call_global(c"deepcopy", &[1], 1);
    let header = vm.field(second, c"ip");
    vm.integer(3);
    vm.call_global(c"bitrshift", &[position, vm.top()], 1);
    vm.set(header, c"ip_off");
    put_number(vm, header, c"ip_len", len - offset);
    vm.assign(header, c"ip_id", ident);
    (first, second)
}

fn append_fragment(vm: Stack, ip: c_int, index: c_int, flags: c_int, ident: c_int) {
    let kind = vm.field(GLOBALS, c"IPPROTO_FRAGMENT");
    vm.call_global(c"bu16", &[flags], 1);
    vm.call_global(c"bu32", &[ident], 1);
    vm.concat(2);
    vm.call_global(c"insert_ip6_exthdr", &[ip, index, kind, vm.top()], 0);
}

fn ipv6_fragments(vm: Stack, index: c_int, offset: f64, extra: f64, length: f64) -> (c_int, c_int) {
    let ident = random_id(vm, 0xFFFF_FFFF);
    let first = vm.call_global(c"deepcopy", &[1], 1);
    let ip = vm.field(first, c"ip6");
    append_fragment(vm, ip, index, vm.field(GLOBALS, c"IP6F_MORE_FRAG"), ident);
    put_number(vm, ip, c"ip6_plen", extra + 8.0 + offset);
    let second = vm.call_global(c"deepcopy", &[1], 1);
    let ip = vm.field(second, c"ip6");
    vm.push_number(offset);
    append_fragment(vm, ip, index, vm.top(), ident);
    let next = vm.field(2, c"ipfrag_next");
    if vm.truth(next) {
        let header = vm.item(vm.field(ip, c"exthdr"), index);
        vm.call_global(c"tonumber", &[vm.field(2, c"ipfrag_next")], 1);
        vm.set(header, c"next");
    }
    let base = vm.field(GLOBALS, c"IP6_BASE_LEN");
    put_number(
        vm,
        ip,
        c"ip6_plen",
        length - vm.arithmetic_number(base) + 8.0 - offset,
    );
    (first, second)
}

unsafe extern "C-unwind" fn ipfrag2(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 92) };
    vm.pad_arguments(2);
    let (field, default) = if vm.truth(vm.field(1, c"tcp")) {
        (c"ipfrag_pos_tcp", 32)
    } else if vm.truth(vm.field(1, c"udp")) {
        (c"ipfrag_pos_udp", 8)
    } else if vm.truth(vm.field(1, c"icmp")) {
        (c"ipfrag_pos_icmp", 8)
    } else {
        (c"ipfrag_pos", 32)
    };
    let pos = vm.field(2, field);
    if !vm.truth(pos) {
        vm.integer(default);
        vm.replace(pos);
    }
    vm.log(b"ipfrag2", &[]);
    let l3 = vm.call_global(c"l3_len", &[1], 1);
    vm.integer(7);
    let remainder = vm.call_global(c"bitand", &[pos, vm.top()], 1);
    vm.integer(0);
    if !vm.equal(remainder, -1) {
        return vm.error(c"ipfrag2: frag position must be multiple of 8");
    }
    let pos_number = vm.arithmetic_number(pos);
    let l3 = vm.arithmetic_number(l3);
    if pos_number + l3 > 65535.0 {
        return vm.error(c"ipfrag2: too high frag offset");
    }
    let l4 = vm.call_global(c"l4_len", &[1], 1);
    let total = l3 + vm.arithmetic_number(l4) + vm.length(vm.field(1, c"payload")) as f64;
    let mut fragments = None;
    let ip4 = vm.field(1, c"ip");
    if vm.truth(ip4) {
        if pos_number + l3 >= total {
            return overflow(vm, pos);
        }
        fragments = Some(ipv4_fragments(vm, ip4, pos, pos_number, l3, total));
    }
    let ip6 = vm.field(1, c"ip6");
    if vm.truth(ip6) {
        let index = fragment_index(vm, vm.field(ip6, c"exthdr"));
        vm.integer(index as isize);
        let index_slot = vm.top();
        vm.integer(index as isize - 1);
        let extra = vm.call_global(c"l3_extra_len", &[1, vm.top()], 1);
        let base = vm.call_global(c"l3_base_len", &[1], 1);
        let extra = vm.arithmetic_number(extra);
        if pos_number + vm.arithmetic_number(base) + extra >= total {
            return overflow(vm, pos);
        }
        fragments = Some(ipv6_fragments(vm, index_slot, pos_number, extra, total));
    }
    let out = vm.table(0);
    if let Some((first, second)) = fragments {
        vm.push(first);
        unsafe { lua_rawseti(vm.0, out, 1) };
        vm.push(second);
        unsafe { lua_rawseti(vm.0, out, 2) };
    }
    1
}
