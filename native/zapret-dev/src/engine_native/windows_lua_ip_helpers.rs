//! Address, transport field and interface helpers for Lua rules.
use super::*;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"dis_ipdst", dis_ipdst),
    (c"dis_ipsrc", dis_ipsrc),
    (c"dis_l4_name", dis_l4_name),
    (c"dis_l4_ports", dis_l4_ports),
    (c"dis_reconstruct_l3", dis_reconstruct_l3),
    (c"dis_reverse", dis_reverse),
    (c"dis_timer_name", dis_timer_name),
    (c"desync_timer_name", desync_timer_name),
    (c"fix_ip_proto", fix_ip_proto),
    (c"ip2ifname", ip2ifname),
    (c"ip_proto", ip_proto),
    (c"ip_proto_l3", ip_proto_l3),
    (c"ip_proto_l4", ip_proto_l4),
    (c"update_ifaddrs", update_ifaddrs),
    (c"wsize_rewrite", wsize_rewrite),
];

unsafe extern "C-unwind" fn ip_proto_l3(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 15) };
    vm.pad_arguments(1);
    let ip = vm.field(1, c"ip");
    if vm.truth(ip) {
        vm.field(ip, c"ip_p");
        return 1;
    }
    let ip6 = vm.field(1, c"ip6");
    if !vm.truth(ip6) {
        return 0;
    }
    let extensions = vm.field(ip6, c"exthdr");
    let length = vm.length(extensions);
    if length == 0 && vm.truth(vm.field(ip6, c"ip6_nxt")) {
        return 1;
    }
    vm.field(vm.array_item(extensions, length), c"next");
    1
}

unsafe extern "C-unwind" fn ip_proto_l4(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    for (header, protocol) in [(c"tcp", c"IPPROTO_TCP"), (c"udp", c"IPPROTO_UDP")] {
        if vm.truth(vm.field(1, header)) {
            vm.field(GLOBALS, protocol);
            return 1;
        }
    }
    for (header, protocol) in [(c"ip", c"IPPROTO_ICMP"), (c"ip6", c"IPPROTO_ICMPV6")] {
        if vm.truth(vm.field(1, header)) {
            if !vm.truth(vm.field(1, c"icmp")) || !vm.truth(vm.field(GLOBALS, protocol)) {
                vm.nil();
            }
            return 1;
        }
    }
    0
}

unsafe extern "C-unwind" fn ip_proto(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 9) };
    vm.pad_arguments(1);
    if !vm.truth(vm.call_global(c"ip_proto_l4", &[1], 1)) {
        vm.call_global(c"ip_proto_l3", &[1], 1);
    }
    1
}

unsafe extern "C-unwind" fn fix_ip_proto(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 13) };
    vm.pad_arguments(2);
    let protocol = if vm.truth(2) {
        2
    } else {
        vm.call_global(c"ip_proto", &[1], 1)
    };
    if vm.truth(protocol) {
        let ip = vm.field(1, c"ip");
        if vm.truth(ip) {
            vm.assign(ip, c"ip_p", protocol);
        } else {
            let ip6 = vm.field(1, c"ip6");
            if vm.truth(ip6) {
                vm.call_global(c"fix_ip6_next", &[ip6, protocol], 0);
            }
        }
    }
    0
}

fn address(vm: Stack, v4: &CStr, v6: &CStr) -> c_int {
    vm.pad_arguments(1);
    let ip = vm.field(1, c"ip");
    if vm.truth(ip) {
        vm.field(ip, v4);
        return 1;
    }
    let ip6 = vm.field(1, c"ip6");
    if vm.truth(ip6) {
        vm.field(ip6, v6);
        return 1;
    }
    0
}

unsafe extern "C-unwind" fn dis_ipsrc(lua: *mut LuaState) -> c_int {
    address(unsafe { Stack::enter(lua, 6) }, c"ip_src", c"ip6_src")
}

unsafe extern "C-unwind" fn dis_ipdst(lua: *mut LuaState) -> c_int {
    address(unsafe { Stack::enter(lua, 6) }, c"ip_dst", c"ip6_dst")
}

unsafe extern "C-unwind" fn dis_l4_name(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    vm.pad_arguments(1);
    for (field, label) in [
        (c"tcp", b"tcp".as_slice()),
        (c"udp", b"udp"),
        (c"icmp", b"icmp"),
    ] {
        if vm.truth(vm.field(1, field)) {
            vm.bytes(label);
            return 1;
        }
    }
    vm.bytes(b"raw");
    vm.call_global(c"ip_proto_l3", &[1], 1);
    vm.concat(2);
    1
}

unsafe extern "C-unwind" fn dis_l4_ports(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    for (field, src, dest) in [
        (c"tcp", c"th_sport", c"th_dport"),
        (c"udp", c"uh_sport", c"uh_dport"),
        (c"icmp", c"icmp_type", c"icmp_code"),
    ] {
        let header = vm.field(1, field);
        if vm.truth(header) {
            let src = vm.field(header, src);
            let dest = vm.field(header, dest);
            if vm.truth(src) {
                vm.push(src);
                vm.bytes(b":");
                vm.push(dest);
                vm.concat(3);
                return 1;
            }
            break;
        }
    }
    vm.bytes(b"?");
    1
}

unsafe extern "C-unwind" fn dis_timer_name(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 26) };
    vm.pad_arguments(1);
    let elements = vm.table(0);
    for (index, arg, separator) in [(1, c"dis_ipsrc", b"->".as_slice()), (3, c"dis_ipdst", b"_")] {
        vm.field(GLOBALS, c"ntop");
        let top = vm.top();
        vm.call_global(arg, &[1], MULTRET);
        vm.call(vm.top() - top, 1);
        vm.raw_array_put(elements, index, vm.top());
        vm.bytes(separator);
        vm.raw_array_put(elements, index + 1, vm.top());
        vm.reset(elements);
    }
    vm.call_global(c"dis_l4_name", &[1], 1);
    vm.raw_array_put(elements, 5, vm.top());
    vm.bytes(b"_");
    vm.raw_array_put(elements, 6, vm.top());
    vm.reset(elements);
    vm.call_global(c"dis_l4_ports", &[1], MULTRET);
    for result in elements + 1..=vm.top() {
        vm.raw_array_put(elements, 6 + result - elements, result);
    }
    vm.reset(elements);
    vm.table_operation(c"concat", &[elements], MULTRET) - elements
}

unsafe extern "C-unwind" fn desync_timer_name(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(1);
    vm.field(1, c"func_instance");
    vm.bytes(b"_");
    let top = vm.top();
    vm.call_global(c"dis_timer_name", &[vm.field(1, c"dis")], 1);
    vm.replace(top + 1);
    vm.concat(3);
    let message = vm.top();
    let track = vm.field(1, c"track");
    if vm.truth(track) {
        let count = vm.path(track, &[c"pos", c"direct", c"pcounter"]);
        vm.push(message);
        vm.bytes(b"_n");
        vm.push(count);
    } else {
        vm.integer(10);
        let random = vm.call_global(c"brandom_az09", &[vm.top()], 1);
        vm.push(message);
        vm.bytes(b"_");
        vm.push(random);
    }
    vm.concat(3);
    1
}

fn swap(vm: Stack, table: c_int, first: &CStr, second: &CStr) {
    let top = vm.top();
    let rhs_first = vm.field(table, second);
    let rhs_second = vm.field(table, first);
    vm.assign(table, second, rhs_second);
    vm.assign(table, first, rhs_first);
    vm.reset(top);
}

unsafe extern "C-unwind" fn dis_reverse(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 13) };
    vm.pad_arguments(1);
    for (field, src, dest) in [
        (c"ip", c"ip_src", c"ip_dst"),
        (c"ip6", c"ip6_src", c"ip6_dst"),
        (c"tcp", c"th_sport", c"th_dport"),
        (c"udp", c"uh_sport", c"uh_dport"),
    ] {
        let header = vm.field(1, field);
        if vm.truth(header) {
            swap(vm, header, src, dest);
            if field == c"tcp" {
                swap(vm, vm.field(1, c"tcp"), c"th_ack", c"th_seq");
                vm.reset(header);
            }
        }
        vm.reset(header - 1);
    }
    0
}

unsafe extern "C-unwind" fn dis_reconstruct_l3(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 15) };
    vm.pad_arguments(2);
    let ip = vm.field(1, c"ip");
    if vm.truth(ip) {
        vm.field(GLOBALS, c"csum_ip4_fix");
        let top = vm.top();
        vm.call_global(c"reconstruct_iphdr", &[ip], MULTRET);
        vm.call(vm.top() - top, MULTRET);
        return vm.top() - top + 1;
    }
    let ip6 = vm.field(1, c"ip6");
    if vm.truth(ip6) {
        return vm.tail_global(c"reconstruct_ip6hdr", &[ip6, 2]);
    }
    0
}

unsafe extern "C-unwind" fn update_ifaddrs(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    if vm.truth(vm.field(GLOBALS, c"ifaddrs")) {
        vm.path(GLOBALS, &[c"os", c"time"]);
        vm.call(0, 1);
        let now = vm.top();
        let last = vm.field(GLOBALS, c"ifaddrs_last");
        if !vm.truth(last) {
            vm.assign(GLOBALS, c"ifaddrs_last", now);
        }
        if !vm.equal(vm.field(GLOBALS, c"ifaddrs_last"), now) {
            vm.call_global(c"get_ifaddrs", &[], 1);
            vm.set(GLOBALS, c"ifaddrs");
            vm.assign(GLOBALS, c"ifaddrs_last", now);
        }
    } else {
        vm.call_global(c"get_ifaddrs", &[], 1);
        vm.set(GLOBALS, c"ifaddrs");
    }
    0
}

unsafe extern "C-unwind" fn ip2ifname(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    vm.pad_arguments(1);
    vm.call_global(c"update_ifaddrs", &[], 0);
    let ifaddrs = vm.field(GLOBALS, c"ifaddrs");
    if !vm.truth(ifaddrs) {
        vm.nil();
        return 1;
    }
    let cursor = vm.call_global(c"pairs", &[ifaddrs], 3);
    while let Some(info) = vm.next_pair(cursor) {
        let addresses = vm.field(info, c"addr");
        vm.bytes(b"addr");
        if vm.truth(vm.call_global(c"array_field_search", &[addresses, vm.top(), 1], 1)) {
            vm.push(cursor);
            return 1;
        }
        vm.reset(cursor);
    }
    0
}

unsafe extern "C-unwind" fn wsize_rewrite(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 37) };
    vm.pad_arguments(2);
    let mut changed = false;
    let width = vm.field(2, c"wsize");
    if vm.truth(width) {
        let width = vm.call_global(c"tonumber", &[width], 1);
        let old = vm.path(1, &[c"tcp", c"th_win"]);
        vm.log(
            b"wsize_rewrite: window size ",
            &[(old, b" => "), (width, b"")],
        );
        let tcp = vm.field(1, c"tcp");
        vm.call_global(c"tonumber", &[vm.field(2, c"wsize")], 1);
        vm.set(tcp, c"th_win");
        changed = true;
    }
    let scale = vm.field(2, c"scale");
    if vm.truth(scale) {
        let scale = vm.call_global(c"tonumber", &[scale], 1);
        let options = vm.path(1, &[c"tcp", c"options"]);
        let kind = vm.field(GLOBALS, c"TCP_KIND_SCALE");
        let index = vm.call_global(c"find_tcp_option", &[options, kind], 1);
        if vm.truth(index) {
            let option = vm.item(options, index);
            let top = vm.top();
            vm.field(GLOBALS, c"u8");
            vm.field(option, c"data");
            vm.call(1, 1);
            if vm.less(top + 1, scale) {
                vm.log(b"wsize_rewrite: not increasing scale factor", &[]);
            } else if vm.less(scale, top + 1) {
                vm.log(
                    b"wsize_rewrite: scale factor ",
                    &[(top + 1, b" => "), (scale, b"")],
                );
                let option = vm.item(vm.path(1, &[c"tcp", c"options"]), index);
                vm.call_global(c"bu8", &[scale], 1);
                vm.set(option, c"data");
                changed = true;
            }
        }
    }
    vm.boolean(changed);
    1
}
