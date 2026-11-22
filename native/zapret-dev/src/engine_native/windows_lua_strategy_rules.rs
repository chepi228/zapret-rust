//! Additional bundled packet rules exposed to custom profiles.
use super::*;

#[path = "windows_lua_strategy_http.rs"]
mod http;
#[path = "windows_lua_strategy_segments.rs"]
mod segments;

pub(super) const ENTRIES: &[(&CStr, Callback)] = &[
    (c"dht_dn", dht_dn),
    (c"drop", drop_packet),
    (c"http_domcase", http::domcase),
    (c"http_hostcase", http::hostcase),
    (c"http_methodeol", http::methodeol),
    (c"http_unixeol", http::unixeol),
    (c"multidisorder_legacy", segments::multidisorder_legacy),
    (c"oob", segments::oob),
    (c"pktmod", pktmod),
    (c"pos_array_normalize", segments::pos_array_normalize),
    (c"pos_normalize", segments::pos_normalize),
    (c"rst", rst),
    (c"send", send),
    (c"send_timer_delayed", send_timer_delayed),
    (c"synack", synack),
    (c"synack_split", synack_split),
    (c"tcpseg", segments::tcpseg),
    (c"tls_client_hello_clone", tls_client_hello_clone),
    (c"udplen", udplen),
    (c"wsize", wsize),
    (c"wssize", wssize),
];

struct Rule(Packet);

impl Rule {
    fn new(vm: Stack, name: &'static [u8]) -> Self {
        Self(Packet::new(vm, name))
    }

    fn vm(&self) -> Stack {
        self.0.vm
    }

    fn type_or_cutoff(&self, kind: &CStr) -> Option<c_int> {
        let header = self.0.dissect(kind);
        if self.vm().truth(header) {
            Some(header)
        } else {
            if !self.vm().truth(self.0.dissect(c"icmp")) {
                self.0.cutoff();
            }
            None
        }
    }

    fn direction_any(&self, cutoff_any: bool) -> bool {
        let vm = self.vm();
        vm.bytes(b"any");
        let any = vm.top();
        if cutoff_any {
            vm.call_global(c"direction_cutoff_opposite", &[1, 2, any], 0);
        } else {
            self.0.cutoff_opposite();
        }
        vm.truth(vm.call_global(c"direction_check", &[2, any], 1))
    }

    fn direction_default(&self) -> bool {
        self.vm()
            .truth(self.vm().call_global(c"direction_check", &[2], 1))
    }

    fn l7(&self, name: &[u8]) -> bool {
        self.vm().text_is(self.vm().field(2, c"l7payload"), name)
    }

    fn payload(&self) -> c_int {
        self.0.dissect(c"payload")
    }

    fn reassembled(&self) -> c_int {
        let vm = self.vm();
        let value = vm.field(2, c"reasm_data");
        if vm.truth(value) {
            value
        } else {
            self.payload()
        }
    }

    fn verdict(&self, value: &CStr) -> c_int {
        self.vm().field(GLOBALS, value);
        1
    }

    fn copy_packet(&self) -> c_int {
        let vm = self.vm();
        vm.call_global(c"deepcopy", &[vm.field(2, c"dis")], 1)
    }

    fn options(&self) -> c_int {
        self.vm().call_global(c"desync_opts", &[2], 1)
    }

    fn prepare_id(&self, dissect: Option<c_int>) {
        let vm = self.vm();
        vm.nil();
        let nil = vm.top();
        vm.bytes(b"none");
        vm.call_global(
            c"apply_ip_id",
            &[2, dissect.unwrap_or(nil), nil, nil + 1],
            0,
        );
    }

    fn send(&self, dissect: c_int, options: c_int) -> bool {
        let vm = self.vm();
        vm.truth(vm.call_global(c"rawsend_dissect_ipfrag", &[dissect, options], 1))
    }

    fn flag_names(&self) -> (c_int, c_int, c_int) {
        let vm = self.vm();
        let syn = vm.field(GLOBALS, c"TH_SYN");
        let ack = vm.field(GLOBALS, c"TH_ACK");
        vm.push_number(vm.arithmetic_number(syn) + vm.arithmetic_number(ack));
        (syn, ack, vm.top())
    }

    fn sequence_matches(&self, tcp: c_int, mask: c_int, expected: c_int) -> bool {
        let vm = self.vm();
        let flags = vm.field(tcp, c"th_flags");
        vm.equal(vm.call_global(c"bitand", &[flags, mask], 1), expected)
    }
}

unsafe extern "C-unwind" fn drop_packet(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 18) };
    let rule = Rule::new(vm, b"drop");
    if rule.direction_any(true) {
        vm.bytes(b"all");
        if vm.truth(vm.call_global(c"payload_check", &[2, vm.top()], 1)) {
            vm.log(b"drop", &[]);
            return rule.verdict(c"VERDICT_DROP");
        }
    }
    0
}

unsafe extern "C-unwind" fn send(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 33) };
    let rule = Rule::new(vm, b"send");
    if rule.direction_any(true) {
        vm.log(b"send", &[]);
        let dissect = rule.copy_packet();
        vm.call_global(c"apply_fooling", &[2, dissect], 0);
        rule.prepare_id(Some(dissect));
        if vm.truth(rule.0.arg(c"delay")) {
            let name = vm.call_global(c"desync_timer_name", &[2], 1);
            vm.bytes(b"send_timer_delayed");
            let handler = vm.top();
            let delay = vm.call_global(c"tonumber", &[rule.0.arg(c"delay")], 1);
            vm.boolean(true);
            let once = vm.top();
            let data = vm.table(2);
            vm.assign(data, c"dis", dissect);
            rule.options();
            vm.set(data, c"opts");
            vm.call_global(c"timer_set", &[name, handler, delay, once, data], 0);
        } else {
            rule.send(dissect, rule.options());
        }
    }
    0
}

unsafe extern "C-unwind" fn send_timer_delayed(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(2);
    vm.call_global(
        c"rawsend_dissect_ipfrag",
        &[vm.field(2, c"dis"), vm.field(2, c"opts")],
        0,
    );
    0
}

unsafe extern "C-unwind" fn pktmod(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 23) };
    let rule = Rule::new(vm, b"pktmod");
    if rule.direction_any(true) {
        vm.call_global(c"apply_fooling", &[2], 0);
        rule.prepare_id(None);
        vm.log(b"pktmod: applied", &[]);
        return rule.verdict(c"VERDICT_MODIFY");
    }
    0
}

fn set_flags(vm: Stack, dis: c_int, flags: c_int) {
    vm.assign(vm.field(dis, c"tcp"), c"th_flags", flags);
}

unsafe extern "C-unwind" fn synack_split(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 43) };
    let rule = Rule::new(vm, b"synack_split");
    let Some(tcp) = rule.type_or_cutoff(c"tcp") else {
        return 0;
    };
    let (syn, ack, both) = rule.flag_names();
    if !rule.sequence_matches(tcp, both, both) {
        rule.0.cutoff();
        return 0;
    }
    let mode = rule.0.arg(c"mode");
    if !vm.truth(mode) {
        vm.bytes(b"synack");
        vm.replace(mode);
    }
    let options = rule.options();
    let syn_leg = (ack, b"synack_split: sending SYN".as_slice());
    let ack_leg = (syn, b"synack_split: sending ACK".as_slice());
    let legs: &[(c_int, &[u8])] = if vm.text_is(mode, b"syn") {
        &[syn_leg]
    } else if vm.text_is(mode, b"synack") {
        &[syn_leg, ack_leg]
    } else if vm.text_is(mode, b"acksyn") {
        &[ack_leg, syn_leg]
    } else {
        vm.call_message(c"error", b"synack_split: bad mode '", &[(mode, b"'")]);
        return 0;
    };
    let packet = rule.copy_packet();
    for &(clear, message) in legs {
        let flags = rule.0.dissect(c"tcp");
        let flags = vm.field(flags, c"th_flags");
        let mask = vm.call_global(c"bitnot", &[clear], 1);
        let bits = vm.call_global(c"bitand", &[flags, mask], 1);
        set_flags(vm, packet, bits);
        vm.log(message, &[]);
        if !rule.send(packet, options) {
            return rule.verdict(c"VERDICT_PASS");
        }
        vm.reset(packet);
    }
    rule.verdict(c"VERDICT_DROP")
}

unsafe extern "C-unwind" fn synack(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 33) };
    let rule = Rule::new(vm, b"synack");
    if let Some(tcp) = rule.type_or_cutoff(c"tcp") {
        let (syn, ack, both) = rule.flag_names();
        if rule.sequence_matches(tcp, both, syn) {
            let dissect = rule.copy_packet();
            let bits = vm.call_global(
                c"bitor",
                &[vm.path(dissect, &[c"tcp", c"th_flags"]), ack],
                1,
            );
            set_flags(vm, dissect, bits);
            vm.log(b"synack: sending", &[]);
            rule.send(dissect, rule.options());
        } else {
            rule.0.cutoff();
        }
    }
    0
}

fn rewrite_window(vm: Stack) -> bool {
    vm.truth(vm.call_global(
        c"wsize_rewrite",
        &[vm.field(2, c"dis"), vm.field(2, c"arg")],
        1,
    ))
}

unsafe extern "C-unwind" fn wsize(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 23) };
    let rule = Rule::new(vm, b"wsize");
    if let Some(tcp) = rule.type_or_cutoff(c"tcp") {
        let (_, _, both) = rule.flag_names();
        if rule.sequence_matches(tcp, both, both) {
            if rewrite_window(vm) {
                return rule.verdict(c"VERDICT_MODIFY");
            }
        } else {
            rule.0.cutoff();
        }
    }
    0
}

unsafe extern "C-unwind" fn wssize(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 26) };
    let rule = Rule::new(vm, b"wssize");
    if rule.type_or_cutoff(c"tcp").is_none() {
        return 0;
    }
    let verdict = vm.field(GLOBALS, c"VERDICT_PASS");
    rule.0.cutoff_opposite();
    if rule.direction_default() {
        if rewrite_window(vm) {
            vm.field(GLOBALS, c"VERDICT_MODIFY");
            vm.replace(verdict);
        }
        if vm.length(rule.payload()) > 0 {
            let filter = rule.0.arg(c"forced_cutoff");
            if !vm.truth(filter)
                || vm.truth(vm.call_global(c"in_list", &[filter, vm.field(2, c"l7payload")], 1))
            {
                vm.log(b"wssize: forced cutoff", &[]);
                rule.0.cutoff();
            }
        }
    }
    vm.push(verdict);
    1
}

unsafe extern "C-unwind" fn tls_client_hello_clone(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 36) };
    let rule = Rule::new(vm, b"tls_client_hello_clone");
    if rule.type_or_cutoff(c"tcp").is_none() {
        return 0;
    }
    rule.0.cutoff_opposite();
    if rule.direction_default() {
        let name = rule.0.arg(c"blob");
        if !vm.truth(name) {
            return vm.error(c"tls_client_hello_clone: 'blob' arg required");
        }
        if rule.l7(b"tls_client_hello") {
            let edited = vm.call_global(
                c"tls_client_hello_mod",
                &[rule.reassembled(), vm.field(2, c"arg")],
                1,
            );
            vm.set_item(2, name, edited);
            let key = rule.0.arg(c"blob");
            if vm.truth(vm.item(2, key)) {
                vm.log(b"tls_client_hello_clone: cloned to desync.", &[(key, b"")]);
            }
        }
        let key = rule.0.arg(c"blob");
        if !vm.truth(vm.item(2, key)) {
            let fallback = rule.0.arg(c"fallback");
            if vm.truth(fallback) {
                vm.log(
                    b"tls_client_hello_clone: desync.",
                    &[(key, b"="), (fallback, b"")],
                );
                let value = vm.call_global(c"blob", &[2, rule.0.arg(c"fallback")], 1);
                vm.set_item(2, rule.0.arg(c"blob"), value);
            }
        }
    }
    0
}

unsafe extern "C-unwind" fn rst(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 33) };
    let rule = Rule::new(vm, b"rst");
    if rule.type_or_cutoff(c"tcp").is_none()
        || !rule.direction_any(false)
        || !vm.truth(vm.call_global(c"payload_check", &[2], 1))
    {
        return 0;
    }
    if !rule.0.replay_first() {
        vm.log(b"rst: not acting on further replay pieces", &[]);
        return 0;
    }
    let dissect = rule.copy_packet();
    vm.bytes(b"");
    vm.set(dissect, c"payload");
    let rst = vm.arithmetic_number(vm.field(GLOBALS, c"TH_RST"));
    let ack = if vm.truth(rule.0.arg(c"rstack")) {
        vm.arithmetic_number(vm.field(GLOBALS, c"TH_ACK"))
    } else {
        0.0
    };
    vm.push_number(rst + ack);
    set_flags(vm, dissect, vm.top());
    vm.call_global(c"apply_fooling", &[2, dissect], 0);
    rule.prepare_id(Some(dissect));
    vm.log(b"rst", &[]);
    rule.send(dissect, rule.options());
    0
}

fn limit_udp(rule: &Rule, length: c_int, name: &CStr, minimum: bool) -> bool {
    let vm = rule.vm();
    let requested = rule.0.arg(name);
    if !vm.truth(requested) {
        return false;
    }
    let limit = vm.call_global(c"tonumber", &[requested], 1);
    if if minimum {
        vm.less(length, limit)
    } else {
        vm.less(limit, length)
    } {
        let suffix: &[u8] = if minimum {
            b" is less than the minimum size "
        } else {
            b" is more than the maximum size "
        };
        vm.log(
            b"udplen: payload size ",
            &[(length, suffix), (requested, b"")],
        );
        return true;
    }
    false
}

unsafe extern "C-unwind" fn udplen(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 40) };
    let rule = Rule::new(vm, b"udplen");
    if rule.type_or_cutoff(c"udp").is_none() {
        return 0;
    }
    rule.0.cutoff_opposite();
    if !rule.0.direction_payload() {
        return 0;
    }
    let payload = rule.payload();
    let length = vm.length(payload) as f64;
    vm.push_number(length);
    let old = vm.top();
    if limit_udp(&rule, old, c"min", true) || limit_udp(&rule, old, c"max", false) {
        return 0;
    }
    let increment = rule.0.arg(c"increment");
    let increment = if vm.truth(increment) {
        vm.call_global(c"tonumber", &[increment], 1)
    } else {
        increment
    };
    let increment = if vm.truth(increment) {
        vm.arithmetic_number(increment)
    } else {
        2.0
    };
    let dis = vm.field(2, c"dis");
    if increment > 0.0 {
        let name = rule.0.arg(c"pattern");
        let mut fill = if vm.truth(name) {
            vm.call_global(c"blob", &[2, name], 1)
        } else {
            name
        };
        if !vm.truth(fill) {
            vm.bytes(b"\0");
            fill = vm.top();
        }
        let offset = rule.0.arg(c"pattern_offset");
        let offset = if vm.truth(offset) {
            let value = vm.call_global(c"tonumber", &[offset], 1);
            vm.arithmetic_number(value) + 1.0
        } else {
            1.0
        };
        vm.field(dis, c"payload");
        rule.0.pattern(fill, offset, increment);
        vm.replace(vm.top() - 1);
        // Drop the second numeric argument as well, retaining the payload.
        vm.replace(vm.top() - 1);
        vm.concat(2);
    } else if increment < 0.0 {
        if length + increment < 1.0 {
            vm.log(b"udplen: will not shrink to zero length", &[]);
            return 0;
        }
        vm.substring(vm.field(dis, c"payload"), 1.0, Some(length + increment));
    } else {
        return 0;
    }
    vm.set(dis, c"payload");
    vm.integer(vm.length(rule.payload()) as isize);
    vm.log(b"udplen: ", &[(old, b" => "), (vm.top(), b"")]);
    rule.verdict(c"VERDICT_MODIFY")
}

unsafe extern "C-unwind" fn dht_dn(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 30) };
    let rule = Rule::new(vm, b"dht_dn");
    if rule.type_or_cutoff(c"udp").is_none() {
        return 0;
    }
    rule.0.cutoff_opposite();
    if !rule.l7(b"dht") || !rule.direction_default() {
        return 0;
    }
    let count = vm.call_global(c"tonumber", &[rule.0.arg(c"dn")], 1);
    if !vm.truth(count) {
        vm.integer(3);
        vm.replace(count);
    }
    vm.bytes(b"d");
    let prefix = vm.top();
    vm.call_global(c"tostring", &[count], 1);
    vm.bytes(b":");
    let repeat = vm.path(GLOBALS, &[c"string", c"rep"]);
    vm.bytes(b"0");
    vm.push(count);
    vm.call(2, 1);
    vm.replace(repeat - 1);
    vm.bytes(b"1:x");
    vm.concat(5);
    let dis = vm.field(2, c"dis");
    vm.push(prefix);
    let payload = vm.field(dis, c"payload");
    vm.substring(payload, 2.0, None);
    vm.replace(payload);
    vm.concat(2);
    vm.set(dis, c"payload");
    vm.log(
        b"dht_dn: tampered dht to start with '",
        &[(prefix, b"' instead of 'd1:'")],
    );
    rule.verdict(c"VERDICT_MODIFY")
}
