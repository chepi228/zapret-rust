//! Adapt the LuaJIT connection and host records to the Rust ring policy.
use super::*;

unsafe extern "C-unwind" fn guarded_detector(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 15) };
    vm.pad_arguments(2);
    let result = vm.protected(capture(1), &[1, 2]);
    if vm.truth(result - 1) {
        return 1;
    }
    let error = vm.call_global(c"tostring", &[result], 1);
    vm.call_message(
        c"DLOG_ERR",
        b"ring: ",
        &[(error, b". using standard detector")],
    );
    let top = vm.top();
    vm.push(capture(2));
    vm.push(1);
    vm.push(2);
    vm.call(2, MULTRET);
    vm.top() - top
}

pub(super) fn install(vm: Stack, native: c_int) {
    let (memory, link) = windows_lua_ring_context::install(vm, native);
    vm.closure(bind, 0);
    for value in [native, memory, link] {
        vm.push(value);
    }
    vm.call(3, 1);
    let module = vm.top();
    for name in [c"rst_guard", c"rst_mark"] {
        vm.assign(GLOBALS, name, vm.field(module, name));
    }
    for (name, handler, fallback) in [
        (c"ring_success", c"success", c"standard_success_detector"),
        (c"ring_failure", c"failure", c"standard_failure_detector"),
    ] {
        vm.field(module, handler);
        vm.field(GLOBALS, fallback);
        vm.closure(guarded_detector, 2);
        vm.set(GLOBALS, name);
    }
}

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    if vm.kind(2) != FUNCTION || vm.kind(3) != FUNCTION {
        return vm.error(c"autoring requires store and link context callbacks");
    }
    let entries: &[(&CStr, Callback)] = &[
        (c"rst_guard", rst_guard),
        (c"rst_mark", rst_mark),
        (c"success", success),
        (c"failure", failure),
    ];
    let out = vm.table(entries.len() as c_int);
    for &(name, callback) in entries {
        vm.push(1);
        vm.push(2);
        vm.push(3);
        vm.closure(callback, 3);
        vm.set(out, name);
    }
    1
}

struct Ring {
    vm: Stack,
    desync: c_int,
}

impl Ring {
    fn call(&self, name: &CStr, args: &[c_int], results: c_int) -> c_int {
        let vm = self.vm;
        vm.field(capture(1), name);
        for &arg in args {
            vm.push(arg);
        }
        vm.call(args.len() as c_int, results);
        vm.top()
    }

    fn arg(&self, name: &CStr) -> c_int {
        self.vm.path(self.desync, &[c"arg", name])
    }

    fn track(&self) -> c_int {
        self.vm.field(self.desync, c"track")
    }

    fn dissect(&self, name: &CStr) -> c_int {
        self.vm.path(self.desync, &[c"dis", name])
    }

    fn outgoing(&self) -> c_int {
        self.vm.field(self.desync, c"outgoing")
    }

    fn tcp_flag(&self, tcp: c_int, flag: &CStr) -> bool {
        let vm = self.vm;
        let flags = vm.field(tcp, c"th_flags");
        let mask = vm.field(GLOBALS, flag);
        let result = vm.call_global(c"bitand", &[flags, mask], 1);
        vm.integer(0);
        !vm.equal(result, -1)
    }

    fn forged(&self) -> bool {
        let vm = self.vm;
        let tcp = self.dissect(c"tcp");
        let track = self.track();
        if !vm.truth(tcp) || !vm.truth(track) || vm.truth(self.outgoing()) {
            return false;
        }
        let ip4 = self.dissect(c"ip");
        let mut ttl = if vm.truth(ip4) {
            vm.field(ip4, c"ip_ttl")
        } else {
            ip4
        };
        if !vm.truth(ttl) {
            let ip6 = self.dissect(c"ip6");
            ttl = if vm.truth(ip6) {
                vm.field(ip6, c"ip6_hlim")
            } else {
                ip6
            };
        }
        let sent = vm.path(track, &[c"lua_state", c"rst_sent"]);
        let incoming = !vm.truth(self.outgoing());
        let rst = self.tcp_flag(tcp, c"TH_RST");
        let observed = vm.field(track, c"incoming_ttl");
        if vm.truth(sent) {
            let now = vm.call_global(c"clock_getfloattime", &[], 1);
            vm.push_number(vm.arithmetic_number(now) - vm.arithmetic_number(sent));
        } else {
            vm.nil();
        }
        let elapsed = vm.top();
        vm.boolean(incoming);
        vm.boolean(true);
        vm.boolean(rst);
        vm.truth(self.call(
            c"forged",
            &[
                elapsed + 1,
                elapsed + 2,
                elapsed + 3,
                ttl,
                observed,
                elapsed,
            ],
            1,
        ))
    }

    fn refused(&self) -> bool {
        let vm = self.vm;
        let tcp = self.dissect(c"tcp");
        let track = self.track();
        if !vm.truth(tcp)
            || !vm.truth(track)
            || vm.truth(self.outgoing())
            || !vm.text_is(vm.field(track, c"l7proto"), b"tls")
            || !self.tcp_flag(tcp, c"TH_FIN")
        {
            return false;
        }
        vm.bytes(b"s");
        let seq = vm.call_global(c"pos_get", &[self.desync, vm.top()], 1);
        let upper = vm.path(track, &[c"pos", c"direct", c"tcp", c"uppos"]);
        if !vm.truth(upper) {
            vm.integer(0);
            vm.replace(upper);
        }
        vm.integer(vm.length(self.dissect(c"payload")) as isize);
        let size = vm.top();
        vm.boolean(true);
        vm.truth(self.call(
            c"refused",
            &[size + 1, size + 1, size + 1, size + 1, seq, upper, size],
            1,
        ))
    }

    fn acked(&self) -> c_int {
        let vm = self.vm;
        let track = self.track();
        if vm.truth(track) {
            let reverse = vm.path(track, &[c"pos", c"reverse"]);
            if vm.truth(reverse) {
                let tcp = vm.field(reverse, c"tcp");
                if vm.truth(tcp) {
                    let count = vm.field(reverse, c"pcounter");
                    vm.integer(1);
                    if vm.truth(count) && !vm.less(count, -1) {
                        vm.boolean(true);
                        let yes = vm.top();
                        let ack = self.tcp_flag(self.dissect(c"tcp"), c"TH_ACK");
                        vm.boolean(ack);
                        let has_ack = vm.top();
                        let sequence = self.vm.path(self.desync, &[c"dis", c"tcp", c"th_ack"]);
                        return self.call(
                            c"acked",
                            &[yes, has_ack, sequence, vm.field(tcp, c"seq0")],
                            1,
                        );
                    }
                }
            }
        }
        vm.integer(0);
        vm.top()
    }

    fn memory(&self) -> c_int {
        let vm = self.vm;
        vm.push(capture(2));
        vm.push(self.desync);
        vm.call(1, 1);
        vm.top()
    }

    fn remember(&self, window: c_int, memory: Option<c_int>) {
        let vm = self.vm;
        let memory = memory.unwrap_or_else(|| self.memory());
        let revision = vm.field(window, c"revision");
        if vm.kind(revision) != NIL && !vm.equal(revision, vm.field(memory, c"revision")) {
            return;
        }
        let store = vm.field(memory, c"store");
        let strategy = vm.field(window, c"strategy");
        vm.integer(1);
        if vm.equal(strategy, -1) {
            vm.nil();
            let empty = vm.top();
            vm.call_method(store, c"put", &[vm.field(window, c"key"), empty], 0);
        } else {
            vm.call_method(store, c"put", &[vm.field(window, c"key"), strategy], 0);
            vm.call_method(
                vm.field(memory, c"store"),
                c"put",
                &[vm.field(window, c"net"), vm.field(window, c"strategy")],
                0,
            );
        }
    }

    fn initialise(&self, host: c_int, key: c_int, window: c_int) -> c_int {
        let vm = self.vm;
        let target = vm.field(self.desync, c"target");
        let mut ip = target;
        if vm.truth(target) {
            ip = vm.field(target, c"ip");
            if !vm.truth(ip) {
                ip = vm.field(target, c"ip6");
            }
        }
        let subnet = if vm.truth(ip) {
            self.call(c"subnet", &[ip], 1)
        } else {
            vm.nil();
            vm.top()
        };
        vm.assign(window, c"net", subnet);
        vm.assign(window, c"key", key);
        vm.assign(window, c"hrec", host);
        let memory = self.memory();
        let revision = vm.field(memory, c"revision");
        let seen = vm.field(host, c"ring_seen");
        let contextual = self.arg(c"context");
        let previous = vm.field(host, c"ring_revision");
        vm.nil();
        let hint = vm.top();
        if !vm.truth(seen) || (vm.truth(contextual) && !vm.equal(previous, revision)) {
            let store = vm.field(memory, c"store");
            let value = vm.call_method(store, c"get", &[key], 1);
            if vm.truth(value) {
                vm.push(value);
                vm.replace(hint);
            } else {
                let subnet = vm.field(window, c"net");
                if vm.truth(subnet) {
                    let store = vm.field(memory, c"store");
                    let value = vm.call_method(store, c"get", &[subnet], 1);
                    vm.push(value);
                    vm.replace(hint);
                }
            }
        }
        if !vm.truth(hint) {
            vm.nil();
            vm.replace(hint);
        }
        let selected = vm.field(host, c"nstrategy");
        let count = vm.field(host, c"ctstrategy");
        let seen = vm.field(host, c"ring_seen");
        vm.boolean(true);
        vm.boolean(vm.equal(seen, -1));
        let seen = vm.top();
        let previous = vm.field(host, c"ring_revision");
        let revision = vm.field(memory, c"revision");
        let contextual = vm.kind(self.arg(c"context")) != NIL;
        vm.boolean(contextual);
        let reset = self.call(
            c"initial",
            &[selected, count, seen, previous, revision, vm.top(), hint],
            2,
        );
        if vm.truth(reset) {
            vm.nil();
            vm.set(host, c"ring_ok");
            vm.integer(0);
            vm.set(host, c"failure_time_last");
            vm.integer(0);
            vm.set(host, c"failure_counter");
            vm.field(memory, c"revision");
            vm.set(host, c"ring_revision");
        }
        vm.assign(host, c"nstrategy", reset - 1);
        vm.boolean(true);
        vm.set(host, c"ring_seen");
        vm.assign(window, c"strategy", reset - 1);
        vm.field(memory, c"revision");
        vm.set(window, c"revision");
        memory
    }

    fn window(&self, connection: c_int) -> (c_int, Option<c_int>) {
        let vm = self.vm;
        let mut window = vm.field(connection, c"ring");
        if !vm.truth(window) {
            window = vm.table(5);
            vm.assign(connection, c"ring", window);
        }
        let mut memory = None;
        if !vm.truth(vm.field(window, c"strategy"))
            && vm.truth(self.outgoing())
            && vm.length(self.dissect(c"payload")) > 0
        {
            let host = vm.call_global(c"automate_host_record", &[self.desync], 1);
            if vm.truth(host) {
                let key = vm.call_global(c"standard_hostkey", &[self.desync], 1);
                if vm.truth(key) {
                    memory = Some(self.initialise(host, key, window));
                }
            }
        }
        (window, memory)
    }

    fn eligible(&self, connection: c_int) -> Option<(c_int, Option<c_int>)> {
        let vm = self.vm;
        if vm.truth(vm.field(connection, c"nocheck")) {
            return None;
        }
        let (window, mut memory) = self.window(connection);
        vm.push(capture(3));
        vm.push(self.desync);
        vm.call(1, 2);
        let paused = vm.top();
        if vm.kind(vm.field(window, c"revision")) != NIL && memory.is_none() {
            memory = Some(self.memory());
        }
        vm.integer(0);
        let mut current = vm.top();
        if let Some(memory) = memory {
            let revision = vm.field(memory, c"revision");
            if vm.truth(revision) {
                current = revision;
            }
        }
        let host = vm.field(window, c"hrec");
        vm.boolean(true);
        let yes = vm.top();
        let evicted = vm.truth(host) && vm.equal(vm.field(host, c"ring_cache_evicted"), yes);
        let tainted = vm.equal(vm.field(window, c"link_tainted"), yes);
        let host_strategy = if vm.truth(host) {
            vm.field(host, c"nstrategy")
        } else {
            host
        };
        vm.boolean(false);
        let no = vm.top();
        vm.boolean(evicted);
        vm.boolean(tainted);
        if vm.truth(host_strategy) {
            vm.push(host_strategy)
        } else {
            vm.nil()
        }
        let host_strategy = vm.top();
        let decision = self.call(
            c"skip",
            &[
                no,
                no + 1,
                vm.field(window, c"link_revision"),
                no + 2,
                paused - 1,
                paused,
                vm.field(window, c"revision"),
                current,
                vm.field(window, c"strategy"),
                host_strategy,
            ],
            3,
        );
        vm.assign(window, c"link_tainted", decision);
        vm.assign(window, c"link_revision", decision - 1);
        if vm.truth(decision - 2) {
            vm.boolean(true);
            vm.set(connection, c"nocheck");
            None
        } else {
            Some((window, memory))
        }
    }
}

unsafe extern "C-unwind" fn rst_guard(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 30) };
    vm.pad_arguments(2);
    let ring = Ring { vm, desync: 2 };
    if ring.forged() {
        vm.log(b"rst_guard: forged rst dropped", &[]);
        vm.field(GLOBALS, c"VERDICT_DROP");
        return 1;
    }
    0
}

unsafe extern "C-unwind" fn rst_mark(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 20) };
    vm.pad_arguments(2);
    let ring = Ring { vm, desync: 2 };
    if vm.truth(ring.track())
        && vm.truth(ring.dissect(c"tcp"))
        && vm.length(ring.dissect(c"payload")) > 0
    {
        let state = vm.path(2, &[c"track", c"lua_state"]);
        vm.call_global(c"clock_getfloattime", &[], 1);
        vm.set(state, c"rst_sent");
    }
    0
}

unsafe extern "C-unwind" fn success(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 178) };
    vm.pad_arguments(2);
    let ring = Ring { vm, desync: 1 };
    if !ring.forged()
        && let Some((window, memory)) = ring.eligible(2)
    {
        let standard = vm.call_global(c"standard_success_detector", &[1, 2], 1);
        let got =
            if !vm.truth(standard) && vm.truth(ring.dissect(c"tcp")) && vm.truth(ring.outgoing()) {
                ring.acked()
            } else {
                vm.integer(0);
                vm.top()
            };
        vm.boolean(vm.truth(standard));
        let verified = vm.top();
        let outgoing = ring.outgoing();
        vm.boolean(true);
        vm.boolean(vm.equal(outgoing, -1));
        let outgoing = vm.top();
        vm.boolean(vm.kind(ring.dissect(c"tcp")) != NIL);
        let tcp = vm.top();
        let required = vm.call_global(c"tonumber", &[ring.arg(c"got")], 1);
        let proved = ring.call(c"success", &[verified, outgoing, tcp, got, required], 2);
        let ok = proved - 1;
        if vm.truth(ok) && vm.truth(proved) && vm.truth(vm.field(window, c"strategy")) {
            let host = vm.field(window, c"hrec");
            vm.field(window, c"strategy");
            vm.set(host, c"ring_ok");
            ring.remember(window, memory);
        }
        vm.push(ok);
    } else {
        vm.boolean(false);
    }
    1
}

unsafe extern "C-unwind" fn failure(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 178) };
    vm.pad_arguments(2);
    let ring = Ring { vm, desync: 1 };
    if ring.forged() || ring.eligible(2).is_none() {
        vm.boolean(false);
        return 1;
    }
    let host = vm.path(2, &[c"ring", c"hrec"]);
    let unproven =
        vm.truth(host) && !vm.equal(vm.field(host, c"ring_ok"), vm.field(host, c"nstrategy"));
    let retrans = ring.arg(c"retrans");
    if unproven && !vm.truth(retrans) {
        let args = vm.field(1, c"arg");
        vm.integer(2);
        vm.set(args, c"retrans");
    }
    vm.field(GLOBALS, c"standard_failure_detector");
    vm.push(1);
    vm.push(2);
    let status = unsafe { lua_pcall(vm.0, 2, 1, 0) };
    let standard = vm.top();
    vm.assign(vm.field(1, c"arg"), c"retrans", retrans);
    if status != 0 {
        vm.call_global(c"error", &[standard], 0);
    }
    let refused = !vm.truth(standard) && ring.refused();
    vm.boolean(vm.truth(standard));
    let found = vm.top();
    vm.boolean(refused);
    vm.boolean(unproven);
    let limit = vm.call_global(c"tonumber", &[ring.arg(c"fails")], 1);
    let count = ring.call(c"failure", &[found, found + 1, found + 2, limit], 2);
    if vm.truth(count) {
        vm.assign(host, c"failure_counter", count);
        vm.path(GLOBALS, &[c"os", c"time"]);
        vm.call(0, 1);
        vm.set(host, c"failure_time_last");
    }
    vm.push(count - 1);
    1
}
