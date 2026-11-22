//! Bundled packet strategies. The engine and Lua hooks supply packet I/O.
use super::{windows_lua_fooling::send_options, *};

#[path = "windows_lua_strategy_rules.rs"]
mod rules;

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    let entries: &[(&CStr, Callback)] = &[
        (c"fake", fake),
        (c"syndata", syndata),
        (c"multisplit", multisplit),
        (c"multidisorder", multidisorder),
        (c"multidisorder_send", multidisorder_send),
        (c"fakedsplit", fakedsplit),
        (c"fakeddisorder", fakeddisorder),
        (c"hostfakesplit", hostfakesplit),
    ];
    let table = vm.table((entries.len() + rules::ENTRIES.len()) as c_int);
    bind_entries(vm, table, entries, &[]);
    let helpers: &[c_int] = if vm.kind(1) == FUNCTION { &[1] } else { &[] };
    bind_entries(vm, table, rules::ENTRIES, helpers);
    1
}

struct Packet {
    vm: Stack,
    desync: c_int,
    name: &'static [u8],
}

impl Packet {
    fn new(vm: Stack, name: &'static [u8]) -> Self {
        vm.pad_arguments(2);
        Self {
            vm,
            desync: 2,
            name,
        }
    }

    fn arg(&self, name: &CStr) -> c_int {
        self.vm.path(self.desync, &[c"arg", name])
    }

    fn dissect(&self, name: &CStr) -> c_int {
        self.vm.path(self.desync, &[c"dis", name])
    }

    fn replay_first(&self) -> bool {
        self.vm
            .truth(self.vm.call_global(c"replay_first", &[self.desync], 1))
    }

    fn direction_payload(&self) -> bool {
        self.vm
            .truth(self.vm.call_global(c"direction_check", &[self.desync], 1))
            && self
                .vm
                .truth(self.vm.call_global(c"payload_check", &[self.desync], 1))
    }

    fn cutoff(&self) {
        self.vm
            .call_global(c"instance_cutoff_shim", &[1, self.desync], 0);
    }

    fn cutoff_opposite(&self) {
        self.vm
            .call_global(c"direction_cutoff_opposite", &[1, self.desync], 0);
    }

    fn debug(&self) -> bool {
        let index = self.vm.field(GLOBALS, c"b_debug");
        let enabled = self.vm.truth(index);
        self.vm.reset(index - 1);
        enabled
    }

    fn log(&self, message: &[u8], parts: &[(c_int, &[u8])]) {
        let vm = self.vm;
        vm.field(GLOBALS, c"DLOG");
        vm.bytes(self.name);
        vm.bytes(message);
        for &(value, suffix) in parts {
            vm.push(value);
            vm.bytes(suffix);
        }
        vm.concat((2 + parts.len() * 2) as c_int);
        vm.call(1, 0);
    }

    fn available_blob(&self, blob: c_int) -> bool {
        self.vm
            .truth(self.vm.call_global(c"blob_exist", &[self.desync, blob], 1))
    }

    fn split_input(&self) -> Option<c_int> {
        let vm = self.vm;
        if !vm.truth(self.dissect(c"tcp")) {
            if !vm.truth(self.dissect(c"icmp")) {
                self.cutoff();
            }
            return None;
        }
        self.cutoff_opposite();
        if vm.truth(self.arg(c"optional")) {
            let blob = self.arg(c"blob");
            if vm.truth(blob) && !self.available_blob(blob) {
                self.log(b": blob '", &[(blob, b"' not found. skipped")]);
                return None;
            }
        }
        let mut data = vm.call_global(c"blob_or_def", &[self.desync, self.arg(c"blob")], 1);
        if !vm.truth(data) {
            data = vm.field(self.desync, c"reasm_data");
        }
        if !vm.truth(data) {
            data = self.dissect(c"payload");
        }
        (vm.length(data) > 0 && self.direction_payload()).then_some(data)
    }

    fn position_arg(&self) -> c_int {
        let marker = self.arg(c"pos");
        if !self.vm.truth(marker) {
            self.vm.bytes(b"2");
            self.vm.replace(marker);
        }
        marker
    }

    fn resolve(&self, resolver: &CStr, data: c_int, marker: c_int) -> c_int {
        let kind = self.vm.field(self.desync, c"l7payload");
        self.vm.call_global(resolver, &[data, kind, marker], 1)
    }

    fn log_positions(&self, prefix: &[u8], positions: c_int) {
        let vm = self.vm;
        vm.path(GLOBALS, &[c"table", c"concat"]);
        vm.call_global(c"zero_based_pos", &[positions], 1);
        vm.bytes(b" ");
        vm.call(2, 1);
        self.log(prefix, &[(vm.top(), b"")]);
    }

    fn resolve_overlap(&self, data: c_int) -> Option<f64> {
        let vm = self.vm;
        let marker = self.arg(c"seqovl");
        if !vm.truth(marker) {
            return None;
        }
        let pos = self.resolve(c"resolve_pos", data, marker);
        if !vm.truth(pos) {
            self.log(
                b": seqovl cancelled because could not resolve marker '",
                &[(marker, b"'")],
            );
            return None;
        }
        Some(vm.arithmetic_number(pos))
    }

    fn numeric_overlap(&self) -> f64 {
        let vm = self.vm;
        let value = self.arg(c"seqovl");
        if vm.truth(value) {
            let number = vm.call_global(c"tonumber", &[value], 1);
            vm.integer(0);
            if vm.less(vm.top(), number) {
                let number = vm.call_global(c"tonumber", &[self.arg(c"seqovl")], 1);
                return vm.arithmetic_number(number);
            }
        }
        0.0
    }

    fn pattern(&self, bytes: c_int, start: f64, count: f64) -> c_int {
        let vm = self.vm;
        vm.push_number(start);
        let start = vm.top();
        vm.push_number(count);
        vm.call_global(c"pattern", &[bytes, start, vm.top()], 1)
    }

    fn prepend_overlap(&self, part: c_int, count: f64) {
        let vm = self.vm;
        let top = vm.top();
        let name = self.arg(c"seqovl_pattern");
        let pattern = if !vm.truth(name) {
            vm.bytes(b"\0");
            vm.top()
        } else if vm.truth(self.arg(c"optional")) && !self.available_blob(name) {
            self.log(b": blob '", &[(name, b"' not found. using zero pattern")]);
            vm.bytes(b"\0");
            vm.top()
        } else {
            vm.call_global(c"blob", &[self.desync, name], 1)
        };
        self.pattern(pattern, 1.0, count);
        vm.push(part);
        vm.concat(2);
        vm.replace(part);
        vm.reset(top);
    }

    fn overlap_fits(&self, overlap: f64, boundary: f64, first: bool) -> bool {
        if overlap < boundary {
            return true;
        }
        let vm = self.vm;
        vm.push_number(overlap);
        let width = vm.top();
        vm.push_number(boundary);
        let suffix: &[u8] = if first {
            b" is not less than the first split pos "
        } else {
            b" is not less than the split pos "
        };
        self.log(
            b": seqovl cancelled because seqovl ",
            &[(width, suffix), (vm.top(), b"")],
        );
        false
    }

    fn part(&self, data: c_int, first: f64, last: Option<f64>) -> c_int {
        self.vm.substring(data, first, last)
    }

    fn send(&self, data: c_int, offset: f64, options: Option<c_int>) -> bool {
        let vm = self.vm;
        let top = vm.top();
        vm.push_number(offset);
        let seq = vm.top();
        let result = if let Some(options) = options {
            vm.call_global(
                c"rawsend_payload_segmented",
                &[self.desync, data, seq, options],
                1,
            )
        } else {
            vm.call_global(c"rawsend_payload_segmented", &[self.desync, data, seq], 1)
        };
        let sent = vm.truth(result);
        vm.reset(top);
        sent
    }

    fn log_part(&self, label: &[u8], part: c_int, first: f64, last: f64, overlap: Option<f64>) {
        if !self.debug() {
            return;
        }
        let vm = self.vm;
        let top = vm.top();
        vm.push_number(first);
        vm.push_number(last);
        vm.integer(vm.length(part) as isize);
        let dump = vm.call_global(c"hexdump_dlog", &[part], 1);
        if let Some(overlap) = overlap {
            vm.push_number(overlap);
            self.log(
                label,
                &[
                    (top + 1, b"-"),
                    (top + 2, b" len="),
                    (top + 3, b" seqovl="),
                    (vm.top(), b" : "),
                    (dump, b""),
                ],
            );
        } else {
            self.log(
                label,
                &[
                    (top + 1, b"-"),
                    (top + 2, b" len="),
                    (top + 3, b" : "),
                    (dump, b""),
                ],
            );
        }
        vm.reset(top);
    }

    fn log_payload(&self, bytes: c_int) {
        if self.debug() {
            let payload = self.vm.call_global(c"hexdump_dlog", &[bytes], 1);
            self.log(b": ", &[(payload, b"")]);
        }
    }

    fn pass(&self) -> c_int {
        self.vm.field(GLOBALS, c"VERDICT_PASS");
        1
    }

    fn drop(&self) -> c_int {
        let vm = self.vm;
        if vm.truth(self.arg(c"nodrop")) && vm.truth(vm.field(GLOBALS, c"VERDICT_PASS")) {
            return 1;
        }
        vm.field(GLOBALS, c"VERDICT_DROP");
        1
    }

    fn sent_reassembly(&self) -> c_int {
        self.vm.call_global(c"replay_drop_set", &[self.desync], 0);
        self.drop()
    }

    fn replay_verdict(&self) -> c_int {
        if self
            .vm
            .truth(self.vm.call_global(c"replay_drop", &[self.desync], 1))
        {
            self.drop()
        } else {
            0
        }
    }
}

unsafe extern "C-unwind" fn fake(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 38) };
    let packet = Packet::new(vm, b"fake");
    packet.cutoff_opposite();
    if (!vm.truth(packet.dissect(c"tcp")) && !vm.truth(packet.dissect(c"udp")))
        || !packet.direction_payload()
    {
        return 0;
    }
    if !packet.replay_first() {
        packet.log(b": not acting on further replay pieces", &[]);
        return 0;
    }
    let name = packet.arg(c"blob");
    if !vm.truth(name) {
        return vm.error(c"fake: 'blob' arg required");
    }
    if vm.truth(packet.arg(c"optional")) && !packet.available_blob(name) {
        packet.log(b": blob '", &[(name, b"' not found. skipped")]);
        return 0;
    }
    let mut payload = vm.call_global(c"blob", &[2, name], 1);
    let reassembled = vm.field(2, c"reasm_data");
    if vm.truth(reassembled) {
        let mods = packet.arg(c"tls_mod");
        if vm.truth(mods) {
            let modded = vm.call_global(c"tls_mod_shim", &[2, payload, mods, reassembled], 1);
            if vm.truth(modded) {
                payload = modded;
            }
        }
    }
    packet.log_payload(payload);
    vm.call_global(c"rawsend_payload_segmented", &[2, payload], 0);
    0
}

unsafe extern "C-unwind" fn syndata(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 44) };
    let packet = Packet::new(vm, b"syndata");
    let tcp = packet.dissect(c"tcp");
    if !vm.truth(tcp) {
        if !vm.truth(packet.dissect(c"icmp")) {
            packet.cutoff();
        }
        return 0;
    }
    let flags = vm.field(tcp, c"th_flags");
    let syn = vm.field(GLOBALS, c"TH_SYN");
    let ack = vm.field(GLOBALS, c"TH_ACK");
    vm.push_number(vm.arithmetic_number(syn) + vm.arithmetic_number(ack));
    let applied = vm.call_global(c"bitand", &[flags, vm.top()], 1);
    if !vm.equal(applied, vm.field(GLOBALS, c"TH_SYN")) {
        packet.cutoff();
        return 0;
    }
    let dissect = vm.call_global(c"deepcopy", &[vm.field(2, c"dis")], 1);
    let name = packet.arg(c"blob");
    vm.bytes(&[0; 16]);
    vm.call_global(c"blob", &[2, name, vm.top()], 1);
    vm.set(dissect, c"payload");
    vm.call_global(c"apply_fooling", &[2, dissect], 0);
    let mods = packet.arg(c"tls_mod");
    if vm.truth(mods) {
        let data = vm.field(dissect, c"payload");
        vm.nil();
        let modded = vm.call_global(c"tls_mod_shim", &[2, data, mods, vm.top()], 1);
        if vm.truth(modded) {
            vm.assign(dissect, c"payload", modded);
        }
    }
    if packet.debug() {
        let payload = vm.field(dissect, c"payload");
        let dump = vm.call_global(c"hexdump_dlog", &[payload], 1);
        packet.log(b": ", &[(dump, b"")]);
    }
    let options = vm.call_global(c"desync_opts", &[2], 1);
    if vm.truth(vm.call_global(c"rawsend_dissect_ipfrag", &[dissect, options], 1)) {
        vm.field(GLOBALS, c"VERDICT_DROP");
        return 1;
    }
    0
}

fn send_multi(
    packet: &Packet,
    data: c_int,
    positions: c_int,
    reverse: bool,
    seqovl: Option<f64>,
) -> bool {
    let vm = packet.vm;
    let count = vm.length(positions);
    let top = vm.top();
    for step in 0..=count {
        let i = if reverse { count - step } else { step };
        let value = vm.array_item(positions, i);
        let first = if vm.truth(value) {
            vm.arithmetic_number(value)
        } else {
            1.0
        };
        let last = if i < vm.length(positions) {
            vm.arithmetic_number(vm.array_item(positions, i + 1)) - 1.0
        } else {
            vm.length(data) as f64
        };
        let part = packet.part(data, first, Some(last));
        let mut overlap = 0.0;
        if reverse {
            if let Some(marker) = seqovl.filter(|marker| i == 1 && *marker > 0.0)
                && packet.overlap_fits(
                    marker - 1.0,
                    vm.arithmetic_number(vm.array_item(positions, 1)) - 1.0,
                    true,
                )
            {
                overlap = marker - 1.0;
                packet.prepend_overlap(part, overlap);
            }
        } else if i == 0 {
            overlap = packet.numeric_overlap();
            if overlap > 0.0 {
                packet.prepend_overlap(part, overlap);
            }
        }
        if packet.debug() {
            vm.integer(i as isize + 1);
            let index = vm.top();
            vm.push_number(first - 1.0);
            vm.push_number(last - 1.0);
            vm.integer(vm.length(part) as isize);
            vm.push_number(overlap);
            let dump = vm.call_global(c"hexdump_dlog", &[part], 1);
            packet.log(
                b": sending part ",
                &[
                    (index, b" "),
                    (index + 1, b"-"),
                    (index + 2, b" len="),
                    (index + 3, b" seqovl="),
                    (index + 4, b" : "),
                    (dump, b""),
                ],
            );
        }
        if !packet.send(part, first - 1.0 - overlap, None) {
            return false;
        }
        vm.reset(top);
    }
    true
}

unsafe extern "C-unwind" fn multidisorder_send(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 52) };
    vm.pad_arguments(4);
    let packet = Packet {
        vm,
        desync: 1,
        name: b"multidisorder",
    };
    let overlap = vm.truth(3).then(|| vm.arithmetic_number(3));
    if send_multi(&packet, 2, 4, true, overlap) {
        vm.field(GLOBALS, c"VERDICT_DROP");
        1
    } else {
        packet.pass()
    }
}

fn multi(vm: Stack, reverse: bool) -> c_int {
    let name: &[u8] = if reverse {
        b"multidisorder"
    } else {
        b"multisplit"
    };
    let packet = Packet::new(vm, name);
    let Some(data) = packet.split_input() else {
        return 0;
    };
    if packet.replay_first() {
        let marker = packet.position_arg();
        if packet.debug() {
            packet.log(b": split pos: ", &[(marker, b"")]);
        }
        let positions = packet.resolve(c"resolve_multi_pos", data, marker);
        if packet.debug() {
            packet.log_positions(b": resolved split pos: ", positions);
        }
        vm.call_global(c"delete_pos_1", &[positions], 0);
        if vm.length(positions) > 0 {
            let sent = if reverse {
                if let Some(overlap) = packet.resolve_overlap(data) {
                    vm.push_number(overlap);
                } else {
                    vm.nil();
                }
                let verdict =
                    vm.call_global(c"multidisorder_send", &[2, data, vm.top(), positions], 1);
                !vm.equal(verdict, vm.field(GLOBALS, c"VERDICT_PASS"))
            } else {
                send_multi(&packet, data, positions, false, None)
            };
            return if sent {
                packet.sent_reassembly()
            } else {
                packet.pass()
            };
        }
        packet.log(b": no valid split positions", &[]);
    } else {
        packet.log(b": not acting on further replay pieces", &[]);
    }
    packet.replay_verdict()
}

unsafe extern "C-unwind" fn multisplit(lua: *mut LuaState) -> c_int {
    multi(unsafe { Stack::enter(lua, 100) }, false)
}

unsafe extern "C-unwind" fn multidisorder(lua: *mut LuaState) -> c_int {
    multi(unsafe { Stack::enter(lua, 100) }, true)
}

struct SplitPart {
    first: f64,
    last: f64,
    before: &'static [u8],
    real: &'static [u8],
    after: &'static [u8],
}

fn fake_pattern(packet: &Packet) -> c_int {
    let vm = packet.vm;
    let name = packet.arg(c"pattern");
    if vm.truth(name) {
        let value = vm.call_global(c"blob", &[packet.desync, name], 1);
        if vm.truth(value) {
            return value;
        }
    }
    vm.bytes(b"\0");
    vm.top()
}

fn fake_parts(packet: &Packet, data: c_int, pos: f64, reverse: bool) -> bool {
    let vm = packet.vm;
    let whole = vm.length(data) as f64;
    let original = send_options(vm, packet.desync, false);
    let fake = send_options(vm, packet.desync, true);
    let pattern = fake_pattern(packet);
    let ranges = [
        SplitPart {
            first: 1.0,
            last: pos - 1.0,
            before: b": sending fake part 1 (1) : ",
            real: b": sending real part 1 : ",
            after: b": sending fake part 1 (2) : ",
        },
        SplitPart {
            first: pos,
            last: whole,
            before: b": sending fake part 2 (1) : ",
            real: b": sending real part 2 : ",
            after: b": sending fake part 2 (2) : ",
        },
    ];
    let flags = [(c"nofake1", c"nofake2"), (c"nofake3", c"nofake4")];
    let top = vm.top();
    let order = if reverse { [1, 0] } else { [0, 1] };
    for (index, (before, after)) in order.into_iter().zip(flags) {
        let range = &ranges[index];
        let cover = packet.pattern(pattern, range.first, range.last - range.first + 1.0);
        let offset = range.first - 1.0;
        let end = range.last - 1.0;
        if !vm.truth(packet.arg(before)) {
            packet.log_part(range.before, cover, offset, end, None);
            if !packet.send(cover, offset, Some(fake)) {
                return false;
            }
        }
        let part = packet.part(data, range.first, (index == 0).then_some(pos - 1.0));
        let mut overlap = 0.0;
        if reverse && index == 1 {
            if let Some(marker) = packet.resolve_overlap(data) {
                let width = marker - 1.0;
                if packet.overlap_fits(width, offset, false) {
                    overlap = width;
                    packet.prepend_overlap(part, width);
                }
            }
        } else if !reverse && index == 0 {
            overlap = packet.numeric_overlap();
            if overlap > 0.0 {
                packet.prepend_overlap(part, overlap);
            }
        }
        packet.log_part(
            range.real,
            part,
            offset,
            end,
            (index == usize::from(reverse)).then_some(overlap),
        );
        if !packet.send(part, offset - overlap, Some(original)) {
            return false;
        }
        if !vm.truth(packet.arg(after)) {
            packet.log_part(range.after, cover, offset, end, None);
            if !packet.send(cover, offset, Some(fake)) {
                return false;
            }
        }
        vm.reset(top);
    }
    true
}

fn fake_split(vm: Stack, reverse: bool) -> c_int {
    let name: &[u8] = if reverse {
        b"fakeddisorder"
    } else {
        b"fakedsplit"
    };
    let packet = Packet::new(vm, name);
    let Some(data) = packet.split_input() else {
        return 0;
    };
    if packet.replay_first() {
        let marker = packet.position_arg();
        let pos = packet.resolve(c"resolve_pos", data, marker);
        if vm.truth(pos) {
            let offset = vm.arithmetic_number(pos);
            if vm.kind(pos) == NUMBER && offset == 1.0 {
                packet.log(b": split pos resolved to 0. cannot split.", &[]);
            } else {
                if packet.debug() {
                    vm.push_number(offset - 1.0);
                    vm.call_global(c"tostring", &[vm.top()], 1);
                    packet.log(b": resolved split pos: ", &[(vm.top(), b"")]);
                }
                return if fake_parts(&packet, data, offset, reverse) {
                    packet.sent_reassembly()
                } else {
                    packet.pass()
                };
            }
        } else {
            packet.log(b": cannot resolve pos '", &[(marker, b"'")]);
        }
    } else {
        packet.log(b": not acting on further replay pieces", &[]);
    }
    packet.replay_verdict()
}

unsafe extern "C-unwind" fn fakedsplit(lua: *mut LuaState) -> c_int {
    fake_split(unsafe { Stack::enter(lua, 110) }, false)
}

unsafe extern "C-unwind" fn fakeddisorder(lua: *mut LuaState) -> c_int {
    fake_split(unsafe { Stack::enter(lua, 110) }, true)
}

fn host_middle(packet: &Packet, data: c_int, first: f64, last: f64) -> Option<f64> {
    let vm = packet.vm;
    let marker = packet.arg(c"midhost");
    if !vm.truth(marker) {
        return None;
    }
    let value = packet.resolve(c"resolve_pos", data, marker);
    if !vm.truth(value) {
        packet.log(b": cannot resolve midhost marker '", &[(marker, b"'")]);
        return None;
    }
    vm.log(
        b"hosfakesplit: midhost marker resolved to ",
        &[(value, b"")],
    );
    let middle = vm.arithmetic_number(value);
    if middle <= first || middle > last {
        packet.log(b": midhost is not inside the host range", &[]);
        None
    } else {
        Some(middle)
    }
}

fn host_disorder(packet: &Packet, data: c_int, last: f64) -> Option<f64> {
    let vm = packet.vm;
    let marker = packet.arg(c"disorder_after");
    if !vm.truth(marker) {
        return None;
    }
    let lookup = if vm.text_is(marker, b"") {
        vm.bytes(b"-1");
        vm.top()
    } else {
        marker
    };
    let pos = packet.resolve(c"resolve_pos", data, lookup);
    if !vm.truth(pos) {
        packet.log(
            b": could not resolve disorder_after marker '",
            &[(marker, b"'")],
        );
        return None;
    }
    let offset = vm.arithmetic_number(pos);
    if offset <= last + 1.0 {
        vm.push_number(offset - 1.0);
        vm.push_number(last);
        packet.log(
            b": disorder_after marker '",
            &[
                (vm.top() - 1, b"' resolved to pos not after after_host pos "),
                (vm.top(), b""),
            ],
        );
        None
    } else {
        Some(offset)
    }
}

fn host_parts(packet: &Packet, data: c_int, range: c_int) -> bool {
    let vm = packet.vm;
    let original = send_options(vm, packet.desync, false);
    let fake = send_options(vm, packet.desync, true);
    let first = vm.arithmetic_number(vm.array_item(range, 1));
    let last = vm.arithmetic_number(vm.array_item(range, 2));
    let before = packet.part(data, 1.0, Some(first - 1.0));
    packet.log_part(
        b": sending before_host part ",
        before,
        0.0,
        first - 2.0,
        None,
    );
    if !packet.send(before, 0.0, Some(original)) {
        return false;
    }
    vm.push_number(last - first + 1.0);
    let width = vm.top();
    let fakehost = vm.call_global(c"genhost", &[width, packet.arg(c"host")], 1);
    if !vm.truth(packet.arg(c"nofake1")) {
        packet.log_part(
            b": sending fake host part (1) ",
            fakehost,
            first - 1.0,
            last - 1.0,
            None,
        );
        if !packet.send(fakehost, first - 1.0, Some(fake)) {
            return false;
        }
    }
    if let Some(middle) = host_middle(packet, data, first, last) {
        let one = packet.part(data, first, Some(middle - 1.0));
        packet.log_part(
            b": sending real host part 1 ",
            one,
            first - 1.0,
            middle - 2.0,
            None,
        );
        if !packet.send(one, first - 1.0, Some(original)) {
            return false;
        }
        let two = packet.part(data, middle, Some(last));
        packet.log_part(
            b": sending real host part 2 ",
            two,
            middle - 1.0,
            last - 1.0,
            None,
        );
        if !packet.send(two, middle - 1.0, Some(original)) {
            return false;
        }
    } else {
        let host = packet.part(data, first, Some(last));
        packet.log_part(
            b": sending real host part ",
            host,
            first - 1.0,
            last - 1.0,
            None,
        );
        if !packet.send(host, first - 1.0, Some(original)) {
            return false;
        }
    }
    if !vm.truth(packet.arg(c"nofake2")) {
        packet.log_part(
            b": sending fake host part (2) ",
            fakehost,
            first - 1.0,
            last - 1.0,
            None,
        );
        if !packet.send(fakehost, first - 1.0, Some(fake)) {
            return false;
        }
    }
    let final_offset = vm.length(data) as f64 - 1.0;
    let suffix = if let Some(offset) = host_disorder(packet, data, last) {
        let tail = packet.part(data, offset, None);
        packet.log_part(
            b": sending after_host part (2) ",
            tail,
            offset - 1.0,
            final_offset,
            None,
        );
        if !packet.send(tail, offset - 1.0, Some(original)) {
            return false;
        }
        let part = packet.part(data, last + 1.0, Some(offset - 1.0));
        packet.log_part(
            b": sending after_host part (1) ",
            part,
            last,
            offset - 2.0,
            None,
        );
        part
    } else {
        let part = packet.part(data, last + 1.0, None);
        packet.log_part(
            b": sending after_host part ",
            part,
            last,
            final_offset,
            None,
        );
        part
    };
    packet.send(suffix, last, Some(original))
}

unsafe extern "C-unwind" fn hostfakesplit(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 130) };
    let packet = Packet::new(vm, b"hostfakesplit");
    let Some(data) = packet.split_input() else {
        return 0;
    };
    if packet.replay_first() {
        let kind = vm.field(2, c"l7payload");
        vm.bytes(b"host,endhost-1");
        vm.boolean(true);
        let range = vm.call_global(c"resolve_range", &[data, kind, kind + 1, kind + 2], 1);
        if vm.truth(range) {
            if packet.debug() {
                packet.log_positions(b": resolved host range: ", range);
            }
            return if host_parts(&packet, data, range) {
                packet.sent_reassembly()
            } else {
                packet.pass()
            };
        }
        packet.log(b": host range cannot be resolved", &[]);
    } else {
        packet.log(b": not acting on further replay pieces", &[]);
    }
    packet.replay_verdict()
}
