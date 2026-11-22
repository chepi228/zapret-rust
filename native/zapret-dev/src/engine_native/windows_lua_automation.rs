//! Automation records, failure accounting and the stock traffic detectors.
use super::*;

pub(super) unsafe extern "C-unwind" fn bind(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 4) };
    if vm.kind(1) != FUNCTION {
        return vm.error(c"automation module requires a Lua comparison callback");
    }
    let entries: &[(&CStr, Callback)] = &[
        (c"standard_hostkey", standard_hostkey),
        (c"automate_conn_record", automate_conn_record),
        (c"automate_failure_counter", automate_failure_counter),
        (
            c"automate_failure_counter_reset",
            automate_failure_counter_reset,
        ),
        (c"automate_failure_check", automate_failure_check),
        (c"is_dpi_redirect", is_dpi_redirect),
        (c"standard_detector_defaults", standard_detector_defaults),
        (c"standard_success_detector", standard_success_detector),
        (c"standard_failure_detector", standard_failure_detector),
        (c"cond_true", cond_true),
        (c"cond_false", cond_false),
        (c"cond_random", cond_random),
        (c"cond_payload_str", cond_payload_str),
        (c"cond_tcp_has_ts", cond_tcp_has_ts),
    ];
    let table = vm.table((entries.len() + windows_lua_plan::ENTRIES.len()) as c_int);
    bind_entries(vm, table, entries, &[1]);
    bind_entries(vm, table, windows_lua_plan::ENTRIES, &[1]);
    1
}

unsafe extern "C-unwind" fn standard_hostkey(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 22) };
    vm.pad_arguments(1);
    let track = vm.field(1, c"track");
    let mut key = track;
    if vm.truth(track) {
        key = vm.field(track, c"hostname");
    }
    if vm.truth(key) {
        let level = vm.path(1, &[c"arg", c"nld"]);
        if vm.truth(level) {
            let number = vm.call_global(c"tonumber", &[level], 1);
            vm.integer(0);
            if vm.less(vm.top(), number) {
                let fresh_track = vm.field(1, c"track");
                if !vm.truth(fresh_track) || !vm.truth(vm.field(fresh_track, c"hostname_is_ip")) {
                    let level = vm.path(1, &[c"arg", c"nld"]);
                    let number = vm.call_global(c"tonumber", &[level], 1);
                    let domain = vm.call_global(c"dissect_nld", &[key, number], 1);
                    if vm.truth(domain) {
                        key = domain;
                    }
                }
            }
        }
    } else if !vm.truth(vm.path(1, &[c"arg", c"reqhost"])) {
        key = vm.call_global(c"host_ip", &[1], 1);
    }
    vm.push(key);
    1
}

unsafe extern "C-unwind" fn automate_conn_record(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 10) };
    let track = vm.field(1, c"track");
    if !vm.truth(track) {
        vm.nil();
        return 1;
    }
    let state = vm.field(track, c"lua_state");
    if !vm.truth(vm.field(state, c"automate")) {
        vm.table(0);
        vm.set(state, c"automate");
    }
    vm.field(state, c"automate");
    1
}

unsafe extern "C-unwind" fn automate_failure_counter(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 40) };
    vm.pad_arguments(4);
    if vm.truth(2) && vm.truth(vm.field(2, c"failure")) {
        vm.log(
            b"automate: duplicate failure in the same connection. not counted",
            &[],
        );
        vm.boolean(false);
        return 1;
    }
    if vm.truth(2) {
        vm.boolean(true);
        vm.set(2, c"failure");
    }
    vm.path(GLOBALS, &[c"os", c"time"]);
    vm.call(0, 1);
    let time = vm.top();
    if !vm.truth(vm.field(1, c"failure_time_last")) {
        vm.assign(1, c"failure_time_last", time);
    }
    let counter = vm.field(1, c"failure_counter");
    if !vm.truth(counter) {
        vm.integer(0);
        vm.set(1, c"failure_counter");
    } else {
        let last = vm.field(1, c"failure_time_last");
        vm.push_number(vm.arithmetic_number(last) + vm.arithmetic_number(4));
        if vm.less(vm.top(), time) {
            let last = vm.field(1, c"failure_time_last");
            vm.push_number(vm.arithmetic_number(time) - vm.arithmetic_number(last));
            vm.log(
                b"automate: failure counter reset because last failure was ",
                &[(vm.top(), b" seconds ago")],
            );
            vm.integer(0);
            vm.set(1, c"failure_counter");
        }
    }
    let counter = vm.field(1, c"failure_counter");
    vm.push_number(vm.arithmetic_number(counter) + 1.0);
    vm.set(1, c"failure_counter");
    vm.assign(1, c"failure_time_last", time);
    if vm.truth(vm.field(GLOBALS, c"b_debug")) {
        let counter = vm.field(1, c"failure_counter");
        let message = b"automate: failure counter ";
        if vm.truth(3) {
            vm.log(message, &[(counter, b"/"), (3, b"")]);
        } else {
            vm.log(message, &[(counter, b"")]);
        }
    }
    let reached = vm.truth(3) && vm.less_equal(3, vm.field(1, c"failure_counter"));
    if reached {
        vm.nil();
        vm.set(1, c"failure_counter");
    }
    vm.boolean(reached);
    1
}

unsafe extern "C-unwind" fn automate_failure_counter_reset(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 6) };
    if vm.truth(vm.field(1, c"failure_counter")) {
        vm.log(b"automate: failure counter reset", &[]);
        vm.nil();
        vm.set(1, c"failure_counter");
    }
    0
}

fn detector(vm: Stack, selector: &CStr, standard: &CStr, error: &[u8]) -> c_int {
    let name = vm.path(1, &[c"arg", selector]);
    if vm.truth(name) {
        let globals = vm.field(GLOBALS, c"_G");
        let selected = vm.item(globals, name);
        if vm.kind(selected) != FUNCTION {
            vm.call_message(c"error", error, &[(name, b"'")]);
        }
        vm.item(globals, name)
    } else {
        vm.field(GLOBALS, standard)
    }
}

fn tonumber_default(vm: Stack, value: c_int, default: isize) -> c_int {
    let output = vm.call_global(c"tonumber", &[value], 1);
    if !vm.truth(output) {
        vm.integer(default);
        vm.replace(output);
    }
    output
}

fn mark_checked(vm: Stack, message: &[u8]) {
    vm.boolean(true);
    vm.set(3, c"nocheck");
    vm.log(message, &[]);
}

unsafe extern "C-unwind" fn automate_failure_check(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 32) };
    vm.pad_arguments(3);
    if !vm.truth(vm.field(3, c"nocheck")) {
        let failure = detector(
            vm,
            c"failure_detector",
            c"standard_failure_detector",
            b"automate: invalid failure detector function '",
        );
        let success = detector(
            vm,
            c"success_detector",
            c"standard_success_detector",
            b"automate: invalid success detector function '",
        );
        vm.push(success);
        vm.push(1);
        vm.push(3);
        vm.call(2, 1);
        if vm.truth(-1) {
            mark_checked(vm, b"automate: success detected");
            vm.call_global(c"automate_failure_counter_reset", &[2], 0);
        } else {
            vm.push(failure);
            vm.push(1);
            vm.push(3);
            vm.call(2, 1);
            if vm.truth(-1) {
                mark_checked(vm, b"automate: failure detected");
                let fails = tonumber_default(vm, vm.path(1, &[c"arg", c"fails"]), 3);
                let max_time = tonumber_default(vm, vm.path(1, &[c"arg", c"time"]), 60);
                let top = vm.top();
                vm.call_global(
                    c"automate_failure_counter",
                    &[2, 3, fails, max_time],
                    MULTRET,
                );
                return vm.top() - top;
            }
        }
    }
    vm.boolean(false);
    1
}

unsafe extern "C-unwind" fn is_dpi_redirect(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(2);
    let url = vm.call_global(c"dissect_url", &[2], 1);
    if vm.truth(url) && vm.truth(vm.field(url, c"domain")) {
        vm.integer(2);
        let level = vm.top();
        let source = vm.call_global(c"dissect_nld", &[1, level], 1);
        let target = vm.call_global(c"dissect_nld", &[vm.field(url, c"domain"), level], 1);
        vm.boolean(vm.truth(target) && !vm.equal(source, target));
    } else {
        vm.boolean(false);
    }
    1
}

unsafe extern "C-unwind" fn standard_detector_defaults(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 8) };
    vm.pad_arguments(1);
    let defaults = vm.table(8);
    for (name, number) in [
        (c"inseq", 4096),
        (c"retrans", 3),
        (c"maxseq", 32_768),
        (c"udp_in", 1),
        (c"udp_out", 4),
    ] {
        tonumber_default(vm, vm.field(1, name), number);
        vm.set(defaults, name);
        vm.reset(defaults);
    }
    for name in [c"no_http_redirect", c"no_rst", c"reset"] {
        vm.field(1, name);
        vm.set(defaults, name);
    }
    1
}

fn position(vm: Stack, mode: &[u8], reverse: Option<bool>) -> c_int {
    let previous = vm.top();
    vm.bytes(mode);
    let mode = vm.top();
    if let Some(reverse) = reverse {
        vm.boolean(reverse);
        vm.call_global(c"pos_get", &[1, mode, vm.top()], 1);
    } else {
        vm.call_global(c"pos_get", &[1, mode], 1);
    }
    vm.replace(previous + 1);
    vm.reset(previous + 1);
    vm.top()
}

fn positive(vm: Stack, index: c_int) -> bool {
    let top = vm.top();
    vm.integer(0);
    let yes = vm.less(-1, index);
    vm.reset(top);
    yes
}

unsafe extern "C-unwind" fn standard_success_detector(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 28) };
    vm.pad_arguments(2);
    let args = vm.call_global(c"standard_detector_defaults", &[vm.field(1, c"arg")], 1);
    let tcp = vm.path(1, &[c"dis", c"tcp"]);
    if vm.truth(tcp) {
        let seq = position(vm, b"s", None);
        let outgoing = vm.truth(vm.field(1, c"outgoing"));
        let limit = vm.field(args, if outgoing { c"maxseq" } else { c"inseq" });
        if positive(vm, limit) && vm.less(limit, seq) {
            let label: &[u8] = if outgoing {
                b"standard_success_detector: outgoing s"
            } else {
                b"standard_success_detector: incoming s"
            };
            vm.log(
                label,
                &[
                    (seq, b" is beyond s"),
                    (limit, b". treating connection as successful"),
                ],
            );
            vm.boolean(true);
            return 1;
        }
    } else if vm.truth(vm.path(1, &[c"dis", c"udp"])) && !vm.truth(vm.field(1, c"outgoing")) {
        let count = position(vm, b"n", None);
        if positive(vm, vm.field(args, c"udp_out")) {
            let limit = vm.field(args, c"udp_in");
            if vm.less(limit, count) {
                if vm.truth(vm.field(GLOBALS, c"b_debug")) {
                    vm.log(
                        b"standard_success_detector: arg.udp_in ",
                        &[(count, b">"), (limit, b"")],
                    );
                }
                vm.boolean(true);
                return 1;
            }
        }
    }
    vm.boolean(false);
    1
}

fn reset_retransmitter(vm: Stack) {
    let dissect = vm.call_global(c"deepcopy", &[vm.field(1, c"dis")], 1);
    vm.nil();
    vm.set(dissect, c"payload");
    vm.call_global(c"dis_reverse", &[dissect], 0);
    let tcp = vm.field(dissect, c"tcp");
    vm.field(GLOBALS, c"TH_RST");
    vm.set(tcp, c"th_flags");
    let track = vm.field(1, c"track");
    let winsize = if vm.truth(track) {
        vm.path(track, &[c"pos", c"reverse", c"tcp", c"winsize"])
    } else {
        track
    };
    if vm.truth(winsize) {
        vm.push(winsize);
    } else {
        vm.integer(64);
    }
    vm.set(tcp, c"th_win");
    vm.nil();
    vm.set(tcp, c"options");
    let ip6 = vm.field(dissect, c"ip6");
    if vm.truth(ip6) {
        let track = vm.field(1, c"track");
        let flow = if vm.truth(track) {
            vm.path(track, &[c"pos", c"reverse", c"ip6_flow"])
        } else {
            track
        };
        if vm.truth(flow) {
            vm.push(flow);
        } else {
            vm.integer(0x6000_0000);
        }
        vm.set(ip6, c"ip6_flow");
    }
    vm.log(
        b"standard_failure_detector: sending RST to retransmitter",
        &[],
    );
    let options = vm.table(1);
    vm.field(1, c"ifin");
    vm.set(options, c"ifout");
    vm.call_global(c"rawsend_dissect", &[dissect, options], 0);
}

fn tcp_retransmission(vm: Stack, args: c_int, seq: c_int) -> bool {
    if vm.length(vm.path(1, &[c"dis", c"payload"])) == 0 {
        return false;
    }
    let limit = vm.field(args, c"retrans");
    if !vm.truth(limit) {
        return false;
    }
    let max_seq = vm.field(args, c"maxseq");
    if !positive(vm, max_seq) || !vm.less_equal(seq, max_seq) {
        return false;
    }
    let count = vm.field(2, c"retrans");
    if !vm.truth(count) {
        vm.integer(0);
        vm.replace(count);
    }
    if !vm.less(count, limit) || !vm.truth(vm.call_global(c"is_retransmission", &[1], 1)) {
        return false;
    }
    let count = vm.field(2, c"retrans");
    vm.push_number(if vm.truth(count) {
        vm.arithmetic_number(count) + 1.0
    } else {
        1.0
    });
    vm.set(2, c"retrans");
    let count = vm.field(2, c"retrans");
    vm.log(
        b"standard_failure_detector: retransmission ",
        &[(count, b"/"), (limit, b"")],
    );
    let trigger = vm.less_equal(vm.field(args, c"retrans"), vm.field(2, c"retrans"));
    if trigger && vm.truth(vm.field(args, c"reset")) {
        reset_retransmitter(vm);
    }
    trigger
}

fn incoming_reset(vm: Stack, args: c_int, seq: c_int) -> Option<bool> {
    if vm.truth(vm.field(args, c"no_rst")) {
        return None;
    }
    let limit = vm.field(args, c"inseq");
    if !positive(vm, limit) {
        return None;
    }
    let flags = vm.path(1, &[c"dis", c"tcp", c"th_flags"]);
    let rst = vm.field(GLOBALS, c"TH_RST");
    let flags = vm.call_global(c"bitand", &[flags, rst], 1);
    vm.integer(0);
    if vm.equal(flags, -1) {
        return None;
    }
    vm.integer(1);
    if !vm.less_equal(vm.top(), seq) {
        return None;
    }
    let trigger = vm.less_equal(seq, limit);
    if vm.truth(vm.field(GLOBALS, c"b_debug")) {
        let (label, boundary): (&[u8], &[u8]) = if trigger {
            (b"standard_failure_detector: incoming RST s", b" in range s")
        } else {
            (
                b"standard_failure_detector: not counting incoming RST s",
                b" beyond s",
            )
        };
        vm.log(label, &[(seq, boundary), (limit, b"")]);
    }
    Some(trigger)
}

fn http_redirect(vm: Stack, args: c_int) -> c_int {
    if !vm.truth(vm.field(args, c"no_http_redirect"))
        && vm.text_is(vm.field(1, c"l7payload"), b"http_reply")
        && vm.truth(vm.path(1, &[c"track", c"hostname"]))
    {
        let payload = vm.path(1, &[c"dis", c"payload"]);
        let http = vm.call_global(c"http_dissect_reply", &[payload], 1);
        if vm.truth(http) {
            let code = vm.field(http, c"code");
            if vm.kind(code) == NUMBER && matches!(vm.number(code), 302.0 | 307.0) {
                let headers = vm.field(http, c"headers");
                vm.bytes(b"header_low");
                vm.bytes(b"location");
                let index = vm.call_global(
                    c"array_field_search",
                    &[headers, headers + 1, headers + 2],
                    1,
                );
                if vm.truth(index) {
                    let host = vm.path(1, &[c"track", c"hostname"]);
                    let location = vm.field(vm.item(vm.field(http, c"headers"), index), c"value");
                    let trigger = vm.call_global(c"is_dpi_redirect", &[host, location], 1);
                    if vm.truth(vm.field(GLOBALS, c"b_debug")) {
                        let suffix: &[u8] = if vm.truth(trigger) {
                            b"'. looks like DPI redirect."
                        } else {
                            b"'. NOT a DPI redirect."
                        };
                        vm.log(
                            b"standard_failure_detector: http redirect ",
                            &[(code, b" to '"), (location, suffix)],
                        );
                    }
                    return trigger;
                }
            }
        }
    }
    vm.boolean(false);
    vm.top()
}

unsafe extern "C-unwind" fn standard_failure_detector(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 62) };
    vm.pad_arguments(2);
    let args = vm.call_global(c"standard_detector_defaults", &[vm.field(1, c"arg")], 1);
    if vm.truth(vm.path(1, &[c"dis", c"tcp"])) {
        let seq = position(vm, b"s", None);
        if vm.truth(vm.field(1, c"outgoing")) {
            vm.boolean(tcp_retransmission(vm, args, seq));
        } else if let Some(trigger) = incoming_reset(vm, args, seq) {
            vm.boolean(trigger);
        } else {
            let trigger = http_redirect(vm, args);
            vm.push(trigger);
        }
        return 1;
    }
    let mut trigger = false;
    if vm.truth(vm.path(1, &[c"dis", c"udp"])) && vm.truth(vm.field(1, c"outgoing")) {
        let out_limit = vm.field(args, c"udp_out");
        if positive(vm, out_limit) {
            let sent = position(vm, b"n", Some(false));
            let received = position(vm, b"n", Some(true));
            let in_limit = vm.field(args, c"udp_in");
            trigger = vm.less_equal(out_limit, sent) && vm.less_equal(received, in_limit);
            if trigger && vm.truth(vm.field(GLOBALS, c"b_debug")) {
                vm.log(
                    b"standard_failure_detector: arg.udp_out ",
                    &[
                        (sent, b">="),
                        (out_limit, b" arg.udp_in "),
                        (received, b"<="),
                        (in_limit, b""),
                    ],
                );
            }
        }
    }
    vm.boolean(trigger);
    1
}

unsafe extern "C-unwind" fn cond_true(lua: *mut LuaState) -> c_int {
    unsafe { Stack::enter(lua, 1) }.boolean(true);
    1
}

unsafe extern "C-unwind" fn cond_false(lua: *mut LuaState) -> c_int {
    unsafe { Stack::enter(lua, 1) }.boolean(false);
    1
}

unsafe extern "C-unwind" fn cond_random(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    vm.pad_arguments(1);
    vm.path(GLOBALS, &[c"math", c"random"]);
    vm.integer(0);
    vm.integer(99);
    vm.call(2, 1);
    let roll = vm.top();
    let percent = tonumber_default(vm, vm.path(1, &[c"arg", c"percent"]), 50);
    vm.boolean(vm.less(roll, percent));
    1
}

unsafe extern "C-unwind" fn cond_payload_str(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 14) };
    vm.pad_arguments(1);
    if !vm.truth(vm.path(1, &[c"arg", c"pattern"])) {
        return vm.error(c"cond_payload_str: missing 'pattern'");
    }
    let payload = vm.path(1, &[c"dis", c"payload"]);
    if vm.truth(payload) {
        vm.path(GLOBALS, &[c"string", c"find"]);
        vm.push(payload);
        let pattern = vm.path(1, &[c"arg", c"pattern"]);
        vm.replace(pattern - 1);
        vm.integer(1);
        vm.boolean(true);
        vm.call(4, 1);
    }
    1
}

unsafe extern "C-unwind" fn cond_tcp_has_ts(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 12) };
    let tcp = vm.path(1, &[c"dis", c"tcp"]);
    if vm.truth(tcp) {
        let options = vm.field(tcp, c"options");
        let ts = vm.field(GLOBALS, c"TCP_KIND_TS");
        vm.call_global(c"find_tcp_option", &[options, ts], 1);
    }
    1
}
