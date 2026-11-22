//! The HTTP transformations available to custom Lua profiles.
use super::*;

fn begin(rule: &Rule) -> bool {
    if rule.type_or_cutoff(c"tcp").is_none() {
        return false;
    }
    rule.0.cutoff_opposite();
    rule.l7(b"http_req") && rule.direction_default()
}

fn set_payload(vm: Stack, payload: c_int) {
    let dis = vm.field(2, c"dis");
    vm.assign(dis, c"payload", payload);
}

fn field_offset(vm: Stack, header: c_int, field: &CStr) -> f64 {
    vm.arithmetic_number(vm.field(header, field))
}

fn dissect(rule: &Rule) -> Option<c_int> {
    let vm = rule.vm();
    let http = vm.call_global(c"http_dissect_req", &[rule.payload()], 1);
    vm.truth(http).then_some(http)
}

fn find_header(vm: Stack, http: c_int, header: &[u8]) -> Option<c_int> {
    let headers = vm.field(http, c"headers");
    vm.bytes(b"header_low");
    vm.bytes(header);
    let index = vm.call_global(
        c"array_field_search",
        &[headers, headers + 1, headers + 2],
        1,
    );
    vm.truth(index).then(|| vm.item(headers, index))
}

pub(super) unsafe extern "C-unwind" fn domcase(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 52) };
    let rule = Rule::new(vm, b"http_domcase");
    if !begin(&rule) {
        return 0;
    }
    let payload = rule.payload();
    vm.bytes(b"host,endhost");
    let positions = rule.0.resolve(c"resolve_multi_pos", payload, vm.top());
    if vm.length(positions) != 2 {
        vm.log(b"http_domcase: cannot find host range", &[]);
        return 0;
    }
    let first = vm.arithmetic_number(vm.array_item(positions, 1));
    let end = vm.arithmetic_number(vm.array_item(positions, 2));
    let host = vm.substring(rule.payload(), first, Some(end - 1.0));
    let chunks = vm.table(0);
    for i in 1..=vm.length(host) {
        let byte = vm.substring(host, i as f64, Some(i as f64));
        vm.path(
            GLOBALS,
            &[c"string", if i % 2 == 0 { c"lower" } else { c"upper" }],
        );
        vm.push(byte);
        vm.call(1, 1);
        vm.raw_array_put(chunks, i as c_int, vm.top());
        vm.reset(chunks);
    }
    let modified = vm.table_operation(c"concat", &[chunks], 1);
    vm.log(b"http_domcase: ", &[(host, b" => "), (modified, b"")]);
    let payload = rule.payload();
    vm.substring(payload, 1.0, Some(first - 1.0));
    vm.push(modified);
    vm.substring(payload, end, None);
    vm.concat(3);
    set_payload(vm, vm.top());
    rule.verdict(c"VERDICT_MODIFY")
}

pub(super) unsafe extern "C-unwind" fn hostcase(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 55) };
    let rule = Rule::new(vm, b"http_hostcase");
    if !begin(&rule) {
        return 0;
    }
    let spelling = rule.0.arg(c"spell");
    if !vm.truth(spelling) {
        vm.bytes(b"host");
        vm.replace(spelling);
    }
    if vm.length(spelling) != 4 {
        vm.call_message(
            c"error",
            b"http_hostcase: invalid host spelling '",
            &[(spelling, b"'")],
        );
        return 0;
    }
    let Some(http) = dissect(&rule) else {
        vm.log(b"http_hostcase: http dissect error", &[]);
        return 0;
    };
    let Some(host) = find_header(vm, http, b"host") else {
        vm.log(b"http_hostcase: 'Host:' header not found", &[]);
        return 0;
    };
    vm.log(b"http_hostcase: 'Host:' => '", &[(spelling, b"'")]);
    let start = field_offset(vm, host, c"pos_start");
    let end = field_offset(vm, host, c"pos_header_end");
    let payload = rule.payload();
    vm.substring(payload, 1.0, Some(start - 1.0));
    vm.push(spelling);
    vm.substring(payload, end + 1.0, None);
    vm.concat(3);
    set_payload(vm, vm.top());
    rule.verdict(c"VERDICT_MODIFY")
}

pub(super) unsafe extern "C-unwind" fn methodeol(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 50) };
    let rule = Rule::new(vm, b"http_methodeol");
    if !begin(&rule) {
        return 0;
    }
    let Some(http) = dissect(&rule) else {
        vm.log(b"http_methodeol: http dissect error", &[]);
        return 0;
    };
    let Some(agent) = find_header(vm, http, b"user-agent") else {
        vm.log(b"http_methodeol: 'User-Agent:' header not found", &[]);
        return 0;
    };
    let end = field_offset(vm, agent, c"pos_end");
    if end - field_offset(vm, agent, c"pos_value_start") < 2.0 {
        vm.log(b"http_methodeol: 'User-Agent:' header is too short", &[]);
        return 0;
    }
    vm.log(b"http_methodeol: applied", &[]);
    let payload = rule.payload();
    vm.bytes(b"\r\n");
    vm.substring(payload, 1.0, Some(end - 2.0));
    let suffix = vm.substring(payload, end + 1.0, None);
    if !vm.truth(suffix) {
        vm.bytes(b"");
        vm.replace(suffix);
    }
    vm.concat(3);
    set_payload(vm, vm.top());
    rule.verdict(c"VERDICT_MODIFY")
}

pub(super) unsafe extern "C-unwind" fn unixeol(lua: *mut LuaState) -> c_int {
    let vm = unsafe { Stack::enter(lua, 63) };
    let rule = Rule::new(vm, b"http_unixeol");
    if !begin(&rule) {
        return 0;
    }
    let Some(http) = dissect(&rule) else {
        vm.log(b"http_unixeol: could not dissect http", &[]);
        return 0;
    };
    let Some(agent) = find_header(vm, http, b"user-agent") else {
        vm.log(b"http_unixeol: 'User-Agent:' header absent", &[]);
        return 0;
    };
    vm.boolean(true);
    let unix = vm.top();
    let original = vm.call_global(c"http_reconstruct_req", &[http, unix], 1);
    let previous = vm.length(rule.payload());
    let rebuilt = vm.length(original);
    if rebuilt < previous {
        let value = vm.field(agent, c"value");
        vm.path(GLOBALS, &[c"string", c"rep"]);
        vm.bytes(b" ");
        vm.integer((previous - rebuilt) as isize);
        vm.call(2, 1);
        vm.replace(value + 1);
        vm.concat(2);
        vm.set(agent, c"value");
    }
    let result = vm.call_global(c"http_reconstruct_req", &[http, unix], 1);
    let size = vm.length(result);
    let previous = vm.length(rule.payload());
    if size == previous {
        set_payload(vm, result);
        vm.log(b"http_unixeol: applied", &[]);
        return rule.verdict(c"VERDICT_MODIFY");
    }
    vm.integer(size as isize);
    vm.integer(previous as isize);
    vm.log(
        b"http_unixeol: reconstruct differs in size from original: ",
        &[(vm.top() - 1, b"!="), (vm.top(), b"")],
    );
    0
}
