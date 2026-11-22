//! Preserve late rule observations and protected LuaJIT return processing.
use super::*;

#[repr(C)]
pub(super) struct Rule {
    function: *const c_char,
    before_args: [MaybeUninit<u8>; 48],
    args: *const c_void,
}

#[derive(Default)]
#[repr(C)]
pub(super) struct Direction {
    pub(super) positions: *const c_void,
    pub(super) current: *const c_void,
    pub(super) opposite: *const c_void,
    cutoff: *mut bool,
}

#[repr(C)]
struct Cursor {
    next: *mut Rule,
    position: *const c_void,
    number: u32,
    payload: u32,
    incoming: bool,
    all_cutoff: bool,
    wanted: bool,
}

#[repr(C)]
struct Step {
    rule: *const Rule,
    range: *const c_void,
    number: u32,
    accepts_payload: bool,
    in_range: bool,
    cutoff: bool,
}

#[derive(Default)]
#[repr(C)]
struct Flow {
    phase: u32,
    verdict: u8,
}

#[derive(Default)]
#[repr(C)]
struct Feedback {
    verdict: u8,
    available: bool,
    cutoff: bool,
    in_range: bool,
    payload: bool,
    function: bool,
    args: bool,
    call: bool,
    result: bool,
    cancelled: bool,
}

const _: () = {
    assert!(offset_of!(Rule, args) == 56);
    assert!(size_of::<Cursor>() == 32 && size_of::<Step>() == 24);
    assert!(size_of::<Direction>() == 32);
    assert!(size_of::<Flow>() == 8 && size_of::<Feedback>() == 10);
};

unsafe extern "C" {
    pub(super) fn zapret_lua_rule_direction(
        track: *mut c_void,
        positions: *const c_void,
        incoming: bool,
        server: bool,
        output: *mut Direction,
    ) -> bool;
    fn zapret_lua_context_rule(
        ctx: *mut Context,
        function: *const c_char,
        number: u32,
        name: *mut c_char,
        capacity: usize,
    ) -> bool;
    fn zapret_lua_scan_next(cursor: &mut Cursor, step: *mut Step) -> bool;
    fn zapret_lua_scan_observe(cursor: &mut Cursor, step: &Step, voluntary: bool);
    fn zapret_lua_scan_result(cursor: &Cursor, direction: &Direction) -> u32;
    fn zapret_lua_rule_scan_report(
        cursor: &Cursor,
        step: &Step,
        ctx: *const Context,
        instance: *const c_char,
        voluntary: bool,
        log: Log,
    );
    fn zapret_lua_rule_range_report(
        cursor: &Cursor,
        step: &Step,
        instance: *const c_char,
        log: Log,
    );
    fn zapret_lua_rule_payload_report(
        cursor: &Cursor,
        step: &Step,
        instance: *const c_char,
        log: Log,
    );
    fn zapret_lua_report_missing_function(name: *const c_char, log: Log);
    fn zapret_lua_invoke_next(cursor: &mut Cursor, step: *mut Step, skip: bool) -> bool;
    fn zapret_lua_context_active(ctx: *mut Context, active: bool) -> bool;
    fn zapret_lua_context_cancelled(ctx: *const Context) -> bool;
    fn zapret_lua_invocation_step(flow: &mut Flow, feedback: &Feedback) -> u32;
    fn zapret_lua_invocation_result(count: c_int, kind: u32, number: i64, verdict: *mut u8) -> u32;
    fn zapret_lua_invocation_error_report(error: u32, count: c_int, log: Log);
}

unsafe extern "C-unwind" {
    fn lua_instance_cutoff_check(lua: Lua, ctx: *const Context, incoming: bool) -> bool;
    fn lua_pcall(lua: Lua, arguments: c_int, results: c_int, message: c_int) -> c_int;
    fn lua_isnumber(lua: Lua, index: c_int) -> c_int;
    fn lua_tointeger(lua: Lua, index: c_int) -> i64;
    fn lua_pushf_args(lua: Lua, args: *const c_void, desync: c_int, prefix: bool) -> bool;
    fn lua_dlog_error();
}

unsafe fn cursor(
    profile: *const Profile,
    position: *const c_void,
    incoming: bool,
    payload: u32,
) -> Cursor {
    Cursor {
        next: unsafe { (*profile).rules },
        position,
        number: 0,
        payload,
        incoming,
        all_cutoff: true,
        wanted: false,
    }
}

unsafe fn name(ctx: *mut Context, step: &Step, instance: *mut c_char, capacity: usize) {
    unsafe { zapret_lua_context_rule(ctx, (*step.rule).function, step.number, instance, capacity) };
}

pub(super) unsafe fn preflight(
    ctx: *mut Context,
    direction: &Direction,
    payload: u32,
    incoming: bool,
    instance: *mut c_char,
    capacity: usize,
) -> u32 {
    unsafe {
        let mut next = cursor((*ctx).profile, direction.current, incoming, payload);
        let mut step = MaybeUninit::<Step>::uninit();
        while zapret_lua_scan_next(&mut next, step.as_mut_ptr()) {
            let step = step.assume_init_ref();
            if !(*ctx).track.is_null() || params.debug {
                name(ctx, step, instance, capacity);
            }
            let voluntary =
                !(*ctx).track.is_null() && lua_instance_cutoff_check(vm(), ctx, incoming);
            if params.debug {
                zapret_lua_rule_scan_report(&next, step, ctx, instance, voluntary, DLOG);
            }
            zapret_lua_scan_observe(&mut next, step, voluntary);
        }
        zapret_lua_scan_result(&next, direction)
    }
}

unsafe fn result(verdict: *mut u8) -> bool {
    unsafe {
        let count = lua_gettop(vm());
        let mut kind = 0;
        let mut number = 0;
        if count == 1 && lua_type(vm(), -1) != NIL {
            if lua_isnumber(vm(), -1) != 0 {
                kind = 1;
                number = lua_tointeger(vm(), -1);
            } else {
                kind = 2;
            }
        }
        let error = zapret_lua_invocation_result(count, kind, number, verdict);
        if error != 0 {
            zapret_lua_invocation_error_report(error, count, DLOG_ERR);
        }
        pop(vm(), count);
        error == 0
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn invoke(
    profile: *mut Profile,
    position: *const c_void,
    incoming: bool,
    payload: u32,
    track: *mut c_void,
    ctx: *mut Context,
    reference: c_int,
    instance: *mut c_char,
    capacity: usize,
    verdict: *mut u8,
) -> bool {
    unsafe {
        let mut cursor = cursor(profile, position, incoming, payload);
        let mut step = MaybeUninit::<Step>::uninit();
        let mut func = ptr::null::<Rule>();
        let mut flow = Flow {
            verdict: verdict.read(),
            ..Flow::default()
        };
        let mut feedback = Feedback::default();
        loop {
            match zapret_lua_invocation_step(&mut flow, &feedback) {
                1 => {
                    feedback.available = zapret_lua_invoke_next(
                        &mut cursor,
                        step.as_mut_ptr(),
                        track.is_null() && !params.debug,
                    );
                    if feedback.available {
                        feedback.in_range = step.assume_init_ref().in_range;
                        feedback.payload = step.assume_init_ref().accepts_payload;
                    }
                }
                2 => {
                    let step = step.assume_init_ref();
                    func = step.rule;
                    name(ctx, step, instance, capacity);
                }
                3 => feedback.cutoff = lua_instance_cutoff_check(vm(), ctx, incoming),
                4 => zapret_lua_rule_range_report(&cursor, step.assume_init_ref(), instance, DLOG),
                5 => {
                    zapret_lua_rule_payload_report(&cursor, step.assume_init_ref(), instance, DLOG)
                }
                6 => {
                    lua_getfield(vm(), GLOBALS, (*func).function);
                    feedback.function = lua_type(vm(), -1) == FUNCTION;
                    if !feedback.function {
                        pop(vm(), 1);
                        zapret_lua_report_missing_function((*func).function, DLOG_ERR);
                    }
                }
                7 => {
                    lua_rawgeti(vm(), REGISTRY, params.context_ref);
                    lua_rawgeti(vm(), REGISTRY, reference);
                    feedback.args =
                        lua_pushf_args(vm(), (&raw const (*func).args).cast(), -1, true);
                    if !feedback.args {
                        pop(vm(), 3);
                    }
                }
                8 => {
                    lua_pushf_str(vm(), c"func".as_ptr(), (*func).function);
                    lua_pushf_int(vm(), c"func_n".as_ptr(), i64::from((*ctx).index));
                    lua_pushf_str(vm(), c"func_instance".as_ptr(), instance);
                }
                9 => {
                    zapret_lua_context_active(ctx, true);
                    feedback.call = lua_pcall(vm(), 2, MULTRET, 0) == 0;
                    zapret_lua_context_active(ctx, false);
                }
                10 => lua_dlog_error(),
                11 => feedback.result = result(&mut feedback.verdict),
                12 => feedback.cancelled = zapret_lua_context_cancelled(ctx),
                13 => {
                    verdict.write(flow.verdict);
                    return true;
                }
                14 => return false,
                _ => {
                    DLOG_ERR(c"invalid Lua invocation state\n".as_ptr());
                    return false;
                }
            }
        }
    }
}
