//! Main argument traversal, option routing and resource-free startup phases.
use crate::{
    cli::{CursorOutput, OptionSpec, zapret_cli_next},
    cli_control::{DEFAULT_INCOMING, DEFAULT_OUTGOING},
    engine_prefix::{zapret_engine_blob_limits, zapret_engine_parse_failure},
    logging::LogSink,
    native_cli_catalog::{zapret_native_cli_kind, zapret_native_cli_skip_numeric},
    packet_policy::Range,
    profile_config::zapret_profile_report_status,
};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};
type RouteCallback = unsafe extern "C" fn(*mut c_void, u32) -> i32;
fn valid<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}

#[repr(C)]
struct MainOptions {
    anonymous: [*mut c_void; 4],
    payload: u64,
    incoming: Range,
    outgoing: Range,
    index: u32,
    sub_index: u32,
    dry: bool,
    duplicate: bool,
    ipv4: bool,
    ipv6: bool,
    lan: bool,
    loopback: bool,
    empty: bool,
    save: [c_char; 256],
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_main_defaults(output: *mut MainOptions) {
    unsafe {
        output.write(MainOptions {
            anonymous: [ptr::null_mut(); 4],
            payload: 0,
            incoming: DEFAULT_INCOMING,
            outgoing: DEFAULT_OUTGOING,
            index: 0,
            sub_index: 0,
            dry: false,
            duplicate: true,
            ipv4: true,
            ipv6: true,
            lan: true,
            loopback: true,
            empty: false,
            save: [0; 256],
        })
    };
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum RouteAction {
    Residual,
    Handled,
    ExitSuccess,
    ExitError,
    NumericError,
    ControlError,
    Invalid,
    ParseDone,
    ParseHelp,
    LoadBlob,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route {
    action: u32,
    status: u32,
}

impl Route {
    fn without_status(action: RouteAction) -> Self {
        Self {
            action: action as u32,
            status: 0,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_option_route(
    context: *mut c_void,
    skip_numeric: bool,
    callback: Option<RouteCallback>,
) -> Route {
    let Some(callback) = callback else {
        return Route {
            action: RouteAction::Invalid as u32,
            status: 0,
        };
    };
    if context.is_null() {
        return Route {
            action: RouteAction::Invalid as u32,
            status: 0,
        };
    }
    for category in u32::from(skip_numeric)..6 {
        // These callbacks perform option parsing/file work and never enter Lua.
        // The context is opaque C storage, read anew by each category adapter.
        let result = unsafe { callback(context, category) };
        if result < 0 {
            let (action, status) = match category {
                0 => (RouteAction::NumericError, 0),
                5 => (RouteAction::ControlError, (-i64::from(result) - 1) as u32),
                _ => (RouteAction::ExitError, 0),
            };
            return Route {
                action: action as u32,
                status,
            };
        }
        if result > 0 {
            return Route {
                action: if category >= 4 && result == 2 {
                    RouteAction::ExitSuccess
                } else {
                    RouteAction::Handled
                } as u32,
                status: 0,
            };
        }
    }
    Route {
        action: RouteAction::Residual as u32,
        status: 0,
    }
}

#[repr(C)]
struct ScanOps {
    options: *const OptionSpec,
    option_count: usize,
    context: *mut c_void,
    category: RouteCallback,
    output: CursorOutput,
    dry: *const bool,
}

#[repr(C)]
struct ScanCursor {
    next: usize,
    stop_at_operand: bool,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_scan_begin(
    environment: unsafe extern "C" fn(*const c_char) -> *const c_char,
) -> ScanCursor {
    ScanCursor {
        next: 1,
        stop_at_operand: !unsafe { environment(c"POSIXLY_CORRECT".as_ptr()) }.is_null(),
    }
}

#[repr(C)]
struct ScanEvent {
    route: Route,
    blob_maximum: usize,
    blob_reserve: usize,
}

impl From<Route> for ScanEvent {
    fn from(route: Route) -> Self {
        Self {
            route,
            blob_maximum: 0,
            blob_reserve: 0,
        }
    }
}

// Only option parsers and diagnostic sinks run while scanning. The caller
// executes the outstanding blob load, exit or cleanup after Rust returns.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_scan_arguments(
    argc: c_int,
    argv: *const *mut c_char,
    cursor: &mut ScanCursor,
    ops: &ScanOps,
) -> ScanEvent {
    loop {
        let next = unsafe {
            zapret_cli_next(
                argc,
                argv,
                ops.options,
                ops.option_count,
                &mut cursor.next,
                cursor.stop_at_operand,
                &ops.output,
            )
        };
        if next == -1 {
            return Route::without_status(RouteAction::ParseDone).into();
        }
        if next != 0 {
            // Reporting the syntax error happens before observing the current dry-run flag.
            let dry = unsafe { ops.dry.read() };
            let action = if zapret_engine_parse_failure(dry) == 1 {
                RouteAction::ExitError
            } else {
                RouteAction::ParseHelp
            };
            return Route::without_status(action).into();
        }
        let index = unsafe { ops.output.index.read() };
        let route = unsafe {
            zapret_engine_option_route(
                ops.context,
                zapret_native_cli_skip_numeric(index),
                Some(ops.category),
            )
        };
        if route.action == RouteAction::Handled as u32 {
            continue;
        }
        if route.action != RouteAction::Residual as u32 {
            return route.into();
        }
        let blob = zapret_engine_blob_limits(index);
        if blob.maximum != 0 {
            return ScanEvent {
                route: Route::without_status(RouteAction::LoadBlob),
                blob_maximum: blob.maximum,
                blob_reserve: blob.reserve,
            };
        }
    }
}

#[repr(u32)]
enum DiagnosticField {
    OptionName = 1,
    ProfileName,
    Argument,
}

unsafe fn report_route(
    route: Route,
    index: i32,
    context: *const c_void,
    observe: unsafe extern "C" fn(*const c_void, u32) -> *const c_char,
    error: LogSink,
) {
    unsafe {
        if route.action == RouteAction::NumericError as u32 {
            let name = observe(context, DiagnosticField::OptionName as u32);
            error(c"invalid numeric value for --%s\n".as_ptr(), name);
        } else if route.action == RouteAction::ControlError as u32 {
            if route.status == 6 {
                error(c"invalid CLI control storage\n".as_ptr());
            } else {
                let field = if zapret_native_cli_kind(index, 5) == 0 {
                    DiagnosticField::ProfileName
                } else {
                    DiagnosticField::Argument
                };
                let name = observe(context, field as u32);
                zapret_profile_report_status(route.status, name, error);
            }
        } else {
            error(c"invalid main CLI routing state\n".as_ptr());
        }
    }
}

#[repr(C)]
struct RouteEffect {
    exit_code: c_int,
    terminate: bool,
    handled: bool,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_route_effect(
    route: Route,
    index: i32,
    context: *const c_void,
    observe: unsafe extern "C" fn(*const c_void, u32) -> *const c_char,
    error: LogSink,
) -> RouteEffect {
    let action = route.action;
    if action == RouteAction::Residual as u32 || action == RouteAction::Handled as u32 {
        return RouteEffect {
            exit_code: 0,
            terminate: false,
            handled: action == RouteAction::Handled as u32,
        };
    }
    if action != RouteAction::ExitSuccess as u32 && action != RouteAction::ExitError as u32 {
        unsafe { report_route(route, index, context, observe, error) };
    }
    RouteEffect {
        exit_code: i32::from(action != RouteAction::ExitSuccess as u32),
        terminate: true,
        handled: true,
    }
}

#[repr(C)]
struct Finish {
    phase: u32,
    result: i32,
}
#[repr(C)]
struct Feedback {
    status: u32,
    result: i32,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<MainOptions>() == 352);
    assert!(std::mem::offset_of!(MainOptions, incoming) == 40);
    assert!(std::mem::offset_of!(MainOptions, save) == 95);
    assert!(size_of::<ScanCursor>() == 16);
    assert!(size_of::<RouteEffect>() == 8);
};

#[repr(u32)]
#[derive(Clone, Copy)]
enum Phase {
    Profile = 1,
    Arguments,
    Validate,
    Capture,
    Lifecycle,
    Run,
    Cleanup,
    Mutex,
    Stdio,
    Return,
    ExitSuccess,
    ExitError,
    ProfileError,
    Invalid,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_engine_finish_step(
    flow: *mut Finish,
    feedback: *const Feedback,
) -> u32 {
    if !valid(flow) || !valid(feedback) {
        return Phase::Invalid as u32;
    }
    // Each borrow ends before C executes the selected operation, including VM
    // initialization, finalizers and process-exit cleanup.
    let flow = unsafe { &mut *flow };
    let feedback = unsafe { &*feedback };
    let next = match flow.phase {
        0 => Phase::Profile,
        1 => {
            if feedback.status == 0 {
                Phase::Arguments
            } else {
                Phase::ProfileError
            }
        }
        2 | 13 => {
            if flow.phase == 2 {
                Phase::Validate
            } else {
                Phase::Arguments
            }
        }
        3 => {
            if feedback.status == 0 {
                Phase::Capture
            } else {
                Phase::ExitError
            }
        }
        4 | 5 => {
            if feedback.status == 8 {
                Phase::ExitSuccess
            } else if feedback.status != 0 {
                flow.result = 1;
                Phase::Cleanup
            } else if flow.phase == 4 {
                Phase::Lifecycle
            } else {
                Phase::Run
            }
        }
        6 => {
            flow.result = feedback.result;
            Phase::Cleanup
        }
        7 => Phase::Mutex,
        8 => Phase::Stdio,
        9 | 10 => Phase::Return,
        11 => Phase::ExitSuccess,
        12 => Phase::ExitError,
        _ => return Phase::Invalid as u32,
    };
    flow.phase = next as u32;
    next as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        trace: Vec<u32>,
        values: [i32; 6],
    }
    unsafe extern "C" fn route(context: *mut c_void, stage: u32) -> i32 {
        let fixture = unsafe { &mut *context.cast::<Fixture>() };
        fixture.trace.push(stage);
        fixture.values[stage as usize]
    }
    #[test]
    fn only_capture_and_control_treat_two_as_a_successful_process_exit() {
        for stage in 0..6 {
            let mut fixture = Fixture {
                trace: Vec::new(),
                values: [0; 6],
            };
            fixture.values[stage] = 2;
            let value = unsafe {
                zapret_engine_option_route(
                    (&mut fixture as *mut Fixture).cast(),
                    false,
                    Some(route),
                )
            };
            assert_eq!(
                value,
                Route {
                    action: if stage >= 4 { 2 } else { 1 },
                    status: 0
                }
            );
            assert_eq!(fixture.trace, (0..=stage as u32).collect::<Vec<_>>());
        }
    }
    #[test]
    fn negative_network_flags_skip_the_numeric_parser_and_control_errors_keep_their_status() {
        let mut fixture = Fixture {
            trace: Vec::new(),
            values: [-1, 0, 0, 0, 0, -7],
        };
        let value = unsafe {
            zapret_engine_option_route((&mut fixture as *mut Fixture).cast(), true, Some(route))
        };
        assert_eq!(fixture.trace, [1, 2, 3, 4, 5]);
        assert_eq!(
            value,
            Route {
                action: 5,
                status: 6
            }
        );
    }
    #[test]
    fn final_startup_retains_the_result_and_cleans_params_before_mutex_and_stdio() {
        let mut flow = Finish {
            phase: 0,
            result: 0,
        };
        let feedback = Feedback {
            status: 0,
            result: i32::MIN,
        };
        for expected in 1..=10 {
            assert_eq!(
                unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
                expected
            );
        }
        assert_eq!(flow.result, i32::MIN);
        assert_eq!(
            unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
            10
        );
    }
    #[test]
    fn filter_export_and_dry_run_exit_successfully_before_main_cleanup_phases() {
        for phase in [4, 5] {
            let mut flow = Finish { phase, result: 99 };
            let feedback = Feedback {
                status: 8,
                result: 0,
            };
            assert_eq!(
                unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
                11
            );
            assert_eq!(
                unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
                11
            );
        }
    }
    #[test]
    fn validation_exits_directly_but_capture_failures_select_the_owned_cleanup_path() {
        let feedback = Feedback {
            status: 1,
            result: 87,
        };
        let mut flow = Finish {
            phase: 3,
            result: 99,
        };
        assert_eq!(
            unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
            12
        );
        for phase in [4, 5] {
            flow = Finish { phase, result: 99 };
            assert_eq!(
                unsafe { zapret_engine_finish_step(&mut flow, &feedback) },
                7
            );
            assert_eq!(flow.result, 1);
        }
    }
    #[test]
    fn bad_storage_is_rejected_before_callbacks_or_state_changes() {
        let mut fixture = Fixture {
            trace: Vec::new(),
            values: [1; 6],
        };
        assert_eq!(
            unsafe {
                zapret_engine_option_route((&mut fixture as *mut Fixture).cast(), false, None)
            },
            Route {
                action: 6,
                status: 0
            }
        );
        assert!(fixture.trace.is_empty());
        assert_eq!(
            unsafe { zapret_engine_finish_step(std::ptr::null_mut(), std::ptr::null()) },
            14
        );
    }
}
