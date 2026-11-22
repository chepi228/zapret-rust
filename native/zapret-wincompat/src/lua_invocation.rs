//! Resource-free invocation policy between C-owned Lua operations.
use crate::{
    logging::LogSink, lua_context::aligned, lua_rules::zapret_lua_verdict,
    packet_policy::zapret_verdict_aggregate,
};

#[repr(u32)]
#[derive(Clone, Copy)]
enum Action {
    Next = 1,
    Instance,
    Cutoff,
    Range,
    Payload,
    Lookup,
    Arguments,
    Identity,
    Call,
    CallError,
    Result,
    Cancel,
    Done,
    Failed,
    Invalid,
}

#[repr(C)]
struct Flow {
    phase: u32,
    verdict: u8,
}

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

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_invocation_step(flow: *mut Flow, feedback: *const Feedback) -> u32 {
    if !aligned(flow) || !aligned(feedback) {
        return Action::Invalid as u32;
    }
    // The caller owns both plain C objects. No VM call occurs while borrowed.
    let flow = unsafe { &mut *flow };
    let feedback = unsafe { &*feedback };
    let next = match flow.phase {
        0 => Action::Next,
        1 => {
            if feedback.available {
                Action::Instance
            } else {
                Action::Done
            }
        }
        2 => Action::Cutoff,
        3 => {
            if feedback.cutoff {
                Action::Cancel
            } else {
                Action::Range
            }
        }
        4 => {
            if feedback.in_range {
                Action::Payload
            } else {
                Action::Cancel
            }
        }
        5 => {
            if feedback.payload {
                Action::Lookup
            } else {
                Action::Cancel
            }
        }
        6 => {
            if feedback.function {
                Action::Arguments
            } else {
                Action::Failed
            }
        }
        7 => {
            if feedback.args {
                Action::Identity
            } else {
                Action::Failed
            }
        }
        8 => Action::Call,
        9 => {
            if feedback.call {
                Action::Result
            } else {
                Action::CallError
            }
        }
        10 => Action::Failed,
        11 => {
            if !feedback.result {
                Action::Failed
            } else if zapret_lua_verdict(feedback.verdict as i64) < 0 {
                return Action::Invalid as u32;
            } else {
                flow.verdict = zapret_verdict_aggregate(flow.verdict, feedback.verdict);
                Action::Cancel
            }
        }
        12 => {
            if feedback.cancelled {
                Action::Done
            } else {
                Action::Next
            }
        }
        13 => Action::Done,
        14 => Action::Failed,
        _ => return Action::Invalid as u32,
    };
    flow.phase = next as u32;
    next as u32
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_invocation_result(
    count: i32,
    kind: u32,
    number: i64,
    output: *mut u8,
) -> u32 {
    if output.is_null() || count < 0 {
        return 4;
    }
    if count > 1 {
        return 1;
    }
    let verdict = if count == 0 || kind == 0 {
        0
    } else if kind == 2 {
        return 2;
    } else if kind == 1 {
        let value = zapret_lua_verdict(number);
        if value < 0 {
            return 3;
        }
        value as u8
    } else {
        return 4;
    };
    // C supplies one writable verdict byte, untouched on classification errors.
    unsafe { output.write(verdict) };
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_invocation_error_report(error: u32, count: i32, log: LogSink) {
    unsafe {
        match error {
            0 => return,
            1 => log(
                c"desync function returned more than one result : %d\n".as_ptr(),
                count,
            ),
            2 => log(c"desync function returned non-int result\n".as_ptr()),
            3 => log(c"desync function returned bad int result\n".as_ptr()),
            _ => log(c"invalid desync result state\n".as_ptr()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{mem::MaybeUninit, ptr};
    fn ready() -> Feedback {
        Feedback {
            available: true,
            in_range: true,
            payload: true,
            function: true,
            args: true,
            call: true,
            result: true,
            ..unsafe { MaybeUninit::zeroed().assume_init() }
        }
    }
    #[test]
    fn callback_result_is_aggregated_before_cancellation_and_errors_do_not_publish_it() {
        let mut flow = Flow {
            phase: 0,
            verdict: 0,
        };
        let mut feedback = ready();
        for expected in 1..=9 {
            assert_eq!(
                unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
                expected
            );
        }
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            11
        );
        feedback.verdict = 5;
        feedback.cancelled = true;
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            12
        );
        assert_eq!(flow.verdict, 5);
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            13
        );
        flow = Flow {
            phase: 9,
            verdict: 5,
        };
        feedback.call = false;
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            10
        );
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            14
        );
    }
    #[test]
    fn result_count_and_type_errors_keep_the_previous_verdict_untouched() {
        let mut verdict = 99;
        assert_eq!(
            unsafe { zapret_lua_invocation_result(2, 2, 7, &mut verdict) },
            1
        );
        assert_eq!(verdict, 99);
        assert_eq!(
            unsafe { zapret_lua_invocation_result(1, 2, 7, &mut verdict) },
            2
        );
        assert_eq!(verdict, 99);
        assert_eq!(
            unsafe { zapret_lua_invocation_result(1, 1, 8, &mut verdict) },
            3
        );
        assert_eq!(verdict, 99);
        assert_eq!(
            unsafe { zapret_lua_invocation_result(0, 2, 8, &mut verdict) },
            0
        );
        assert_eq!(verdict, 0);
        assert_eq!(
            unsafe { zapret_lua_invocation_result(1, 1, 7, &mut verdict) },
            0
        );
        assert_eq!(verdict, 7);
        assert_eq!(
            unsafe { zapret_lua_invocation_result(1, 1, 0, ptr::null_mut()) },
            4
        );
    }
    #[test]
    fn voluntary_cutoff_and_filters_skip_lookup_but_still_check_cancellation() {
        for (phase, feedback) in [
            (
                3,
                Feedback {
                    cutoff: true,
                    ..ready()
                },
            ),
            (
                4,
                Feedback {
                    in_range: false,
                    ..ready()
                },
            ),
            (
                5,
                Feedback {
                    payload: false,
                    ..ready()
                },
            ),
        ] {
            let mut flow = Flow { phase, verdict: 6 };
            assert_eq!(
                unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
                12
            );
            assert_eq!(flow.verdict, 6);
            assert_eq!(
                unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
                1
            );
        }
    }
    #[test]
    fn failure_after_a_previous_drop_is_terminal_and_does_not_consume_more_feedback() {
        let feedback = Feedback {
            args: false,
            ..ready()
        };
        let mut flow = Flow {
            phase: 7,
            verdict: 2,
        };
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            14
        );
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &ready()) },
            14
        );
        assert_eq!(flow.verdict, 2);
        flow.phase = 13;
        assert_eq!(
            unsafe { zapret_lua_invocation_step(&mut flow, &feedback) },
            13
        );
    }
}
