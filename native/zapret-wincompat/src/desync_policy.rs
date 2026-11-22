//! Resource-free final packet/Lua stages. VM operations execute in C between steps.
use crate::{logging::LogSink, packet::Packet, protocol::l7payload_str};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum DesyncAction {
    Direction = 1,
    Cutoff,
    StackEnter,
    Functions,
    Context,
    Prepare,
    Preflight,
    AllCutoff,
    Filtered,
    Arguments,
    Reference,
    Invoke,
    Modify,
    Reconstruct,
    PopInvalid,
    InvalidDissect,
    Error,
    PopReconstructed,
    Reconstructed,
    ReconstructionFailed,
    NoFunctions,
    Unreference,
    StackLeave,
    Done,
    Invalid,
}

#[repr(C)]
struct DesyncFlow {
    phase: u32,
    verdict: u8,
    preserve: bool,
}
#[repr(C)]
struct DesyncFeedback {
    verdict: u8,
    ok: bool,
    functions: bool,
    gate: u32,
    kind: u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_desync_step(flow: &mut DesyncFlow, value: &DesyncFeedback) -> u32 {
    use DesyncAction::*;
    let next = match flow.phase {
        0 => Direction,
        1 => {
            if value.ok {
                StackEnter
            } else {
                Cutoff
            }
        }
        2 => Done,
        3 => Functions,
        4 => {
            if value.functions {
                Context
            } else {
                NoFunctions
            }
        }
        5 => Prepare,
        6 => {
            if value.ok {
                Preflight
            } else {
                Error
            }
        }
        7 => match value.gate {
            0 => AllCutoff,
            1 => Filtered,
            _ => Arguments,
        },
        8 | 9 | 21 => Unreference,
        10 => Reference,
        11 => Invoke,
        12 => {
            if !value.ok {
                Error
            } else {
                flow.verdict = value.verdict;
                flow.preserve = value.verdict & 4 != 0;
                if value.verdict & 3 == 1 {
                    Modify
                } else {
                    Unreference
                }
            }
        }
        13 => {
            if value.kind == 5 {
                Reconstruct
            } else {
                PopInvalid
            }
        }
        14 => PopReconstructed,
        15 => InvalidDissect,
        16 => Error,
        17 => {
            flow.verdict = 0;
            Unreference
        }
        18 => {
            if value.ok {
                Reconstructed
            } else {
                ReconstructionFailed
            }
        }
        19 => {
            flow.verdict |= 8;
            Unreference
        }
        20 => {
            flow.verdict = 0;
            Unreference
        }
        22 => StackLeave,
        23 | 24 => Done,
        _ => Invalid,
    };
    flow.phase = next as u32;
    next as u32
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_desync_report(
    flow: &DesyncFlow,
    incoming: bool,
    payload: u32,
    packet: *const Packet,
    modified_length: *const usize,
    debug: LogSink,
    error: LogSink,
) {
    use DesyncAction::*;
    let direction = if incoming { c"in" } else { c"out" };
    unsafe {
        match flow.phase {
            phase if phase == Cutoff as u32 => {
                let format = if incoming {
                    c"lua in cutoff\n"
                } else {
                    c"lua out cutoff\n"
                };
                debug(format.as_ptr())
            }
            phase if phase == AllCutoff as u32 => debug(
                c"all %s desync functions reached cutoff condition\n".as_ptr(),
                direction.as_ptr(),
            ),
            phase if phase == Filtered as u32 => debug(
                c"all %s desync functions do not want `%s` payload\n".as_ptr(),
                direction.as_ptr(),
                l7payload_str(payload),
            ),
            phase if phase == InvalidDissect as u32 => {
                error(c"dissect data is bad. VERDICT_MODIFY cancel.\n".as_ptr())
            }
            phase if phase == Error as u32 => {
                error(c"desync ERROR. passing packet unmodified.\n".as_ptr())
            }
            phase if phase == Reconstructed as u32 => debug(
                c"reconstructed packet due to VERDICT_MODIFY. size %zu => %zu\n".as_ptr(),
                (*packet).length,
                *modified_length,
            ),
            phase if phase == ReconstructionFailed as u32 => {
                error(c"failed to reconstruct packet after VERDICT_MODIFY\n".as_ptr())
            }
            phase if phase == NoFunctions as u32 => {
                debug(c"no lua functions in this profile\n".as_ptr())
            }
            _ => error(c"invalid final desync policy\n".as_ptr()),
        };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum FinishAction {
    Rediscover = 1,
    Desync,
    Cancel,
    Observe,
    Postnat,
    Done,
    Invalid,
    Tcp,
}
#[repr(C)]
struct FinishFlow {
    phase: u32,
    verdict: u8,
}
#[repr(C)]
struct FinishFeedback {
    verdict: u8,
    found: bool,
    tcp: bool,
    incoming: bool,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_play_finish_step(flow: &mut FinishFlow, value: &FinishFeedback) -> u32 {
    use FinishAction::*;
    let next = match flow.phase {
        0 => Rediscover,
        1 => {
            if value.found {
                Desync
            } else {
                Tcp
            }
        }
        2 | 3 => Observe,
        4 => {
            flow.verdict = value.verdict;
            if !value.incoming && value.verdict & 3 == 2 {
                Postnat
            } else {
                Done
            }
        }
        5 => {
            flow.verdict = value.verdict;
            Done
        }
        6 => Done,
        8 => {
            if value.tcp {
                Cancel
            } else {
                Observe
            }
        }
        _ => Invalid,
    };
    flow.phase = next as u32;
    next as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modification_requires_reconstruction_before_nocsum_and_cleanup() {
        let mut flow = DesyncFlow {
            phase: 0,
            verdict: 0,
            preserve: false,
        };
        let value = DesyncFeedback {
            verdict: 5,
            ok: true,
            functions: true,
            gate: 2,
            kind: 5,
        };
        let expected = [
            DesyncAction::Direction,
            DesyncAction::StackEnter,
            DesyncAction::Functions,
            DesyncAction::Context,
            DesyncAction::Prepare,
            DesyncAction::Preflight,
            DesyncAction::Arguments,
            DesyncAction::Reference,
            DesyncAction::Invoke,
            DesyncAction::Modify,
            DesyncAction::Reconstruct,
            DesyncAction::PopReconstructed,
            DesyncAction::Reconstructed,
            DesyncAction::Unreference,
            DesyncAction::StackLeave,
            DesyncAction::Done,
        ];
        for action in expected {
            assert_eq!(
                unsafe { zapret_desync_step(&mut flow, &value) },
                action as u32
            );
            if action == DesyncAction::Reconstruct {
                assert!(flow.preserve);
                assert_eq!(flow.verdict, 5);
            }
        }
        assert_eq!(flow.verdict, 13);
    }
    #[test]
    fn failed_profile_discovery_cancels_tcp_before_sampling_final_verdict() {
        let mut flow = FinishFlow {
            phase: 0,
            verdict: 0,
        };
        let mut value = FinishFeedback {
            verdict: 2,
            found: false,
            tcp: true,
            incoming: false,
        };
        for action in [
            FinishAction::Rediscover,
            FinishAction::Tcp,
            FinishAction::Cancel,
            FinishAction::Observe,
            FinishAction::Postnat,
        ] {
            assert_eq!(
                unsafe { zapret_play_finish_step(&mut flow, &value) },
                action as u32
            );
        }
        value.verdict = 9;
        assert_eq!(
            unsafe { zapret_play_finish_step(&mut flow, &value) },
            FinishAction::Done as u32
        );
        assert_eq!(flow.verdict, 9);
    }
    fn next(flow: &mut DesyncFlow, value: &DesyncFeedback) -> u32 {
        unsafe { zapret_desync_step(flow, value) }
    }
    #[test]
    fn cutoff_has_no_registry_cleanup_but_skipped_profiles_do() {
        let mut flow = DesyncFlow {
            phase: 0,
            verdict: 0,
            preserve: false,
        };
        let mut value = DesyncFeedback {
            verdict: 0,
            ok: false,
            functions: false,
            gate: 0,
            kind: 0,
        };
        assert_eq!(next(&mut flow, &value), 1);
        assert_eq!(next(&mut flow, &value), 2);
        assert_eq!(next(&mut flow, &value), 24);
        flow.phase = 0;
        value.ok = true;
        let mut trace = Vec::new();
        loop {
            let a = next(&mut flow, &value);
            trace.push(a);
            if a == 24 {
                break;
            }
        }
        assert_eq!(trace, [1, 3, 4, 21, 22, 23, 24]);
    }
    #[test]
    fn invalid_modify_and_failed_reconstruction_keep_distinct_error_paths() {
        let mut flow = DesyncFlow {
            phase: 13,
            verdict: 5,
            preserve: true,
        };
        let value = DesyncFeedback {
            verdict: 5,
            ok: false,
            functions: true,
            gate: 2,
            kind: 0,
        };
        let mut trace = Vec::new();
        loop {
            let a = next(&mut flow, &value);
            trace.push(a);
            if a == 24 {
                break;
            }
        }
        assert_eq!(trace, [15, 16, 17, 22, 23, 24]);
        assert_eq!(flow.verdict, 0);
        flow.phase = 14;
        flow.verdict = 5;
        let mut trace = Vec::new();
        loop {
            let a = next(&mut flow, &value);
            trace.push(a);
            if a == 24 {
                break;
            }
        }
        assert_eq!(trace, [18, 20, 22, 23, 24]);
        assert_eq!(flow.verdict, 0);
    }
    #[test]
    fn only_outgoing_drop_requests_postnat_and_observes_the_late_verdict() {
        for (incoming, verdict, expected) in [(true, 2, 6), (false, 1, 6), (false, 6, 5)] {
            let mut flow = FinishFlow {
                phase: 4,
                verdict: 0,
            };
            let value = FinishFeedback {
                verdict,
                found: false,
                tcp: false,
                incoming,
            };
            assert_eq!(
                unsafe { zapret_play_finish_step(&mut flow, &value) },
                expected
            );
            assert_eq!(flow.verdict, verdict);
        }
    }
}
