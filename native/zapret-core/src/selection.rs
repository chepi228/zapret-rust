use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeState {
    Ok,
    Fail,
    Freeze,
    Na,
}
pub fn transfer_state(
    code: &str,
    exit: Option<i32>,
    up: f64,
    down: f64,
    post: bool,
    target_reached: bool,
) -> ProbeState {
    let Some(exit) = exit else {
        return ProbeState::Fail;
    };
    if exit == 6 {
        return ProbeState::Na;
    }
    let valid_code = code.len() == 3
        && code.as_bytes()[0].is_ascii_digit()
        && code.as_bytes()[0] != b'0'
        && code.bytes().all(|b| b.is_ascii_digit());
    if valid_code && (exit == 0 || (target_reached && [0, 23, 28].contains(&exit))) {
        return ProbeState::Ok;
    }
    if exit == 28 && (down > 0. || (post && up > 0.)) {
        return ProbeState::Freeze;
    }
    ProbeState::Fail
}
