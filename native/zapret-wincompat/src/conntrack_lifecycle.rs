//! Conntrack lifecycle steps; potentially throwing VM operations stay in C.
#[repr(C)]
#[derive(Default)]
struct State {
    entry: u32,
    stage: u32,
    status: u32,
    reverse: u32,
    reset: u32,
    find_direction: u32,
    protocol: u32,
    queue_limit: u32,
    after_clear: u32,
    after_init: u32,
    after_new: u32,
    after_feed: u32,
    incoming: i32,
    tcp: u32,
    udp: u32,
    padding: u32,
    track: usize,
    element: usize,
    out_track: usize,
    out_reverse: usize,
    cursor: u64,
    now: i64,
    last: i64,
    interval: i64,
    result: usize,
}
const DONE: u32 = 9999;
fn emit(s: &mut State, next: u32, op: u32) -> u32 {
    s.stage = next;
    op
}
fn clear(s: &mut State, after: u32) -> u32 {
    s.after_clear = after;
    emit(s, 101, 1)
}
fn initialize(s: &mut State, after: u32) -> u32 {
    s.after_init = after;
    s.queue_limit = 64;
    emit(s, 201, 8)
}
fn new(s: &mut State, after: u32) -> u32 {
    s.after_new = after;
    emit(s, 301, 18)
}
fn feed(s: &mut State, after: u32) -> u32 {
    s.after_feed = after;
    emit(s, 401, 27)
}
fn step(s: &mut State) -> u32 {
    loop {
        match s.stage {
            0 => match s.entry {
                1 => return emit(s, 11, 1),
                2 => return clear(s, DONE),
                3 => return emit(s, 12, 21),
                4 => return initialize(s, DONE),
                5 => {
                    s.cursor = 0;
                    s.stage = 20;
                }
                6 => return emit(s, 31, 15),
                7 => return new(s, DONE),
                8 => return feed(s, DONE),
                9 => {
                    s.find_direction = 1;
                    s.reverse = 0;
                    return emit(s, 41, 24);
                }
                10 => {
                    s.find_direction = 1;
                    s.reverse = 0;
                    return emit(s, 51, 24);
                }
                11 => {
                    s.find_direction = 0;
                    s.reverse = 0;
                    return emit(s, 61, 24);
                }
                12 => return emit(s, 71, 16),
                _ => return 0,
            },
            11 => return emit(s, DONE, 2),
            12 => return clear(s, 13),
            13 => return emit(s, DONE, 7),
            20 => return emit(s, 21, 22),
            21 => {
                if s.element == 0 {
                    return 0;
                } else {
                    return emit(s, 22, 23);
                }
            }
            22 => return emit(s, 23, 21),
            23 => return clear(s, 24),
            24 => return emit(s, 20, 7),
            31 => return emit(s, 32, 16),
            32 => return emit(s, DONE, 17),
            41 => {
                if s.status == 0 {
                    return 0;
                } else {
                    return emit(s, 42, 25);
                }
            }
            42 => {
                if s.element == 0 {
                    return 0;
                } else {
                    return emit(s, 43, 21);
                }
            }
            43 => s.stage = 900,
            51 => {
                if s.status == 0 {
                    return 0;
                } else {
                    return emit(s, 52, 25);
                }
            }
            52 => {
                if s.element != 0 {
                    return emit(s, 56, 21);
                } else {
                    return emit(s, 53, 26);
                }
            }
            53 => {
                if s.status == 0 {
                    return 0;
                }
                s.incoming = i32::from(s.status == 2);
                s.reverse = u32::from(s.incoming != 0);
                if s.reverse != 0 {
                    return emit(s, 54, 24);
                } else {
                    return new(s, 55);
                }
            }
            54 => return new(s, 55),
            55 => {
                if s.element == 0 {
                    return 0;
                } else {
                    return emit(s, 56, 21);
                }
            }
            56 => {
                s.reverse = u32::from(s.incoming != 0);
                return feed(s, 57);
            }
            57 => return emit(s, 58, 34),
            58 => {
                s.protocol = if s.tcp != 0 {
                    6
                } else if s.udp != 0 {
                    17
                } else {
                    59
                };
                return emit(s, 59, 35);
            }
            59 => s.stage = 900,
            61 => {
                if s.status == 0 {
                    return 0;
                } else {
                    return emit(s, 62, 25);
                }
            }
            62 => {
                if s.element == 0 {
                    return 0;
                } else {
                    return emit(s, 63, 23);
                }
            }
            63 => return emit(s, 64, 21),
            64 => return clear(s, 65),
            65 => return emit(s, 66, 7),
            66 => {
                s.result = 1;
                return 0;
            }
            71 => {
                if s.now == 0 {
                    return 0;
                } else {
                    return emit(s, 72, 36);
                }
            }
            72 => {
                if s.now.wrapping_sub(s.last) < s.interval {
                    return 0;
                }
                s.cursor = 0;
                s.stage = 73;
            }
            73 => return emit(s, 74, 22),
            74 => {
                if s.element == 0 {
                    return emit(s, DONE, 38);
                } else {
                    return emit(s, 75, 37);
                }
            }
            75 => {
                if s.status != 0 {
                    return emit(s, 76, 23);
                } else {
                    s.stage = 73;
                }
            }
            76 => return emit(s, 77, 21),
            77 => return clear(s, 78),
            78 => return emit(s, 73, 7),
            101 => return emit(s, 102, 2),
            102 => return emit(s, 103, 3),
            103 => return emit(s, 104, 4),
            104 => return emit(s, 105, 5),
            105 => return emit(s, 106, 6),
            106 => s.stage = s.after_clear,
            201 => return emit(s, 202, 9),
            202 => return emit(s, 203, 10),
            203 => return emit(s, 204, 11),
            204 => return emit(s, 205, 12),
            205 => return emit(s, 206, 11),
            206 => return emit(s, 207, 14),
            207 => s.stage = s.after_init,
            301 => {
                if s.element == 0 {
                    s.result = 0;
                    s.stage = s.after_new;
                } else {
                    return emit(s, 302, 19);
                }
            }
            302 => return emit(s, 303, 20),
            303 => {
                if s.status != 0 {
                    return emit(s, 305, 21);
                } else {
                    return emit(s, 304, 7);
                }
            }
            304 => {
                s.element = 0;
                s.result = 0;
                s.stage = s.after_new;
            }
            305 => return initialize(s, 306),
            306 => {
                s.result = s.element;
                s.stage = s.after_new;
            }
            401 => {
                s.reset = 0;
                return emit(s, 402, 28);
            }
            402 => {
                if s.status != 0 {
                    return clear(s, 403);
                } else {
                    return emit(s, 406, 29);
                }
            }
            403 => return initialize(s, 404),
            404 => {
                s.reset = 1;
                return emit(s, 405, 28);
            }
            405 => return emit(s, 406, 29),
            406 => return emit(s, 407, 30),
            407 => {
                if s.status != 0 {
                    return emit(s, 408, 31);
                } else {
                    s.stage = s.after_feed;
                }
            }
            408 => s.stage = s.after_feed,
            900 => {
                if s.out_track != 0 {
                    return emit(s, 901, 32);
                }
                s.stage = 901;
            }
            901 => {
                s.reverse = u32::from(s.incoming != 0);
                if s.out_reverse != 0 {
                    return emit(s, 902, 33);
                }
                s.stage = 902;
            }
            902 => {
                s.result = 1;
                return 0;
            }
            _ => return 0,
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn zapret_conntrack_lifecycle_step(state: &mut State) -> u32 {
    step(state)
}
const _: () = {
    use std::mem::offset_of;
    let pointer = size_of::<usize>();
    assert!(size_of::<State>() == 104 + 4 * pointer);
    assert!(offset_of!(State, track) == 64);
    assert!(offset_of!(State, cursor) == 64 + 4 * pointer);
    assert!(offset_of!(State, result) == 96 + 4 * pointer);
};
#[cfg(test)]
mod tests {
    use super::*;
    fn drive(mut s: State, mut native: impl FnMut(u32, &mut State)) -> (State, Vec<u32>) {
        let mut ops = Vec::new();
        loop {
            let op = step(&mut s);
            if op == 0 {
                break;
            }
            ops.push(op);
            native(op, &mut s);
            assert!(ops.len() < 100);
        }
        (s, ops)
    }
    #[test]
    fn new_failed_insert_frees_without_initializing_vm() {
        let (s, ops) = drive(
            State {
                entry: 7,
                ..State::default()
            },
            |op, s| match op {
                18 => s.element = 41,
                20 => s.status = 0,
                _ => {}
            },
        );
        assert_eq!(ops, [18, 19, 20, 7]);
        assert_eq!(s.result, 0);
    }
    #[test]
    fn new_initializes_after_inserting_and_uses_original_queue_limit() {
        let (s, ops) = drive(
            State {
                entry: 7,
                ..State::default()
            },
            |op, s| match op {
                18 => s.element = 41,
                20 => s.status = 1,
                21 => s.track = 51,
                10 => assert_eq!(s.queue_limit, 64),
                _ => {}
            },
        );
        assert_eq!(ops, [18, 19, 20, 21, 8, 9, 10, 11, 12, 11, 14]);
        assert_eq!(s.result, 41);
    }
    #[test]
    fn reuse_resets_resources_between_original_update_and_reset_update() {
        let mut updates = 0;
        let (_, ops) = drive(
            State {
                entry: 8,
                track: 42,
                ..State::default()
            },
            |op, s| match op {
                28 => {
                    assert_eq!(s.reset, updates);
                    s.status = u32::from(updates == 0);
                    updates += 1;
                }
                30 => s.status = 1,
                _ => {}
            },
        );
        assert_eq!(
            ops,
            [
                27, 28, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 11, 14, 28, 29, 30, 31
            ]
        );
    }
    #[test]
    fn zero_clock_purge_does_not_read_table_or_publish() {
        let (_, ops) = drive(
            State {
                entry: 12,
                ..State::default()
            },
            |op, s| {
                if op == 16 {
                    s.now = 0;
                }
            },
        );
        assert_eq!(ops, [16]);
    }
    #[test]
    fn backwards_clock_purge_skips_enumeration() {
        let (_, ops) = drive(
            State {
                entry: 12,
                ..State::default()
            },
            |op, s| match op {
                16 => s.now = 99,
                36 => {
                    s.last = 100;
                    s.interval = 1;
                }
                _ => {}
            },
        );
        assert_eq!(ops, [16, 36]);
    }
    #[test]
    fn purge_removes_then_clears_then_frees_before_last_time_publish() {
        let mut scanned = 0;
        let (_, ops) = drive(
            State {
                entry: 12,
                ..State::default()
            },
            |op, s| match op {
                16 => s.now = 100,
                36 => {
                    s.last = 90;
                    s.interval = 10;
                }
                22 => {
                    s.element = if scanned == 0 { 41 } else { 0 };
                    scanned += 1;
                }
                37 => s.status = 1,
                21 => s.track = 51,
                _ => {}
            },
        );
        assert_eq!(ops, [16, 36, 22, 37, 23, 21, 1, 2, 3, 4, 5, 6, 7, 22, 38]);
    }
    #[test]
    fn reverse_start_ignores_reextract_return_and_publishes_protocol_late() {
        let mut extracts = 0;
        let (_, ops) = drive(
            State {
                entry: 10,
                out_track: 1,
                out_reverse: 1,
                ..State::default()
            },
            |op, s| match op {
                24 => {
                    s.status = u32::from(extracts == 0);
                    extracts += 1;
                }
                25 => s.element = 0,
                26 => s.status = 2,
                18 => s.element = 41,
                20 => s.status = 1,
                21 => s.track = 51,
                28 => s.status = 0,
                30 => s.status = 0,
                34 => {
                    s.tcp = 1;
                    s.udp = 1;
                }
                35 => assert_eq!(s.protocol, 6),
                _ => {}
            },
        );
        assert_eq!(
            ops,
            [
                24, 25, 26, 24, 18, 19, 20, 21, 8, 9, 10, 11, 12, 11, 14, 21, 27, 28, 29, 30, 34,
                35, 32, 33
            ]
        );
    }
}
