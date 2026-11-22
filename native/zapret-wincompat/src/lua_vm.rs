//! Resource-free VM startup, cleanup and GC decisions between C calls.
use std::{ffi::c_char, ptr};

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_vm_text(label: u32) -> *const c_char {
    let text = match label {
        0 => c"LUA SHUTDOWN\n",
        1 => c"LUA INIT ERROR\n",
        2 => c"_LOADED",
        3 => c"jit",
        4 => c"status",
        5 => c" %s",
        6 => c"\n",
        7 => c"\nLUA GARBAGE COLLECT: %dK => %dK\n",
        8 => c"INTERRUPT",
        _ => return ptr::null(),
    };
    text.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_lua_vm_jit_status(enabled: bool) -> *const c_char {
    if enabled { c"JIT: ON" } else { c"JIT: OFF" }.as_ptr()
}

#[repr(C)]
struct Version {
    format: *const c_char,
    edition: *const c_char,
    major: u32,
    minor: u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_version(
    number: u32,
    jit: bool,
    openresty: bool,
    output: *mut Version,
) {
    if !aligned(output) {
        return;
    }
    let (format, edition) = match (jit, openresty) {
        (true, true) => (c"LUA v%u.%u %s%s\n", c" OpenResty".as_ptr()),
        (true, false) => (c"LUA v%u.%u %s%s\n", c"".as_ptr()),
        (false, _) => (c"LUA v%u.%u\n", ptr::null()),
    };
    unsafe {
        output.write(Version {
            format: format.as_ptr(),
            edition,
            major: number / 100,
            minor: number % 100,
        });
    }
}

#[repr(C)]
#[derive(Default)]
struct Init {
    phase: u32,
    index: i32,
}
#[repr(C)]
#[derive(Default)]
struct Feedback {
    kind: i32,
    top: i32,
    ok: u32,
}
fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}
fn next_argument(state: &mut Init) -> u32 {
    let Some(index) = state.index.checked_add(1) else {
        return 19;
    };
    state.index = index;
    state.phase = 12;
    15
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_init_step(state: *mut Init, input: *const Feedback) -> u32 {
    if !aligned(state) || !aligned(input) {
        return 19;
    }
    // SAFETY: disjoint fixed records owned by C, with no callbacks in this step.
    let (state, value) = unsafe { (&mut *state, &*input) };
    if value.ok > 1 {
        return 19;
    }
    match state.phase {
        0..=5 => {
            state.phase += 1;
            state.phase
        }
        6 => {
            if value.ok == 0 {
                state.phase = 20;
                7
            } else {
                state.phase = 7;
                10
            }
        }
        7 => {
            if value.kind == 5 {
                state.phase = 8;
                11
            } else {
                state.phase = 18;
                18
            }
        }
        8 => {
            if value.kind == 5 {
                state.phase = 9;
                12
            } else {
                state.phase = 18;
                18
            }
        }
        9 => {
            if value.kind == 6 && value.top >= 1 {
                state.index = value.top;
                state.phase = 10;
                13
            } else {
                state.phase = 18;
                18
            }
        }
        10 => {
            state.phase = 11;
            14
        }
        11 => next_argument(state),
        12 => {
            if value.ok != 0 {
                state.phase = 11;
                16
            } else {
                state.phase = 17;
                17
            }
        }
        17 => {
            state.phase = 18;
            18
        }
        18 => {
            state.phase = 24;
            0
        }
        20 => {
            state.phase = 21;
            8
        }
        21 => {
            state.phase = 25;
            9
        }
        22 => {
            state.phase = 25;
            20 // initialization diagnostic
        }
        24 => 0,
        25 => 9,
        _ => 19,
    }
}
// Creation is the only early branch before libraries/registration. Keep it in
// its own observation so a missing VM never reaches hooks or diagnostics.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_created(state: *mut Init, available: u32) -> bool {
    if !aligned(state) || available > 1 {
        return false;
    }
    let state = unsafe { &mut *state };
    if state.phase != 2 {
        return false;
    }
    if available == 0 {
        state.phase = 22;
    }
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_vm_cleanup_step(state: *mut u32, mode: u32, available: u32) -> u32 {
    if !aligned(state) || mode > 1 || available > 1 {
        return 9;
    }
    // SAFETY: C owns one scalar cursor; availability is sampled only initially.
    let state = unsafe { &mut *state };
    if mode == 0 {
        match *state {
            0..=2 => {
                *state += 1;
                *state
            }
            3 => 0,
            _ => 9,
        }
    } else {
        if *state == 0 && available == 0 {
            *state = 5;
            return 0;
        }
        match *state {
            0..=4 => {
                let action = *state + 4;
                *state += 1;
                action
            }
            5 => 0,
            _ => 9,
        }
    }
}
#[repr(C)]
#[derive(Default)]
struct Gc {
    now: u64,
    phase: u32,
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_gc_step(state: *mut Gc, interval: u64, now: u64, last: u64) -> u32 {
    if !aligned(state) {
        return 7;
    }
    // SAFETY: fixed C-owned state; native clock and every VM operation run later.
    let state = unsafe { &mut *state };
    match state.phase {
        0 => {
            if interval == 0 {
                state.phase = 7;
                0
            } else {
                state.phase = 1;
                1
            }
        }
        1 => {
            state.now = now;
            if now.wrapping_sub(last) >= interval {
                state.phase = 2;
                2
            } else {
                state.phase = 7;
                0
            }
        }
        2..=5 => {
            state.phase += 1;
            state.phase
        }
        6 => {
            state.phase = 7;
            0
        }
        7 => 0,
        _ => 7,
    }
}
const _: () = {
    assert!(size_of::<Init>() == 8);
    assert!(size_of::<Feedback>() == 12);
    assert!(size_of::<Gc>() == 16);
    assert!(size_of::<Version>() == 2 * size_of::<*const c_char>() + 2 * size_of::<u32>());
};
#[cfg(test)]
mod tests {
    use super::*;
    fn step(state: &mut Init, value: &Feedback) -> u32 {
        unsafe { zapret_lua_vm_init_step(state, value) }
    }
    #[test]
    fn successful_init_retains_jit_result_start_and_argument_stop() {
        let mut state = Init::default();
        let mut value = Feedback {
            kind: 5,
            top: 4,
            ok: 1,
        };
        for action in [1, 2] {
            assert_eq!(step(&mut state, &value), action);
        }
        assert!(unsafe { zapret_lua_vm_created(&mut state, 1) });
        for action in [3, 4, 5, 6, 10, 11, 12] {
            assert_eq!(step(&mut state, &value), action);
        }
        value.kind = 6;
        assert_eq!(step(&mut state, &value), 13);
        assert_eq!(state.index, 4);
        assert_eq!(step(&mut state, &value), 14);
        for index in 5..8 {
            assert_eq!(step(&mut state, &value), 15);
            assert_eq!(state.index, index);
            assert_eq!(step(&mut state, &value), 16);
        }
        assert_eq!(step(&mut state, &value), 15);
        value.ok = 0;
        for action in [17, 18, 0, 0] {
            assert_eq!(step(&mut state, &value), action);
        }
    }
    #[test]
    fn failed_creation_or_registration_stops_before_later_vm_calls() {
        let mut state = Init::default();
        let mut value = Feedback {
            ok: 1,
            ..Default::default()
        };
        assert_eq!(step(&mut state, &value), 1);
        assert_eq!(step(&mut state, &value), 2);
        assert!(unsafe { zapret_lua_vm_created(&mut state, 0) });
        assert_eq!(step(&mut state, &value), 20);
        assert_eq!(step(&mut state, &value), 9);
        let mut state = Init::default();
        for _ in 0..6 {
            step(&mut state, &value);
        }
        value.ok = 0;
        for action in [7, 8, 9] {
            assert_eq!(step(&mut state, &value), action);
        }
    }
    #[test]
    fn missing_jit_tables_or_function_only_clear_the_stack() {
        for phase in [7, 8, 9] {
            let mut state = Init { phase, index: 0 };
            let value = Feedback {
                kind: 0,
                ok: 1,
                ..Default::default()
            };
            assert_eq!(step(&mut state, &value), 18);
            assert_eq!(step(&mut state, &value), 0);
        }
    }
    #[test]
    fn shutdown_and_cleanup_order_allow_independent_nested_cursors() {
        let mut outer = 0;
        for expected in [4, 5, 6, 7, 8, 0] {
            assert_eq!(
                unsafe { zapret_lua_vm_cleanup_step(&mut outer, 1, 1) },
                expected
            );
            if expected == 6 {
                let mut inner = 0;
                for action in [1, 2, 3, 0] {
                    assert_eq!(
                        unsafe { zapret_lua_vm_cleanup_step(&mut inner, 0, 1) },
                        action
                    );
                }
            }
        }
        let mut absent = 0;
        assert_eq!(unsafe { zapret_lua_vm_cleanup_step(&mut absent, 1, 0) }, 0);
    }
    #[test]
    fn gc_reads_changed_interval_and_last_time_after_clock_query() {
        let mut state = Gc::default();
        assert_eq!(unsafe { zapret_lua_gc_step(&mut state, 100, 0, 0) }, 1);
        assert_eq!(unsafe { zapret_lua_gc_step(&mut state, 0, 42, 900) }, 2);
        for action in [3, 4, 5, 6, 0] {
            assert_eq!(
                unsafe { zapret_lua_gc_step(&mut state, u64::MAX, 999, 999) },
                action
            );
        }
        assert_eq!(state.now, 42);
    }
    #[test]
    fn gc_wraps_unsigned_elapsed_and_disabled_gc_skips_clock() {
        for (interval, now, last, expected) in [
            (0, 999, 0, 0),
            (20, 5, u64::MAX - 20, 2),
            (50, 5, u64::MAX - 20, 0),
            (10, 10, 0, 2),
        ] {
            let mut state = Gc::default();
            let action = unsafe { zapret_lua_gc_step(&mut state, interval, 0, 0) };
            if interval == 0 {
                assert_eq!(action, expected);
            } else {
                assert_eq!(action, 1);
                assert_eq!(
                    unsafe { zapret_lua_gc_step(&mut state, interval, now, last) },
                    expected
                );
            }
        }
    }
    #[test]
    fn invalid_metadata_cannot_advance_a_vm_plan() {
        let mut state = Init::default();
        assert_eq!(
            step(
                &mut state,
                &Feedback {
                    ok: 2,
                    ..Default::default()
                }
            ),
            19
        );
        assert_eq!(state.phase, 0);
        assert!(!unsafe { zapret_lua_vm_created(&mut state, 1) });
        assert_eq!(unsafe { zapret_lua_vm_cleanup_step(&mut 0, 2, 1) }, 9);
        assert_eq!(
            unsafe { zapret_lua_gc_step(std::ptr::null_mut(), 1, 1, 1) },
            7
        );
    }
}
