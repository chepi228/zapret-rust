//! Live LuaJIT reads around the shared Rust packet assembly state.
use super::*;

#[repr(C)]
struct State {
    buffer: *mut u8,
    capacity: usize,
    used: usize,
    network: usize,
    problem: usize,
    output: *mut u8,
    available: usize,
    phase: u32,
    error: u32,
    version: u8,
    transport: u8,
    last_protocol: u8,
    fragmented: bool,
    keep_sum: bool,
    bad_sum: bool,
    preserve_next: bool,
    serialize: bool,
}

#[derive(Default)]
#[repr(C)]
struct Observation {
    data: *const u8,
    length: usize,
    present: bool,
    success: bool,
}

#[repr(C)]
struct Probe {
    next: u32,
    protocol: u8,
    done: bool,
}

const _: () = {
    assert!(size_of::<State>() == 72 && size_of::<Observation>() == 24);
    assert!(size_of::<Probe>() == 8);
};

unsafe extern "C" {
    fn zapret_lua_packet_begin(
        out: *mut u8,
        capacity: usize,
        flags: u8,
        protocol: u8,
        state: *mut State,
    ) -> bool;
    fn zapret_lua_packet_observe(state: &mut State, observed: &Observation) -> bool;
    fn zapret_lua_packet_probe_protocol(protocol: u8) -> bool;
    fn zapret_lua_packet_protocol_step(step: u32, present: bool) -> Probe;
    fn zapret_lua_protocol_label(step: u32) -> *const c_char;
    fn zapret_lua_assembly_label(phase: u32) -> *const c_char;
    fn zapret_lua_assembly_error_format(error: u32) -> *const c_char;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_ip6_l4proto_from_dissect(lua: Lua, index: c_int) -> u8 {
    let mut step = 0;
    unsafe {
        loop {
            lua_getfield(lua, index, zapret_lua_protocol_label(step));
            let present = lua_type(lua, -1) == TABLE;
            pop(lua, 1);
            let probe = zapret_lua_packet_protocol_step(step, present);
            if probe.done {
                return probe.protocol;
            }
            step = probe.next;
        }
    }
}

unsafe fn report_error(state: &State) {
    unsafe {
        let format = zapret_lua_assembly_error_format(state.error);
        if !format.is_null() {
            match state.error {
                8 => DLOG_ERR(format, state.problem),
                9 => DLOG_ERR(format, state.problem, state.available),
                _ => DLOG_ERR(format),
            };
        }
    }
}

unsafe fn observe(lua: Lua, index: c_int, state: &mut State) -> bool {
    let mut value = Observation::default();
    unsafe {
        let name = zapret_lua_assembly_label(state.phase);
        if name.is_null() || state.phase == 0 {
            return false;
        }
        lua_getfield(lua, index, name);
        if state.phase == 11 {
            value.data = lua_tolstring(lua, -1, &mut value.length);
            // Keep the borrowed Lua string rooted while it is copied.
            let accepted = zapret_lua_packet_observe(state, &value);
            pop(lua, 1);
            return accepted;
        }
        value.present = lua_type(lua, -1) == TABLE;
        value.length = state.available;
        if value.present && state.serialize {
            let mut protocol = state.last_protocol;
            let header = match state.phase {
                2 => 3,
                4 => {
                    if zapret_lua_packet_probe_protocol(protocol) {
                        protocol = lua_ip6_l4proto_from_dissect(lua, index);
                    }
                    4
                }
                6 => 0,
                8 => {
                    value.length = 8;
                    1
                }
                10 => {
                    value.length = 8;
                    2
                }
                _ => return false,
            };
            value.success = windows_lua_header_write::write_header(
                lua,
                -1,
                header,
                state.output,
                &mut value.length,
                protocol,
                state.preserve_next,
            );
        }
        pop(lua, 1);
        zapret_lua_packet_observe(state, &value)
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C-unwind" fn lua_reconstruct_dissect(
    lua: Lua,
    index: c_int,
    out: *mut u8,
    length: *mut usize,
    keep: bool,
    bad: bool,
    last_protocol: u8,
    preserve: bool,
) -> bool {
    unsafe {
        let top = lua_gettop(lua);
        let index = lua_absindex(lua, index);
        lua_getfield(lua, index, zapret_lua_assembly_label(0));
        let fragmented = lua_type(lua, -1) != NIL;
        if fragmented {
            luaL_checkinteger(lua, -1);
        }
        pop(lua, 1);
        let flags = u8::from(keep)
            | (u8::from(bad) << 1)
            | (u8::from(preserve) << 2)
            | (u8::from(fragmented) << 3);
        let mut state = MaybeUninit::<State>::uninit();
        if zapret_lua_packet_begin(out, length.read(), flags, last_protocol, state.as_mut_ptr()) {
            let mut state = state.assume_init();
            loop {
                match state.phase {
                    12 => {
                        length.write(state.used);
                        guard(lua, top, 0);
                        return true;
                    }
                    13 => {
                        report_error(&state);
                        break;
                    }
                    _ => {
                        if !observe(lua, index, &mut state) {
                            break;
                        }
                    }
                }
            }
        }
        lua_settop(lua, top);
        false
    }
}
