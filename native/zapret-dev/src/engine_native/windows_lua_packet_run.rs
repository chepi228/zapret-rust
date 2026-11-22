//! Packet argument publication, rule iteration and protected LuaJIT calls.
#![no_std]

mod windows_lua_rule_run;

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
    ptr,
};

type Lua = *mut c_void;
type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
const REGISTRY: c_int = -10_000;
const GLOBALS: c_int = -10_002;
const MULTRET: c_int = -1;
const NIL: c_int = 0;
const FUNCTION: c_int = 6;

#[repr(C)]
struct Profile {
    before_rules: [MaybeUninit<u8>; 160],
    rules: *mut windows_lua_rule_run::Rule,
}

#[repr(C)]
struct Context {
    index: u32,
    function: *const c_char,
    instance: *const c_char,
    profile: *mut Profile,
    packet: *const c_void,
    track: *mut c_void,
}

#[repr(C)]
struct Params {
    before_debug: [MaybeUninit<u8>; 4252],
    debug: bool,
    before_server: [MaybeUninit<u8>; 12705 - 4253],
    server: bool,
    before_context: [MaybeUninit<u8>; 16880 - 12706],
    context_ref: c_int,
    lua: Lua,
}

#[repr(C)]
struct Arguments {
    profile: *const Profile,
    packet: *const c_void,
    current: *const c_void,
    opposite: *const c_void,
    inbound: *const c_char,
    outbound: *const c_char,
    target4: *const u8,
    target6: *const u8,
    reassembly: *const u8,
    decryption: *const u8,
    reassembly_length: usize,
    decryption_length: usize,
    reassembly_offset: usize,
    mark: u32,
    piece: u32,
    pieces: u32,
    payload: u32,
    protocol: u32,
    port: u16,
    incoming: bool,
}

#[repr(C)]
struct Argument {
    name: *const c_char,
    data: *const c_void,
    length: usize,
    number: i64,
    kind: u32,
}

#[derive(Default)]
#[repr(C)]
struct Flow {
    phase: u32,
    verdict: u8,
    preserve: bool,
}

#[derive(Default)]
#[repr(C)]
struct Feedback {
    verdict: u8,
    ok: bool,
    functions: bool,
    gate: u32,
    kind: u32,
}

const _: () = {
    assert!(size_of::<Arguments>() == 128 && size_of::<Argument>() == 40);
    assert!(offset_of!(Arguments, mark) == 104 && offset_of!(Arguments, incoming) == 126);
    assert!(offset_of!(Context, profile) == 24 && offset_of!(Context, track) == 40);
    assert!(offset_of!(Profile, rules) == 160 && offset_of!(Params, debug) == 4252);
    assert!(offset_of!(Params, server) == 12705 && offset_of!(Params, context_ref) == 16880);
    assert!(offset_of!(Params, lua) == 16888 && size_of::<Params>() == 16896);
    assert!(size_of::<Flow>() == 8 && size_of::<Feedback>() == 12);
};

unsafe extern "C" {
    static mut params: Params;
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn l7payload_str(payload: u32) -> *const c_char;
    fn l7proto_str(protocol: u32) -> *const c_char;
    fn zapret_lua_packet_argument_next(
        index: &mut u32,
        input: &Arguments,
        field: *mut Argument,
    ) -> u32;
    fn zapret_lua_context_prepare(
        ctx: *mut Context,
        profile: *const Profile,
        track: *mut c_void,
        packet: *const c_void,
        incoming: bool,
    ) -> bool;
    fn zapret_desync_step(flow: &mut Flow, feedback: &Feedback) -> u32;
    fn zapret_desync_report(
        flow: &Flow,
        incoming: bool,
        payload: u32,
        packet: *const c_void,
        length: *const usize,
        debug: Log,
        error: Log,
    );
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: Lua) -> c_int;
    fn lua_settop(lua: Lua, index: c_int);
    fn lua_type(lua: Lua, index: c_int) -> c_int;
    fn lua_getfield(lua: Lua, index: c_int, name: *const c_char);
    fn lua_rawgeti(lua: Lua, index: c_int, item: c_int);
    fn lua_createtable(lua: Lua, array: c_int, fields: c_int);
    fn luaL_error(lua: Lua, format: *const c_char, ...) -> c_int;
    fn luaL_ref(lua: Lua, table: c_int) -> c_int;
    fn luaL_unref(lua: Lua, table: c_int, key: c_int);
    fn luaL_checkudata(lua: Lua, index: c_int, name: *const c_char) -> *mut c_void;
    fn lua_pushf_int(lua: Lua, name: *const c_char, value: i64);
    fn lua_pushf_bool(lua: Lua, name: *const c_char, value: bool);
    fn lua_pushf_str(lua: Lua, name: *const c_char, text: *const c_char);
    fn lua_pushf_lstr(lua: Lua, name: *const c_char, text: *const c_char, length: usize);
    fn lua_pushf_raw(lua: Lua, name: *const c_char, data: *const c_void, length: usize);
    fn lua_pushf_table(lua: Lua, name: *const c_char);
    fn lua_pushf_global(lua: Lua, name: *const c_char, global: *const c_char);
    fn lua_pushf_dissect(lua: Lua, packet: *const c_void);
    fn lua_pushf_ctrack(lua: Lua, track: *const c_void, positions: *const c_void, incoming: bool);
    fn lua_reconstruct_dissect(
        lua: Lua,
        index: c_int,
        data: *mut u8,
        length: *mut usize,
        keep: bool,
        bad: bool,
        protocol: u8,
        preserve: bool,
    ) -> bool;
}

unsafe fn vm() -> Lua {
    unsafe { (&raw const params.lua).read() }
}

unsafe fn pop(lua: Lua, count: c_int) {
    unsafe { lua_settop(lua, -1 - count) };
}

unsafe fn publish(input: &Arguments, track: *const c_void, positions: *const c_void) {
    let mut index = 0;
    let mut field = MaybeUninit::<Argument>::uninit();
    unsafe {
        lua_createtable(vm(), 0, 0);
        lua_pushf_dissect(vm(), input.packet);
        lua_pushf_ctrack(vm(), track, positions, input.incoming);
        loop {
            match zapret_lua_packet_argument_next(&mut index, input, field.as_mut_ptr()) {
                0 => return,
                1 => {}
                _ => {
                    luaL_error(vm(), c"invalid Lua packet argument state".as_ptr());
                    return;
                }
            }
            let field = field.assume_init_read();
            let name = field.name;
            match field.kind {
                1 => lua_pushf_int(vm(), name, field.number),
                2 => lua_pushf_bool(vm(), name, field.number != 0),
                3 => lua_pushf_str(vm(), name, field.data.cast()),
                4 => lua_pushf_lstr(vm(), name, field.data.cast(), field.length),
                5 => lua_pushf_raw(vm(), name, field.data, field.length),
                6 => lua_pushf_table(vm(), name),
                7 => lua_getfield(vm(), -1, name),
                8 => pop(vm(), 1),
                9 => lua_pushf_str(vm(), name, l7payload_str(field.number as u32)),
                10 => lua_pushf_str(vm(), name, l7proto_str(field.number as u32)),
                11 => lua_pushf_global(vm(), name, field.data.cast()),
                _ => {
                    luaL_error(vm(), c"invalid Lua packet argument kind".as_ptr());
                    return;
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_native_desync(
    profile: *mut Profile,
    mark: u32,
    inbound: *const c_char,
    outbound: *const c_char,
    incoming: bool,
    track: *mut c_void,
    positions: *const c_void,
    payload: u32,
    protocol: u32,
    packet: *const c_void,
    target4: *const u8,
    target6: *const u8,
    port: u16,
    modified: *mut u8,
    modified_length: *mut usize,
    piece: u32,
    pieces: u32,
    reassembly_offset: usize,
    reassembly: *const u8,
    reassembly_length: usize,
    decryption: *const u8,
    decryption_length: usize,
) -> u8 {
    use windows_lua_rule_run::{Direction, invoke, preflight, zapret_lua_rule_direction};
    let mut flow = Flow::default();
    let mut value = Feedback::default();
    let mut direction = Direction::default();
    let mut context: *mut Context = ptr::null_mut();
    let mut stack = 0;
    let mut reference = -2; // LUA_NOREF
    let mut instance = MaybeUninit::<[c_char; 256]>::uninit();
    let instance = instance.as_mut_ptr().cast();
    unsafe {
        loop {
            match zapret_desync_step(&mut flow, &value) {
                1 => {
                    value.ok = zapret_lua_rule_direction(
                        track,
                        positions,
                        incoming,
                        params.server,
                        &mut direction,
                    )
                }
                2 | 8 | 9 | 16 | 17 | 19..=21 => zapret_desync_report(
                    &flow,
                    incoming,
                    payload,
                    packet,
                    modified_length,
                    DLOG,
                    DLOG_ERR,
                ),
                3 => stack = lua_gettop(vm()),
                4 => value.functions = !(*profile).rules.is_null(),
                5 => {
                    lua_rawgeti(vm(), REGISTRY, params.context_ref);
                    context = luaL_checkudata(vm(), -1, c"desync_ctx".as_ptr()).cast();
                    pop(vm(), 1);
                }
                6 => {
                    value.ok = zapret_lua_context_prepare(context, profile, track, packet, incoming)
                }
                7 => value.gate = preflight(context, &direction, payload, incoming, instance, 256),
                10 => {
                    let arguments = Arguments {
                        profile,
                        packet,
                        current: direction.current,
                        opposite: direction.opposite,
                        inbound,
                        outbound,
                        target4,
                        target6,
                        reassembly,
                        decryption,
                        reassembly_length,
                        decryption_length,
                        reassembly_offset,
                        mark,
                        piece,
                        pieces,
                        payload,
                        protocol,
                        port,
                        incoming,
                    };
                    publish(&arguments, track, direction.positions);
                }
                11 => reference = luaL_ref(vm(), REGISTRY),
                12 => {
                    value.ok = invoke(
                        profile,
                        direction.current,
                        incoming,
                        payload,
                        track,
                        context,
                        reference,
                        instance,
                        256,
                        &mut value.verdict,
                    )
                }
                13 => {
                    lua_rawgeti(vm(), REGISTRY, reference);
                    lua_getfield(vm(), -1, c"dis".as_ptr());
                    value.kind = lua_type(vm(), -1) as u32;
                }
                14 => {
                    value.ok = lua_reconstruct_dissect(
                        vm(),
                        -1,
                        modified,
                        modified_length,
                        false,
                        false,
                        59,
                        flow.preserve,
                    )
                }
                15 | 18 => pop(vm(), 2),
                22 => luaL_unref(vm(), REGISTRY, reference),
                23 => {
                    if stack != lua_gettop(vm()) {
                        luaL_error(vm(), c"stack guard failure".as_ptr());
                    }
                }
                24 => return flow.verdict,
                _ => {
                    zapret_desync_report(
                        &flow,
                        incoming,
                        payload,
                        packet,
                        modified_length,
                        DLOG,
                        DLOG_ERR,
                    );
                    return 0;
                }
            }
        }
    }
}
