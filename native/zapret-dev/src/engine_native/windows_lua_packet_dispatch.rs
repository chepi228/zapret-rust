//! LuaJIT packet API entries using the existing native dispatch state.
use super::{
    windows_lua_packet_assembly::lua_reconstruct_dissect,
    windows_lua_packet_options::{lua_rawsend_extract_options, lua_reconstruct_extract_options},
    *,
};

const PACKET_CAPACITY: usize = 65_536;
const IPPROTO_NONE: u8 = 59;

#[repr(C, align(8))]
struct Dissect([MaybeUninit<u8>; 112]);

#[repr(C, align(4))]
struct Destination([MaybeUninit<u8>; 32]);

#[repr(C)]
struct State {
    buffer: *mut u8,
    data: *const u8,
    track: *mut c_void,
    capacity: usize,
    length: usize,
    mode: u32,
    phase: u32,
    reverse: u32,
    no_payload: u32,
    success: u32,
    error: u32,
}

#[repr(C)]
struct Action {
    name: *const c_char,
    kind: u32,
    index: c_int,
    minimum: c_int,
    maximum: c_int,
    count: u32,
    error: u32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    data: *const u8,
    length: usize,
    track: *mut c_void,
    reverse: u32,
    success: u32,
    tag: c_int,
    extra: u32,
}

const _: () = {
    assert!(size_of::<State>() == 64 && size_of::<Action>() == 32);
    assert!(size_of::<Value>() == 40 && core::mem::offset_of!(Value, tag) == 32);
};

unsafe extern "C" {
    #[link_name = "params"]
    static mut PARAMS: [MaybeUninit<u8>; 16_896];
    fn zapret_lua_packet_dispatch_begin(
        mode: u32,
        out: *mut u8,
        capacity: usize,
        state: *mut State,
        action: *mut Action,
    ) -> bool;
    fn zapret_lua_packet_dispatch_step(
        state: &mut State,
        value: &Value,
        action: &mut Action,
    ) -> bool;
    fn proto_dissect_l3l4(bytes: *const u8, size: usize, out: *mut Dissect, partial: bool);
    fn zapret_packet_extract_dst(packet: *const u8, size: usize, dst: *mut Destination) -> bool;
    fn rawsend_rep(
        repeats: c_int,
        dest: *const Destination,
        mark: u32,
        interface: *const c_char,
        data: *const u8,
        length: usize,
    ) -> bool;
    fn DLOG(format: *const c_char, ...) -> c_int;
}

unsafe extern "C-unwind" {
    fn lua_reqlstring(lua: Lua, index: c_int, size: *mut usize) -> *const u8;
    fn lua_pushboolean(lua: Lua, truth: c_int);
    fn lua_pushnil(lua: Lua);
    fn lua_push_ctrack(lua: Lua, track: *const c_void, positions: *const c_void, reverse: bool);
    fn lua_push_dissect(lua: Lua, dis: *const Dissect);
    fn ConntrackPoolPurge(table: *mut c_void);
    fn ConntrackPoolFeed(
        table: *mut c_void,
        packet: *const Dissect,
        track: *mut *mut c_void,
        reverse: *mut bool,
    ) -> bool;
}

unsafe fn dispatch(lua: Lua, mode: u32, buffer: *mut u8, capacity: usize) -> c_int {
    let mut state = MaybeUninit::<State>::uninit();
    let mut action = MaybeUninit::<Action>::uninit();
    let mut keep = false;
    let mut bad = false;
    let mut preserve = false;
    let mut protocol = IPPROTO_NONE;
    let mut repeats = 1;
    let mut mark = 0;
    let mut interface = ptr::null();
    let mut destination = MaybeUninit::<Destination>::uninit();
    let mut packet = MaybeUninit::<Dissect>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_packet_dispatch_begin(
            mode,
            buffer,
            capacity,
            state.as_mut_ptr(),
            action.as_mut_ptr(),
        ) {
            return luaL_error(lua, c"invalid packet dispatch storage".as_ptr());
        }
        let mut state = state.assume_init();
        let mut action = action.assume_init();
        let params = (&raw mut PARAMS).cast::<u8>();
        let table = params.add(12_664).cast();
        loop {
            let mut value = Value::default();
            match action.kind {
                1 => lua_check_argc_range(lua, action.name, action.minimum, action.maximum),
                2 => value.success = u32::from(params.add(12_704).read() != 0),
                3 => value.tag = lua_type(lua, 1),
                4 => luaL_checktype(lua, 1, TABLE),
                5 => value.data = lua_reqlstring(lua, 1, &mut value.length),
                6 => value.data = lua_tolstring(lua, 1, &mut value.length),
                7 => lua_rawsend_extract_options(
                    lua,
                    action.index,
                    &mut repeats,
                    &mut mark,
                    &mut interface,
                ),
                8 => lua_reconstruct_extract_options(
                    lua,
                    action.index,
                    &mut keep,
                    &mut bad,
                    &mut preserve,
                    &mut protocol,
                ),
                9 => {
                    value.length = capacity;
                    value.success = lua_reconstruct_dissect(
                        lua,
                        1,
                        buffer,
                        &mut value.length,
                        keep,
                        bad,
                        protocol,
                        preserve,
                    )
                    .into();
                }
                10 => value.tag = lua_gettop(lua),
                11 => proto_dissect_l3l4(
                    state.data,
                    state.length,
                    packet.as_mut_ptr(),
                    state.no_payload != 0,
                ),
                12 => ConntrackPoolPurge(table),
                13 => {
                    let mut reverse = false;
                    value.success =
                        ConntrackPoolFeed(table, packet.as_ptr(), &mut value.track, &mut reverse)
                            .into();
                    if value.success != 0 {
                        value.reverse = reverse.into();
                    }
                }
                14 => lua_push_ctrack(lua, state.track, ptr::null(), state.reverse != 0),
                15 => lua_pushboolean(lua, c_int::from(state.reverse == 0)),
                16 => {
                    lua_pushnil(lua);
                    lua_pushnil(lua);
                }
                17 => {
                    value.success = zapret_packet_extract_dst(
                        state.data,
                        state.length,
                        destination.as_mut_ptr(),
                    )
                    .into()
                }
                18 => {
                    let name = if interface.is_null() {
                        c"".as_ptr()
                    } else {
                        interface
                    };
                    if action.index != 0 {
                        DLOG(
                            action.name,
                            repeats,
                            state.length,
                            u32::from(bad),
                            name,
                            mark,
                        );
                    } else {
                        DLOG(action.name, repeats, state.length, name, mark);
                    }
                }
                19 => {
                    value.success = rawsend_rep(
                        repeats,
                        destination.as_ptr(),
                        mark,
                        interface,
                        state.data,
                        state.length,
                    )
                    .into()
                }
                20 => lua_pushboolean(lua, c_int::from(state.success != 0)),
                21 => lua_pushlstring(lua, state.data, state.length),
                22 => lua_push_dissect(lua, packet.as_ptr()),
                23 => {
                    let count = action.count as c_int;
                    guard(lua, top, count);
                    return count;
                }
                24 => return luaL_error(lua, action.name),
                25 => value.success = lua_toboolean(lua, 2) as u32,
                _ => return luaL_error(lua, c"invalid packet dispatch action".as_ptr()),
            }
            if !zapret_lua_packet_dispatch_step(&mut state, &value, &mut action) {
                return luaL_error(lua, c"invalid packet dispatch state".as_ptr());
            }
        }
    }
}

macro_rules! packet_api {
    ($entry:ident, $mode:literal, 0) => {
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $entry(lua: Lua) -> c_int {
            unsafe { dispatch(lua, $mode, ptr::null_mut(), 0) }
        }
    };
    ($entry:ident, $mode:literal, buffer) => {
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $entry(lua: Lua) -> c_int {
            let mut buffer = MaybeUninit::<Buffer<PACKET_CAPACITY>>::uninit();
            unsafe { dispatch(lua, $mode, buffer.as_mut_ptr().cast(), PACKET_CAPACITY) }
        }
    };
}

packet_api!(luacall_rawsend, 0, 0);
packet_api!(luacall_rawsend_dissect, 1, buffer);
packet_api!(luacall_conntrack_feed, 2, buffer);
packet_api!(luacall_reconstruct_dissect, 3, buffer);
packet_api!(luacall_dissect, 4, 0);
