//! Observe each Lua option after the preceding field has been published.
use super::*;

const BOOLEAN: c_int = 1;

#[derive(Default)]
#[repr(C)]
struct Targets {
    keep: *mut bool,
    bad: *mut bool,
    preserve: *mut bool,
    protocol: *mut u8,
    repeats: *mut c_int,
    mark: *mut u32,
    interface: *mut *const c_char,
    default_mark: *const u32,
}

#[repr(C)]
struct Cursor {
    targets: Targets,
    index: u32,
    mode: u32,
}

#[derive(Default)]
#[repr(C)]
struct Field {
    name: *const c_char,
    kind: u32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    data: *const c_char,
    number: i64,
    tag: c_int,
    truth: u32,
}

const _: () = {
    assert!(size_of::<Targets>() == 64 && size_of::<Cursor>() == 72);
    assert!(size_of::<Field>() == 16 && size_of::<Value>() == 24);
};

unsafe extern "C" {
    #[link_name = "params"]
    static PARAMS: [MaybeUninit<u8>; 16_896];
    fn zapret_lua_packet_options_begin(
        mode: u32,
        absent: u32,
        targets: &Targets,
        cursor: *mut Cursor,
        field: *mut Field,
    ) -> u32;
    fn zapret_lua_packet_options_observe(
        cursor: *mut Cursor,
        value: &Value,
        field: *mut Field,
    ) -> u32;
    fn zapret_lua_packet_option_error_format(status: u32) -> *const c_char;
}

unsafe fn options(lua: Lua, index: c_int, mode: u32, targets: &Targets) {
    unsafe {
        let absent = lua_type(lua, index) <= NIL;
        if !absent {
            luaL_checktype(lua, index, TABLE);
        }
        let mut cursor = MaybeUninit::<Cursor>::uninit();
        let mut field = Field::default();
        let mut status = zapret_lua_packet_options_begin(
            mode,
            absent.into(),
            targets,
            cursor.as_mut_ptr(),
            &mut field,
        );
        while status == 1 {
            lua_getfield(lua, index, field.name);
            let mut value = Value {
                tag: lua_type(lua, -1),
                ..Value::default()
            };
            match field.kind {
                1 if value.tag == BOOLEAN => value.truth = lua_toboolean(lua, -1) as u32,
                2 if value.tag != NIL => value.number = lua_tointeger(lua, -1),
                3 | 4 => value.number = lua_tointeger(lua, -1),
                5 if value.tag == STRING => {
                    value.data = lua_tolstring(lua, -1, ptr::null_mut()).cast()
                }
                1 | 2 | 5 => {}
                _ => {
                    luaL_error(lua, c"invalid packet option field".as_ptr());
                    return;
                }
            }
            status = zapret_lua_packet_options_observe(cursor.as_mut_ptr(), &value, &mut field);
            if matches!(status, 2 | 3) {
                luaL_error(lua, zapret_lua_packet_option_error_format(status));
                return;
            }
            pop(lua, 1);
        }
        if status != 0 {
            luaL_error(lua, c"invalid packet option storage".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C-unwind" fn lua_reconstruct_extract_options(
    lua: Lua,
    index: c_int,
    keep: *mut bool,
    bad: *mut bool,
    preserve: *mut bool,
    protocol: *mut u8,
) {
    let targets = Targets {
        keep,
        bad,
        preserve,
        protocol,
        ..Targets::default()
    };
    unsafe { options(lua, index, 0, &targets) };
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C-unwind" fn lua_rawsend_extract_options(
    lua: Lua,
    index: c_int,
    repeats: *mut c_int,
    mark: *mut u32,
    interface: *mut *const c_char,
) {
    // engine_config_exports_abi.h checks the Windows fwmark offset.
    let default_mark = unsafe { (&raw const PARAMS).cast::<u8>().add(4264).cast() };
    let targets = Targets {
        repeats,
        mark,
        interface,
        default_mark,
        ..Targets::default()
    };
    unsafe { options(lua, index, 1, &targets) };
}
