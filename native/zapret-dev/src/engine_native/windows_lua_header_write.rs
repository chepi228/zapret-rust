//! Decode native header descriptors and variable-length options from LuaJIT.
use super::*;

const IPV4: u32 = 0;
const IPV6: u32 = 1;
const TCP: u32 = 2;
const UDP: u32 = 3;
const ICMP: u32 = 4;

#[repr(C)]
struct Cursor {
    target: *mut c_void,
    index: u32,
    kind: u32,
}

#[repr(C)]
struct Field {
    name: *const c_char,
    conversion: u32,
}

#[derive(Default)]
#[repr(C)]
struct Value {
    data: *const u8,
    length: usize,
    number: i64,
    tag: i32,
}

#[repr(C)]
struct WriteApi {
    options_field: *const c_char,
    minimum: usize,
    table: c_int,
    options: c_int,
}

#[repr(C)]
struct ListState {
    output: *mut u8,
    fields: *const c_void,
    capacity: usize,
    used: usize,
    next_offset: usize,
    item: i64,
    phase: u32,
    mode: u32,
    kind: u8,
    next: u8,
    protocol: u8,
    preserve: u8,
}

#[repr(C)]
struct ListAction {
    item: i64,
    operation: u32,
    pop: u32,
    name: *const c_char,
    length: usize,
}

const _: () = {
    assert!(size_of::<Cursor>() == 16 && size_of::<Field>() == 16);
    assert!(size_of::<Value>() == 32 && size_of::<WriteApi>() == 24);
    assert!(size_of::<ListState>() == 64 && size_of::<ListAction>() == 32);
};

unsafe extern "C" {
    fn zapret_lua_header_write_entry(kind: u32) -> WriteApi;
    fn zapret_lua_header_begin(
        kind: u32,
        fields: *mut c_void,
        size: usize,
        cursor: *mut Cursor,
    ) -> bool;
    fn zapret_lua_header_next(cursor: &Cursor, field: *mut Field) -> u32;
    fn zapret_lua_header_observe(cursor: &mut Cursor, value: &Value) -> u32;
    fn zapret_lua_header_field_error_format(error: u32) -> *const c_char;
    fn zapret_lua_header_list_begin(
        mode: u32,
        output: *mut u8,
        capacity: usize,
        fields: *const c_void,
        protocol: u8,
        preserve: u8,
        state: *mut ListState,
        action: *mut ListAction,
    ) -> bool;
    fn zapret_lua_header_list_step(
        state: &mut ListState,
        value: &Value,
        action: &mut ListAction,
    ) -> bool;
    fn zapret_write_ipv4(
        out: *mut u8,
        capacity: usize,
        fields: *const c_void,
        options: *const u8,
        length: usize,
    ) -> usize;
    fn zapret_write_udp(out: *mut u8, fields: *const c_void);
    fn zapret_write_icmp(out: *mut u8, fields: *const c_void);
}

unsafe fn read_fields(lua: Lua, index: c_int, kind: u32, fields: *mut c_void, size: usize) -> bool {
    let mut cursor = MaybeUninit::<Cursor>::uninit();
    let mut field = MaybeUninit::<Field>::uninit();
    unsafe {
        if !zapret_lua_header_begin(kind, fields, size, cursor.as_mut_ptr()) {
            luaL_error(lua, c"invalid Lua header descriptor".as_ptr());
            return false;
        }
        let mut cursor = cursor.assume_init();
        loop {
            match zapret_lua_header_next(&cursor, field.as_mut_ptr()) {
                0 => return true,
                1 => {}
                _ => {
                    luaL_error(lua, c"invalid Lua header cursor".as_ptr());
                    return false;
                }
            }
            let field = field.assume_init_read();
            lua_getfield(lua, index, field.name);
            let mut value = Value {
                tag: lua_type(lua, -1),
                ..Value::default()
            };
            match field.conversion {
                1 => value.number = lua_tointeger(lua, -1),
                2 | 3 if value.tag == NUMBER => value.number = lua_tointeger(lua, -1),
                4 if value.tag == STRING => value.data = lua_tolstring(lua, -1, &mut value.length),
                5 if value.tag == NUMBER => value.number = luaL_checkinteger(lua, -1),
                2..=5 => {}
                _ => {
                    luaL_error(lua, c"invalid Lua header conversion".as_ptr());
                    return false;
                }
            }
            let error = zapret_lua_header_observe(&mut cursor, &value);
            if matches!(error, 2 | 3) {
                luaL_error(lua, zapret_lua_header_field_error_format(error));
                return false;
            }
            pop(lua, 1);
            if error != 0 {
                return false;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn write_list(
    lua: Lua,
    index: c_int,
    mode: u32,
    out: *mut u8,
    length: *mut usize,
    fields: *const c_void,
    protocol: u8,
    preserve: bool,
) -> bool {
    let mut state = MaybeUninit::<ListState>::uninit();
    let mut action = MaybeUninit::<ListAction>::uninit();
    unsafe {
        let top = lua_gettop(lua);
        if !zapret_lua_header_list_begin(
            mode,
            out,
            length.read(),
            fields,
            protocol,
            preserve.into(),
            state.as_mut_ptr(),
            action.as_mut_ptr(),
        ) {
            luaL_error(lua, c"invalid Lua header list storage".as_ptr());
            return false;
        }
        let mut state = state.assume_init();
        let mut action = action.assume_init();
        loop {
            if action.pop != 0 {
                pop(lua, action.pop as c_int);
            }
            let mut value = Value::default();
            match action.operation {
                0 => {
                    length.write(action.length);
                    return true;
                }
                6 => {
                    lua_settop(lua, top);
                    return false;
                }
                1 => {
                    lua_getfield(lua, index, action.name);
                    value.tag = lua_type(lua, -1);
                }
                2 => {
                    lua_rawgeti(lua, -1, action.item as c_int);
                    value.tag = lua_type(lua, -1);
                }
                3..=5 => {
                    lua_getfield(lua, -1, action.name);
                    value.tag = lua_type(lua, -1);
                    if action.operation == 5 {
                        if value.tag == STRING {
                            value.data = lua_tolstring(lua, -1, &mut value.length);
                        }
                    } else {
                        if action.operation == 3 || value.tag == NUMBER {
                            value.number = lua_tointeger(lua, -1);
                        }
                        pop(lua, 1);
                    }
                }
                _ => {
                    luaL_error(lua, c"invalid Lua header list action".as_ptr());
                    return false;
                }
            }
            if !zapret_lua_header_list_step(&mut state, &value, &mut action) {
                luaL_error(lua, c"invalid Lua header list state".as_ptr());
                return false;
            }
        }
    }
}

unsafe fn write(
    lua: Lua,
    index: c_int,
    out: *mut u8,
    length: *mut usize,
    kind: u32,
    protocol: u8,
    preserve: bool,
) -> bool {
    // The size and alignment of the largest native descriptor are 44 and 4.
    let mut descriptor = MaybeUninit::<[u32; 11]>::uninit();
    let fields = descriptor.as_mut_ptr().cast::<c_void>();
    unsafe {
        let api = zapret_lua_header_write_entry(kind);
        if (!length.is_null() && length.read() < api.minimum) || lua_type(lua, index) != api.table {
            return false;
        }
        let top = lua_gettop(lua);
        let index = lua_absindex(lua, index);
        let size = match kind {
            IPV4 => 18,
            IPV6 => 44,
            TCP => 20,
            UDP | ICMP => 8,
            _ => return false,
        };
        if !read_fields(lua, index, kind, fields, size) {
            return false;
        }
        match kind {
            IPV4 => {
                lua_getfield(lua, index, api.options_field);
                let mut size = 0;
                let options = if lua_type(lua, -1) == api.options {
                    lua_tolstring(lua, -1, &mut size)
                } else {
                    ptr::null()
                };
                let written = zapret_write_ipv4(out, length.read(), fields, options, size);
                pop(lua, 1);
                guard(lua, top, 0);
                if written == 0 {
                    return false;
                }
                length.write(written);
                return true;
            }
            IPV6 | TCP => {
                if !write_list(
                    lua,
                    index,
                    u32::from(kind == IPV6),
                    out,
                    length,
                    fields,
                    protocol,
                    preserve,
                ) {
                    return false;
                }
            }
            UDP => zapret_write_udp(out, fields),
            ICMP => zapret_write_icmp(out, fields),
            _ => return false,
        }
        guard(lua, top, 0);
    }
    true
}

pub(super) unsafe fn write_header(
    lua: Lua,
    index: c_int,
    kind: u32,
    out: *mut u8,
    length: *mut usize,
    protocol: u8,
    preserve: bool,
) -> bool {
    unsafe {
        match kind {
            0 => lua_reconstruct_tcphdr(lua, index, out, length),
            1 => lua_reconstruct_udphdr(lua, index, out),
            2 => lua_reconstruct_icmphdr(lua, index, out),
            3 => lua_reconstruct_iphdr(lua, index, out, length),
            4 => lua_reconstruct_ip6hdr(lua, index, out, length, protocol, preserve),
            _ => {
                luaL_error(lua, c"invalid header builder".as_ptr());
                false
            }
        }
    }
}

macro_rules! length_header {
    ($name:ident, $kind:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $name(
            lua: Lua,
            index: c_int,
            output: *mut u8,
            length: *mut usize,
        ) -> bool {
            unsafe { write(lua, index, output, length, $kind, 0, false) }
        }
    };
}

macro_rules! fixed_header {
    ($name:ident, $kind:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C-unwind" fn $name(lua: Lua, index: c_int, output: *mut u8) -> bool {
            unsafe { write(lua, index, output, ptr::null_mut(), $kind, 0, false) }
        }
    };
}

length_header!(lua_reconstruct_tcphdr, TCP);
length_header!(lua_reconstruct_iphdr, IPV4);
fixed_header!(lua_reconstruct_udphdr, UDP);
fixed_header!(lua_reconstruct_icmphdr, ICMP);

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_reconstruct_ip6hdr(
    lua: Lua,
    index: c_int,
    output: *mut u8,
    length: *mut usize,
    protocol: u8,
    preserve: bool,
) -> bool {
    unsafe { write(lua, index, output, length, IPV6, protocol, preserve) }
}
