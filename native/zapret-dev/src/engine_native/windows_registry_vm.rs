//! Publish the existing Lua catalog in the caller's protected VM frame.
#![no_std]

use core::{
    ffi::{c_char, c_int},
    mem::MaybeUninit,
};

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

type Callback = unsafe extern "C-unwind" fn(*mut LuaState) -> c_int;
type MetatableAction = unsafe extern "C-unwind" fn(*mut LuaState);
const GLOBALS: c_int = -10002;

#[repr(C)]
struct Sources {
    lua: *const *mut LuaState,
    version: *const c_char,
    mark: *const u32,
    debug: *const bool,
    daemon: *const bool,
    server: *const bool,
    cache_hostname: *const bool,
    ctrack_disable: *const bool,
    callbacks: *const Option<Callback>,
    count: usize,
    create_context: MetatableAction,
}

#[derive(Default)]
#[repr(C)]
struct Values {
    version: *const c_char,
    mark: u32,
    debug: bool,
    daemon: bool,
    server: bool,
    cache_hostname: bool,
    ctrack_disable: bool,
}

#[repr(C)]
struct Section {
    title: *const c_char,
    before_log: u32,
    after_log: u32,
}

#[repr(C)]
struct Constant {
    name: *const c_char,
    text: *const c_char,
    value: u32,
}

#[repr(C)]
struct Binding {
    name: *const c_char,
    slot: u32,
}

#[repr(C)]
struct Metatable {
    name: *const c_char,
    first: *const c_char,
    second: *const c_char,
    action: u32,
}

const _: () = {
    use core::mem::offset_of;
    let pointer = size_of::<*const LuaState>();
    assert!(size_of::<Sources>() == 11 * pointer && offset_of!(Sources, callbacks) == 8 * pointer);
    assert!(size_of::<Values>() == if pointer == 4 { 16 } else { 24 });
    assert!(offset_of!(Values, debug) == pointer + 4);
    assert!(offset_of!(Values, ctrack_disable) == pointer + 8);
    assert!(size_of::<Section>() == pointer + 8);
    assert!(size_of::<Constant>() == 3 * pointer && offset_of!(Constant, value) == 2 * pointer);
    assert!(size_of::<Binding>() == 2 * pointer);
    assert!(size_of::<Metatable>() == 4 * pointer && offset_of!(Metatable, action) == 3 * pointer);
};

unsafe extern "C" {
    static zapret_lua_registry_sources: Sources;

    fn DLOG(format: *const c_char, ...) -> c_int;
    fn zapret_lua_registry_group(group: u32, section: *mut Section) -> u32;
    fn zapret_lua_registry_constant(
        group: u32,
        index: usize,
        values: *const Values,
        entry: *mut Constant,
    ) -> u32;
    fn zapret_lua_registry_entry_format() -> *const c_char;
    fn zapret_lua_registry_function(index: usize, count: usize, entry: *mut Binding) -> u32;
    fn zapret_lua_registry_metatable(index: usize, entry: *mut Metatable) -> u32;
}

unsafe extern "C-unwind" {
    fn lua_gettop(lua: *mut LuaState) -> c_int;
    fn lua_settop(lua: *mut LuaState, index: c_int);
    fn lua_setfield(lua: *mut LuaState, index: c_int, name: *const c_char);
    fn lua_pushstring(lua: *mut LuaState, value: *const c_char);
    fn lua_pushinteger(lua: *mut LuaState, value: isize);
    fn lua_pushboolean(lua: *mut LuaState, value: c_int);
    fn lua_pushcclosure(lua: *mut LuaState, callback: Option<Callback>, upvalues: c_int);
    fn luaL_newmetatable(lua: *mut LuaState, name: *const c_char) -> c_int;
    fn luaL_error(lua: *mut LuaState, format: *const c_char, ...) -> c_int;
    fn lua_cfunc_zstream_gc(lua: *mut LuaState) -> c_int;
}

unsafe fn vm() -> *mut LuaState {
    // VM callbacks can change live state. Resolve the slot at each operation.
    unsafe { zapret_lua_registry_sources.lua.read() }
}

unsafe fn observe(values: &mut Values, fields: u32) {
    unsafe {
        let source = &zapret_lua_registry_sources;
        match fields {
            1 => values.version = source.version,
            2 => values.mark = source.mark.read(),
            3 => {
                values.debug = source.debug.read();
                values.daemon = source.daemon.read();
                values.server = source.server.read();
                values.cache_hostname = source.cache_hostname.read();
                values.ctrack_disable = source.ctrack_disable.read();
            }
            _ => {}
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init_const() {
    unsafe {
        let top = lua_gettop(vm());
        let mut values = Values::default();
        let mut group = 0;
        loop {
            let mut section = MaybeUninit::<Section>::uninit();
            let status = zapret_lua_registry_group(group, section.as_mut_ptr());
            if status > 1 {
                luaL_error(vm(), c"invalid Lua constant section".as_ptr());
                return;
            }
            let section = section.assume_init();
            if status == 0 {
                DLOG(section.title);
                break;
            }
            observe(&mut values, section.before_log);
            DLOG(section.title);
            observe(&mut values, section.after_log);
            let mut index = 0;
            loop {
                let mut entry = MaybeUninit::<Constant>::uninit();
                match zapret_lua_registry_constant(group, index, &values, entry.as_mut_ptr()) {
                    0 => break,
                    1 => {}
                    _ => {
                        luaL_error(vm(), c"invalid Lua constant catalog".as_ptr());
                        return;
                    }
                }
                let entry = entry.assume_init();
                match group {
                    0 => lua_pushstring(vm(), entry.text),
                    1 => lua_pushinteger(vm(), entry.value as isize),
                    2 => lua_pushboolean(vm(), entry.value as c_int),
                    _ => {}
                }
                lua_setfield(vm(), GLOBALS, entry.name);
                DLOG(zapret_lua_registry_entry_format(), entry.name);
                index += 1;
            }
            group += 1;
        }
        if top != lua_gettop(vm()) {
            luaL_error(vm(), c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init_functions() {
    unsafe {
        let top = lua_gettop(vm());
        let sources = &zapret_lua_registry_sources;
        let mut index = 0;
        loop {
            let mut entry = MaybeUninit::<Binding>::uninit();
            match zapret_lua_registry_function(index, sources.count, entry.as_mut_ptr()) {
                0 => break,
                1 => {}
                _ => {
                    luaL_error(vm(), c"invalid Lua function catalog".as_ptr());
                    return;
                }
            }
            let entry = entry.assume_init();
            let slot = entry.slot as usize;
            if slot >= sources.count {
                luaL_error(vm(), c"invalid Lua callback slot".as_ptr());
                return;
            }
            lua_pushcclosure(vm(), sources.callbacks.add(slot).read(), 0);
            lua_setfield(vm(), GLOBALS, entry.name);
            index += 1;
        }
        if top != lua_gettop(vm()) {
            luaL_error(vm(), c"stack guard failure".as_ptr());
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_init_mt() {
    unsafe {
        let sources = &zapret_lua_registry_sources;
        let mut index = 0;
        loop {
            let mut mt = MaybeUninit::<Metatable>::uninit();
            match zapret_lua_registry_metatable(index, mt.as_mut_ptr()) {
                0 => return,
                1 => {}
                _ => {
                    luaL_error(vm(), c"invalid Lua metatable plan".as_ptr());
                    return;
                }
            }
            match mt.assume_init().action {
                1 => {
                    let lua = vm();
                    let top = lua_gettop(lua);
                    native_lua_registry_metatable(lua, 0, Some(lua_cfunc_zstream_gc));
                    if top != lua_gettop(lua) {
                        luaL_error(lua, c"stack guard failure".as_ptr());
                    }
                }
                2 => native_lua_registry_metatable(vm(), 1, None),
                3 => (sources.create_context)(vm()),
                _ => {
                    luaL_error(vm(), c"invalid Lua metatable action".as_ptr());
                    return;
                }
            }
            index += 1;
        }
    }
}

unsafe fn native_lua_registry_metatable(
    lua: *mut LuaState,
    index: usize,
    finalizer: Option<Callback>,
) {
    unsafe {
        let mut mt = MaybeUninit::<Metatable>::uninit();
        if zapret_lua_registry_metatable(index, mt.as_mut_ptr()) != 1 {
            luaL_error(lua, c"invalid Lua metatable catalog".as_ptr());
            return;
        }
        let mt = mt.assume_init();
        if mt.name.is_null() || (!mt.first.is_null() && finalizer.is_none()) {
            luaL_error(lua, c"invalid Lua metatable catalog".as_ptr());
            return;
        }
        luaL_newmetatable(lua, mt.name);
        for name in [mt.first, mt.second] {
            if !name.is_null() {
                lua_pushcclosure(lua, finalizer, 0);
                lua_setfield(lua, -2, name);
            }
        }
        lua_settop(lua, -2);
    }
}
