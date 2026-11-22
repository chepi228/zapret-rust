//! Windows Lua 5.1 embedding ABI used by the engine, on the Rust Lua 5.2 VM.
//!
//! This module is built inside the pinned interpreter. Its C stack shares
//! the VM's collector and nested calls are protected by the same Lua frames.

use super::{
    Vm,
    num::{as_num, concat_piece},
};
use crate::runtime::{Gc, Table, UserdataPayload, Value};
use crate::version::LuaVersion;
use crate::vm::LuaError;
use std::{
    any::TypeId,
    ffi::{CStr, VaList, c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    ptr, slice,
    sync::atomic::{AtomicPtr, Ordering},
};

type State = *mut Vm;
type Callback = unsafe extern "C-unwind" fn(State) -> c_int;
type LoadBuffer = unsafe extern "C-unwind" fn(State, *const c_char, usize, *const c_char) -> c_int;
type ReleaseBuffer = unsafe extern "C" fn(*mut c_void);

const GLOBALS: c_int = -10_002;
const REGISTRY: c_int = -10_000;
const MAX_FRAME_SLOTS: usize = 8000;
const MAX_DIAGNOSTIC_BYTES: usize = 65536;
const ERRRUN: c_int = 2;
const ERRSYNTAX: c_int = 3;
const ERRERR: c_int = 5;
const ERRFILE: c_int = 6;

struct Trap;

fn fail(vm: &mut Vm, error: Value) -> ! {
    vm.capi_stack.push(error);
    if vm.capi_depth == 0 {
        if let Some(callback) = vm.capi_panic {
            unsafe { callback(vm) };
        }
        std::process::abort();
    }
    resume_unwind(Box::new(Trap))
}

fn fail_text(vm: &mut Vm, message: &str) -> ! {
    let error = Value::Str(vm.heap.intern(message.as_bytes()));
    fail(vm, error)
}

fn result<T>(vm: &mut Vm, result: Result<T, LuaError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => fail(vm, error.0),
    }
}

fn slot(vm: &Vm, index: c_int) -> Option<usize> {
    let cursor = match index {
        1.. => vm.capi_base as i64 + i64::from(index) - 1,
        -9999..=-1 => vm.capi_stack.len() as i64 + i64::from(index),
        _ => return None,
    };
    let cursor = usize::try_from(cursor).ok()?;
    (vm.capi_base..vm.capi_stack.len())
        .contains(&cursor)
        .then_some(cursor)
}

fn value(vm: &Vm, index: c_int) -> Option<Value> {
    match index {
        GLOBALS => Some(Value::Table(vm.globals())),
        REGISTRY => vm.registry.map(Value::Table),
        ..GLOBALS => {
            Some(vm.running_native_upvalue((i64::from(GLOBALS) - i64::from(index)) as usize))
        }
        _ => slot(vm, index).map(|slot| vm.capi_stack[slot]),
    }
}

fn read(vm: &Vm, index: c_int) -> Value {
    value(vm, index).unwrap_or(Value::Nil)
}

fn tag(v: Value) -> c_int {
    match v {
        Value::Nil => 0,
        Value::Bool(_) => 1,
        Value::LightUserdata(_) => 2,
        Value::Float(_) | Value::Int(_) => 3,
        Value::Str(_) => 4,
        Value::Table(_) => 5,
        Value::Native(_) | Value::Closure(_) => 6,
        Value::Userdata(_) => 7,
        Value::Coro(_) => 8,
    }
}

fn callback(vm: &mut Vm, fs: u32, nargs: u32) -> Result<u32, LuaError> {
    let Value::LightUserdata(function) = vm.running_native_upvalue(0) else {
        unreachable!("C callback always carries its own pointer");
    };
    let function = unsafe { std::mem::transmute::<*const (), Callback>(function) };
    let previous = vm.capi_base;
    let base = vm.capi_stack.len();
    vm.capi_base = base;
    vm.capi_depth += 1;
    for i in 0..nargs {
        let argument = vm.nat_arg(fs, nargs, i);
        vm.capi_stack.push(argument);
    }
    vm.nny += 1;
    let p = vm as State;
    let outcome = catch_unwind(AssertUnwindSafe(|| unsafe { function(p) }));
    let vm = unsafe { &mut *p };
    vm.nny -= 1;
    vm.capi_base = previous;
    vm.capi_depth -= 1;
    let out = match outcome {
        Ok(count) if count >= 0 && count as usize <= vm.capi_stack.len() - base => {
            let index = vm.capi_stack.len() - count as usize;
            let values = vm.capi_stack[index..].to_vec();
            Ok(vm.nat_return(fs, &values))
        }
        Ok(_) => Err(LuaError(Value::Str(
            vm.heap.intern(b"invalid native return count"),
        ))),
        Err(error) if error.is::<Trap>() => {
            Err(LuaError(vm.capi_stack.pop().unwrap_or(Value::Nil)))
        }
        Err(error) => {
            vm.capi_stack.truncate(base);
            resume_unwind(error)
        }
    };
    vm.capi_stack.truncate(base);
    out
}

fn call(vm: &mut Vm, arguments: c_int, results: c_int, handler: c_int, protected: bool) -> c_int {
    if arguments < 0 || results < -1 || results > MAX_FRAME_SLOTS as c_int {
        fail_text(vm, "invalid native call arity");
    }
    let count = arguments as usize;
    let start = vm.capi_stack.len().saturating_sub(count + 1);
    if start < vm.capi_base || count >= vm.capi_stack.len() {
        fail_text(vm, "invalid native call frame");
    }
    let handler = read(vm, handler);
    let (f, args) = vm.capi_stack.split_at(start + 1);
    let f = f[start];
    let args = args.to_vec();
    let outcome = if handler.is_nil() {
        vm.call_noyield(f, &args)
    } else {
        vm.call_value_with_handler(f, &args, handler)
    };
    vm.capi_stack.truncate(start);
    match outcome {
        Ok(values) => {
            vm.capi_stack.extend(values);
            if results != -1 {
                vm.capi_stack.resize(start + results as usize, Value::Nil);
            }
            0
        }
        Err(error) if protected => {
            vm.capi_stack.push(error.0);
            if error.0.as_bytes() == Some(b"error in error handling") {
                ERRERR
            } else {
                ERRRUN
            }
        }
        Err(error) => fail(vm, error.0),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_newstate() -> State {
    Box::into_raw(Box::new(Vm::new_minimal(LuaVersion::Lua52)))
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_openlibs(lua: State) {
    let vm = unsafe { &mut *lua };
    vm.open_all_libs();
    vm.set_bytecode_loading(false);
    let name = Value::Str(vm.heap.intern(b"coroutine"));
    if let Value::Table(coroutine) = vm.globals().get(name) {
        let name = Value::Str(vm.heap.intern(b"running"));
        let running = vm.native(coroutine_running);
        raw_set(vm, coroutine, name, running);
    }
}

// LuaJIT callers use nil to distinguish the main thread from a coroutine.
fn coroutine_running(vm: &mut Vm, function_slot: u32, _: u32) -> Result<u32, LuaError> {
    let running = vm.current.map_or(Value::Nil, Value::Coro);
    Ok(vm.nat_return(function_slot, &[running]))
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_close(lua: State) {
    clear_interrupt(lua);
    drop(unsafe { Box::from_raw(lua) });
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_atpanic(lua: State, handler: Option<Callback>) -> Option<Callback> {
    std::mem::replace(unsafe { &mut (*lua).capi_panic }, handler)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushcclosure(lua: State, function: Callback, count: c_int) {
    let vm = unsafe { &mut *lua };
    let n = count as usize;
    let start = vm.capi_stack.len() - n;
    let mut items = Vec::with_capacity(n + 1);
    items.push(Value::LightUserdata(function as *const ()));
    items.extend_from_slice(&vm.capi_stack[start..]);
    let f = vm.native_with(callback, items.into_boxed_slice());
    vm.capi_stack.truncate(start);
    vm.capi_stack.push(f);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pcall(
    lua: State,
    n: c_int,
    results: c_int,
    handler: c_int,
) -> c_int {
    call(unsafe { &mut *lua }, n, results, handler, true)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_call(lua: State, n: c_int, results: c_int) {
    call(unsafe { &mut *lua }, n, results, 0, false);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_error(lua: State) -> c_int {
    let vm = unsafe { &mut *lua };
    let error = read(vm, -1);
    fail(vm, error)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_gettop(lua: State) -> c_int {
    let vm = unsafe { &*lua };
    (vm.capi_stack.len() - vm.capi_base) as c_int
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_settop(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let position = if index < 0 {
        vm.capi_stack.len() as i64 + i64::from(index) + 1
    } else {
        vm.capi_base as i64 + i64::from(index)
    };
    if !(vm.capi_base as i64..=(vm.capi_base + MAX_FRAME_SLOTS) as i64).contains(&position) {
        fail_text(vm, "invalid stack limit");
    }
    vm.capi_stack.resize(position as usize, Value::Nil);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checkstack(lua: State, size: c_int, reason: *const c_char) {
    let vm = unsafe { &mut *lua };
    let size = size.max(0) as usize;
    if size > MAX_FRAME_SLOTS.saturating_sub(vm.capi_stack.len() - vm.capi_base)
        || vm.capi_stack.try_reserve(size).is_err()
    {
        let reason = if reason.is_null() {
            ""
        } else {
            unsafe { CStr::from_ptr(reason) }.to_str().unwrap_or("")
        };
        fail_text(vm, &format!("stack overflow ({reason})"));
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_type(lua: State, index: c_int) -> c_int {
    value(unsafe { &*lua }, index).map_or(-1, tag)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushvalue(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let value = read(vm, index);
    vm.capi_stack.push(value);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_remove(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    if let Some(at) = slot(vm, index) {
        vm.capi_stack.remove(at);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_insert(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    if let Some(at) = slot(vm, index) {
        vm.capi_stack[at..].rotate_right(1);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_replace(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    if let Some(at) = slot(vm, index) {
        vm.capi_stack[at] = vm.capi_stack[vm.capi_stack.len() - 1];
        vm.capi_stack.pop();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushnil(lua: State) {
    unsafe { (*lua).capi_stack.push(Value::Nil) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushnumber(lua: State, number: f64) {
    unsafe { (*lua).capi_stack.push(Value::Float(number)) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushinteger(lua: State, number: isize) {
    unsafe { (*lua).capi_stack.push(Value::Float(number as f64)) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushboolean(lua: State, flag: c_int) {
    unsafe { (*lua).capi_stack.push(Value::Bool(flag != 0)) };
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushlightuserdata(lua: State, pointer: *mut c_void) {
    unsafe { (*lua).capi_stack.push(Value::LightUserdata(pointer.cast())) };
}

fn text(vm: &mut Vm, bytes: &[u8]) -> *const c_char {
    let value = vm.heap.intern(bytes);
    vm.capi_stack.push(Value::Str(value));
    value.as_bytes().as_ptr().cast()
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushlstring(lua: State, bytes: *const u8, count: usize) {
    let source = if count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(bytes, count) }
    };
    text(unsafe { &mut *lua }, source);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_pushstring(lua: State, bytes: *const c_char) {
    if bytes.is_null() {
        unsafe { lua_pushnil(lua) };
    } else {
        text(
            unsafe { &mut *lua },
            unsafe { CStr::from_ptr(bytes) }.to_bytes(),
        );
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_tolstring(
    lua: State,
    index: c_int,
    length: *mut usize,
) -> *const c_char {
    let vm = unsafe { &mut *lua };
    let string = match read(vm, index) {
        Value::Str(s) => Some(s),
        number @ (Value::Float(_) | Value::Int(_)) => {
            let bytes = concat_piece(number, vm.float_fmt()).unwrap();
            let s = vm.heap.intern(&bytes);
            if let Some(slot) = slot(vm, index) {
                vm.capi_stack[slot] = Value::Str(s);
            } else {
                return ptr::null();
            }
            Some(s)
        }
        _ => None,
    };
    if !length.is_null() {
        unsafe { length.write(string.map_or(0, |s| s.as_bytes().len())) };
    }
    string.map_or(ptr::null(), |s| s.as_bytes().as_ptr().cast())
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_toboolean(lua: State, index: c_int) -> c_int {
    c_int::from(read(unsafe { &*lua }, index).truthy())
}

fn number(vm: &Vm, index: c_int) -> Option<f64> {
    as_num(read(vm, index), vm.version()).map(|value| value.as_f64())
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_tonumber(lua: State, index: c_int) -> f64 {
    number(unsafe { &*lua }, index).unwrap_or(0.0)
}

#[cfg(target_arch = "x86_64")]
fn integer(number: f64) -> isize {
    use std::arch::x86_64::{_mm_cvttsd_si64, _mm_set_sd};
    // Match the signed Win64 conversion used by the legacy ABI on NaN/overflow.
    unsafe { _mm_cvttsd_si64(_mm_set_sd(number)) as isize }
}

#[cfg(target_arch = "x86")]
fn integer(number: f64) -> isize {
    use std::arch::x86::{_mm_cvttsd_si32, _mm_set_sd};
    // Win32 uses a 32-bit lua_Integer and the same signed overflow convention.
    unsafe { _mm_cvttsd_si32(_mm_set_sd(number)) as isize }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_tointeger(lua: State, index: c_int) -> isize {
    integer(number(unsafe { &*lua }, index).unwrap_or(0.0))
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_isnumber(lua: State, index: c_int) -> c_int {
    c_int::from(number(unsafe { &*lua }, index).is_some())
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_isstring(lua: State, index: c_int) -> c_int {
    c_int::from(matches!(unsafe { lua_type(lua, index) }, 3 | 4))
}

fn expected(vm: &mut Vm, index: c_int, kind: &str) -> ! {
    let actual = value(vm, index).map_or("no value", Value::type_name);
    fail_text(
        vm,
        &format!("bad argument #{index} ({kind} expected, got {actual})"),
    )
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checknumber(lua: State, index: c_int) -> f64 {
    let vm = unsafe { &mut *lua };
    number(vm, index).unwrap_or_else(|| expected(vm, index, "number"))
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checkinteger(lua: State, index: c_int) -> isize {
    integer(unsafe { luaL_checknumber(lua, index) })
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checklstring(
    lua: State,
    index: c_int,
    length: *mut usize,
) -> *const c_char {
    let text = unsafe { lua_tolstring(lua, index, length) };
    if text.is_null() {
        expected(unsafe { &mut *lua }, index, "string");
    }
    text
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checktype(lua: State, index: c_int, kind: c_int) {
    if unsafe { lua_type(lua, index) } != kind {
        let name = [
            "nil",
            "boolean",
            "lightuserdata",
            "number",
            "string",
            "table",
            "function",
            "userdata",
            "thread",
        ];
        expected(
            unsafe { &mut *lua },
            index,
            name.get(kind as usize).unwrap_or(&"value"),
        );
    }
}

fn raw_set(vm: &mut Vm, table: Gc<Table>, key: Value, value: Value) {
    let update = unsafe { table.as_mut() }.set(&mut vm.heap, key, value);
    if let Err(error) = update {
        fail_text(vm, &format!("{error:?}"));
    }
    vm.barrier_back_table(table);
}

fn table(vm: &mut Vm, index: c_int) -> Gc<Table> {
    match read(vm, index) {
        Value::Table(table) => table,
        _ => expected(vm, index, "table"),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_createtable(lua: State, array: c_int, records: c_int) {
    let vm = unsafe { &mut *lua };
    let table = vm.heap.new_table_sized(array.max(0) as usize);
    unsafe { table.as_mut() }.ensure_hash(&mut vm.heap, records.max(0) as usize);
    vm.capi_stack.push(Value::Table(table));
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_getfield(lua: State, index: c_int, name: *const c_char) {
    let vm = unsafe { &mut *lua };
    let target = read(vm, index);
    let key = Value::Str(vm.heap.intern(unsafe { CStr::from_ptr(name) }.to_bytes()));
    let value = vm.index_value(target, key);
    let value = result(vm, value);
    vm.capi_stack.push(value);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_gettable(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let target = read(vm, index);
    let key = read(vm, -1);
    let value = vm.index_value(target, key);
    let value = result(vm, value);
    vm.capi_stack.pop();
    vm.capi_stack.push(value);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_setfield(lua: State, index: c_int, name: *const c_char) {
    let vm = unsafe { &mut *lua };
    let target = read(vm, index);
    let key = Value::Str(vm.heap.intern(unsafe { CStr::from_ptr(name) }.to_bytes()));
    let update = vm.newindex_value(target, key, read(vm, -1));
    result(vm, update);
    vm.capi_stack.pop();
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_settable(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let update = vm.newindex_value(read(vm, index), read(vm, -2), read(vm, -1));
    result(vm, update);
    vm.capi_stack.truncate(vm.capi_stack.len() - 2);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_rawget(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    let key = vm.capi_stack.pop().unwrap_or(Value::Nil);
    vm.capi_stack.push(table.get(key));
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_rawgeti(lua: State, index: c_int, key: c_int) {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    vm.capi_stack.push(table.get_int(i64::from(key)));
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_rawset(lua: State, index: c_int) {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    raw_set(vm, table, read(vm, -2), read(vm, -1));
    vm.capi_stack.truncate(vm.capi_stack.len() - 2);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_rawseti(lua: State, index: c_int, key: c_int) {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    raw_set(vm, table, Value::Int(i64::from(key)), read(vm, -1));
    vm.capi_stack.pop();
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_next(lua: State, index: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    let next = table.next(read(vm, -1));
    vm.capi_stack.pop();
    match next {
        Ok(Some((key, value))) => {
            vm.capi_stack.extend([key, value]);
            1
        }
        Ok(None) => 0,
        Err(error) => fail_text(vm, &format!("{error:?}")),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_rawequal(lua: State, a: c_int, b: c_int) -> c_int {
    let vm = unsafe { &*lua };
    c_int::from(
        value(vm, a)
            .zip(value(vm, b))
            .is_some_and(|(a, b)| a.raw_eq(b)),
    )
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_equal(lua: State, a: c_int, b: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    if let Some((a, b)) = value(vm, a).zip(value(vm, b)) {
        let equal = vm.equal(a, b);
        c_int::from(result(vm, equal))
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_lessthan(lua: State, a: c_int, b: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    if let Some((a, b)) = value(vm, a).zip(value(vm, b)) {
        let less = vm.less_than(a, b, false);
        c_int::from(result(vm, less))
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_getmetatable(lua: State, at: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    if let Some(table) = vm.metatable_of(read(vm, at)) {
        vm.capi_stack.push(Value::Table(table));
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_setmetatable(lua: State, at: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    let metatable = match read(vm, -1) {
        Value::Nil => None,
        Value::Table(t) => Some(t),
        _ => expected(vm, -1, "table"),
    };
    match read(vm, at) {
        Value::Table(value) => {
            unsafe { value.as_mut() }.set_metatable(metatable);
            vm.barrier_back_table(value);
            vm.check_finalizer(value);
        }
        Value::Userdata(value) => {
            unsafe { value.as_mut() }.set_metatable(metatable);
            vm.heap.barrier_back(value.as_ptr().cast());
            vm.check_finalizer_userdata(value);
        }
        other => vm.set_type_metatable(other, metatable),
    }
    vm.capi_stack.pop();
    1
}

struct UserBytes {
    data: Box<[u128]>,
    bytes: usize,
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_newuserdata(lua: State, bytes: usize) -> *mut c_void {
    let vm = unsafe { &mut *lua };
    let words = bytes.div_ceil(16).max(1);
    let mut data = Vec::new();
    if data.try_reserve_exact(words).is_err() {
        fail_text(vm, "not enough memory for userdata");
    }
    data.resize(words, 0u128);
    let mut data = data.into_boxed_slice();
    let pointer = data.as_mut_ptr().cast();
    let value = vm.heap.new_userdata(
        UserdataPayload::Host {
            type_id: TypeId::of::<UserBytes>(),
            data: Box::new(UserBytes { data, bytes }),
            trace_fn: None,
        },
        true,
    );
    vm.capi_stack.push(Value::Userdata(value));
    pointer
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_touserdata(lua: State, at: c_int) -> *mut c_void {
    userdata_pointer(read(unsafe { &*lua }, at))
}

fn userdata_pointer(value: Value) -> *mut c_void {
    match value {
        Value::LightUserdata(p) => p.cast_mut().cast(),
        Value::Userdata(value) => unsafe { value.as_mut() }
            .downcast_mut::<UserBytes>()
            .map_or(ptr::null_mut(), |u| u.data.as_mut_ptr().cast()),
        _ => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_objlen(lua: State, index: c_int) -> usize {
    let vm = unsafe { &mut *lua };
    match read(vm, index) {
        Value::Str(s) => s.as_bytes().len(),
        number @ (Value::Float(_) | Value::Int(_)) => {
            concat_piece(number, vm.float_fmt()).unwrap().len()
        }
        Value::Table(t) => t.len() as usize,
        Value::Userdata(u) => u.downcast::<UserBytes>().map_or(0, |u| u.bytes),
        _ => 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_newmetatable(lua: State, name: *const c_char) -> c_int {
    let vm = unsafe { &mut *lua };
    let registry = table(vm, REGISTRY);
    let key = Value::Str(vm.heap.intern(unsafe { CStr::from_ptr(name) }.to_bytes()));
    let mut value = registry.get(key);
    let missing = value.is_nil();
    if missing {
        value = Value::Table(vm.heap.new_table());
        raw_set(vm, registry, key, value);
    }
    vm.capi_stack.push(value);
    c_int::from(missing)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_checkudata(
    lua: State,
    index: c_int,
    name: *const c_char,
) -> *mut c_void {
    let vm = unsafe { &mut *lua };
    let raw = userdata_pointer(read(vm, index));
    let key = Value::Str(vm.heap.intern(unsafe { CStr::from_ptr(name) }.to_bytes()));
    let wanted = table(vm, REGISTRY).get(key);
    if let (Value::Userdata(data), Value::Table(wanted)) = (read(vm, index), wanted) {
        if !raw.is_null() && data.metatable().is_some_and(|actual| actual.ptr_eq(wanted)) {
            return raw;
        }
    }
    expected(
        vm,
        index,
        unsafe { CStr::from_ptr(name) }
            .to_str()
            .unwrap_or("userdata"),
    );
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_ref(lua: State, index: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    let value = vm.capi_stack.pop().unwrap_or(Value::Nil);
    if value.is_nil() {
        return -1;
    }
    let index = if let Value::Int(free @ 1..) = table.get_int(0) {
        raw_set(vm, table, Value::Int(0), table.get_int(free));
        free
    } else {
        table.len() + 1
    };
    raw_set(vm, table, Value::Int(index), value);
    index as c_int
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_unref(lua: State, index: c_int, reference: c_int) {
    if reference <= 0 {
        return;
    }
    let vm = unsafe { &mut *lua };
    let table = table(vm, index);
    let reference = Value::Int(i64::from(reference));
    raw_set(vm, table, reference, table.get_int(0));
    raw_set(vm, table, Value::Int(0), reference);
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_concat(lua: State, count: c_int) {
    let vm = unsafe { &mut *lua };
    if count == 0 {
        text(vm, b"");
    }
    for _ in 1..count {
        let left = read(vm, -2);
        let right = read(vm, -1);
        let pair = vm.capi_concat(left, right);
        let result = result(vm, pair);
        vm.capi_stack.truncate(vm.capi_stack.len() - 2);
        vm.capi_stack.push(result);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn lua_gc(lua: State, command: c_int, data: c_int) -> c_int {
    let vm = unsafe { &mut *lua };
    match command {
        0 | 1 => {
            vm.heap.gc_set_stopped(command == 0);
            0
        }
        2 => {
            vm.collect_garbage();
            0
        }
        3 => (vm.memory_used() / 1024) as c_int,
        4 => (vm.memory_used() % 1024) as c_int,
        5 => c_int::from(vm.gc_step(data.max(0) as usize * 1024)),
        _ => -1,
    }
}

fn load(vm: &mut Vm, source: &[u8], name: &[u8]) -> c_int {
    match vm.load_buffer(source, name, None) {
        Ok(function) => {
            vm.capi_stack.push(function);
            0
        }
        Err(error) => {
            text(vm, error.to_string().as_bytes());
            ERRSYNTAX
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_loadbuffer(
    lua: State,
    data: *const u8,
    length: usize,
    name: *const c_char,
) -> c_int {
    let source = if length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, length) }
    };
    load(
        unsafe { &mut *lua },
        source,
        unsafe { CStr::from_ptr(name) }.to_bytes(),
    )
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_loadstring(lua: State, data: *const c_char) -> c_int {
    let content = unsafe { CStr::from_ptr(data) }.to_bytes();
    load(unsafe { &mut *lua }, content, content)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn luaL_loadfile(lua: State, path: *const c_char) -> c_int {
    let path = unsafe { CStr::from_ptr(path) };
    let vm = unsafe { &mut *lua };
    match crate::vm::zapret_io::read_source(path.to_bytes(), vm.loader_input_budget()) {
        Ok(bytes) => {
            let mut input = bytes
                .as_slice()
                .strip_prefix(b"\xef\xbb\xbf")
                .unwrap_or(&bytes);
            if input.starts_with(b"#") {
                input = input
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(&[], |at| &input[at..]);
            }
            let mut name = vec![b'@'];
            name.extend_from_slice(path.to_bytes());
            load(vm, input, &name)
        }
        Err(error) => {
            text(
                vm,
                format!("cannot open {}: {error}", path.to_string_lossy()).as_bytes(),
            );
            ERRFILE
        }
    }
}

struct OwnedScriptBuffer {
    bytes: *mut c_char,
    release: ReleaseBuffer,
}

impl Drop for OwnedScriptBuffer {
    fn drop(&mut self) {
        unsafe { (self.release)(self.bytes.cast()) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_lua_load_owned_buffer(
    lua: State,
    bytes: *mut c_char,
    length: usize,
    source: *const c_char,
    load: LoadBuffer,
    release: ReleaseBuffer,
) -> c_int {
    // The VM's protected error unwinds through this owner before lua_pcall catches it.
    let buffer = OwnedScriptBuffer { bytes, release };
    unsafe { load(lua, buffer.bytes, length, source) }
}

unsafe extern "C" {
    fn _vscprintf(format: *const c_char, list: VaList<'_>) -> c_int;
    fn vsnprintf(
        out: *mut c_char,
        capacity: usize,
        format: *const c_char,
        list: VaList<'_>,
    ) -> c_int;
}

unsafe fn push_native_diagnostic(
    lua: State,
    format: *const c_char,
    list: VaList<'_>,
) -> *const c_char {
    let vm = unsafe { &mut *lua };
    let needed = unsafe { _vscprintf(format, list.clone()) };
    if !(0..MAX_DIAGNOSTIC_BYTES as c_int).contains(&needed) {
        return text(vm, b"invalid native diagnostic");
    }
    let mut formatted = vec![0u8; needed as usize + 1];
    if unsafe { vsnprintf(formatted.as_mut_ptr().cast(), formatted.len(), format, list) } != needed
    {
        return text(vm, b"invalid native diagnostic");
    }
    text(vm, &formatted[..needed as usize])
}

#[unsafe(export_name = "lua_pushfstring")]
unsafe extern "C-unwind" fn push_formatted_string(
    lua: State,
    format: *const c_char,
    args: ...
) -> *const c_char {
    unsafe { push_native_diagnostic(lua, format, args) }
}

#[unsafe(export_name = "luaL_error")]
unsafe extern "C-unwind" fn raise_formatted_error(
    lua: State,
    format: *const c_char,
    args: ...
) -> c_int {
    unsafe {
        push_native_diagnostic(lua, format, args);
        lua_error(lua)
    }
}

type Hook = unsafe extern "C-unwind" fn(State, *mut c_void);

// The engine publishes one VM per process. A control thread records only the
// address and never borrows or dereferences a VM that is executing Lua.
static PENDING_INTERRUPT: AtomicPtr<Vm> = AtomicPtr::new(ptr::null_mut());

fn clear_interrupt(lua: State) -> bool {
    PENDING_INTERRUPT.load(Ordering::Relaxed) == lua
        && PENDING_INTERRUPT
            .compare_exchange(lua, ptr::null_mut(), Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
}

pub(super) fn take_interrupt(vm: &mut Vm) -> bool {
    clear_interrupt(ptr::from_mut(vm))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn lua_sethook(lua: State, hook: Option<Hook>, _: c_int, _: c_int) -> c_int {
    if hook.is_some() {
        PENDING_INTERRUPT.store(lua, Ordering::Release);
    } else {
        clear_interrupt(lua);
    }
    1
}
