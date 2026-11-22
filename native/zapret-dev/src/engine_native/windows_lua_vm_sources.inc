/* MIT. Publish native storage and header metadata for the Rust VM entries. */
#include "windows_lua_vm_abi.h"
#include <luajit.h>

_Static_assert(__builtin_strcmp(LUAJIT_VERSION, "LuaJIT 2.1.1756211046") == 0,
    "Rust Lua VM pinned version");
#ifndef OPENRESTY_LUAJIT
#error Rust VM metadata expects the OpenResty LuaJIT edition
#endif

static uint64_t native_lua_gc_time;
const zapret_lua_vm_source_fields zapret_lua_vm_sources = {
    .lua = &params.L,
    .conntrack = &params.conntrack,
    .timers = &params.timers,
    .gc_interval = &params.lua_gc,
    .gc_time = &native_lua_gc_time,
    .jit_version = LUAJIT_VERSION,
#ifdef OPENRESTY_LUAJIT
    .jit_edition = " OpenResty",
#else
    .jit_edition = "",
#endif
    .lua_version = LUA_VERSION_NUM,
};
