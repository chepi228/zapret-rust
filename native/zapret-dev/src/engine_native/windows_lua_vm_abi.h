/* MIT. Data addresses and entries for the Windows Lua lifecycle. */
#pragma once
#include "windows_startup_params_abi.h"
#include <stddef.h>

typedef struct {
    lua_State **lua;
    t_conntrack *conntrack;
    timer_pool **timers;
    const uint64_t *gc_interval;
    uint64_t *gc_time;
    const char *jit_version;
    const char *jit_edition;
    unsigned int lua_version;
} zapret_lua_vm_source_fields;

_Static_assert(sizeof(zapret_lua_vm_source_fields) == 8 * sizeof(void *) &&
    offsetof(zapret_lua_vm_source_fields, jit_version) == 5 * sizeof(void *) &&
    offsetof(zapret_lua_vm_source_fields, lua_version) == 7 * sizeof(void *),
    "Rust Lua VM source ABI");
_Static_assert(LUA_VERSION_NUM == 501 && LUA_REGISTRYINDEX == -10000 &&
    LUA_MULTRET == -1 && LUA_TTABLE == 5 && LUA_TFUNCTION == 6 &&
    LUA_GCCOLLECT == 2 && LUA_GCCOUNT == 3, "Rust Lua VM macro ABI");

extern const zapret_lua_vm_source_fields zapret_lua_vm_sources;
bool lua_basic_init(void);
void lua_cleanup(lua_State *);
void lua_shutdown(void);
void lua_do_gc(void);
