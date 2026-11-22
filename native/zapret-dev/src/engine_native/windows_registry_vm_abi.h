/* MIT. Native parameter slots and callback addresses for Rust registration. */
#pragma once

#include <lua.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    lua_State *const *lua;
    const char *version;
    const uint32_t *mark;
    const bool *debug, *daemon, *server, *cache_hostname, *ctrack_disable;
    const lua_CFunction *callbacks;
    size_t count;
    void (*create_context)(lua_State *);
} zapret_lua_registry_source;

_Static_assert(sizeof(zapret_lua_registry_source) == 11 * sizeof(void *) &&
    offsetof(zapret_lua_registry_source, callbacks) == 8 * sizeof(void *) &&
    LUA_GLOBALSINDEX == -10002 && sizeof(lua_Integer) == sizeof(ptrdiff_t),
    "Rust Lua registry VM ABI");

void lua_init_const(void);
void lua_init_functions(void);
void lua_init_mt(void);
