/* MIT. Win64 LuaJIT position and range result ABI. */
#pragma once
#include <lua.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "protocol.h"

typedef struct {
    int64_t values[128];
    uint32_t count, kind;
} zapret_lua_position_result;

_Static_assert(LUA_VERSION_NUM == 501 && sizeof(int) == 4 && sizeof(lua_Integer) == 8 &&
    sizeof(zapret_lua_position_result) == 1032 && offsetof(zapret_lua_position_result, count) == 1024 &&
    L7P_INVALID == 31 && sizeof(ssize_t) == 8, "Rust Lua position ABI");

uint32_t zapret_lua_positions(uint32_t, const uint8_t *, size_t, const char *, const char *,
    uint32_t, zapret_lua_position_result *);

int luacall_resolve_pos(lua_State *);
int luacall_resolve_multi_pos(lua_State *);
int luacall_resolve_range(lua_State *);
