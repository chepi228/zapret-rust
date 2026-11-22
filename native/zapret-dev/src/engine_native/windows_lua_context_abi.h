/* MIT. Include after the engine's lua.h to check its registry-context ABI. */
#pragma once

int luacall_raw_packet(lua_State *);
#include "params.h"
#include "lua_aux_abi.h"
#include <stddef.h>

_Static_assert(sizeof(struct params_s) == 16896 &&
    offsetof(struct params_s, ref_desync_ctx) == 16880 &&
    offsetof(struct params_s, L) == 16888 &&
    __builtin_types_compatible_p(__typeof__(params.ref_desync_ctx), int) &&
    __builtin_types_compatible_p(__typeof__(params.L), lua_State *),
    "Rust Lua context parameters ABI");
_Static_assert(LUA_VERSION_NUM == 501 && LUA_REGISTRYINDEX == -10000 &&
    LUA_TNIL == 0 && sizeof(t_lua_desync_context) == 56 &&
    LUA_CTX_METATABLE == 0 && LUA_CTX_MISSING == 1 && LUA_CTX_INVALID == 2 &&
    LUA_CTX_STORAGE_INVALID == 7, "Rust Lua registry context ABI");

t_lua_desync_context *lua_desync_ctx(lua_State *);
void lua_desync_ctx_create(lua_State *);
