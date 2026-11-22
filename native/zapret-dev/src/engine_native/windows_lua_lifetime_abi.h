/* MIT. Verify the pinned Win64 LuaJIT lifetime and diagnostic entry ABI. */
#pragma once
#include "params.h"
#include <stddef.h>

_Static_assert(sizeof(struct params_s) == 16896 &&
    offsetof(struct params_s, ref_desync_ctx) == 16880 &&
    offsetof(struct params_s, L) == 16888 &&
    __builtin_types_compatible_p(__typeof__(params.ref_desync_ctx), int) &&
    __builtin_types_compatible_p(__typeof__(params.L), lua_State *),
    "Rust Lua lifetime state ABI");
_Static_assert(LUA_VERSION_NUM == 501 && LUA_REGISTRYINDEX == -10000 &&
    (LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT | LUA_MASKLINE) == 15,
    "Rust Lua lifetime macro ABI");

void zapret_lua_publish(lua_State *);
void lua_req_quit(void);
void lua_desync_ctx_destroy(lua_State *);
void lua_perror(lua_State *);
int lua_panic(lua_State *);
void lua_dlog_error(void);
