/* MIT. LuaJIT execution cutoff and cancellation entries in Rust. */
#pragma once

#include "lua_context_windows.h"

_Static_assert(sizeof(zapret_lua_context_scope_values) == 24 &&
    offsetof(zapret_lua_context_scope_values, profile) == 8 &&
    offsetof(zapret_lua_context_scope_values, registry) == 12 &&
    offsetof(zapret_lua_context_scope_values, incoming) == 16 &&
    offsetof(zapret_lua_context_scope_values, tracked) == 18,
    "Rust Lua cutoff scope ABI");
_Static_assert(LUA_VERSION_NUM == 501 && LUA_REGISTRYINDEX == -10000 &&
    LUA_TBOOLEAN == 1 && sizeof(lua_Integer) == sizeof(intptr_t),
    "Rust Lua cutoff VM ABI");
_Static_assert(LUA_CTX_NIL == 0 && LUA_CTX_HAS_DIRECTION == 1 &&
    LUA_CTX_DIRECTION_PROVIDED == 2 && LUA_CTX_SCRIPT_DIRECTION == 3 &&
    LUA_CTX_NATIVE_DIRECTION == 4 && LUA_CTX_TABLE_NEEDED == 5 &&
    LUA_CTX_CUTOFF_INVALID == 3 && LUA_CTX_EXECUTION_INVALID == 4 &&
    LUA_CTX_INSTANCE_CUTOFF == 15 && LUA_CTX_LUA_CUTOFF == 16 && LUA_CTX_CANCEL == 17 &&
    LUA_CTX_REPORT_MISSING == 0 && LUA_CTX_REPORT_INSTANCE_CUTOFF == 1 &&
    LUA_CTX_REPORT_LUA_CUTOFF == 2 && LUA_CTX_REPORT_CANCEL == 3,
    "Rust Lua cutoff policy constants");

int luacall_instance_cutoff(lua_State *);
bool lua_instance_cutoff_check(lua_State *, const t_lua_desync_context *, bool);
int luacall_lua_cutoff(lua_State *);
int luacall_execution_plan_cancel(lua_State *);
