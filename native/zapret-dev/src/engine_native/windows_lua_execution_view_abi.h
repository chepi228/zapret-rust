/* MIT. Pinned Win64 LuaJIT argument and execution-view entry ABI. */
#pragma once
#include "params.h"
#include "lua_aux_abi.h"
#include <stddef.h>

typedef struct {
    const char *name, *text;
    uint32_t kind;
} zapret_lua_execution_argument_abi;

typedef struct {
    const struct func_list *next;
    uint32_t number, completed, profile;
    bool incoming;
} zapret_lua_execution_cursor_abi;

typedef struct {
    const char *name;
    const struct str2_list_head *args;
    const struct packet_range *range;
    uint64_t payload;
    uint32_t number, index;
    char instance[256];
} zapret_lua_execution_entry_abi;

_Static_assert(sizeof(zapret_lua_execution_argument_abi) == 24 &&
    offsetof(zapret_lua_execution_argument_abi, kind) == 16 &&
    sizeof(struct str2_list_head) == 8 && offsetof(struct str2_list_head, lh_first) == 0 &&
    sizeof(struct str2_list) == 32 && offsetof(struct str2_list, next.le_next) == 16,
    "Rust Lua execution arguments ABI");
_Static_assert(sizeof(zapret_lua_execution_cursor_abi) == 24 &&
    offsetof(zapret_lua_execution_cursor_abi, incoming) == 20 &&
    sizeof(zapret_lua_execution_entry_abi) == 296 &&
    offsetof(zapret_lua_execution_entry_abi, instance) == 40 &&
    offsetof(struct func_list, args) == 56 && offsetof(struct func_list, next.le_next) == 64,
    "Rust Lua execution plan ABI");
_Static_assert(LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == 8 &&
    LUA_CTX_PLAN_INVALID == 6 && LUA_PLAN_FUNC == 8 && LUA_PLAN_FUNC_N == 9 &&
    LUA_PLAN_INSTANCE == 10 && LUA_PLAN_RANGE == 11 && LUA_PLAN_PAYLOAD == 12 &&
    LUA_PLAN_FILTER == 13 && LUA_PLAN_ARG == 14, "Rust Lua execution constants ABI");

bool lua_pushf_args(lua_State *, const struct str2_list_head *, int, bool);
int luacall_execution_plan(lua_State *);
