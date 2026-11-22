/* MIT. Windows Lua sandbox and blob publication entries. */
#pragma once
#include "windows_startup_params_abi.h"
#include "blob_windows.h"
#include <stddef.h>

typedef struct {
    lua_State *const *lua;
    struct blob_collection_head *blobs;
    const zapret_blob_allocator *allocator;
} zapret_lua_sandbox_source_fields;

_Static_assert(sizeof(zapret_lua_sandbox_source_fields) == 3 * sizeof(void *) &&
    offsetof(zapret_lua_sandbox_source_fields, allocator) == 2 * sizeof(void *),
    "Rust Lua sandbox source ABI");
_Static_assert(LUA_VERSION_NUM == 501 && LUA_GLOBALSINDEX == -10002 && LUA_TTABLE == 5,
    "Rust Lua sandbox macro ABI");

extern const zapret_lua_sandbox_source_fields zapret_lua_sandbox_sources;
void lua_sec_harden(void);
void lua_init_blobs(void);
