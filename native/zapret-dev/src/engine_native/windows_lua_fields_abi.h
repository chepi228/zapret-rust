/* MIT. Type checks for the field helpers declared by the engine lua.h. */
#pragma once
#include <stddef.h>
#include <lua.h>

_Static_assert(LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == sizeof(ptrdiff_t) &&
    sizeof(lua_Number) == 8 &&
    LUA_REGISTRYINDEX == -10000 && LUA_GLOBALSINDEX == -10002,
    "Rust Lua field VM ABI");
