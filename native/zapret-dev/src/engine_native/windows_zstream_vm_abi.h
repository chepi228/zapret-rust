/* MIT. Windows streaming codec entries with Lua-owned output. */
#pragma once
#include <lua.h>
#include <stddef.h>

_Static_assert(offsetof(struct userdata_zs, zs) == sizeof(void *) &&
    sizeof(lua_Integer) == sizeof(ptrdiff_t) && LUA_TNIL == 0, "Rust zstream VM ABI");

int luacall_gunzip_inflate(lua_State *);
int luacall_gzip_deflate(lua_State *);
