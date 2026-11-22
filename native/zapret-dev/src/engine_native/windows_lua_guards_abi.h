/* MIT. Shared Rust guards for the pinned Windows LuaJIT ABI. */
#pragma once
#include <lua.h>
#include <stddef.h>

_Static_assert(LUA_VERSION_NUM == 501 && LUA_TSTRING == 4 && sizeof(int) == 4 &&
    sizeof(size_t) == 8 && sizeof(void *) == 8, "Rust Lua guard ABI");

void lua_check_argc(lua_State *, const char *, int);
void lua_check_argc_range(lua_State *, const char *, int, int);
const char *lua_reqlstring(lua_State *, int, size_t *);
const char *lua_reqstring(lua_State *, int);
int lua_absindex(lua_State *, int);
