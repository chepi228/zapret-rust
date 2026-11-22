/* MIT. Read-only Win64 LuaJIT header entries. */
#pragma once
#include <lua.h>

_Static_assert(LUA_VERSION_NUM == 501 && sizeof(void *) == 8,
    "Rust Lua header decode ABI");

int luacall_dissect_tcphdr(lua_State *);
int luacall_dissect_udphdr(lua_State *);
int luacall_dissect_icmphdr(lua_State *);
int luacall_dissect_iphdr(lua_State *);
int luacall_dissect_ip6hdr(lua_State *);
