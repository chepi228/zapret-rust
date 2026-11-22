/* MIT. Existing native address publication entries on Win64 LuaJIT. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <ws2tcpip.h>
#include <lua.h>

_Static_assert(AF_INET == 2 && AF_INET6 == 23 &&
    offsetof(struct sockaddr_in, sin_addr) == 4 && offsetof(struct sockaddr_in6, sin6_addr) == 8,
    "Rust Lua socket address layout");
_Static_assert(LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == sizeof(intptr_t) &&
    sizeof(size_t) == 8, "Rust Lua address publication ABI");

void lua_push_ipaddr(lua_State *, const struct sockaddr *);
void lua_pushf_ipaddr(lua_State *, const char *, const struct sockaddr *);
void lua_pushi_ipaddr(lua_State *, lua_Integer, const struct sockaddr *);
