/* MIT. Crypto and address conversion Lua entries in the Windows Rust unwind object. */
#pragma once
#include <stddef.h>

_Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t) && (lua_Integer)-1 < (lua_Integer)0 &&
    LUA_TNIL == 0 && LUA_TNONE < LUA_TNIL, "Rust crypto Lua ABI");

int luacall_aes(lua_State *);
int luacall_aes_ctr(lua_State *);
int luacall_aes_gcm(lua_State *);
int luacall_hash(lua_State *);
int luacall_hkdf(lua_State *);
int luacall_ntop(lua_State *);
int luacall_pton(lua_State *);
