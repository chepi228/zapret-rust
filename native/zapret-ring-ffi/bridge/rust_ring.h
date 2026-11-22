/* Narrow built-in Lua bridge. No generic library loader or FFI is enabled. */
#ifndef ZAPRET_RUST_RING_H
#define ZAPRET_RUST_RING_H
#include <lua.h>
int rust_ring_register(lua_State *L);
#endif
