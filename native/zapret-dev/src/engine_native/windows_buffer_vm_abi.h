/* MIT. Binary-buffer callbacks from the Windows Rust VM object. */
#pragma once

#include <lua.h>
#include <stddef.h>

_Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t), "Rust Lua buffer VM ABI");

int luacall_brandom(lua_State *);
int luacall_brandom_az(lua_State *);
int luacall_brandom_az09(lua_State *);
int luacall_bcryptorandom(lua_State *);
int luacall_parse_hex(lua_State *);
int luacall_bxor(lua_State *);
int luacall_bor(lua_State *);
int luacall_band(lua_State *);
