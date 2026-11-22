/* Windows Lua callbacks linked from the standalone Rust unwind object. */
#pragma once
#include <stddef.h>

_Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t) && sizeof(lua_Number) == 8 && LUA_TNIL == 0,
    "Rust numeric VM ABI");

int luacall_bitlshift(lua_State *);
int luacall_bitrshift(lua_State *);
int luacall_bitand(lua_State *);
int luacall_bitor(lua_State *);
int luacall_bitxor(lua_State *);
int luacall_bitnot8(lua_State *);
int luacall_bitnot16(lua_State *);
int luacall_bitnot24(lua_State *);
int luacall_bitnot32(lua_State *);
int luacall_bitnot48(lua_State *);
int luacall_bitget(lua_State *);
int luacall_bitset(lua_State *);
int luacall_swap16(lua_State *);
int luacall_swap24(lua_State *);
int luacall_swap32(lua_State *);
int luacall_swap48(lua_State *);
int luacall_u8add(lua_State *);
int luacall_u16add(lua_State *);
int luacall_u24add(lua_State *);
int luacall_u32add(lua_State *);
int luacall_u48add(lua_State *);
int luacall_divint(lua_State *);
int luacall_u8(lua_State *);
int luacall_u16(lua_State *);
int luacall_u24(lua_State *);
int luacall_u32(lua_State *);
int luacall_u48(lua_State *);
int luacall_bu8(lua_State *);
int luacall_bu16(lua_State *);
int luacall_bu24(lua_State *);
int luacall_bu32(lua_State *);
int luacall_bu48(lua_State *);
