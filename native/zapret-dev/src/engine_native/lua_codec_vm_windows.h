/* Windows Lua codec callbacks linked from the standalone Rust unwind object. */
#pragma once
#include <stddef.h>

_Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t) && sizeof(uInt) == 4 &&
    sizeof(struct userdata_zs) == sizeof(z_stream) + sizeof(void *) &&
    offsetof(struct userdata_zs, zs) == sizeof(void *) &&
    LUA_REGISTRYINDEX == -10000 && LUA_TNIL == 0, "Rust codec VM ABI");

int lua_cfunc_zstream_gc(lua_State *);
struct userdata_zs *lua_uzs(lua_State *, int, bool);
int luacall_gunzip_init(lua_State *);
int luacall_gzip_init(lua_State *);
int luacall_gunzip_end(lua_State *);
int luacall_gzip_end(lua_State *);
