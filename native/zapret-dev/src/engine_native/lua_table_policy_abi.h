/* MIT. Preexisting Lua table policy records and fixed VM constants. */
#pragma once
#include <stddef.h>

typedef struct {
    const char *name;
    const void *data;
    int64_t number;
    uint32_t kind, flag;
} zapret_lua_table_action;
typedef struct {
    const void *source;
    const char *name;
    uint32_t mode, phase;
} zapret_lua_range_state;
typedef struct {
    const char *blob, *field;
    int32_t index;
    uint32_t mode, phase, success;
} zapret_lua_blob_state;

bool zapret_lua_range_begin(uint32_t, const void *, const char *,
    zapret_lua_range_state *, zapret_lua_table_action *);
bool zapret_lua_range_step(zapret_lua_range_state *, zapret_lua_table_action *);
bool zapret_lua_blob_begin(uint32_t, int32_t, const char *, const char *,
    zapret_lua_blob_state *, zapret_lua_table_action *);
bool zapret_lua_blob_step(zapret_lua_blob_state *, int32_t, zapret_lua_table_action *);

_Static_assert(LUA_TNIL == 0 && LUA_GLOBALSINDEX == -10002 && sizeof(lua_Integer) == sizeof(ptrdiff_t) &&
    sizeof(unsigned int) == 4 && sizeof(zapret_lua_table_action) == 2 * sizeof(void *) + 16 &&
    sizeof(zapret_lua_range_state) == 2 * sizeof(void *) + 8 &&
    sizeof(zapret_lua_blob_state) == 2 * sizeof(void *) + 16 &&
    sizeof(struct packet_pos) == 8 && offsetof(struct packet_pos, pos) == 4 &&
    sizeof(struct packet_range) == 20 && offsetof(struct packet_range, to) == 8 &&
    offsetof(struct packet_range, upper_cutoff) == 16, "Rust Lua table policy ABI");
