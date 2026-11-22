/* MIT. Win64 LuaJIT connection publication ABI. */
#pragma once
#include <stddef.h>
#include "lua_connection_view_types.h"

typedef struct {
    const char *name, *data;
    int64_t integer;
    double floating;
    uint32_t kind;
    int32_t index;
} zapret_lua_connection_action;

typedef struct {
    const zapret_lua_track_position_values *view;
    uint32_t index, phase;
} zapret_lua_position_publication_state;

typedef struct {
    zapret_lua_track_values view;
    uint32_t mode, phase;
} zapret_lua_track_publication_state;

_Static_assert(sizeof(struct params_s) == 16896 && offsetof(struct params_s, server) == 12705 &&
    sizeof(params.server) == 1 && LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == 8,
    "Rust Lua connection view fields");
_Static_assert(sizeof(zapret_lua_connection_action) == 40 &&
    offsetof(zapret_lua_connection_action, kind) == 32 &&
    sizeof(zapret_lua_position_publication_state) == 16 &&
    sizeof(zapret_lua_track_publication_state) == 280 &&
    offsetof(zapret_lua_track_publication_state, mode) == 272, "Rust Lua connection publication state");

bool zapret_lua_position_publication_begin(const zapret_lua_track_position_values *,
    zapret_lua_position_publication_state *, zapret_lua_connection_action *);
bool zapret_lua_position_publication_step(zapret_lua_position_publication_state *, zapret_lua_connection_action *);
bool zapret_lua_track_publication_begin(uint32_t, zapret_lua_track_publication_state *, zapret_lua_connection_action *);
bool zapret_lua_track_publication_step(zapret_lua_track_publication_state *, uint32_t, zapret_lua_connection_action *);

void native_lua_push_track_position(lua_State *, const zapret_lua_track_position_values *);
void lua_pushf_ctrack_pos(lua_State *, const t_ctrack *, const t_ctrack_position *);
void lua_push_ctrack(lua_State *, const t_ctrack *, const t_ctrack_positions *, bool);
void lua_pushf_ctrack(lua_State *, const t_ctrack *, const t_ctrack_positions *, bool);
