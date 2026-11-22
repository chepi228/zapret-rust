/* Guest timer callbacks from the standalone Win64 Rust SEH object. */
#pragma once
#include "windows_timer_vm_abi.h"

_Static_assert(offsetof(struct params_s, timers) == 16856 &&
    offsetof(struct params_s, timers_dirty) == 16864 && sizeof(params.timers_dirty) == 1,
    "Rust Lua timer pool ABI");
_Static_assert(LUA_GLOBALSINDEX == -10002 && LUA_TFUNCTION == 6 && sizeof(lua_Integer) == 8,
    "Rust Lua timer macros ABI");

int luacall_timer_set(lua_State *);
int luacall_timer_del(lua_State *);
int luacall_timer_info(lua_State *);
int luacall_timer_enum(lua_State *);
