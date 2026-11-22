/* MIT. Pinned LuaJIT initialization entry and stack layout. */
#pragma once

_Static_assert(sizeof(struct params_s) == 16896 &&
    offsetof(struct params_s, L) == 16888, "Rust Lua startup state");

bool lua_init(void);
