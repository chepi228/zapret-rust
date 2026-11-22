/* MIT. The timer scheduler returns before the engine uses LuaJIT. */
#pragma once
#include "timer_windows.h"

typedef struct {
    uint32_t entry, stage, status, succeeded;
    uint64_t now, after, output;
    zapret_timer_info info, removed;
} zapret_timer_lifecycle_state;

_Static_assert(sizeof(zapret_timer_lifecycle_state) == 120 &&
    offsetof(zapret_timer_lifecycle_state, now) == 16 &&
    offsetof(zapret_timer_lifecycle_state, info) == 40 &&
    offsetof(zapret_timer_lifecycle_state, removed) == 80, "Rust timer lifecycle ABI");
