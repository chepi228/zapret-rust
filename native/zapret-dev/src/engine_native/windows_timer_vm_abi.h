/* MIT. Verify the pinned Windows engine layout used by the timer VM entry. */
#pragma once
#include "params.h"
#include "timer_lifecycle_windows.h"

_Static_assert(sizeof(struct params_s) == 16896 && offsetof(struct params_s, L) == 16888 &&
    sizeof(params.L) == 8 && __builtin_types_compatible_p(__typeof__(params.L), lua_State *),
    "Rust timer VM state ABI");
_Static_assert(LUA_REGISTRYINDEX == -10000 && sizeof(zapret_timer_info) == 40 &&
    offsetof(zapret_timer_info, name_ref) == 20 && offsetof(zapret_timer_info, func_ref) == 24 &&
    offsetof(zapret_timer_info, data_ref) == 28, "Rust timer reference ABI");
