/* MIT. Declare the Rust Win64 host timer entries with their pinned layouts. */
#pragma once
#include "windows_timer_vm_abi.h"
#include "lua_timer_report_windows.h"

_Static_assert(sizeof(zapret_lua_timer_log) == 16 && offsetof(zapret_lua_timer_log, reason) == 8,
    "Rust timer host diagnostic ABI");
