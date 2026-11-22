/* MIT. Rust provides report data before C performs any Lua stack operation. */
#pragma once
#include <stdbool.h>
typedef struct {const char *format,*reason;} zapret_lua_timer_log;
zapret_lua_timer_log zapret_lua_timer_report(bool,bool);
