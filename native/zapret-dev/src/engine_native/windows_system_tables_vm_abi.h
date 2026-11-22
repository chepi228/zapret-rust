/* MIT. System and calendar snapshot types borrowed by Rust Lua projections. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/utsname.h>

_Static_assert(LUA_TNUMBER == 3 && sizeof(lua_Integer) == sizeof(ptrdiff_t) && sizeof(time_t) == 8 &&
    sizeof(struct tm) == 36 && _Alignof(struct tm) == 4 &&
    offsetof(struct tm, tm_year) == 20 && offsetof(struct tm, tm_isdst) == 32 &&
    sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8 &&
    sizeof(wf_file_info) == 48 && offsetof(wf_file_info, modified) == 32 &&
    sizeof(struct utsname) == 516 && offsetof(struct utsname, nodename) == 65 &&
    offsetof(struct utsname, machine) == 451, "Rust Lua system/time snapshot ABI");

int native_lua_system_project(lua_State *, uint32_t, const void *);
void lua_timex(lua_State *, time_t (*)(struct tm *));
