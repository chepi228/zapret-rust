/* MIT. Windows scalar Lua entries compiled as a VM-unwinding Rust object. */
#pragma once
#define ZAPRET_LUA_SCALAR_OUTER_RUST 1
#include <stddef.h>
#include <stdint.h>
#include <sys/utsname.h>

_Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t) && (lua_Integer)-1 < (lua_Integer)0 &&
    sizeof(time_t) == 8 && sizeof(clockid_t) == 4 && CLOCK_REALTIME == 0 &&
    sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8 &&
    sizeof(struct utsname) == 516 && _Alignof(struct utsname) == 1 &&
    sizeof(struct tm) == 36 && _Alignof(struct tm) == 4 &&
    sizeof(wf_file_info) == 48 && _Alignof(wf_file_info) == 8,
    "Rust scalar Lua observations ABI");

int native_lua_system_project(lua_State *, uint32_t, const void *);
int lua_get_ifaddrs(lua_State *);
void lua_timex(lua_State *, time_t (*)(struct tm *));

int luacall_DLOG(lua_State *);
int luacall_DLOG_ERR(lua_State *);
int luacall_DLOG_CONDUP(lua_State *);
int luacall_getpid(lua_State *);
int luacall_gettid(lua_State *);
int luacall_get_ifaddrs(lua_State *);
int luacall_get_source_ip(lua_State *);
int luacall_uname(lua_State *);
int luacall_clock_gettime(lua_State *);
int luacall_clock_getfloattime(lua_State *);
int luacall_stat(lua_State *);
int luacall_localtime(lua_State *);
int luacall_gmtime(lua_State *);
int luacall_timelocal(lua_State *);
int luacall_timegm(lua_State *);
