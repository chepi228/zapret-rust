/* MIT. Native observations and all VM calls execute between Rust policy steps. */
#define ZAPRET_LUA_SCALAR_OUTER_RUST 1
#include "lua_aux_abi.h"
#include "route_source_windows.h"
typedef struct {const uint8_t *data;size_t length;}zapret_lua_scalar_span;
typedef struct {const void *pointer;const char *text;int64_t integer;size_t length;int32_t guard,count;uint32_t mode,phase;}zapret_lua_scalar_state;
typedef struct {const char *text;const void *data;int64_t integer;size_t length;uint32_t kind;int32_t index;uint32_t mode;int32_t count;}zapret_lua_scalar_action;
typedef struct {zapret_lua_scalar_span span;const void *pointer;int64_t integer;int32_t status,count;}zapret_lua_scalar_value;
bool zapret_lua_scalar_begin(uint32_t,int32_t,zapret_lua_scalar_state *,zapret_lua_scalar_action *);
bool zapret_lua_scalar_step(zapret_lua_scalar_state *,const zapret_lua_scalar_value *,zapret_lua_scalar_action *);
static int native_lua_system_project(lua_State *,uint32_t,const void *);
static void lua_timex(lua_State *,time_t (*)(struct tm *));
static int lua_get_ifaddrs(lua_State *);
_Static_assert(sizeof(zapret_lua_scalar_state) == 2 * sizeof(void *) + 32 &&
    sizeof(zapret_lua_scalar_action) == 2 * sizeof(void *) + 32 &&
    sizeof(zapret_lua_scalar_value) == 2 * sizeof(void *) + 24, "Rust Lua scalar entry ABI");
static int native_lua_scalar(lua_State *L,uint32_t mode)
{
    zapret_lua_scalar_state state;zapret_lua_scalar_action action;zapret_lua_scalar_value value={0};
    struct utsname system;struct timespec clock;wf_file_info file;struct tm calendar;time_t seconds;uint8_t source[16];
    if(!zapret_lua_scalar_begin(mode,lua_gettop(L),&state,&action))return luaL_error(L,"invalid Lua scalar entry");
    for(;;){
        switch(action.kind){
        case 0:return action.count;
        case 1:return luaL_error(L,zapret_lua_arity_error(action.count,(int)action.integer,(int)action.integer,false),action.text,(int)action.integer,action.count);
        case 2:value.span.data=(const uint8_t *)luaL_checkstring(L,action.index);value.span.length=0;break;
        case 3:value.span.data=(const uint8_t *)lua_reqlstring(L,action.index,&value.span.length);break;
        case 4:value.integer=(int64_t)luaL_checklint(L,action.index);break;
        case 5:value.integer=lua_gettop(L);break;
        case 6:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 7:lua_pushnil(L);break;
        case 8:lua_pushinteger(L,(lua_Integer)action.integer);break;
        case 9:lua_pushstring(L,(const char *)action.data);break;
        case 10:switch(action.mode){case 0:DLOG(action.text,(const char *)action.data);break;case 1:DLOG_ERR(action.text,(const char *)action.data);break;case 2:DLOG_CONDUP(action.text,(const char *)action.data);break;}break;
        case 11:switch(action.mode){case 0:return luaL_error(L,action.text,(unsigned int)action.length);case 1:return luaL_error(L,action.text);}return luaL_error(L,"invalid Lua scalar error");
        case 12:value.count=native_lua_system_project(L,action.mode,action.data);break;
        case 30:value.integer=getpid();break;
        case 31:value.integer=GetCurrentThreadId();break;
        case 32:lua_get_ifaddrs(L);break;
        case 33:value.status=(int32_t)zapret_lua_source_ip(action.data,action.length,source,NULL);value.pointer=source;break;
        case 34:value.status=uname(&system);value.pointer=&system;break;
        case 35:value.status=clock_gettime(CLOCK_REALTIME,&clock);value.pointer=&clock;break;
        case 36:value.status=wf_file_stat(action.data,&file);value.pointer=&file;break;
        case 37:seconds=(time_t)action.integer;value.pointer=localtime_r(&seconds,&calendar);break;
        case 38:seconds=(time_t)action.integer;value.pointer=gmtime_r(&seconds,&calendar);break;
        case 39:lua_timex(L,mktime);break;
        case 40:lua_timex(L,timegm);break;
        case 41:value.span.data=(const uint8_t *)strerror(errno);value.span.length=0;break;
        case 42:value.integer=errno;break;
        default:return luaL_error(L,"invalid Lua scalar action");
        }
        if(!zapret_lua_scalar_step(&state,&value,&action))return luaL_error(L,"invalid Lua scalar state");
    }
}
#define NATIVE_SCALAR(name,mode) static int luacall_##name(lua_State *L){return native_lua_scalar(L,mode);}
NATIVE_SCALAR(DLOG,0)
NATIVE_SCALAR(DLOG_ERR,1)
NATIVE_SCALAR(DLOG_CONDUP,2)
NATIVE_SCALAR(getpid,3)
NATIVE_SCALAR(gettid,4)
NATIVE_SCALAR(get_ifaddrs,5)
NATIVE_SCALAR(get_source_ip,6)
NATIVE_SCALAR(uname,7)
NATIVE_SCALAR(clock_gettime,8)
NATIVE_SCALAR(clock_getfloattime,9)
NATIVE_SCALAR(stat,10)
NATIVE_SCALAR(localtime,11)
NATIVE_SCALAR(gmtime,12)
NATIVE_SCALAR(timelocal,13)
NATIVE_SCALAR(timegm,14)
#undef NATIVE_SCALAR
