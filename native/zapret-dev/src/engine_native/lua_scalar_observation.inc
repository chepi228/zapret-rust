/* MIT. Trace complete scalar entries, preserving real LuaJIT native coercion. */
#include <stdarg.h>
#include "route_source_windows.h"
static unsigned current_api,scalar_basic_api,scalar_errno_mutation;
static bool current_rust;
static uint64_t scalar_hash(const void *data,size_t size){const uint8_t *bytes=data;uint64_t value=1469598103934665603ULL;for(size_t i=0;i<size;++i){value^=bytes[i];value*=1099511628211ULL;}return value;}
static void scalar_event(const char *name,int64_t first,int64_t second){char text[100];snprintf(text,sizeof(text),"%s:%lld:%lld",name,(long long)first,(long long)second);trace(text);}
static int scalar_top(lua_State *L){int value=lua_gettop(L);scalar_event("top",value,0);return value;}
static void scalar_checktype(lua_State *L,int index,int type){scalar_event("checktype",index,type);luaL_checktype(L,index,type);}
static const char *scalar_checkstring(lua_State *L,int index,size_t *length){scalar_event("checkstring",index,length!=NULL);const char *value=luaL_checklstring(L,index,length);return value;}
static const char *scalar_tolstring(lua_State *L,int index,size_t *length){scalar_event("tolstring",index,length!=NULL);return lua_tolstring(L,index,length);}
static lua_Integer scalar_checkinteger(lua_State *L,int index){scalar_event("checkinteger",index,0);return luaL_checkinteger(L,index);}
static void scalar_integer(lua_State *L,lua_Integer value){scalar_event("integer",(int64_t)value,0);lua_pushinteger(L,value);}
static void scalar_number(lua_State *L,lua_Number value){uint64_t bits;memcpy(&bits,&value,8);scalar_event("number",(int64_t)bits,0);lua_pushnumber(L,value);}
static void scalar_string(lua_State *L,const char *value){scalar_event("string",value?(int64_t)scalar_hash(value,strlen(value)):0,value!=NULL);lua_pushstring(L,value);if(scalar_errno_mutation==2 && current_api==0)errno=EBUSY;}
static void scalar_bytes(lua_State *L,const char *value,size_t size){scalar_event("bytes",size,(int64_t)scalar_hash(value,size));lua_pushlstring(L,value,size);}
static void scalar_nil(lua_State *L){trace("nil");lua_pushnil(L);if(scalar_errno_mutation && current_api==0)errno=ESPIPE;}
static void scalar_table(lua_State *L,int array,int records){scalar_event("table",array,records);lua_createtable(L,array,records);}
static void scalar_field(lua_State *L,int index,const char *name){scalar_event("field",index,(int64_t)scalar_hash(name,strlen(name)));lua_getfield(L,index,name);}
static int scalar_error(lua_State *L,const char *format,...){char text[1024];va_list args;va_start(args,format);vsnprintf(text,sizeof(text),format,args);va_end(args);scalar_event("error",(int64_t)scalar_hash(text,strlen(text)),0);return luaL_error(L,"%s",text);}
static int scalar_pid(void){trace("pid");if(active)++active->native_calls;return native_variant%3==0?INT_MIN:native_variant%3==1?0:12345;}
static DWORD scalar_tid(void){trace("tid");if(active)++active->native_calls;return native_variant%3==0?UINT32_MAX:native_variant%3==1?0:42;}
static int scalar_log(unsigned target,const char *format,va_list arguments){char text[1024];vsnprintf(text,sizeof(text),format,arguments);scalar_event("log",target,(int64_t)scalar_hash(text,strlen(text)));return (int)strlen(text);}
static int scalar_dlog(const char *format,...){va_list args;va_start(args,format);int result=scalar_log(0,format,args);va_end(args);return result;}
static int scalar_dlog_error(const char *format,...){va_list args;va_start(args,format);int result=scalar_log(1,format,args);va_end(args);return result;}
static int scalar_dlog_condup(const char *format,...){va_list args;va_start(args,format);int result=scalar_log(2,format,args);va_end(args);return result;}
static uint32_t scalar_source(const uint8_t *input,size_t length,uint8_t *output,const zapret_route_source_ops *ops){CHECK(!ops);scalar_event("source",length,0);if(active)++active->native_calls;if(length!=4 && length!=16)return 2;if(native_variant%7==0)return 0;memcpy(output,input,length);return 1;}
static int lua_get_ifaddrs(lua_State *L){trace("ifaddrs");if(active)++active->native_calls;lua_createtable(L,0,1);lua_pushinteger(L,native_variant);lua_setfield(L,-2,"fixture");return native_variant%3?1:0;}
#undef getpid
#define getpid scalar_pid
#undef GetCurrentThreadId
#define GetCurrentThreadId scalar_tid
#undef DLOG
#undef DLOG_ERR
#undef DLOG_CONDUP
#define DLOG scalar_dlog
#define DLOG_ERR scalar_dlog_error
#define DLOG_CONDUP scalar_dlog_condup
#define zapret_lua_source_ip scalar_source
#define lua_gettop scalar_top
#define luaL_checktype scalar_checktype
#define luaL_checklstring scalar_checkstring
#define lua_tolstring scalar_tolstring
#define luaL_checkinteger scalar_checkinteger
#define lua_pushinteger scalar_integer
#define lua_pushnumber scalar_number
#define lua_pushstring scalar_string
#define lua_pushlstring scalar_bytes
#define lua_pushnil scalar_nil
#define lua_createtable scalar_table
#define lua_getfield scalar_field
#define luaL_error scalar_error
