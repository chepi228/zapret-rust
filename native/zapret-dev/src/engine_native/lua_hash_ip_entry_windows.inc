/* MIT. All VM operations and longjmp remain in C, between Rust policy steps. */
#include "lua_aux_abi.h"
typedef struct {const uint8_t *data;size_t length;}zapret_lua_hash_ip_span;
typedef struct {zapret_lua_hash_ip_span inputs[3];const char *name;uint8_t *output;size_t length;uint8_t bytes[65];uint32_t mode,phase,bits,cursor;}zapret_lua_hash_ip_state;
typedef struct {const char *name;const uint8_t *data;size_t length;uint32_t kind;int32_t index;uint32_t count;int32_t expected;uint32_t error;}zapret_lua_hash_ip_action;
typedef struct {zapret_lua_hash_ip_span span;int64_t integer;int32_t kind;}zapret_lua_hash_ip_value;
typedef struct {
    size_t (*hash)(uint32_t,const uint8_t *,size_t,uint8_t *,size_t);
    bool (*hkdf)(uint32_t,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *,size_t);
    size_t (*ntop)(const uint8_t *,size_t,char *,size_t);
    size_t (*pton)(const char *,uint8_t *,size_t);
}zapret_lua_hash_ip_ops;
bool zapret_lua_hash_ip_entry_begin(uint32_t,int32_t,zapret_lua_hash_ip_state *,zapret_lua_hash_ip_action *);
bool zapret_lua_hash_ip_entry_step(zapret_lua_hash_ip_state *,const zapret_lua_hash_ip_value *,zapret_lua_hash_ip_action *,const zapret_lua_hash_ip_ops *);
#ifndef ZAPRET_LUA_HASH_IP_OPS
#define ZAPRET_LUA_HASH_IP_OPS NULL
#endif
_Static_assert(INET6_ADDRSTRLEN == 65 &&
    sizeof(zapret_lua_hash_ip_state) == (sizeof(void *) == 8 ? 160 : 120) &&
    offsetof(zapret_lua_hash_ip_state, mode) == 9 * sizeof(void *) + 68 &&
    sizeof(zapret_lua_hash_ip_action) == (sizeof(void *) == 8 ? 48 : 32) &&
    sizeof(zapret_lua_hash_ip_value) == 2 * sizeof(void *) + 16 &&
    sizeof(zapret_lua_hash_ip_ops) == 4 * sizeof(void *), "Rust Lua hash/IP entry ABI");
static int native_lua_hash_ip_entry(lua_State *L,uint32_t mode)
{
    zapret_lua_hash_ip_state state;zapret_lua_hash_ip_action action;zapret_lua_hash_ip_value value={0};
    if(!zapret_lua_hash_ip_entry_begin(mode,lua_gettop(L),&state,&action))return luaL_error(L,"invalid Lua hash/IP entry");
    for(;;){
        switch(action.kind){
        case 0:return (int)action.count;
        case 1:return luaL_error(L,zapret_lua_arity_error((int)action.count,action.expected,action.expected,false),action.name,action.expected,(int)action.count);
        case 2:value.span.data=(const uint8_t *)luaL_checkstring(L,action.index);value.span.length=0;break;
        case 3:value.span.data=(const uint8_t *)lua_reqlstring(L,action.index,&value.span.length);break;
        case 4:value.kind=lua_type(L,action.index);break;
        case 5:value.span.data=(const uint8_t *)luaL_checklstring(L,action.index,&value.span.length);break;
        case 6:value.integer=(int64_t)luaL_checkinteger(L,action.index);break;
        case 7:value.span.data=lua_newuserdata(L,action.length);value.span.length=action.length;break;
        case 8:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 9:lua_pushnil(L);break;
        case 10:lua_remove(L,action.index);break;
        case 12:value.span.data=(const uint8_t *)lua_reqstring(L,action.index);value.span.length=0;break;
        case 11:switch(action.error){
            case 1:return luaL_error(L,action.name,(const char *)action.data);
            case 2:case 3:return luaL_error(L,action.name);
            }
        default:return luaL_error(L,"invalid Lua hash/IP action");
        }
        if(!zapret_lua_hash_ip_entry_step(&state,&value,&action,ZAPRET_LUA_HASH_IP_OPS))return luaL_error(L,"invalid Lua hash/IP state");
    }
}
static int luacall_hash(lua_State *L){return native_lua_hash_ip_entry(L,0);}
static int luacall_hkdf(lua_State *L){return native_lua_hash_ip_entry(L,1);}
static int luacall_ntop(lua_State *L){return native_lua_hash_ip_entry(L,2);}
static int luacall_pton(lua_State *L){return native_lua_hash_ip_entry(L,3);}
