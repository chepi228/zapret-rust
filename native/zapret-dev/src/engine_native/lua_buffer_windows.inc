/* MIT. Resource-free Rust policy; C alone enters Lua and raises VM errors. */
#include "lua_buffer_abi.h"
#ifndef ZAPRET_LUA_BUFFER_OPS
#define ZAPRET_LUA_BUFFER_OPS NULL
#endif
static int native_lua_buffer(lua_State *L,uint32_t mode)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_buffer_state state;zapret_lua_buffer_action action;zapret_lua_buffer_value value={0};
    if(!zapret_lua_buffer_begin(mode,&state,&action))return luaL_error(L,"invalid Lua buffer entry");
    for(;;){
        switch(action.kind){
        case 0:LUA_STACK_GUARD_RETURN(L,(int)action.argc)
        case 1:lua_check_argc(L,action.name,(int)action.argc);break;
        case 2:value.integer=luaL_checkinteger(L,action.index);break;
        case 3:value.span.data=(const uint8_t *)lua_reqlstring(L,action.index,&value.span.length);break;
        case 4:value.span.length=action.length;value.span.data=lua_newuserdata(L,action.length);break;
        case 5:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 6:lua_pop(L,action.index);break;
        case 7:lua_remove(L,action.index);break;
        case 8:lua_pushnil(L);break;
        case 9:switch(action.error){
            case 1:return luaL_error(L,(const char *)action.data,action.name);
            case 2:case 3:return luaL_error(L,(const char *)action.data);
            }
        default:return luaL_error(L,"invalid Lua buffer action");
        }
        if(!zapret_lua_buffer_step(&state,&value,&action,ZAPRET_LUA_BUFFER_OPS))return luaL_error(L,"invalid Lua buffer state");
    }
}
static int luacall_brandom(lua_State *L){return native_lua_buffer(L,0);}
static int luacall_brandom_az(lua_State *L){return native_lua_buffer(L,1);}
static int luacall_brandom_az09(lua_State *L){return native_lua_buffer(L,2);}
static int luacall_bcryptorandom(lua_State *L){return native_lua_buffer(L,3);}
static int luacall_parse_hex(lua_State *L){return native_lua_buffer(L,4);}
static int luacall_bxor(lua_State *L){return native_lua_buffer(L,5);}
static int luacall_bor(lua_State *L){return native_lua_buffer(L,6);}
static int luacall_band(lua_State *L){return native_lua_buffer(L,7);}
