/* MIT. Borrowed Rust policy; every Lua operation and error runs after return. */
#include "lua_table_policy_abi.h"
static void native_lua_range_table(lua_State *L,const char *name,const void *source,uint32_t mode)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_range_state state;zapret_lua_table_action action;
    if(!zapret_lua_range_begin(mode,source,name,&state,&action)){luaL_error(L,"invalid range projection");return;}
    for(;;){switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,0)return;
        case 1:lua_pushf_table(L,action.name);break;
        case 2:lua_getfield(L,-1,action.name);break;
        case 3:{char text[2]={(char)action.number,0};lua_pushf_str(L,action.name,text);break;}
        case 4:lua_pushf_lint(L,action.name,action.number);break;
        case 5:lua_pop(L,(int)action.number);break;
        case 6:native_lua_range_table(L,action.name,action.data,0);break;
        case 7:lua_pushf_bool(L,action.name,action.number!=0);break;
        default:luaL_error(L,"invalid range action");return;}
        if(!zapret_lua_range_step(&state,&action)){luaL_error(L,"invalid range state");return;}
    }
}
void lua_pushf_pos(lua_State *L,const char *name,const struct packet_pos *source){native_lua_range_table(L,name,source,0);}
void lua_pushf_range(lua_State *L,const char *name,const struct packet_range *source){native_lua_range_table(L,name,source,1);}
static bool native_lua_blob(lua_State *L,int index,const char *field,const char *blob,uint32_t mode)
{
    zapret_lua_blob_state state;zapret_lua_table_action action;
    if(!zapret_lua_blob_begin(mode,index,field,blob,&state,&action)){luaL_error(L,"invalid blob projection");return false;}
    for(;;){int tag=0;switch(action.kind){
        case 0:return action.flag!=0;
        case 1:lua_pushstring(L,action.name);break;
        case 2:lua_getfield(L,(int)action.number,action.name);break;
        case 3:tag=lua_type(L,-1);break;
        case 4:lua_pop(L,(int)action.number);break;
        case 5:lua_getglobal(L,action.name);break;
        case 6:lua_tostring(L,-1);break;
        case 7:lua_rawset(L,(int)action.number);break;
        case 8:DLOG_ERR((const char *)action.data,action.name);break;
        default:luaL_error(L,"invalid blob action");return false;}
        if(!zapret_lua_blob_step(&state,tag,&action)){luaL_error(L,"invalid blob state");return false;}
    }
}
bool lua_push_blob(lua_State *L,int index,const char *blob){return native_lua_blob(L,index,NULL,blob,0);}
bool lua_pushf_blob(lua_State *L,int index,const char *field,const char *blob){return native_lua_blob(L,index,field,blob,1);}
