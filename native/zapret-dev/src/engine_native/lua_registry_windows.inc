/* MIT. C VM operations run only after resource-free Rust catalog queries. */
#include "lua_registry_windows.h"
/* The builder binds pinned C callback addresses; Rust owns their public names. */
#include "lua_registry_callbacks.inc"
static void lua_registry_observe(zapret_lua_registry_values *values,uint32_t source)
{
    switch(source){
        case 1:values->version=params.verstr;break;
        case 2:values->mark=params.desync_fwmark;break;
        case 3:
            values->debug=!!params.debug;
            values->daemon=!!params.daemon;
            values->server=!!params.server;
            values->cache_hostname=!!params.cache_hostname;
            values->ctrack_disable=!!params.ctrack_disable;break;
    }
}
static void lua_init_const(void)
{
    LUA_STACK_GUARD_ENTER(params.L)
    zapret_lua_registry_values values={0};
    zapret_lua_registry_section section;
    zapret_lua_registry_value entry;uint32_t status;
    for(uint32_t group=0;(status=zapret_lua_registry_group(group,&section))==1;++group){
        lua_registry_observe(&values,section.before_log);
        DLOG(section.title);
        lua_registry_observe(&values,section.after_log);
        for(size_t index=0;(status=zapret_lua_registry_constant(group,index,&values,&entry))==1;++index){
            switch(group){
                case 0:lua_pushstring(params.L,entry.text);break;
                case 1:lua_pushinteger(params.L,(lua_Integer)entry.value);break;
                case 2:lua_pushboolean(params.L,entry.value);break;
            }
            lua_setglobal(params.L,entry.name);DLOG(zapret_lua_registry_entry_format(),entry.name);
        }
        if(status!=0){luaL_error(params.L,"invalid Lua constant catalog");return;}
    }
    if(status!=0){luaL_error(params.L,"invalid Lua constant section");return;}
    DLOG(section.title);
    LUA_STACK_GUARD_LEAVE(params.L,0)
}
static void lua_init_functions(void)
{
    LUA_STACK_GUARD_ENTER(params.L)
    const size_t count=sizeof(native_lua_registry_callbacks)/sizeof(*native_lua_registry_callbacks);
    zapret_lua_registry_binding entry;uint32_t status;
    for(size_t index=0;(status=zapret_lua_registry_function(index,count,&entry))==1;++index){
        if(entry.slot>=count){luaL_error(params.L,"invalid Lua callback slot");return;}
        lua_register(params.L,entry.name,native_lua_registry_callbacks[entry.slot]);
    }
    if(status!=0){luaL_error(params.L,"invalid Lua function catalog");return;}
    LUA_STACK_GUARD_LEAVE(params.L,0)
}
static void lua_init_mt(void)
{
    zapret_lua_registry_mt mt;uint32_t status;
    for(size_t index=0;(status=zapret_lua_registry_metatable(index,&mt))==1;++index){
        switch(mt.action){
            case 1:lua_mt_init_zstream(params.L);break;
            case 2:lua_mt_init_desync_ctx(params.L);break;
            case 3:lua_desync_ctx_create(params.L);break;
            default:luaL_error(params.L,"invalid Lua metatable action");return;
        }
    }
    if(status!=0)luaL_error(params.L,"invalid Lua metatable plan");
}
