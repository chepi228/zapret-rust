/* MIT. All Lua lookups, errors and table writes happen after Rust returns. */
#include "lua_context_windows.h"
_Static_assert(LUA_TNIL == 0 && LUA_TTABLE == 5, "Lua context tag ABI");
// lua.h can precede params.h; check the complete profile here, after both.
_Static_assert(offsetof(struct desync_profile,n)==0 && offsetof(struct desync_profile,lua_desync)==160,
    "Rust Lua context profile ABI");
static t_lua_desync_context *lua_desync_ctx(lua_State *L)
{
    if(zapret_lua_context_vm(LUA_CTX_NIL,lua_type(L,1)))luaL_error(L,zapret_lua_context_label(LUA_CTX_MISSING));
    t_lua_desync_context *ctx=luaL_checkudata(L,1,zapret_lua_context_label(LUA_CTX_METATABLE));
    if(!zapret_lua_context_valid(ctx,lua_rawlen(L,1)))luaL_error(L,zapret_lua_context_label(LUA_CTX_INVALID));
    return ctx;
}
static void lua_desync_ctx_create(lua_State *L)
{
    if(zapret_lua_context_vm(LUA_CTX_CREATE_REF,params.ref_desync_ctx)){
        LUA_STACK_GUARD_ENTER(L)
        t_lua_desync_context *ctx=lua_newuserdata(L,sizeof(*ctx));
        if(!zapret_lua_context_init(ctx)){luaL_error(L,zapret_lua_context_label(LUA_CTX_STORAGE_INVALID));return;}
        luaL_getmetatable(L,zapret_lua_context_label(LUA_CTX_METATABLE));lua_setmetatable(L,-2);
        params.ref_desync_ctx=luaL_ref(params.L,LUA_REGISTRYINDEX);
        LUA_STACK_GUARD_LEAVE(L,0)
    }
}
static uint32_t native_lua_cutoff_direction(lua_State *L)
{
    if(zapret_lua_context_vm(LUA_CTX_HAS_DIRECTION,lua_gettop(L)) &&
       zapret_lua_context_vm(LUA_CTX_DIRECTION_PROVIDED,lua_type(L,2))){
        luaL_checktype(L,2,LUA_TBOOLEAN);
        return zapret_lua_context_vm(LUA_CTX_SCRIPT_DIRECTION,lua_toboolean(L,2));
    }
    return 0;
}
static int luacall_instance_cutoff(lua_State *L)
{
    lua_check_argc_range(L,zapret_lua_context_label(LUA_CTX_INSTANCE_CUTOFF),1,2);
    LUA_STACK_GUARD_ENTER(L)
    if(zapret_lua_context_vm(LUA_CTX_NIL,lua_type(L,1)))DLOG(zapret_lua_context_report(LUA_CTX_REPORT_MISSING,false));
    else{
        const t_lua_desync_context *ctx=lua_desync_ctx(L);
        uint32_t direction=native_lua_cutoff_direction(L);
        zapret_lua_context_scope_values scope;
        if(!zapret_lua_context_scope(ctx,direction,true,&scope))return luaL_error(L,zapret_lua_context_label(LUA_CTX_CUTOFF_INVALID));
        DLOG(zapret_lua_context_report(LUA_CTX_REPORT_INSTANCE_CUTOFF,scope.tracked),
            scope.instance,(unsigned int)scope.incoming,(unsigned int)scope.outgoing);
        if(scope.tracked){
            lua_rawgeti(L,LUA_REGISTRYINDEX,scope.registry);lua_getfield(L,-1,scope.instance);
            if(zapret_lua_context_vm(LUA_CTX_TABLE_NEEDED,lua_type(L,-1))){lua_pop(L,1);lua_pushf_table(L,scope.instance);lua_getfield(L,-1,scope.instance);}
            lua_rawgeti(L,-1,scope.profile);
            if(zapret_lua_context_vm(LUA_CTX_TABLE_NEEDED,lua_type(L,-1))){lua_pop(L,1);lua_pushi_table(L,scope.profile);lua_rawgeti(L,-1,scope.profile);}
            if(scope.outgoing)lua_pushi_bool(L,0,true);
            if(scope.incoming)lua_pushi_bool(L,1,true);
            lua_pop(L,3);
        }
    }
    LUA_STACK_GUARD_RETURN(L,0)
}
bool lua_instance_cutoff_check(lua_State *L,const t_lua_desync_context *ctx,bool incoming)
{
    zapret_lua_context_scope_values scope;
    if(!zapret_lua_context_scope(ctx,zapret_lua_context_vm(LUA_CTX_NATIVE_DIRECTION,incoming),true,&scope) || !scope.tracked)return false;
    lua_rawgeti(L,LUA_REGISTRYINDEX,scope.registry);lua_getfield(L,-1,scope.instance);
    if(zapret_lua_context_vm(LUA_CTX_TABLE_NEEDED,lua_type(L,-1))){lua_pop(L,2);return false;}
    lua_rawgeti(L,-1,scope.profile);
    if(zapret_lua_context_vm(LUA_CTX_TABLE_NEEDED,lua_type(L,-1))){lua_pop(L,3);return false;}
    lua_rawgeti(L,-1,incoming);bool result=lua_toboolean(L,-1);lua_pop(L,4);return result;
}
static int luacall_lua_cutoff(lua_State *L)
{
    lua_check_argc_range(L,zapret_lua_context_label(LUA_CTX_LUA_CUTOFF),1,2);
    LUA_STACK_GUARD_ENTER(L)
    const t_lua_desync_context *ctx=lua_desync_ctx(L);
    uint32_t direction=native_lua_cutoff_direction(L);zapret_lua_context_scope_values scope;
    if(!zapret_lua_context_scope(ctx,direction,false,&scope))return luaL_error(L,zapret_lua_context_label(LUA_CTX_CUTOFF_INVALID));
    DLOG(zapret_lua_context_report(LUA_CTX_REPORT_LUA_CUTOFF,scope.tracked),
        scope.instance,(unsigned int)scope.incoming,(unsigned int)scope.outgoing);
    if(scope.tracked){
        if(!zapret_lua_context_cutoff(ctx,direction))return luaL_error(L,zapret_lua_context_label(LUA_CTX_CUTOFF_INVALID));
    }
    LUA_STACK_GUARD_RETURN(L,0)
}
static int luacall_execution_plan_cancel(lua_State *L)
{
    lua_check_argc(L,zapret_lua_context_label(LUA_CTX_CANCEL),1);t_lua_desync_context *ctx=lua_desync_ctx(L);
    zapret_lua_context_scope_values scope;
    if(!zapret_lua_context_scope(ctx,0,false,&scope))return luaL_error(L,zapret_lua_context_label(LUA_CTX_EXECUTION_INVALID));
    DLOG(zapret_lua_context_report(LUA_CTX_REPORT_CANCEL,scope.tracked),scope.instance);
    if(!zapret_lua_context_cancel(ctx))return luaL_error(L,zapret_lua_context_label(LUA_CTX_EXECUTION_INVALID));
    return 0;
}
static int luacall_raw_packet(lua_State *L)
{
    lua_check_argc(L,zapret_lua_context_label(LUA_CTX_RAW_PACKET),1);
    LUA_STACK_GUARD_ENTER(L)
    const t_lua_desync_context *ctx=lua_desync_ctx(L);zapret_lua_context_span packet;
    if(!zapret_lua_context_packet(ctx,&packet))return luaL_error(L,zapret_lua_context_label(LUA_CTX_PACKET_INVALID));
    lua_pushlstring(L,(const char *)packet.data,packet.length);
    LUA_STACK_GUARD_RETURN(L,1)
}
