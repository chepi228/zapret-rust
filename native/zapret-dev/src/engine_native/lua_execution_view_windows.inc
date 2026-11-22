/* MIT. C performs VM marshalling after resource-free Rust metadata selection. */
#include "lua_aux_abi.h"
static void lua_plan_literal(lua_State *L, uint32_t label)
{
    const char *key = zapret_lua_context_label(label);
    lua_pushlstring(L, key, strlen(key));
}

typedef struct { const char *name,*text; uint32_t kind; } zapret_lua_argument_view;
uint32_t zapret_lua_argument_view_next(const struct str2_list **,bool,zapret_lua_argument_view *);
_Static_assert(sizeof(zapret_lua_argument_view)==24 && sizeof(struct str2_list)==32 && offsetof(struct str2_list,next.le_next)==16,"Rust argument view ABI");
bool lua_pushf_args(lua_State *L,const struct str2_list_head *args,int idx_desync,bool substitute)
{
    LUA_STACK_GUARD_ENTER(L)
    idx_desync=lua_absindex(L,idx_desync);
    lua_plan_literal(L,LUA_PLAN_ARG);lua_newtable(L);
    const struct str2_list *cursor=LIST_FIRST(args);
    zapret_lua_argument_view argument;uint32_t status;
    while((status=zapret_lua_argument_view_next(&cursor,substitute,&argument))==1) {
        if(argument.kind==0) lua_pushf_str(L,argument.name,argument.text);
        else if(argument.kind==1) {
            if(!lua_pushf_blob(L,idx_desync,argument.name,argument.text)) {lua_pop(L,2);LUA_STACK_GUARD_LEAVE(L,0)return false;}
        } else {
            if(!lua_push_blob(L,idx_desync,argument.text)) {lua_pop(L,2);LUA_STACK_GUARD_LEAVE(L,0)return false;}
            lua_Integer length=lua_rawlen(L,-1);lua_pop(L,1);
            lua_pushstring(L,argument.name);lua_pushinteger(L,length);lua_tostring(L,-1);lua_rawset(L,-3);
        }
    }
    if(status==2){lua_pop(L,2);LUA_STACK_GUARD_LEAVE(L,0)return false;}
    lua_rawset(L,-3);
    LUA_STACK_GUARD_LEAVE(L,0)return true;
}
typedef struct {const struct func_list *next;uint32_t number,completed,profile;bool incoming;}zapret_lua_plan_cursor;
typedef struct {const char *name;const struct str2_list_head *args;const struct packet_range *range;uint64_t payload;uint32_t number,index;char instance[256];}zapret_lua_plan_entry;
bool zapret_lua_plan_begin(const struct func_list *,uint32_t,uint32_t,bool,zapret_lua_plan_cursor *);
bool zapret_lua_plan_begin_context(const t_lua_desync_context *,zapret_lua_plan_cursor *);
uint32_t zapret_lua_plan_next(zapret_lua_plan_cursor *,zapret_lua_plan_entry *);
const char *zapret_lua_plan_payload_next(uint64_t,uint32_t *);
_Static_assert(sizeof(zapret_lua_plan_cursor)==24 && sizeof(zapret_lua_plan_entry)==296 && offsetof(struct func_list,args)==56 && offsetof(struct func_list,next.le_next)==64,"Rust execution plan view ABI");
static int luacall_execution_plan(lua_State *L)
{
    lua_check_argc(L,"execution_plan",1);
    LUA_STACK_GUARD_ENTER(L)
    const t_lua_desync_context *ctx=lua_desync_ctx(L);
    zapret_lua_plan_cursor cursor;
    if(!zapret_lua_plan_begin_context(ctx,&cursor))return luaL_error(L,zapret_lua_context_label(LUA_CTX_PLAN_INVALID));
    lua_newtable(L);
    zapret_lua_plan_entry entry;uint32_t status;
    while((status=zapret_lua_plan_next(&cursor,&entry))==1) {
        lua_pushinteger(L,entry.index);lua_createtable(L,0,7);
        lua_pushf_args(L,entry.args,-1,false);
        lua_pushf_str(L,zapret_lua_context_label(LUA_PLAN_FUNC),entry.name);
        lua_pushf_int(L,zapret_lua_context_label(LUA_PLAN_FUNC_N),entry.number);
        lua_pushf_str(L,zapret_lua_context_label(LUA_PLAN_INSTANCE),entry.instance);
        lua_pushf_range(L,zapret_lua_context_label(LUA_PLAN_RANGE),entry.range);
        lua_plan_literal(L,LUA_PLAN_PAYLOAD);lua_newtable(L);
        uint32_t payload=0;const char *name;
        while((name=zapret_lua_plan_payload_next(entry.payload,&payload))) {lua_pushstring(L,name);lua_pushboolean(L,true);lua_rawset(L,-3);}
        lua_rawset(L,-3);
        char filter[2048];
        const char *filter_key=zapret_lua_context_label(LUA_PLAN_FILTER);
        if(l7_payload_str_list(entry.payload,filter,sizeof(filter)))lua_pushf_str(L,filter_key,filter);else lua_pushf_nil(L,filter_key);
        lua_rawset(L,-3);
    }
    if(status==2)return luaL_error(L,zapret_lua_context_label(LUA_CTX_PLAN_INVALID));
    LUA_STACK_GUARD_RETURN(L,1)
}
