/* MIT. Rust selects timer entry policy; C alone executes Lua/native callbacks. */
typedef struct {zapret_timer_info timer,old;const char *name,*function;uint64_t after;int64_t index;int32_t argc,result;uint32_t mode,phase;}zapret_lua_timer_state;
typedef struct {const char *name,*data;int64_t integer;uint32_t kind;int32_t index;}zapret_lua_timer_action;
typedef struct {const char *data;int64_t integer;int32_t code;}zapret_lua_timer_value;
bool zapret_lua_timer_begin(uint32_t,zapret_lua_timer_state *,zapret_lua_timer_action *);
bool zapret_lua_timer_step(zapret_lua_timer_state *,const zapret_lua_timer_value *,zapret_lua_timer_action *);
_Static_assert(sizeof(zapret_lua_timer_state)==128 && offsetof(zapret_lua_timer_state,mode)==120 && sizeof(zapret_lua_timer_action)==32 && sizeof(zapret_lua_timer_value)==24,"Rust Lua timer policy ABI");
static int native_lua_timer(lua_State *L,uint32_t mode)
{
    int _lsg=0;
    zapret_lua_timer_state state;zapret_lua_timer_action action;zapret_lua_timer_value value={0};
    if(!zapret_lua_timer_begin(mode,&state,&action))return luaL_error(L,"invalid Lua timer entry");
    for(;;){switch(action.kind){
        case 0:LUA_STACK_GUARD_RETURN(L,(int)action.integer)
        case 1:if(action.integer==action.index)lua_check_argc(L,action.name,action.index);else lua_check_argc_range(L,action.name,(int)action.integer,action.index);_lsg=lua_gettop(L);if(action.integer!=action.index)value.integer=lua_gettop(L);break;
        case 2:value.data=luaL_checkstring(L,action.index);break;
        case 3:value.integer=luaL_checkinteger(L,action.index);break;
        case 4:value.code=lua_type(L,action.index);break;
        case 5:value.data=lua_tostring(L,action.index);break;
        case 6:lua_getglobal(L,action.data);break;
        case 7:value.code=lua_isfunction(L,action.index);break;
        case 8:lua_pushvalue(L,action.index);break;
        case 9:value.code=lua_toboolean(L,action.index);break;
        case 10:value.code=luaL_ref(L,LUA_REGISTRYINDEX);break;
        case 11:lua_pushstring(L,action.data);break;
        case 12:value.code=zapret_timer_set(&params.timers,state.name,&state.timer,boottime_ms(),&state.old);break;
        case 13:zapret_timer_unref(action.index?&state.old:&state.timer);break;
        case 14:params.timers_dirty=true;break;
        case 15:DLOG(action.name,state.name,action.data,(unsigned long long)state.timer.period,state.timer.oneshot);break;
        case 16:if(action.index)return luaL_error(L,action.name,action.data);return luaL_error(L,"%s",action.name);
        case 17:value.code=zapret_timer_get(params.timers,state.name,&state.timer);break;
        case 18:value.code=zapret_timer_remove(&params.timers,state.timer.id,&state.old);break;
        case 19:DLOG(action.name,state.name,action.data);break;
        case 20:lua_pushboolean(L,action.integer!=0);break;
        case 21:lua_newtable(L);break;
        case 22:lua_pushlstring(L,action.name,(size_t)action.integer);break;
        case 23:lua_rawgeti(L,LUA_REGISTRYINDEX,(int)action.integer);break;
        case 24:lua_rawset(L,action.index);break;
        case 25:lua_pushf_lint(L,action.name,action.integer);break;
        case 26:lua_pushf_bool(L,action.name,action.integer!=0);break;
        case 27:value.code=zapret_timer_after(params.timers,state.after,&state.timer);break;
        case 28:lua_rawseti(L,action.index,(lua_Integer)action.integer);break;
        case 29:lua_pushnil(L);break;
        case 30:value.code=zapret_timer_get(params.timers,luaL_checkstring(L,action.index),&state.timer);break;
        default:return luaL_error(L,"invalid Lua timer action");}
        if(!zapret_lua_timer_step(&state,&value,&action))return luaL_error(L,"invalid Lua timer state");
    }
}
static int luacall_timer_set(lua_State *L){return native_lua_timer(L,0);}
static int luacall_timer_del(lua_State *L){return native_lua_timer(L,1);}
static int luacall_timer_info(lua_State *L){return native_lua_timer(L,2);}
static int luacall_timer_enum(lua_State *L){return native_lua_timer(L,3);}
