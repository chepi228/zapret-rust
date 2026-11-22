/* MIT. Native snapshots remain Rust; C alone performs the selected VM calls. */
#include "lua_connection_view_types.h"
typedef struct{const char *name,*data;int64_t integer;double floating;uint32_t kind;int32_t index;}zapret_lua_connection_action;
typedef struct{const zapret_lua_track_position_values *view;uint32_t index,phase;}zapret_lua_position_publication_state;
typedef struct{zapret_lua_track_values view;uint32_t mode,phase;}zapret_lua_track_publication_state;
bool zapret_lua_position_publication_begin(const zapret_lua_track_position_values *,zapret_lua_position_publication_state *,zapret_lua_connection_action *);
bool zapret_lua_position_publication_step(zapret_lua_position_publication_state *,zapret_lua_connection_action *);
bool zapret_lua_track_publication_begin(uint32_t,zapret_lua_track_publication_state *,zapret_lua_connection_action *);
bool zapret_lua_track_publication_step(zapret_lua_track_publication_state *,uint32_t,zapret_lua_connection_action *);
_Static_assert(sizeof(zapret_lua_connection_action)==40 && sizeof(zapret_lua_position_publication_state)==16 && sizeof(zapret_lua_track_publication_state)==280 && offsetof(zapret_lua_track_publication_state,mode)==272,"Rust connection publication ABI");
static void native_lua_push_track_position(lua_State *L,const zapret_lua_track_position_values *view)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_position_publication_state state;zapret_lua_connection_action action;
    if(!zapret_lua_position_publication_begin(view,&state,&action)){luaL_error(L,"invalid connection position view");return;}
    for(;;){switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,0)return;
        case 3:lua_createtable(L,0,(int)action.integer);break;
        case 4:lua_pushf_lint(L,action.name,action.integer);break;
        case 5:lua_pushf_bool(L,action.name,action.integer!=0);break;
        case 9:lua_pushlstring(L,action.name,(size_t)action.integer);break;
        case 10:lua_rawset(L,action.index);break;
        default:luaL_error(L,"invalid connection position action");return;}
        if(!zapret_lua_position_publication_step(&state,&action)){luaL_error(L,"invalid connection position state");return;}
    }
}
void lua_pushf_ctrack_pos(lua_State *L,const t_ctrack *track,const t_ctrack_position *position)
{
    zapret_lua_track_position_values view;
    if(!zapret_lua_track_position(track,position,&view)){luaL_error(L,"invalid connection position view");return;}
    native_lua_push_track_position(L,&view);
}
static void native_lua_publish_track(lua_State *L,const t_ctrack *track,const t_ctrack_positions *positions,bool incoming,uint32_t mode)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_track_publication_state state;zapret_lua_connection_action action;
    if(!zapret_lua_track_publication_begin(mode,&state,&action)){luaL_error(L,"invalid connection view");return;}
    for(;;){uint32_t status=0;switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,action.index)return;
        case 1:status=zapret_lua_track_view(track,positions,incoming,params.server,&state.view);break;
        case 2:lua_pushnil(L);break;
        case 3:lua_createtable(L,0,(int)action.integer);break;
        case 4:lua_pushf_int(L,action.name,action.integer);break;
        case 5:lua_pushf_bool(L,action.name,action.integer!=0);break;
        case 6:lua_pushf_str(L,action.name,action.data);break;
        case 7:lua_pushf_reg(L,action.name,(int)action.integer);break;
        case 8:lua_pushf_number(L,action.name,action.floating);break;
        case 9:lua_pushlstring(L,action.name,(size_t)action.integer);break;
        case 10:lua_rawset(L,action.index);break;
        case 11:lua_getfield(L,action.index,action.name);break;
        case 12:native_lua_push_track_position(L,&state.view.positions[action.index]);break;
        case 13:luaL_error(L,"%s",action.name);return;
        default:luaL_error(L,"invalid connection view action");return;}
        if(!zapret_lua_track_publication_step(&state,status,&action)){luaL_error(L,"invalid connection view state");return;}
    }
}
void lua_push_ctrack(lua_State *L,const t_ctrack *track,const t_ctrack_positions *positions,bool incoming){native_lua_publish_track(L,track,positions,incoming,0);}
void lua_pushf_ctrack(lua_State *L,const t_ctrack *track,const t_ctrack_positions *positions,bool incoming){native_lua_publish_track(L,track,positions,incoming,1);}
