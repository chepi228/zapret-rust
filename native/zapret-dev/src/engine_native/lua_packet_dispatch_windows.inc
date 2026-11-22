/* MIT. Rust selects stages; every VM/pool/driver operation is on the C stack. */
typedef struct{uint8_t *buffer;const uint8_t *data;void *track;size_t capacity,length;uint32_t mode,phase,reverse,no_payload,success,error;}zapret_lua_packet_dispatch_state;
typedef struct{const char *name;uint32_t kind;int32_t index,minimum,maximum;uint32_t count,error;}zapret_lua_packet_dispatch_action;
typedef struct{const uint8_t *data;size_t length;void *track;uint32_t reverse,success;int32_t tag;uint32_t extra;}zapret_lua_packet_dispatch_value;
bool zapret_lua_packet_dispatch_begin(uint32_t,uint8_t *,size_t,zapret_lua_packet_dispatch_state *,zapret_lua_packet_dispatch_action *);
bool zapret_lua_packet_dispatch_step(zapret_lua_packet_dispatch_state *,const zapret_lua_packet_dispatch_value *,zapret_lua_packet_dispatch_action *);
_Static_assert(sizeof(zapret_lua_packet_dispatch_state) == 5 * sizeof(void *) + 24 &&
    sizeof(zapret_lua_packet_dispatch_action) == sizeof(void *) + 24 &&
    sizeof(zapret_lua_packet_dispatch_value) == 3 * sizeof(void *) + 16 &&
    offsetof(zapret_lua_packet_dispatch_state, mode) == 5 * sizeof(void *) &&
    offsetof(zapret_lua_packet_dispatch_value, tag) == 3 * sizeof(void *) + 8 &&
    LUA_TSTRING == 4 && LUA_TTABLE == 5, "Rust outer packet Lua ABI");
static int native_lua_packet_dispatch(lua_State *L,uint32_t mode,uint8_t *buffer,size_t capacity)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_packet_dispatch_state state;zapret_lua_packet_dispatch_action action;
    bool keepsum=false,badsum=false,preserve=false;uint8_t protocol=IPPROTO_NONE;
    int repeats=1;uint32_t mark=0;const char *ifout=NULL;sockaddr_in46 destination;struct dissect dis;
    if(!zapret_lua_packet_dispatch_begin(mode,buffer,capacity,&state,&action))return luaL_error(L,"invalid packet dispatch storage");
    for(;;){
        zapret_lua_packet_dispatch_value value={0};
        switch(action.kind){
        case 1:lua_check_argc_range(L,action.name,action.minimum,action.maximum);break;
        case 2:value.success=params.ctrack_disable;break;
        case 3:value.tag=lua_type(L,1);break;
        case 4:luaL_checktype(L,1,LUA_TTABLE);break;
        case 5:value.data=(const uint8_t *)lua_reqlstring(L,1,&value.length);break;
        case 6:value.data=(const uint8_t *)lua_tolstring(L,1,&value.length);break;
        case 7:lua_rawsend_extract_options(L,action.index,&repeats,&mark,&ifout);break;
        case 8:lua_reconstruct_extract_options(L,action.index,&keepsum,&badsum,&preserve,&protocol);break;
        case 9:value.length=capacity;value.success=lua_reconstruct_dissect(L,1,buffer,&value.length,keepsum,badsum,protocol,preserve);break;
        case 10:value.tag=lua_gettop(L);break;
        case 11:proto_dissect_l3l4(state.data,state.length,&dis,state.no_payload!=0);break;
        case 12:ConntrackPoolPurge(&params.conntrack);break;
        case 13:{t_ctrack *track;bool reverse;value.success=ConntrackPoolFeed(&params.conntrack,&dis,&track,&reverse);if(value.success){value.track=track;value.reverse=reverse;}break;}
        case 14:lua_push_ctrack(L,state.track,NULL,state.reverse!=0);break;
        case 15:lua_pushboolean(L,state.reverse==0);break;
        case 16:lua_pushnil(L);lua_pushnil(L);break;
        case 17:value.success=extract_dst(state.data,state.length,(struct sockaddr *)&destination);break;
        case 18:
            if(action.index)DLOG(action.name,repeats,state.length,(unsigned int)badsum,ifout?ifout:"",mark);
            else DLOG(action.name,repeats,state.length,ifout?ifout:"",mark);
            break;
        case 19:value.success=rawsend_rep(repeats,(struct sockaddr *)&destination,mark,ifout,state.data,state.length);break;
        case 20:lua_pushboolean(L,state.success!=0);break;
        case 21:lua_pushlstring(L,(const char *)state.data,state.length);break;
        case 22:lua_push_dissect(L,&dis);break;
        case 23:LUA_STACK_GUARD_LEAVE(L,(int)action.count)return (int)action.count;
        case 24:return luaL_error(L,action.name);
        case 25:value.success=lua_toboolean(L,2);break;
        default:return luaL_error(L,"invalid packet dispatch action");
        }
        if(!zapret_lua_packet_dispatch_step(&state,&value,&action))return luaL_error(L,"invalid packet dispatch state");
    }
}
static int luacall_reconstruct_dissect(lua_State *L){uint8_t buffer[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));return native_lua_packet_dispatch(L,3,buffer,sizeof(buffer));}
static int luacall_dissect(lua_State *L){return native_lua_packet_dispatch(L,4,NULL,0);}
static int luacall_rawsend(lua_State *L){return native_lua_packet_dispatch(L,0,NULL,0);}
static int luacall_rawsend_dissect(lua_State *L){uint8_t buffer[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));return native_lua_packet_dispatch(L,1,buffer,sizeof(buffer));}
static int luacall_conntrack_feed(lua_State *L){uint8_t buffer[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));return native_lua_packet_dispatch(L,2,buffer,sizeof(buffer));}
