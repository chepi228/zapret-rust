/* MIT. Rust metadata/policy; C executes VM calls only after Rust returns. */
#ifndef ZAPRET_LUA_PACKET_TYPES_DEFINED
#define ZAPRET_LUA_PACKET_TYPES_DEFINED
typedef struct{const uint8_t *data;size_t length,offset;uint8_t next,kind;bool stopped;}zapret_lua_packet_cursor;
typedef struct{uint32_t values[10];const uint8_t *source,*destination;zapret_lua_packet_cursor cursor;uint8_t count,address_width,table_capacity;}zapret_lua_packet_header_values;
typedef struct{const uint8_t *data;size_t length;uint8_t kind,next;bool has_data;}zapret_lua_packet_item;
bool zapret_lua_packet_header(uint8_t,const uint8_t *,size_t,zapret_lua_packet_header_values *);
uint32_t zapret_lua_packet_item_next(zapret_lua_packet_cursor *,zapret_lua_packet_item *);
#endif
typedef struct{const char *name;const uint8_t *data;size_t length;int64_t number;uint32_t kind,reserved;}zapret_lua_packet_metadata_action;
typedef struct{zapret_lua_packet_header_values header;uint32_t kind,index,phase,present;}zapret_lua_packet_header_projection_state;
typedef struct{zapret_lua_packet_cursor *cursor;zapret_lua_packet_item item;int64_t index;uint32_t phase;}zapret_lua_packet_items_state;
bool zapret_lua_packet_header_projection_begin(uint32_t,const uint8_t *,size_t,zapret_lua_packet_header_projection_state *,zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_header_projection_step(zapret_lua_packet_header_projection_state *,zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_items_prepare(uint32_t,const uint8_t *,size_t,zapret_lua_packet_cursor *,const char **);
bool zapret_lua_packet_items_begin(const char *,zapret_lua_packet_cursor *,zapret_lua_packet_items_state *,zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_items_step(zapret_lua_packet_items_state *,zapret_lua_packet_metadata_action *);
_Static_assert(sizeof(zapret_lua_packet_cursor)==32 && sizeof(zapret_lua_packet_header_values)==96 && sizeof(zapret_lua_packet_item)==24 && sizeof(zapret_lua_packet_metadata_action)==40 && sizeof(zapret_lua_packet_header_projection_state)==112 && sizeof(zapret_lua_packet_items_state)==48,"Rust packet metadata ABI");
static void native_lua_push_packet_items(lua_State *L,const char *field,zapret_lua_packet_cursor *cursor)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_packet_items_state state;zapret_lua_packet_metadata_action action;
    if(!zapret_lua_packet_items_begin(field,cursor,&state,&action)){luaL_error(L,"invalid packet item projection");return;}
    for(;;){switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,0)return;
        case 2:lua_createtable(L,0,(int)action.number);break;
        case 3:lua_pushf_int(L,action.name,action.number);break;
        case 4:lua_pushf_raw(L,action.name,action.data,action.length);break;
        case 6:lua_pushstring(L,action.name);break;
        case 7:lua_pushinteger(L,action.number);break;
        case 8:lua_rawset(L,(int)action.number);break;
        case 9:luaL_error(L,"%s",action.name);return;
        default:luaL_error(L,"invalid packet item action");return;}
        if(!zapret_lua_packet_items_step(&state,&action)){luaL_error(L,"invalid packet item state");return;}
    }
}
static void native_lua_packet_items_for_header(lua_State *L,uint32_t kind,const uint8_t *data,size_t length)
{
    zapret_lua_packet_cursor cursor;const char *field;
    if(!zapret_lua_packet_items_prepare(kind,data,length,&cursor,&field)){luaL_error(L,"invalid packet item input");return;}
    native_lua_push_packet_items(L,field,&cursor);
}
void lua_pushf_tcphdr_options(lua_State *L,const struct tcphdr *data,size_t length){native_lua_packet_items_for_header(L,0,(const uint8_t *)data,length);}
void lua_pushf_ip6exthdr(lua_State *L,const struct ip6_hdr *data,size_t length){native_lua_packet_items_for_header(L,4,(const uint8_t *)data,length);}
static void native_lua_push_packet_header(lua_State *L,uint8_t kind,const uint8_t *data,size_t length)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_packet_header_projection_state state;zapret_lua_packet_metadata_action action;
    if(!zapret_lua_packet_header_projection_begin(kind,data,length,&state,&action)){luaL_error(L,"invalid packet header projection");return;}
    for(;;){switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,1)return;
        case 1:lua_pushnil(L);break;
        case 2:lua_createtable(L,0,(int)action.number);break;
        case 3:lua_pushf_lint(L,action.name,action.number);break;
        case 4:lua_pushf_raw(L,action.name,action.data,action.length);break;
        case 5:native_lua_push_packet_items(L,action.name,&state.header.cursor);break;
        default:luaL_error(L,"invalid packet header action");return;}
        if(!zapret_lua_packet_header_projection_step(&state,&action)){luaL_error(L,"invalid packet header state");return;}
    }
}
void lua_push_tcphdr(lua_State *L,const struct tcphdr *data,size_t length){native_lua_push_packet_header(L,0,(const uint8_t *)data,length);}
void lua_push_udphdr(lua_State *L,const struct udphdr *data,size_t length){native_lua_push_packet_header(L,1,(const uint8_t *)data,length);}
void lua_push_icmphdr(lua_State *L,const struct icmp46 *data,size_t length){native_lua_push_packet_header(L,2,(const uint8_t *)data,length);}
void lua_push_iphdr(lua_State *L,const struct ip *data,size_t length){native_lua_push_packet_header(L,3,(const uint8_t *)data,length);}
void lua_push_ip6hdr(lua_State *L,const struct ip6_hdr *data,size_t length){native_lua_push_packet_header(L,4,(const uint8_t *)data,length);}
