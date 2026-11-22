/* MIT. Rust selects policy and fields; C drives header reconstruction. */
typedef struct{uint8_t *buffer;const uint8_t *data;size_t length,capacity;uint32_t mode,phase,preserve,protocol;}zapret_lua_header_entry_state;
typedef struct{const char *name;const uint8_t *data;size_t length;uint32_t kind;int32_t index,minimum,maximum;uint32_t header,count;}zapret_lua_header_entry_action;
typedef struct{const uint8_t *data;size_t length;uint32_t success,preserve,protocol;}zapret_lua_header_entry_value;
typedef struct{const char *name;const uint8_t *data;size_t length;int64_t number;uint32_t kind,header;}zapret_lua_packet_projection_action;
bool zapret_lua_header_entry_begin(uint32_t,uint8_t *,size_t,zapret_lua_header_entry_state *,zapret_lua_header_entry_action *);
bool zapret_lua_header_entry_step(zapret_lua_header_entry_state *,const zapret_lua_header_entry_value *,zapret_lua_header_entry_action *);
const char *zapret_lua_header_field_name(uint32_t);
const char *zapret_lua_dissect_field_name(void);
bool zapret_lua_packet_projection(const struct dissect *,uint32_t *,zapret_lua_packet_projection_action *);
_Static_assert(sizeof(zapret_lua_header_entry_state)==48 && sizeof(zapret_lua_header_entry_action)==48 && sizeof(zapret_lua_header_entry_value)==32 && sizeof(zapret_lua_packet_projection_action)==40,"Rust header entry ABI");
_Static_assert(sizeof(struct dissect)==112 && offsetof(struct dissect,proto)==40 && offsetof(struct dissect,len_l4)==72 && offsetof(struct dissect,data_payload)==88 && offsetof(struct dissect,frag)==104 && offsetof(struct dissect,frag_off)==106,"Rust packet projection source ABI");
static void lua_reconstruct_extract_options(lua_State *,int,bool *,bool *,bool *,uint8_t *);
static int native_lua_header_entry(lua_State *L,uint32_t mode)
{
    LUA_STACK_GUARD_ENTER(L)
    uint8_t buffer[512] __attribute__((aligned(16)));zapret_lua_header_entry_state state;zapret_lua_header_entry_action action;
    if(!zapret_lua_header_entry_begin(mode,buffer,sizeof(buffer),&state,&action))return luaL_error(L,"invalid header entry");
    for(;;){zapret_lua_header_entry_value value={0};switch(action.kind){
        case 0:LUA_STACK_GUARD_RETURN(L,(int)action.count)
        case 1:if(action.minimum==action.maximum)lua_check_argc(L,action.name,action.minimum);else lua_check_argc_range(L,action.name,action.minimum,action.maximum);break;
        case 3:{bool preserve;uint8_t protocol;lua_reconstruct_extract_options(L,action.index,NULL,NULL,&preserve,&protocol);value.preserve=preserve;value.protocol=protocol;break;}
        case 4:value.length=action.length;switch(action.header){
            case 0:value.success=lua_reconstruct_tcphdr(L,action.index,(struct tcphdr *)action.data,&value.length);break;
            case 1:value.success=lua_reconstruct_udphdr(L,action.index,(struct udphdr *)action.data);break;
            case 2:value.success=lua_reconstruct_icmphdr(L,action.index,(struct icmp46 *)action.data);break;
            case 3:value.success=lua_reconstruct_iphdr(L,action.index,(struct ip *)action.data,&value.length);break;
            case 4:value.success=lua_reconstruct_ip6hdr(L,action.index,(struct ip6_hdr *)action.data,&value.length,state.protocol,state.preserve!=0);break;
            default:return luaL_error(L,"invalid header builder");}break;
        case 6:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 7:return luaL_error(L,"%s",action.name);
        default:return luaL_error(L,"invalid header action");}
        if(!zapret_lua_header_entry_step(&state,&value,&action))return luaL_error(L,"invalid header state");
    }
}
static void native_lua_header_field(lua_State *L,uint32_t kind,const uint8_t *data,size_t length)
{
    LUA_STACK_GUARD_ENTER(L)
    const char *field=zapret_lua_header_field_name(kind);if(!field){luaL_error(L,"invalid header field");return;}
    lua_pushlstring(L,field,strlen(field));native_lua_push_packet_header(L,kind,data,length);lua_rawset(L,-3);
    LUA_STACK_GUARD_LEAVE(L,0)
}
void lua_pushf_tcphdr(lua_State *L,const struct tcphdr *data,size_t length){native_lua_header_field(L,0,(const uint8_t *)data,length);}
void lua_pushf_udphdr(lua_State *L,const struct udphdr *data,size_t length){native_lua_header_field(L,1,(const uint8_t *)data,length);}
void lua_pushf_icmphdr(lua_State *L,const struct icmp46 *data,size_t length){native_lua_header_field(L,2,(const uint8_t *)data,length);}
void lua_pushf_iphdr(lua_State *L,const struct ip *data,size_t length){native_lua_header_field(L,3,(const uint8_t *)data,length);}
void lua_pushf_ip6hdr(lua_State *L,const struct ip6_hdr *data,size_t length){native_lua_header_field(L,4,(const uint8_t *)data,length);}
#include "windows_lua_header_decode_abi.h"
static int luacall_reconstruct_tcphdr(lua_State *L){return native_lua_header_entry(L,5);}
static int luacall_reconstruct_udphdr(lua_State *L){return native_lua_header_entry(L,6);}
static int luacall_reconstruct_icmphdr(lua_State *L){return native_lua_header_entry(L,7);}
static int luacall_reconstruct_iphdr(lua_State *L){return native_lua_header_entry(L,8);}
static int luacall_reconstruct_ip6hdr(lua_State *L){return native_lua_header_entry(L,9);}
void lua_push_dissect(lua_State *L,const struct dissect *dis)
{
    LUA_STACK_GUARD_ENTER(L)
    uint32_t cursor=0;zapret_lua_packet_projection_action action;
    for(;;){if(!zapret_lua_packet_projection(dis,&cursor,&action)){luaL_error(L,"invalid packet projection");return;}
        switch(action.kind){
        case 0:LUA_STACK_GUARD_LEAVE(L,1)return;
        case 1:lua_pushnil(L);break;
        case 2:lua_createtable(L,0,(int)action.number);break;
        case 3:lua_pushf_int(L,action.name,action.number);break;
        case 4:lua_pushf_raw(L,action.name,action.data,action.length);break;
        case 5:native_lua_header_field(L,action.header,action.data,action.length);break;
        default:luaL_error(L,"invalid packet projection action");return;}
    }
}
void lua_pushf_dissect(lua_State *L,const struct dissect *dis)
{
    const char *field=zapret_lua_dissect_field_name();
    lua_pushlstring(L,field,strlen(field));lua_push_dissect(L,dis);lua_rawset(L,-3);
}
