/* MIT. Lua allocation/errors stay in C; Rust selects and fills checksum data. */
typedef struct {
    const uint8_t *ip,*header,*payload;
    size_t header_length,payload_length,total_length;
    uint32_t kind;
    uint8_t family,stage;
} zapret_lua_checksum_plan;
typedef struct {const char *name,*header_error;} zapret_lua_checksum_api;
zapret_lua_checksum_api zapret_lua_checksum_entry(uint32_t);
const char *zapret_lua_checksum_error(uint32_t);
bool zapret_lua_checksum_ipv4(const uint8_t *,size_t,uint8_t *,size_t);
bool zapret_lua_checksum_begin(uint32_t,const uint8_t *,size_t,zapret_lua_checksum_plan *);
bool zapret_lua_checksum_header(zapret_lua_checksum_plan *,const uint8_t *,size_t);
bool zapret_lua_checksum_payload(zapret_lua_checksum_plan *,const uint8_t *,size_t);
bool zapret_lua_checksum_finish(const zapret_lua_checksum_plan *,uint8_t *,size_t);
_Static_assert(sizeof(zapret_lua_checksum_plan)==56 && offsetof(zapret_lua_checksum_plan,kind)==48 &&
    offsetof(zapret_lua_checksum_plan,stage)==53,"Rust Lua checksum plan ABI");
static int luacall_csum_ip4_fix(lua_State *L)
{
    zapret_lua_checksum_api api=zapret_lua_checksum_entry(3);
    lua_check_argc(L,api.name,1);
    LUA_STACK_GUARD_ENTER(L)
    size_t length;const uint8_t *input=(const uint8_t *)lua_reqlstring(L,1,&length);
    uint8_t output[60];
    if(!zapret_lua_checksum_ipv4(input,length,output,sizeof(output)))return luaL_error(L,api.header_error);
    lua_pushlstring(L,(const char *)output,length);
    LUA_STACK_GUARD_RETURN(L,1)
}
static int native_lua_transport_checksum(lua_State *L,uint32_t kind)
{
    zapret_lua_checksum_api api=zapret_lua_checksum_entry(kind);
    lua_check_argc(L,api.name,3);
    LUA_STACK_GUARD_ENTER(L)
    size_t length;const uint8_t *input=(const uint8_t *)lua_reqlstring(L,1,&length);
    zapret_lua_checksum_plan plan;
    if(!zapret_lua_checksum_begin(kind,input,length,&plan))return luaL_error(L,zapret_lua_checksum_error(0));
    input=(const uint8_t *)lua_reqlstring(L,2,&length);
    if(!zapret_lua_checksum_header(&plan,input,length))return luaL_error(L,"%s",api.header_error);
    input=(const uint8_t *)lua_reqlstring(L,3,&length);
    if(!zapret_lua_checksum_payload(&plan,input,length))return luaL_error(L,zapret_lua_checksum_error(1));
    uint8_t *output=lua_newuserdata(L,plan.total_length);
    if(!zapret_lua_checksum_finish(&plan,output,plan.total_length))return luaL_error(L,zapret_lua_checksum_error(2));
    lua_pushlstring(L,(const char *)output,plan.header_length);lua_remove(L,-2);
    LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_tcp_fix(lua_State *L)
{return native_lua_transport_checksum(L,0);}
static int luacall_csum_udp_fix(lua_State *L)
{return native_lua_transport_checksum(L,1);}
static int luacall_csum_icmp_fix(lua_State *L)
{return native_lua_transport_checksum(L,2);}
