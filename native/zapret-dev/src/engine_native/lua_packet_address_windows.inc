/* MIT. C performs the VM publication after a borrowed Rust address view. */
typedef struct{const uint8_t *data;size_t length;}zapret_lua_packet_address_view;
bool zapret_lua_packet_address(const void *,zapret_lua_packet_address_view *);
_Static_assert(sizeof(zapret_lua_packet_address_view)==16 && AF_INET==2 && AF_INET6==23 && offsetof(struct sockaddr_in,sin_addr)==4 && offsetof(struct sockaddr_in6,sin6_addr)==8,"Rust packet address ABI");
void lua_push_ipaddr(lua_State *L,const struct sockaddr *source)
{
    zapret_lua_packet_address_view view;
    if(!zapret_lua_packet_address(source,&view)){luaL_error(L,"invalid packet address view");return;}
    if(view.data)lua_pushlstring(L,(const char *)view.data,view.length);else lua_pushnil(L);
}
void lua_pushf_ipaddr(lua_State *L,const char *field,const struct sockaddr *source){lua_pushstring(L,field);lua_push_ipaddr(L,source);lua_rawset(L,-3);}
void lua_pushi_ipaddr(lua_State *L,lua_Integer index,const struct sockaddr *source){lua_pushinteger(L,index);lua_push_ipaddr(L,source);lua_rawset(L,-3);}
