/* MIT. Windows fills Lua-owned userdata between protected VM operations. */
typedef struct{const IP_ADAPTER_ADDRESSES *adapter;const IP_ADAPTER_UNICAST_ADDRESS_LH *address;int64_t index;uint32_t phase,host_mask;}zapret_lua_interface_cursor;
typedef struct{const char *name;const uint8_t *data;int64_t number;size_t length;uint32_t kind;uint8_t bytes[16],label[16];}zapret_lua_interface_field;
bool zapret_lua_interfaces_read(PIP_ADAPTER_ADDRESSES,ULONG *,
    ULONG (WINAPI *query)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG));
bool zapret_lua_interfaces_begin(const IP_ADAPTER_ADDRESSES *,zapret_lua_interface_cursor *);
bool zapret_lua_interfaces_next(zapret_lua_interface_cursor *,zapret_lua_interface_field *);
_Static_assert(sizeof(zapret_lua_interface_cursor) == 2 * sizeof(void *) + 16 &&
    offsetof(zapret_lua_interface_cursor, index) == 2 * sizeof(void *) &&
    sizeof(zapret_lua_interface_field) == (sizeof(void *) == 8 ? 72 : 56) &&
    offsetof(zapret_lua_interface_field, bytes) == 3 * sizeof(void *) + 12,
    "Rust Lua interface ABI");
#ifdef _WIN64
_Static_assert(sizeof(IP_ADAPTER_ADDRESSES) == 448 &&
    offsetof(IP_ADAPTER_ADDRESSES, PhysicalAddress) == 80 &&
    offsetof(IP_ADAPTER_ADDRESSES, TransmitLinkSpeed) == 184 &&
    offsetof(IP_ADAPTER_ADDRESSES, ConnectionType) == 268 &&
    offsetof(IP_ADAPTER_UNICAST_ADDRESS_LH, Address) == 16, "Win64 adapter ABI");
#else
_Static_assert(sizeof(IP_ADAPTER_ADDRESSES) == 376 &&
    offsetof(IP_ADAPTER_ADDRESSES, PhysicalAddress) == 44 &&
    offsetof(IP_ADAPTER_ADDRESSES, TransmitLinkSpeed) == 144 &&
    offsetof(IP_ADAPTER_ADDRESSES, ConnectionType) == 212 &&
    offsetof(IP_ADAPTER_UNICAST_ADDRESS_LH, Address) == 12, "Win32 adapter ABI");
#endif
static int lua_get_ifaddrs(lua_State *L)
{
    LUA_STACK_GUARD_ENTER(L)
    ULONG size=0;
    if(!zapret_lua_interfaces_read(NULL,&size,GetAdaptersAddresses)){lua_pushnil(L);LUA_STACK_GUARD_RETURN(L,1)}
    PIP_ADAPTER_ADDRESSES adapters=lua_newuserdata(L,size);
    if(!zapret_lua_interfaces_read(adapters,&size,GetAdaptersAddresses)){lua_pop(L,1);lua_pushnil(L);LUA_STACK_GUARD_RETURN(L,1)}
    lua_newtable(L);zapret_lua_interface_cursor cursor;zapret_lua_interface_field field;
    if(!zapret_lua_interfaces_begin(adapters,&cursor))return luaL_error(L,"invalid interface view storage");
    for(;;){
        if(!zapret_lua_interfaces_next(&cursor,&field))return luaL_error(L,"invalid interface view cursor");
        switch(field.kind){
        case 0:lua_remove(L,-2);LUA_STACK_GUARD_RETURN(L,1)
        case 1:lua_pushf_table(L,(const char *)field.label);lua_getfield(L,-1,(const char *)field.label);break;
        case 2:lua_pushf_str(L,field.name,(const char *)field.data);break;
        case 3:lua_pushf_lstr(L,field.name,(const char *)field.data,field.length);break;
        case 4:lua_pushf_lint(L,field.name,field.number);break;
        case 5:lua_pushf_table(L,field.name);lua_getfield(L,-1,field.name);break;
        case 6:lua_pushi_table(L,field.number);lua_rawgeti(L,-1,field.number);break;
        case 7:lua_pushstring(L,field.name);if(field.length)lua_pushlstring(L,(const char *)field.bytes,field.length);else lua_pushnil(L);lua_rawset(L,-3);break;
        case 8:lua_pop(L,1);break;
        case 9:lua_pop(L,2);break;
        default:return luaL_error(L,"invalid interface view field");
        }
    }
}
