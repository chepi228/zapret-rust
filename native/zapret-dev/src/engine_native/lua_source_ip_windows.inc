/* MIT. The Rust call has closed its socket before C enters the VM. */
#include "route_source_windows.h"
static int luacall_get_source_ip(lua_State *L)
{
    lua_check_argc(L,"get_source_ip",1);
    LUA_STACK_GUARD_ENTER(L)
    size_t length;const uint8_t *target=(const uint8_t *)lua_reqlstring(L,1,&length);uint8_t source[16];
    switch(zapret_lua_source_ip(target,length,source,NULL)){
    case 0:lua_pushnil(L);break;
    case 1:lua_pushlstring(L,(const char *)source,length);break;
    default:return luaL_error(L,"invalid IP length %u",(unsigned int)length);
    }
    LUA_STACK_GUARD_RETURN(L,1)
}
