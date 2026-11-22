/* MIT. Lua predicates/coercion stay in C; Rust classifies the result. */
#include "lua_invocation_abi.h"
static bool desync_get_result(uint8_t *verdict)
{
    int count=lua_gettop(params.L);uint32_t kind=0;lua_Integer number=0;
    if(count==1 && !lua_isnil(params.L,-1)){
        kind=lua_isinteger(params.L,-1)?1:2;
        if(kind==1)number=lua_tointeger(params.L,-1);
    }
    uint32_t error=zapret_lua_invocation_result(count,kind,number,verdict);
    if(error)zapret_lua_invocation_error_report(error,count,DLOG_ERR);
    lua_pop(params.L,count);return error==0;
}
