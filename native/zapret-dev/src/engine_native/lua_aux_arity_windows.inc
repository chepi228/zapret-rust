/* VM errors are raised only after Rust returns the corresponding format. */
#include "lua_aux_abi.h"

static void lua_check_argc(lua_State *L, const char *where, int argc)
{
    int actual = lua_gettop(L);
    const char *format = zapret_lua_arity_error(actual, argc, argc, false);
    if (format) luaL_error(L, format, where, argc, actual);
}

static void lua_check_argc_range(lua_State *L, const char *where, int minimum, int maximum)
{
    int actual = lua_gettop(L);
    const char *format = zapret_lua_arity_error(actual, minimum, maximum, true);
    if (format) luaL_error(L, format, where, minimum, maximum, actual);
}
