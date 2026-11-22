/* MIT. Lua shutdown runs on the engine's C frame. */
#include "engine_cleanup_exports_abi.h"

void cleanup_params(struct params_s *params)
{
    lua_shutdown();
    zapret_cleanup_closed_params(params);
}
