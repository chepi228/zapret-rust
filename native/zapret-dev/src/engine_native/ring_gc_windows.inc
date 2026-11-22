/* MIT. C projects Lua userdata and calls the loaded backend when requested. */
#include "ring_bridge_policy_abi.h"
static bool ring_release_native(void *object)
{
    const rr_api *backend = rr_backend;
    if (!backend) return false;
    backend->drop_object(object);
    return true;
}
static int rr_gc(lua_State *L)
{
    rr_userdata *object = (rr_userdata *)lua_touserdata(L, 1);
    zapret_ring_release_object(object ? &object->object : NULL, ring_release_native);
    return 0;
}
