/* The registry operation itself can run a VM callback before clearing the slot. */
#include "lua_aux_abi.h"

static void lua_desync_ctx_destroy(lua_State *L)
{
    if (zapret_lua_context_vm(LUA_CTX_RELEASE_REF, params.ref_desync_ctx)) {
        luaL_unref(L, LUA_REGISTRYINDEX, params.ref_desync_ctx);
        params.ref_desync_ctx = 0;
    }
}
