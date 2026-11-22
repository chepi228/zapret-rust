/* MIT. References to the current engine fields and pinned function addresses. */
#include "windows_registry_vm_abi.h"
#include "windows_startup_params_abi.h"
#include "lua_registry_callbacks.inc"

const zapret_lua_registry_source zapret_lua_registry_sources = {
    .lua = &params.L,
    .version = params.verstr,
    .mark = &params.desync_fwmark,
    .debug = &params.debug,
    .daemon = &params.daemon,
    .server = &params.server,
    .cache_hostname = &params.cache_hostname,
    .ctrack_disable = &params.ctrack_disable,
    .callbacks = native_lua_registry_callbacks,
    .count = sizeof(native_lua_registry_callbacks) / sizeof(*native_lua_registry_callbacks),
    .create_context = lua_desync_ctx_create,
};
