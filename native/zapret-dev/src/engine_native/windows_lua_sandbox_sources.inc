/* MIT. Bind the current VM and native blob ownership for Lua startup. */
#include "windows_lua_sandbox_abi.h"

const zapret_lua_sandbox_source_fields zapret_lua_sandbox_sources = {
    .lua = &params.L,
    .blobs = &params.blobs,
    .allocator = &native_blob_allocator,
};
