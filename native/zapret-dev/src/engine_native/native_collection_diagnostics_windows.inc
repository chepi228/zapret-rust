/* MIT. Bind engine state and native callbacks to the Rust presenters. */
#include "native_diagnostic_views_abi.h"
static void BlobDebug(void)
{
    zapret_native_blob_debug(&LIST_FIRST(&params.blobs),DLOG);
}
static void LuaDesyncDebug(const struct desync_profile *profile,const char *entity)
{
    zapret_native_lua_debug(profile,entity,params.debug,l7payload_str,DLOG);
}
