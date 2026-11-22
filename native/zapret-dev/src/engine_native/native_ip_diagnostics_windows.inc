/* MIT. Bind engine list heads and the native sink to the Rust presenter. */
#include "native_diagnostic_views_abi.h"
void IpsetsDebugProfile(const struct desync_profile *profile,const char *entity)
{
    zapret_native_list_profile_debug(profile,entity,true,DLOG);
}
void IpsetsDebug(void)
{
    const zapret_list_debug_sources sources={
        &params.debug,&params.ipsets,&LIST_FIRST(&params.desync_profiles),&LIST_FIRST(&params.desync_templates)
    };
    zapret_native_list_debug(&sources,true,DLOG);
}
