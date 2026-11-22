/* MIT. Bind engine list heads and the native sink to the Rust presenter. */
#include "native_diagnostic_views_abi.h"
void HostlistsDebug(void)
{
    const zapret_list_debug_sources sources={
        &params.debug,&params.hostlists,&LIST_FIRST(&params.desync_profiles),&LIST_FIRST(&params.desync_templates)
    };
    zapret_native_list_debug(&sources,false,DLOG);
}
