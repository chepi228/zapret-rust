/* MIT. These callbacks never invoke Lua or mutate profile references. */
#include "list_policy_windows.h"
static zapret_host_policy_ops native_host_policy(void)
{
    return (zapret_host_policy_ops){LoadHostList, MakeAutolistsNonEmpty,
        params.debug ? DLOG : NULL};
}
bool LoadAllHostLists(void)
{
    zapret_host_policy_ops ops = native_host_policy();
    return zapret_hostlists_load_all(params.hostlists, &ops);
}
bool HostlistsReloadCheckForProfile(const struct desync_profile *profile)
{
    zapret_host_policy_ops ops = native_host_policy();
    return zapret_hostlists_reload_pair(profile->hl_collection, profile->hl_collection_exclude, &ops);
}
bool HostlistCheck(const struct desync_profile *profile, const char *host, bool no_subdomains, bool *excluded, bool skip_reload)
{
    zapret_list_report_profile(profile, false, DLOG);
    zapret_host_policy_ops ops = native_host_policy();
    return zapret_hostlists_check(profile->hl_collection, profile->hl_collection_exclude, host, no_subdomains, excluded, skip_reload, &ops);
}
