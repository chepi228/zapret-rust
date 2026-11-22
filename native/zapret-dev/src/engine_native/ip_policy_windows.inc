/* MIT. Pool decisions execute in Rust; IPv4/IPv6 diagnostics use the old text. */
#include "list_policy_windows.h"
static zapret_ip_policy_ops native_ip_policy(void)
{
    return (zapret_ip_policy_ops){LoadIpset, params.debug ? DLOG : NULL, zapret_lua_ntop};
}
bool LoadAllIpsets(void)
{
    zapret_ip_policy_ops ops = native_ip_policy();
    return zapret_ipsets_load_all(params.ipsets, &ops);
}
bool IpsetsReloadCheckForProfile(const struct desync_profile *profile)
{
    zapret_ip_policy_ops ops = native_ip_policy();
    return zapret_ipsets_reload_pair(profile->ips_collection, profile->ips_collection_exclude, &ops);
}
bool IpsetCheck(const struct desync_profile *profile, const struct in_addr *ipv4, const struct in6_addr *ipv6,
    const struct in_addr *reverse4, const struct in6_addr *reverse6)
{
    if (PROFILE_IPSETS_ABSENT(profile)) return true;
    zapret_list_report_profile(profile, true, DLOG);
    zapret_ip_policy_ops ops = native_ip_policy();
    return zapret_ipsets_check(profile->ips_collection, profile->ips_collection_exclude, ipv4, ipv6, reverse4, reverse6, &ops);
}
