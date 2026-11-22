/* MIT. C profile records and list callbacks for the Rust selector. */
#include <stddef.h>

struct zapret_profile_query {
    const struct in_addr *ipv4;
    const struct in6_addr *ipv6;
    const struct in_addr *reverse_ipv4;
    const struct in6_addr *reverse_ipv6;
    const char *hostname;
    bool *check_done, *check_result, *excluded;
    uint32_t l7;
    uint16_t port;
    uint8_t icmp_type, icmp_code;
    bool no_subdomains;
    uint8_t protocol;
};

struct zapret_profile_list_checks {
    bool (*reload_hosts)(const struct desync_profile *);
    bool (*check_ips)(const struct desync_profile *, const struct in_addr *,
        const struct in6_addr *, const struct in_addr *, const struct in6_addr *);
    bool (*check_host)(const struct desync_profile *, const char *, bool, bool *, bool);
};

#define PROFILE_FILTER_OFFSET offsetof(struct desync_profile, filter_ipv4)
#define CHECK_PROFILE_OFFSET(field, offset) \
    _Static_assert(offsetof(struct desync_profile, field) - PROFILE_FILTER_OFFSET == offset, \
        "Rust profile ABI: " #field)
CHECK_PROFILE_OFFSET(filter_ipv6, 1);
CHECK_PROFILE_OFFSET(pf_tcp, 8);
CHECK_PROFILE_OFFSET(pf_udp, 16);
CHECK_PROFILE_OFFSET(icf, 24);
CHECK_PROFILE_OFFSET(ipf, 32);
CHECK_PROFILE_OFFSET(filter_l7, 40);
CHECK_PROFILE_OFFSET(ips_collection, 48);
CHECK_PROFILE_OFFSET(ips_collection_exclude, 56);
CHECK_PROFILE_OFFSET(hl_collection, 64);
CHECK_PROFILE_OFFSET(hl_collection_exclude, 72);
CHECK_PROFILE_OFFSET(hostlist_auto, 80);
#undef CHECK_PROFILE_OFFSET

_Static_assert(offsetof(struct desync_profile_list, dp) == 0 &&
    offsetof(struct desync_profile, hl_collection) == 88 &&
    offsetof(struct desync_profile, hl_collection_exclude) == 96 &&
    offsetof(struct desync_profile, hostlist_auto) == 104 &&
    sizeof(struct port_filters_head) == sizeof(void *) &&
    sizeof(struct icmp_filters_head) == sizeof(void *) &&
    sizeof(struct ipp_filters_head) == sizeof(void *), "Rust profile link ABI");
_Static_assert(sizeof(bool) == 1 && sizeof(port_filter) == 6 &&
    offsetof(port_filter, neg) == 4 && offsetof(struct port_filter_item, next.le_next) == 8 &&
    sizeof(icmp_filter) == 4 && offsetof(icmp_filter, code_valid) == 3 &&
    offsetof(struct icmp_filter_item, next.le_next) == 8 && sizeof(ipp_filter) == 2 &&
    offsetof(struct ipp_filter_item, next.le_next) == 8, "Rust filter item ABI");
_Static_assert(FLTMODE_ANY == 1 && FLTMODE_FILTER == 2 && IPPROTO_ICMP == 1 &&
    IPPROTO_TCP == 6 && IPPROTO_UDP == 17 && IPPROTO_ICMPV6 == 58, "Rust filter values");
_Static_assert(sizeof(struct zapret_profile_query) == 80 &&
    offsetof(struct zapret_profile_query, check_done) == 40 &&
    offsetof(struct zapret_profile_query, l7) == 64 &&
    offsetof(struct zapret_profile_query, protocol) == 73, "Rust profile query ABI");

struct desync_profile *zapret_profile_find(struct desync_profile_list *, size_t, size_t,
    const struct zapret_profile_query *, const struct zapret_profile_list_checks *);

static struct desync_profile *profile_find_windows(struct desync_profile_list_head *head,
    const struct zapret_profile_query *query)
{
    static const struct zapret_profile_list_checks checks = {
        HostlistsReloadCheckForProfile, IpsetCheck, HostlistCheck
    };
    struct desync_profile *profile = zapret_profile_find(LIST_FIRST(head), PROFILE_FILTER_OFFSET,
        offsetof(struct desync_profile_list, next.le_next), query, &checks);
    if (profile) {
        if (profile->hostlist_auto && query->hostname)
            DLOG("autohostlist profile %u (%s) wins because hostname is known\n", profile->n, profile->name);
        DLOG("desync profile %u (%s) matches\n", profile->n, PROFILE_NAME(profile));
    } else {
        DLOG("desync profile not found\n");
    }
    return profile;
}
