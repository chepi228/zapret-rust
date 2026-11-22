/* MIT. Lua-owning connection operations run between Rust packet-setup calls. */
#include "runtime_log_windows.h"

typedef struct {
    bool (*cached_hostname)(struct play_state *, bool *);
    char *(*duplicate)(const char *);
    struct desync_profile *(*find)(const struct play_state *, const char *, bool);
    void (*purge_failures)(struct desync_profile *);
    void (*update_ttl)(const struct play_state *, const char *);
    void (*get_ttl)(const struct play_state *, const char *);
    zapret_log_sink log, error;
    void (*format_address)(const struct in_addr *, const struct in6_addr *, char *, size_t);
    const bool *debug_enabled, *server;
} zapret_play_ops;

uint32_t zapret_play_begin(struct play_state *, const struct dissect *,
    const t_ctrack_positions *, bool, uint32_t, uint32_t);
bool zapret_play_resume(struct play_state *, const char *, const char *,
    bool, bool, uint32_t, const zapret_play_ops *);

#define CHECK_PLAY_OFFSET(field, offset) \
    _Static_assert(offsetof(struct play_state, field) == offset, "Rust play state ABI: " #field)
CHECK_PLAY_OFFSET(dis, 0);
CHECK_PLAY_OFFSET(dp, 8);
CHECK_PLAY_OFFSET(tpos, 16);
CHECK_PLAY_OFFSET(ctrack, 24);
CHECK_PLAY_OFFSET(ctrack_replay, 32);
CHECK_PLAY_OFFSET(src, 40);
CHECK_PLAY_OFFSET(dst, 168);
CHECK_PLAY_OFFSET(sdip4, 296);
CHECK_PLAY_OFFSET(sdip6, 304);
CHECK_PLAY_OFFSET(sdport, 312);
CHECK_PLAY_OFFSET(verdict, 314);
CHECK_PLAY_OFFSET(host, 315);
CHECK_PLAY_OFFSET(l7proto, 572);
CHECK_PLAY_OFFSET(l7payload, 576);
CHECK_PLAY_OFFSET(ssid, 584);
CHECK_PLAY_OFFSET(fwmark, 592);
CHECK_PLAY_OFFSET(bReverse, 596);
CHECK_PLAY_OFFSET(bReverseFixed, 597);
CHECK_PLAY_OFFSET(bHaveHost, 598);
#undef CHECK_PLAY_OFFSET
_Static_assert(sizeof(struct play_state) == 600 && offsetof(t_ctrack, pos) == 24 &&
    offsetof(t_ctrack, dp) == 184 && offsetof(t_ctrack, incoming_ttl) == 195,
    "Rust track prefix ABI");
_Static_assert(sizeof(zapret_play_ops) == 88 && INET6_ADDRSTRLEN == 65 &&
    offsetof(struct desync_profile, n) == 0 && offsetof(struct desync_profile, name) == 8,
    "Rust play diagnostics ABI");
_Static_assert(sizeof(struct dissect) == 112 && offsetof(struct dissect, ip) == 16 &&
    offsetof(struct dissect, ip6) == 24 && offsetof(struct dissect, tcp) == 48 &&
    offsetof(struct dissect, udp) == 56 && offsetof(struct dissect, len_payload) == 96,
    "Rust play packet ABI");
_Static_assert(AF_INET == 2 && AF_INET6 == 23 && sizeof(struct sockaddr_storage) == 128 &&
    offsetof(struct sockaddr_in, sin_port) == 2 && offsetof(struct sockaddr_in, sin_addr) == 4 &&
    offsetof(struct sockaddr_in6, sin6_port) == 2 && offsetof(struct sockaddr_in6, sin6_flowinfo) == 4 &&
    offsetof(struct sockaddr_in6, sin6_addr) == 8 && offsetof(struct sockaddr_in6, sin6_scope_id) == 24,
    "Rust endpoint ABI");
_Static_assert(VERDICT_PASS == 0 && L7_UNKNOWN == 1 && L7P_UNKNOWN == 1 && L7P_EMPTY == 2,
    "Rust initial play values");

static bool prolog_cached_hostname(struct play_state *ps, bool *is_ip)
{
    return ipcache_get_hostname(ps->sdip4, ps->sdip6, ps->host, sizeof(ps->host), is_ip);
}

static struct desync_profile *prolog_find(const struct play_state *ps, const char *host, bool is_ip)
{
    return dp_find(&params.desync_profiles, ps->dis->proto, ps->sdip4, ps->sdip6, NULL, NULL,
        ps->sdport, 0xff, 0xff, host, is_ip, ps->l7proto, ps->ssid, ps->fwmark, NULL, NULL, NULL);
}

static void prolog_purge_failures(struct desync_profile *profile)
{
    HostFailPoolPurgeRateLimited(&profile->hostlist_auto_fail_counters, &profile->hostlist_auto_last_purge);
}

static void prolog_update_ttl(const struct play_state *ps, const char *interface)
{
    ipcache_update_ttl(ps->ctrack, ps->sdip4, ps->sdip6, interface);
}

static void prolog_get_ttl(const struct play_state *ps, const char *interface)
{
    ipcache_get_ttl(ps->ctrack, ps->sdip4, ps->sdip6, interface);
}

static bool play_prolog(struct play_state *ps, const struct dissect *packet,
    const t_ctrack_positions *positions, bool replay, const char *ifin,
    const char *ifout, uint32_t mark)
{
    static const zapret_play_ops ops = {
        prolog_cached_hostname, strdup, prolog_find, prolog_purge_failures,
        prolog_update_ttl, prolog_get_ttl, DLOG, DLOG_ERR, ntopa46, &params.debug, &params.server
    };
    uint32_t flags = (params.server ? 1u : 0u) | (params.ctrack_disable ? 2u : 0u) |
        (params.debug ? 4u : 0u);
    uint32_t operation = zapret_play_begin(ps, packet, positions, replay, flags, mark);
    bool found = false;
    /* Conntrack can allocate or release Lua objects. It runs after Rust returns. */
    switch (operation) {
    case 0: return false;
    case 1:
        found = ConntrackPoolDoubleSearch(&params.conntrack, packet, &ps->ctrack_replay, &ps->bReverse);
        break;
    case 2:
        ConntrackPoolPurge(&params.conntrack);
        found = ConntrackPoolFeed(&params.conntrack, packet, &ps->ctrack, &ps->bReverse);
        break;
    case 3: break;
    default: return false;
    }
    return zapret_play_resume(ps, ifin, ifout, replay, found, flags, &ops);
}
