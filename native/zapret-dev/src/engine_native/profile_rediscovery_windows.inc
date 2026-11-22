/* MIT. Profile discovery callbacks around the Rust connection state machine. */
#include "runtime_log_windows.h"

typedef struct {
    bool done, result, excluded;
} zapret_host_check;

typedef struct {
    void *context;
    struct desync_profile **profile;
    void *connection;
    zapret_host_check *checks;
    char *host;
    uint32_t l7;
    uint8_t protocol;
    bool have_host;
} zapret_profile_session;

typedef struct {
    bool (*normalize)(char *);
    char *(*duplicate)(const char *);
    void (*release)(void *);
    bool (*cache)(void *, const char *, bool);
    struct desync_profile *(*find)(void *, const char *, bool, zapret_host_check *);
    bool (*check_host)(const struct desync_profile *, const char *, bool, bool *, bool);
    void (*udp_failure)(void *);
    zapret_log_sink log, error;
    void (*format_endpoint)(const struct sockaddr *, char *, size_t);
    const bool *debug_enabled;
} zapret_rediscovery_ops;

bool zapret_profile_rediscover(const zapret_profile_session *, const zapret_rediscovery_ops *);

#define CHECK_DISCOVERY_OFFSET(field, offset) \
    _Static_assert(offsetof(t_ctrack, field) - offsetof(t_ctrack, dp) == offset, \
        "Rust profile discovery ABI: " #field)
CHECK_DISCOVERY_OFFSET(dp_search_complete, 8);
CHECK_DISCOVERY_OFFSET(req_retrans_counter, 9);
CHECK_DISCOVERY_OFFSET(failure_detect_finalized, 10);
CHECK_DISCOVERY_OFFSET(incoming_ttl, 11);
CHECK_DISCOVERY_OFFSET(b_cutoff, 12);
CHECK_DISCOVERY_OFFSET(b_lua_in_cutoff, 13);
CHECK_DISCOVERY_OFFSET(b_lua_out_cutoff, 14);
CHECK_DISCOVERY_OFFSET(l7proto, 16);
CHECK_DISCOVERY_OFFSET(l7proto_discovered, 20);
CHECK_DISCOVERY_OFFSET(hostname, 24);
CHECK_DISCOVERY_OFFSET(hostname_is_ip, 32);
CHECK_DISCOVERY_OFFSET(hostname_discovered, 33);
CHECK_DISCOVERY_OFFSET(hostname_ah_check, 34);
#undef CHECK_DISCOVERY_OFFSET
_Static_assert(offsetof(t_ctrack, bCheckResult) - offsetof(t_ctrack, bCheckDone) == 1 &&
    offsetof(t_ctrack, bCheckExcluded) - offsetof(t_ctrack, bCheckDone) == 2 &&
    sizeof(zapret_host_check) == 3, "Rust host check ABI");
_Static_assert(sizeof(zapret_profile_session) == 48 &&
    offsetof(zapret_profile_session, l7) == 40 &&
    offsetof(zapret_profile_session, protocol) == 44 &&
    L7_UNKNOWN == 1 && RETRANS_COUNTER_STOP == 255, "Rust discovery session ABI");
_Static_assert(sizeof(zapret_rediscovery_ops) == 88 &&
    offsetof(zapret_rediscovery_ops, format_endpoint) == 72, "Rust rediscovery effects ABI");
_Static_assert(offsetof(struct play_state, src) == 40 && offsetof(struct play_state, dst) == 168 &&
    offsetof(struct play_state, l7proto) == 572 && offsetof(struct play_state, l7payload) == 576 &&
    offsetof(struct play_state, bReverse) == 596 && offsetof(struct play_state, bReverseFixed) == 597,
    "Rust rediscovery endpoint ABI");

static bool rediscovery_cache(void *context, const char *host, bool is_ip)
{
    const struct play_state *ps = context;
    return ipcache_put_hostname(ps->sdip4, ps->sdip6, host, is_ip);
}

static struct desync_profile *rediscovery_find(void *context, const char *host,
    bool is_ip, zapret_host_check *check)
{
    const struct play_state *ps = context;
    return dp_find(&params.desync_profiles, ps->dis->proto, ps->sdip4, ps->sdip6,
        NULL, NULL, ps->sdport, 0xff, 0xff, host, is_ip, ps->l7proto,
        ps->ssid, ps->fwmark, &check->done, &check->result, &check->excluded);
}

static void rediscovery_udp_failure(void *context)
{
    const struct play_state *ps = context;
    process_udp_fail(ps->ctrack_replay, ps->tpos, (const struct sockaddr *)&ps->src);
}

static bool dp_rediscovery(struct play_state *ps)
{
    static const zapret_rediscovery_ops ops = {
        .normalize = strip_host_to_ip,
        .duplicate = strdup,
        .release = free,
        .cache = rediscovery_cache,
        .find = rediscovery_find,
        .check_host = HostlistCheck,
        .udp_failure = rediscovery_udp_failure,
        .log = DLOG, .error = DLOG_ERR,
        .format_endpoint = ntop46_port, .debug_enabled = &params.debug,
    };
    const zapret_profile_session session = {
        .context = ps,
        .profile = &ps->dp,
        .connection = ps->ctrack_replay ? &ps->ctrack_replay->dp : NULL,
        .checks = ps->ctrack_replay ? (zapret_host_check *)&ps->ctrack_replay->bCheckDone : NULL,
        .host = ps->host,
        .l7 = ps->l7proto,
        .protocol = ps->dis->proto,
        .have_host = ps->bHaveHost,
    };
    return zapret_profile_rediscover(&session, &ops);
}
