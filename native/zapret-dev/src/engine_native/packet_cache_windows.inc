/* MIT. Foreign cache/allocation/logging adapters; policy lives in Rust. */
typedef struct {
    const struct in_addr *ipv4;
    const struct in6_addr *ipv6;
    const char *interface;
} zapret_packet_cache_context;

typedef struct {
    ip_cache_item *(*find)(void *);
    ip_cache_item *(*touch)(void *);
    char *(*duplicate)(const char *);
    void (*release)(void *);
    void (*report)(void *, uint32_t, const ip_cache_item *);
} zapret_packet_cache_ops;

typedef struct {
    void *context;
    const zapret_packet_cache_ops *ops;
    bool enabled, server;
} zapret_packet_cache_session;

bool zapret_cache_put_hostname(const zapret_packet_cache_session *, const char *, bool);
bool zapret_cache_get_hostname(const zapret_packet_cache_session *, char *, size_t, bool *);
void zapret_cache_ttl(const zapret_packet_cache_session *, uint8_t *, bool);

_Static_assert(sizeof(ip_cache_item) == 24 && offsetof(ip_cache_item, hostname) == 8 &&
    offsetof(ip_cache_item, hostname_is_ip) == 16 && offsetof(ip_cache_item, ttl) == 17 &&
    sizeof(zapret_packet_cache_session) == 24 && sizeof(zapret_packet_cache_ops) == 40,
    "Rust packet cache ABI");

static ip_cache_item *packet_cache_find(void *context)
{
    const zapret_packet_cache_context *c = context;
    return ipcacheFind(&params.ipcache, c->ipv4, c->ipv6, c->interface);
}
static ip_cache_item *packet_cache_touch(void *context)
{
    const zapret_packet_cache_context *c = context;
    return ipcacheTouch(&params.ipcache, c->ipv4, c->ipv6, c->interface);
}
#include "runtime_log_windows.h"
_Static_assert(INET6_ADDRSTRLEN == 65 && offsetof(zapret_packet_cache_context, ipv6) == 8,
    "Rust packet cache diagnostic ABI");
void zapret_packet_cache_report(const zapret_packet_cache_context *, uint32_t, const ip_cache_item *,
    bool, zapret_log_sink, zapret_log_sink);

static void packet_cache_report(void *context, uint32_t event, const ip_cache_item *item)
{
    zapret_packet_cache_report(context, event, item, params.debug, DLOG, DLOG_ERR);
}
static const zapret_packet_cache_ops packet_cache_ops = {
    .find = packet_cache_find, .touch = packet_cache_touch, .duplicate = strdup,
    .release = free, .report = packet_cache_report,
};

static zapret_packet_cache_session packet_cache_session(zapret_packet_cache_context *context)
{
    return (zapret_packet_cache_session){context, &packet_cache_ops, params.cache_hostname, params.server};
}
static bool ipcache_put_hostname(const struct in_addr *a4, const struct in6_addr *a6,
    const char *hostname, bool is_ip)
{
    zapret_packet_cache_context context = {a4, a6, NULL};
    zapret_packet_cache_session session = packet_cache_session(&context);
    return zapret_cache_put_hostname(&session, hostname, is_ip);
}
static bool ipcache_get_hostname(const struct in_addr *a4, const struct in6_addr *a6,
    char *hostname, size_t capacity, bool *is_ip)
{
    zapret_packet_cache_context context = {a4, a6, NULL};
    zapret_packet_cache_session session = packet_cache_session(&context);
    return zapret_cache_get_hostname(&session, hostname, capacity, is_ip);
}
static void ipcache_update_ttl(t_ctrack *track, const struct in_addr *a4,
    const struct in6_addr *a6, const char *interface)
{
    zapret_packet_cache_context context = {a4, a6, interface};
    zapret_packet_cache_session session = packet_cache_session(&context);
    zapret_cache_ttl(&session, track ? &track->incoming_ttl : NULL, true);
}
static void ipcache_get_ttl(t_ctrack *track, const struct in_addr *a4,
    const struct in6_addr *a6, const char *interface)
{
    zapret_packet_cache_context context = {a4, a6, interface};
    zapret_packet_cache_session session = packet_cache_session(&context);
    zapret_cache_ttl(&session, track ? &track->incoming_ttl : NULL, false);
}
