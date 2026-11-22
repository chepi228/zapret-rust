/* MIT. Clocks, C hostname buffers and diagnostic formatting around Rust. */
#include "cache_windows.h"

void HostFailPoolDestroy(hostfail_index **pool) { zapret_hostfail_destroy(pool); }
hostfail_pool *HostFailPoolAdd(hostfail_index **pool, const char *name, int timeout)
{
    return zapret_hostfail_add(pool, name, timeout, boottime());
}
hostfail_pool *HostFailPoolFind(hostfail_index *pool, const char *name)
{
    return zapret_hostfail_find(pool, name);
}
void HostFailPoolDel(hostfail_index **pool, hostfail_pool *entry)
{
    zapret_hostfail_remove(pool, entry);
}
void HostFailPoolPurge(hostfail_index **pool)
{
    time_t now = boottime();
    uint64_t cursor = 0;
    hostfail_pool *entry;
    while ((entry = zapret_hostfail_after(*pool, &cursor)))
        if (zapret_hostfail_expired(entry, now)) zapret_hostfail_remove(pool, entry);
}
void HostFailPoolPurgeRateLimited(hostfail_index **pool, time_t *previous)
{
    time_t now = boottime();
    if (zapret_cache_purge_due(*previous, now)) {
        HostFailPoolPurge(pool);
        *previous = now;
    }
}
void HostFailPoolDump(hostfail_index *pool)
{
    time_t now = boottime();
    uint64_t cursor = 0;
    hostfail_pool *entry;
    while ((entry = zapret_hostfail_after(pool, &cursor)))
        printf("host=%s counter=%d time_left=%lld\n", entry->str, entry->counter,
            (long long)entry->expire - now);
}

static void cache_family_destroy(ip_cache4 **pool)
{
    uint64_t cursor = 0;
    ip_cache_item *item;
    while ((item = zapret_ipcache_after(*pool, &cursor, NULL, NULL))) {
        free(item->hostname);
        zapret_ipcache_remove(pool, item);
    }
}
void ipcacheDestroy(ip_cache *cache)
{
    cache_family_destroy(&cache->ipcache4);
    cache_family_destroy(&cache->ipcache6);
}
static void cache_family_print(ip_cache4 *pool, int family)
{
    char text[INET6_ADDRSTRLEN];
    unsigned char address[16], iface[IFNAMSIZ];
    time_t now = boottime();
    uint64_t cursor = 0;
    ip_cache_item *item;
    while ((item = zapret_ipcache_after(pool, &cursor, address, iface))) {
        *text = 0;
        inet_ntop(family, address, text, sizeof(text));
        printf("%s iface=%s : ttl %u hostname=%s hostname_is_ip=%u now=last+%llu\n",
            text, iface, item->ttl, item->hostname ? item->hostname : "",
            item->hostname_is_ip, (unsigned long long)(now - item->last));
    }
}
void ipcachePrint(ip_cache *cache)
{
    cache_family_print(cache->ipcache4, AF_INET);
    cache_family_print(cache->ipcache6, AF_INET6);
}
ip_cache_item *ipcacheFind(ip_cache *cache, const struct in_addr *a4,
    const struct in6_addr *a6, const char *iface)
{
    if (a4) return zapret_ipcache_find(cache->ipcache4, (const unsigned char *)a4, 4, iface);
    if (a6) return zapret_ipcache_find(cache->ipcache6, (const unsigned char *)a6, 16, iface);
    return NULL;
}
ip_cache_item *ipcacheTouch(ip_cache *cache, const struct in_addr *a4,
    const struct in6_addr *a6, const char *iface)
{
    ip_cache4 **pool;
    const unsigned char *address;
    size_t length;
    if (a4) pool = &cache->ipcache4, address = (const unsigned char *)a4, length = 4;
    else if (a6) pool = &cache->ipcache6, address = (const unsigned char *)a6, length = 16;
    else return NULL;
    ip_cache_item *item = zapret_ipcache_find(*pool, address, length, iface);
    if (!item) item = zapret_ipcache_add(pool, address, length, iface, boottime());
    if (item) zapret_ipcache_touch(item, boottime());
    return item;
}
static void cache_family_purge(ip_cache4 **pool, time_t lifetime)
{
    time_t now = boottime();
    uint64_t cursor = 0;
    ip_cache_item *item;
    while ((item = zapret_ipcache_after(*pool, &cursor, NULL, NULL))) {
        if (zapret_ipcache_expired(item, lifetime, now)) {
            free(item->hostname);
            zapret_ipcache_remove(pool, item);
        }
    }
}
static time_t ipcache_purge_prev = 0;
void ipcachePurgeRateLimited(ip_cache *cache, time_t lifetime)
{
    time_t now = boottime();
    if (zapret_cache_purge_due(ipcache_purge_prev, now)) {
        if (lifetime) {
            cache_family_purge(&cache->ipcache4, lifetime);
            cache_family_purge(&cache->ipcache6, lifetime);
        }
        ipcache_purge_prev = now;
    }
}
