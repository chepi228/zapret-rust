/* MIT. Rust-owned auxiliary indexes and stable public cache payloads. */
#pragma once
#include <stddef.h>
#include <stdint.h>

_Static_assert(IFNAMSIZ == 44, "Rust cache interface key width");
_Static_assert(sizeof(hostfail_pool) == 2 * sizeof(void *) + 8 &&
    offsetof(hostfail_pool, expire) == 2 * sizeof(void *),
    "Rust host failure payload ABI");
_Static_assert(sizeof(ip_cache_item) == 2 * sizeof(void *) + 8 &&
    offsetof(ip_cache_item, ttl) == sizeof(void *) + 9,
    "Rust IP cache payload ABI");

hostfail_pool *zapret_hostfail_add(hostfail_index **, const char *, int, int64_t);
hostfail_pool *zapret_hostfail_find(const hostfail_index *, const char *);
hostfail_pool *zapret_hostfail_after(const hostfail_index *, uint64_t *);
hostfail_pool *zapret_hostfail_next_expired(const hostfail_index *, uint64_t *, int64_t);
void zapret_hostfail_remove(hostfail_index **, const hostfail_pool *);
void zapret_hostfail_destroy(hostfail_index **);
void zapret_hostfail_increment(hostfail_pool *);
int zapret_hostfail_expired(const hostfail_pool *, int64_t);

ip_cache_item *zapret_ipcache_find(const ip_cache4 *, const unsigned char *, size_t, const char *);
ip_cache_item *zapret_ipcache_add(ip_cache4 **, const unsigned char *, size_t, const char *, int64_t);
void zapret_ipcache_touch(ip_cache_item *, int64_t);
ip_cache_item *zapret_ipcache_after(const ip_cache4 *, uint64_t *, unsigned char *, unsigned char *);
ip_cache_item *zapret_ipcache_next_expired(const ip_cache4 *, uint64_t *, int64_t, int64_t);
void zapret_ipcache_remove(ip_cache4 **, const ip_cache_item *);
int zapret_ipcache_expired(const ip_cache_item *, int64_t, int64_t);
int zapret_cache_purge_due(int64_t, int64_t);
