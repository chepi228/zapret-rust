/* MIT. Bounded DNS framing, compressed query names and cache decisions in Rust. */
#include "runtime_log_windows.h"

typedef struct {
    zapret_log_sink log;
    size_t (*format_address)(const uint8_t *, size_t, char *, size_t);
} zapret_dns_report;

_Static_assert(sizeof(zapret_dns_report) == 16 && INET6_ADDRSTRLEN == 65,
    "Rust DNS diagnostics ABI");
_Static_assert(sizeof(struct in_addr) == 4 && sizeof(struct in6_addr) == 16 &&
    _Alignof(struct in_addr) <= 4 && _Alignof(struct in6_addr) <= 4, "Rust DNS address ABI");
size_t zapret_lua_ntop(const uint8_t *, size_t, char *, size_t);
bool zapret_feed_dns_response(const uint8_t *, size_t, bool, bool,
    bool (*)(const struct in_addr *, const struct in6_addr *, const char *, bool),
    const zapret_dns_report *);

static bool feed_dns_response(const uint8_t *data, size_t length)
{
    static const zapret_dns_report report = {DLOG, zapret_lua_ntop};
    return zapret_feed_dns_response(data, length, params.cache_hostname, params.debug,
        ipcache_put_hostname, &report);
}
