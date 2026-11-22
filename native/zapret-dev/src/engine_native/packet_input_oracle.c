/* MIT. In-memory comparisons of detector order, DNS and packet cache effects. */
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "darkmagic.h"
#include "protocol.h"
#undef main

struct params_s params;
static unsigned cases;
#define CHECK(value) do { \
    if (!(value)) { fprintf(stderr, "FAIL packet input case %u line %d: %s\n", cases, __LINE__, #value); exit(1); } \
} while (0)

static char trace[32768];
static size_t trace_length;
static uint8_t *late_dns_address;
static int log_message(const char *format, va_list args)
{
    int count = vsnprintf(trace + trace_length, sizeof(trace) - trace_length, format, args);
    CHECK(count >= 0 && (size_t)count < sizeof(trace) - trace_length);
    trace_length += count;
    return count;
}
int DLOG(const char *format, ...)
{
    if (!params.debug) return 0;
    va_list args;
    va_start(args, format);
    int count = log_message(format, args);
    va_end(args);
    if (late_dns_address && !strcmp(format, "DNS response type %u : %s\n"))
        *late_dns_address = 0x7f;
    return count;
}
int DLOG_ERR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int count = log_message(format, args);
    va_end(args);
    return count;
}
static void clear_trace(void)
{
    trace_length = 0;
    trace[0] = 0;
}

#undef pntoh16
uint16_t pntoh16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
void ntopa46(const struct in_addr *v4, const struct in6_addr *v6, char *text, size_t capacity)
{
    CHECK(v4 || v6);
    CHECK(inet_ntop(v4 ? AF_INET : AF_INET6, v4 ? (const void *)v4 : v6, text, capacity));
}

#include "protocol_probe_descriptor.inc"
#define protocol_probe reference_protocol_probe
#include "protocol_probe_reference.inc"
#undef protocol_probe
#include "protocol_probe_windows.inc"

static uint32_t calls;
static bool checking(unsigned number, const uint8_t *data, size_t length)
{
    calls = (calls << 4) | number;
    return length && (data[0] & (1u << number)) != 0;
}
static bool detect1(const uint8_t *p, size_t n) { return checking(1, p, n); }
static bool detect2(const uint8_t *p, size_t n) { return checking(2, p, n); }
static bool detect3(const uint8_t *p, size_t n) { return checking(3, p, n); }
static bool detect4(const uint8_t *p, size_t n) { return checking(4, p, n); }

static void check_probe(void)
{
    t_protocol_probe probes[] = {
        {L7P_HTTP_REQ, L7_HTTP, detect1, false},
        {L7P_WIREGUARD_DATA, L7_WIREGUARD, detect2, true},
        {L7P_DNS_RESPONSE, L7_DNS, detect3, false},
        {L7P_TLS_CLIENT_HELLO, L7_TLS, detect4, false}
    };
    static const uint64_t disabled[] = {0, 1, 1ull << L7P_KNOWN, 1ull << L7P_HTTP_REQ,
        1ull << L7P_DNS_RESPONSE, (1ull << L7P_HTTP_REQ) | (1ull << L7P_WIREGUARD_DATA)};
    char expected[128];
    for (unsigned mask = 0; mask < 32; ++mask)
    for (unsigned gate = 0; gate < sizeof(disabled) / sizeof(*disabled); ++gate)
    for (int count = -1; count <= 4; ++count)
    for (unsigned state = 0; state < 8; ++state) {
        t_ctrack left = {0}, right = {0};
        t_l7proto p = state & 1 ? L7_UNKNOWN : L7_WIREGUARD, q = p;
        t_l7payload u = L7P_UNKNOWN, v = u;
        left.l7proto = right.l7proto = state & 2 ? L7_UNKNOWN : L7_XMPP;
        params.payload_disable = disabled[gate];
        params.debug = (mask & 1) != 0;
        uint8_t data = (uint8_t)mask;
        clear_trace();
        calls = 0;
        reference_protocol_probe(probes, count, &data, 1, state & 4 ? NULL : &left, &p, &u);
        memcpy(expected, trace, trace_length + 1);
        uint32_t order = calls;
        clear_trace();
        calls = 0;
        protocol_probe(probes, count, &data, 1, state & 4 ? NULL : &right, &q, &v);
        CHECK(p == q && u == v && left.l7proto == right.l7proto && calls == order);
        CHECK(!strcmp(expected, trace));
        ++cases;
    }
    printf("PASS protocol_probe cases=%u\n", cases);
    cases = 0;
}

static ip_cache_item cache_record;
static bool cache_present, fail_touch, fail_duplicate;
static unsigned finds, touches, duplicates;
ip_cache_item *ipcacheFind(ip_cache *pool, const struct in_addr *v4,
    const struct in6_addr *v6, const char *iface)
{
    CHECK(pool == &params.ipcache && (!!v4 != !!v6));
    if (iface) CHECK(!strcmp(iface, "fixture"));
    ++finds;
    return cache_present ? &cache_record : NULL;
}
ip_cache_item *ipcacheTouch(ip_cache *pool, const struct in_addr *v4,
    const struct in6_addr *v6, const char *iface)
{
    CHECK(pool == &params.ipcache && (!!v4 != !!v6));
    if (iface) CHECK(!strcmp(iface, "fixture"));
    ++touches;
    if (fail_touch) return NULL;
    cache_present = true;
    ++cache_record.last;
    return &cache_record;
}
static char *duplicate(const char *name)
{
    ++duplicates;
    return fail_duplicate ? NULL : strdup(name);
}

#define strdup duplicate
#define ipcache_get_hostname reference_ipcache_get_hostname
#define ipcache_put_hostname reference_ipcache_put_hostname
#define ipcache_update_ttl reference_ipcache_update_ttl
#define ipcache_get_ttl reference_ipcache_get_ttl
#include "packet_cache_reference.inc"
#undef ipcache_get_hostname
#undef ipcache_put_hostname
#undef ipcache_update_ttl
#undef ipcache_get_ttl
#include "packet_cache_windows.inc"
#undef strdup

struct cache_result {
    char hostname[64], output[32], log[1024];
    unsigned finds, touches, duplicates;
    int64_t last;
    uint8_t ttl, next_ttl;
    bool cached, found, is_ip, entry_is_ip, present;
};
static const struct in_addr loopback = {.s_addr = 0x0100007f};
static void run_cache(struct cache_result *result, bool actual, unsigned flags, unsigned test)
{
    memset(result, 0, sizeof(*result));
    memset(&cache_record, 0, sizeof(cache_record));
    memset(result->output, '-', sizeof(result->output));
    clear_trace();
    finds = touches = duplicates = 0;
    params.cache_hostname = (flags & 1) != 0;
    params.server = (flags & 2) != 0;
    params.debug = (flags & 4) != 0;
    cache_present = (flags & 8) != 0;
    fail_touch = (flags & 16) != 0;
    fail_duplicate = (flags & 32) != 0;
    if (cache_present && (flags & 64)) {
        cache_record.hostname = strdup("old.example");
        CHECK(cache_record.hostname);
        cache_record.hostname_is_ip = 1;
    }
    cache_record.ttl = flags & 128 ? 64 : 0;
    t_ctrack track = {0};
    track.incoming_ttl = test & 1 ? 63 : 0;
    const char *name = test & 2 ? "old.example" : "new.example";
    size_t capacity = test & 4 ? 1 : test & 8 ? 5 : sizeof(result->output);
    result->is_ip = true;
    bool *flag = test & 16 ? NULL : &result->is_ip;
    if (actual) {
        result->cached = ipcache_put_hostname(&loopback, NULL, name, false);
        result->found = ipcache_get_hostname(&loopback, NULL, result->output, capacity, flag);
        ipcache_update_ttl(&track, &loopback, NULL, "fixture");
        ipcache_get_ttl(&track, &loopback, NULL, "fixture");
        ipcache_update_ttl(NULL, &loopback, NULL, "fixture");
    } else {
        result->cached = reference_ipcache_put_hostname(&loopback, NULL, name, false);
        result->found = reference_ipcache_get_hostname(&loopback, NULL, result->output, capacity, flag);
        reference_ipcache_update_ttl(&track, &loopback, NULL, "fixture");
        reference_ipcache_get_ttl(&track, &loopback, NULL, "fixture");
        reference_ipcache_update_ttl(NULL, &loopback, NULL, "fixture");
    }
    result->present = cache_present;
    result->entry_is_ip = cache_record.hostname_is_ip;
    result->ttl = cache_record.ttl;
    result->next_ttl = track.incoming_ttl;
    result->last = cache_record.last;
    result->finds = finds;
    result->touches = touches;
    result->duplicates = duplicates;
    if (cache_record.hostname) {
        strcpy(result->hostname, cache_record.hostname);
        free(cache_record.hostname);
        cache_record.hostname = NULL;
    }
    CHECK(trace_length < sizeof(result->log));
    memcpy(result->log, trace, trace_length + 1);
}

static void check_cache(void)
{
    for (unsigned flags = 0; flags < 256; ++flags)
    for (unsigned test = 0; test < 32; ++test) {
        struct cache_result a, b;
        // This specific allocation failure preserves the previous name now.
        if ((flags & 121) == 105 && !(test & 2)) continue;
        run_cache(&a, false, flags, test);
        run_cache(&b, true, flags, test);
        CHECK(!memcmp(&a, &b, sizeof(a)));
        ++cases;
    }
    struct cache_result b;
    run_cache(&b, true, 105, 0);
    CHECK(!b.cached && b.found && b.is_ip && b.entry_is_ip && b.duplicates == 1);
    CHECK(!strcmp(b.hostname, "old.example") && !strcmp(b.output, "old.example"));
    run_cache(&b, true, 1, 0);
    CHECK(b.cached && b.found && !b.is_ip && !strcmp(b.hostname, "new.example"));
    printf("PASS packet_cache cases=%u allocation_regressions=2\n", cases);
    cases = 0;
}

static bool quiet_cache, reject_address, require_aligned_address;
struct address {
    size_t length;
    uint8_t bytes[16];
    char hostname[256];
};
static struct address addresses[16];
static unsigned writes;
static __attribute__((noinline)) bool capture_dns(const struct in_addr *v4, const struct in6_addr *v6,
    const char *host, bool is_ip)
{
    if (quiet_cache) return true;
    CHECK((!!v4 != !!v6) && !is_ip && writes < sizeof(addresses) / sizeof(*addresses));
    if (require_aligned_address)
        CHECK(v4 ? (uintptr_t)v4 % _Alignof(struct in_addr) == 0 :
            (uintptr_t)v6 % _Alignof(struct in6_addr) == 0);
    struct address *address = &addresses[writes++];
    address->length = v4 ? 4 : 16;
    memcpy(address->bytes, v4 ? (const void *)v4 : v6, address->length);
    CHECK(strlen(host) < sizeof(address->hostname));
    strcpy(address->hostname, host);
    return !reject_address;
}
#define ipcache_put_hostname capture_dns
#define feed_dns_response reference_feed_dns_response
#include "dns_response_reference.inc"
#undef feed_dns_response
#include "dns_response_windows.inc"
#undef ipcache_put_hostname

struct message { uint8_t data[1024]; size_t length; };
static void bytes(struct message *m, const void *p, size_t n)
{
    CHECK(n <= sizeof(m->data) - m->length);
    memcpy(m->data + m->length, p, n);
    m->length += n;
}
static void word(struct message *m, uint16_t n)
{
    uint8_t value[] = {(uint8_t)(n >> 8), (uint8_t)n};
    bytes(m, value, sizeof(value));
}
static struct message dns(unsigned q, unsigned a)
{
    struct message m = {{0, 1, 0x81, 0x80, 0, (uint8_t)q, 0, (uint8_t)a}, 12};
    return m;
}
static void question(struct message *m, bool root, unsigned type, unsigned class)
{
    if (root) bytes(m, "\0", 1);
    else bytes(m, "\x05MiXeD\x07""Example\0", 15);
    word(m, type);
    word(m, class);
}
static void answer(struct message *m, unsigned owner, unsigned type, unsigned class, size_t n)
{
    switch (owner) {
    case 0: bytes(m, "\xc0\x0c", 2); break;
    case 1: bytes(m, "\x03www\xc0\x0c", 6); break;
    default: bytes(m, "\x03www\0", 5); break;
    }
    word(m, type);
    word(m, class);
    word(m, 0);
    word(m, 30);
    word(m, (uint16_t)n);
    CHECK(n <= 16);
    const uint8_t address[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    bytes(m, address, n);
}
static void reset_dns(void)
{
    clear_trace();
    writes = 0;
    memset(addresses, 0, sizeof(addresses));
}
static void equal_dns(const struct message *m)
{
    struct address expected[16];
    char expected_log[2048];
    reset_dns();
    bool ret = reference_feed_dns_response(m->data, m->length);
    unsigned expected_writes = writes;
    memcpy(expected, addresses, sizeof(expected));
    CHECK(trace_length < sizeof(expected_log));
    memcpy(expected_log, trace, trace_length + 1);
    reset_dns();
    CHECK(feed_dns_response(m->data, m->length) == ret);
    CHECK(writes == expected_writes && !memcmp(addresses, expected, sizeof(expected)));
    CHECK(!strcmp(trace, expected_log));
    ++cases;
}
static void check_dns(void)
{
    static const uint16_t type[] = {1, 28, 5, 16, 65};
    for (unsigned i = 0; i < 4096; ++i) {
        unsigned count = (i >> 9) & 7;
        bool root = (i & 256) != 0;
        struct message m = dns(root ? 2 : 1, count);
        params.debug = (i & 1) != 0;
        params.cache_hostname = !(i & 2);
        if (root) question(&m, true, 1, 1);
        question(&m, false, i & 4 ? 28 : i & 8 ? 16 : 1, i & 16 ? 3 : 1);
        for (unsigned j = 0; j < count; ++j) {
            uint16_t t = type[((i >> 5) + j) % (sizeof(type) / sizeof(*type))];
            answer(&m, (i + j) % 3, t, (i + j) % 7 ? 1 : 3,
                (i + j) % 4 ? (t == 1 ? 4 : 16) : 3);
        }
        if (i & 128) bytes(&m, "tail", 4);
        equal_dns(&m);
    }
    params.cache_hostname = true;
    params.debug = true;
    struct message m = dns(1, 2);
    question(&m, false, 1, 1);
    answer(&m, 0, 1, 1, 4);
    size_t first = m.length;
    answer(&m, 1, 28, 1, 16);
    unsigned boundaries = 0;
    for (size_t n = 0; n < m.length; ++n) {
        reset_dns();
        CHECK(!feed_dns_response(n ? m.data : NULL, n) && !writes);
        ++boundaries;
    }
    reset_dns();
    CHECK(feed_dns_response(m.data, m.length) && writes == 2);
    CHECK(addresses[0].length == 4 && addresses[1].length == 16);
    CHECK(!strcmp(addresses[0].hostname, "mixed.example") && !strcmp(addresses[1].hostname, "mixed.example"));
    ++boundaries;
    reset_dns();
    m.data[first + 5] = 0xff; // Second owner has an out-of-bounds pointer.
    m.data[first + 4] = 0xff;
    CHECK(!feed_dns_response(m.data, m.length) && !writes);
    ++boundaries;
    m = dns(1, 1);
    bytes(&m, "\x03WWW\xc0\0", 6);
    word(&m, 1); word(&m, 1);
    answer(&m, 0, 1, 1, 4);
    m.data[17] = (uint8_t)m.length;
    word(&m, 0xc000 | (uint16_t)(m.length + 2));
    bytes(&m, "\x03" "COM\0", 5);
    reset_dns();
    CHECK(feed_dns_response(m.data, m.length) && writes == 1 && !strcmp(addresses[0].hostname, "www.com"));
    ++boundaries;
    reset_dns();
    reject_address = true;
    CHECK(!feed_dns_response(m.data, m.length) && writes == 1);
    reject_address = false;
    ++boundaries;
    reset_dns();
    m.data[17] = 12;
    CHECK(!feed_dns_response(m.data, m.length) && !writes);
    ++boundaries;
    for (unsigned ipv6 = 0; ipv6 < 2; ++ipv6) {
        unsigned type = ipv6 ? 28 : 1;
        size_t width = ipv6 ? 16 : 4;
        for (unsigned rust = 0; rust < 2; ++rust) {
            m = dns(1, 1);
            question(&m, false, type, 1);
            answer(&m, 0, type, 1, width);
            reset_dns();
            late_dns_address = m.data + m.length - width;
            require_aligned_address = rust;
            CHECK((rust ? feed_dns_response : reference_feed_dns_response)(m.data, m.length));
            CHECK(writes == 1 && addresses[0].length == width && addresses[0].bytes[0] == 0x7f);
            late_dns_address = NULL;
            require_aligned_address = false;
            ++boundaries;
        }
    }
    printf("PASS dns_response cases=%u boundary_cases=%u late_addresses=2\n", cases, boundaries);
    cases = 0;
}

#define pos_get reference_pos_get
#define pos_overflow reference_pos_overflow
#define check_pos_cutoff reference_check_pos_cutoff
#define check_pos_range reference_check_pos_range
#include "packet_range_reference.inc"
#undef pos_get
#undef pos_overflow
#undef check_pos_cutoff
#undef check_pos_range
#define verdict_aggregate reference_verdict_aggregate
#include "packet_verdict_reference.inc"
#undef verdict_aggregate
#include "packet_range_windows.inc"
#include "packet_verdict_windows.inc"

static void check_packet_policy(void)
{
    static const char modes[] = "axndspb?";
    static const uint32_t limits[] = {0, 1, 7, 8, 12, 20, 0x7fffffff, 0x80000000u, UINT32_MAX};
    t_ctrack_position pos[] = {
        {0},
        {.pcounter = 7, .pdcounter = 1, .pbcounter = 20, .seq0 = 2, .seq_last = 10, .pos = 14},
        {.pcounter = UINT32_MAX + 1ull, .pdcounter = UINT32_MAX, .pbcounter = UINT64_MAX,
            .seq0 = UINT32_MAX - 3, .seq_last = 3, .pos = 16},
        {.pcounter = 7, .pbcounter = 20, .seq0 = 16, .seq_last = 3, .pos = 15, .rseq_over_2G = true}
    };
    for (unsigned p = 0; p <= sizeof(pos) / sizeof(*pos); ++p) {
        const t_ctrack_position *snapshot = p ? &pos[p - 1] : NULL;
        for (unsigned from = 0; from < sizeof(modes) - 1; ++from)
        for (unsigned to = 0; to < sizeof(modes) - 1; ++to)
        for (unsigned lo = 0; lo < sizeof(limits) / sizeof(*limits); ++lo)
        for (unsigned hi = 0; hi < sizeof(limits) / sizeof(*limits); ++hi)
        for (unsigned strict = 0; strict < 2; ++strict) {
            struct packet_range range = {{modes[from], limits[lo]}, {modes[to], limits[hi]}, strict};
            CHECK(check_pos_range(snapshot, &range) == reference_check_pos_range(snapshot, &range));
            CHECK(check_pos_cutoff(snapshot, &range) == reference_check_pos_cutoff(snapshot, &range));
            ++cases;
        }
        for (const char *mode = modes; *mode; ++mode) {
            CHECK(pos_get(snapshot, *mode) == reference_pos_get(snapshot, *mode));
            CHECK(pos_overflow(snapshot, *mode) == reference_pos_overflow(snapshot, *mode));
        }
    }
    printf("PASS packet_range cases=%u\n", cases);
    cases = 0;
    for (unsigned a = 0; a <= UINT8_MAX; ++a)
    for (unsigned b = 0; b <= UINT8_MAX; ++b) {
        CHECK(verdict_aggregate((uint8_t)a, (uint8_t)b) == reference_verdict_aggregate((uint8_t)a, (uint8_t)b));
        ++cases;
    }
    printf("PASS packet_verdict cases=%u\n", cases);
    cases = 0;
}

enum { ROUNDS = 9, REPEAT = 65536 };
static volatile unsigned bench_sum;
static __attribute__((noinline)) double time_dns(bool actual, const struct message *m)
{
    LARGE_INTEGER frequency, begin, end;
    CHECK(QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&begin));
    unsigned sum = 0;
    for (unsigned i = 0; i < REPEAT; ++i) {
        sum += actual ? feed_dns_response(m->data, m->length) : reference_feed_dns_response(m->data, m->length);
    }
    bench_sum = sum;
    CHECK(QueryPerformanceCounter(&end) && sum == REPEAT);
    return (double)(end.QuadPart - begin.QuadPart) * 1e9 / frequency.QuadPart / REPEAT;
}
static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}
static void benchmark_dns(unsigned count)
{
    struct message m = dns(1, count);
    question(&m, false, 1, 1);
    for (unsigned i = 0; i < count; ++i) answer(&m, 0, i ? 28 : 1, 1, i ? 16 : 4);
    params.cache_hostname = true;
    params.debug = false;
    quiet_cache = true;
    double reference[ROUNDS], actual[ROUNDS];
    for (unsigned i = 0; i < ROUNDS; ++i) {
        if (i & 1) actual[i] = time_dns(true, &m);
        reference[i] = time_dns(false, &m);
        if (!(i & 1)) actual[i] = time_dns(true, &m);
    }
    qsort(reference, ROUNDS, sizeof(*reference), cmp_double);
    qsort(actual, ROUNDS, sizeof(*actual), cmp_double);
    printf("BENCH dns_response answers%u c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",
        count, reference[ROUNDS / 2], actual[ROUNDS / 2], ROUNDS, REPEAT);
    quiet_cache = false;
}
int main(void)
{
    check_probe();
    check_dns();
    check_cache();
    check_packet_policy();
    benchmark_dns(1);
    benchmark_dns(4);
    return 0;
}
