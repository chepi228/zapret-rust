/* MIT. Deterministic C/Rust cache conformance; no driver or network traffic. */
#include "cache_fixture.h"
#include <inttypes.h>

void *reference_fail_create(void);
void *reference_fail_add(void *, const char *, int);
void *reference_fail_find(void *, const char *);
void reference_fail_read(void *, cache_fail_view *);
void reference_fail_increment(void *);
void reference_fail_set_counter(void *, int);
void reference_fail_delete(void *, void *);
void reference_fail_purge(void *, time_t *, bool);
void reference_fail_destroy(void *);
void reference_fail_dump(void *);
void *reference_fail_after(void *, size_t *);
void *reference_ip_create(void);
ip_cache_item *reference_ip_touch(void *, const struct in_addr *, const struct in6_addr *, const char *);
ip_cache_item *reference_ip_find(void *, const struct in_addr *, const struct in6_addr *, const char *);
void reference_ip_purge(void *, time_t);
void reference_ip_destroy(void *);
void reference_ip_dump(void *);
ip_cache_item *reference_ip_after(void *, bool, size_t *, unsigned char *, unsigned char *);

static time_t fake_time = 100;
static unsigned clock_calls, step;
static uint32_t seed = 0x49e81f62;
static uint64_t fail_operations, ip_operations, snapshots, dumps;
static char printed[1048576], expected_print[1048576];
static size_t printed_length;
#define REQUIRE(value) do { if (!(value)) { \
    fprintf(stderr,"FAIL auxiliary cache step %u line %d: %s\n", step, __LINE__, #value); exit(1); \
} } while (0)

time_t boottime(void) { ++clock_calls; return fake_time; }
static uint32_t random32(void)
{
    seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
    return seed;
}
int cache_oracle_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int length = vsnprintf(printed + printed_length, sizeof(printed) - printed_length, format, args);
    va_end(args);
    REQUIRE(length >= 0 && (size_t)length < sizeof(printed) - printed_length);
    printed_length += length;
    return length;
}
static void same_failure(void *left, const hostfail_pool *right)
{
    REQUIRE(!!left == !!right);
    if (!left) return;
    cache_fail_view a;
    reference_fail_read(left, &a);
    REQUIRE(!strcmp(a.name, right->str) && a.counter == right->counter && a.expires == right->expire);
    ++snapshots;
}
static void same_fail_table(void *reference, hostfail_index *actual)
{
    size_t left = 0; uint64_t right = 0;
    for (;;) {
        void *a = reference_fail_after(reference, &left);
        hostfail_pool *b = zapret_hostfail_after(actual, &right);
        same_failure(a, b);
        if (!a) break;
    }
    printed_length = 0; reference_fail_dump(reference);
    memcpy(expected_print, printed, printed_length + 1);
    size_t expected = printed_length;
    printed_length = 0; HostFailPoolDump(actual);
    REQUIRE(printed_length == expected && !memcmp(printed, expected_print, expected));
    ++dumps;
}
static void same_item(const ip_cache_item *a, const ip_cache_item *b)
{
    REQUIRE(!!a == !!b);
    if (!a) return;
    REQUIRE(a->last == b->last && a->ttl == b->ttl && a->hostname_is_ip == b->hostname_is_ip);
    REQUIRE(!!a->hostname == !!b->hostname);
    if (a->hostname) REQUIRE(!strcmp(a->hostname, b->hostname));
    ++snapshots;
}
static void same_ip_table(void *reference, ip_cache *actual)
{
    for (unsigned family = 0; family < 2; ++family) {
        size_t left = 0; uint64_t right = 0;
        unsigned char aa[16], ba[16], ai[IFNAMSIZ], bi[IFNAMSIZ];
        for (;;) {
            ip_cache_item *a = reference_ip_after(reference, family, &left, aa, ai);
            ip_cache_item *b = zapret_ipcache_after(family ? actual->ipcache6 : actual->ipcache4, &right, ba, bi);
            same_item(a, b);
            if (!a) break;
            REQUIRE(!memcmp(aa, ba, 16) && !memcmp(ai, bi, IFNAMSIZ));
        }
    }
    printed_length = 0; reference_ip_dump(reference);
    memcpy(expected_print, printed, printed_length + 1);
    size_t expected = printed_length;
    printed_length = 0; ipcachePrint(actual);
    REQUIRE(printed_length == expected && !memcmp(printed, expected_print, expected));
    ++dumps;
}
static void fail_add_pair(void *reference, hostfail_index **actual, const char *name, int timeout)
{
    clock_calls = 0;
    void *a = reference_fail_add(reference, name, timeout);
    unsigned calls = clock_calls;
    clock_calls = 0;
    hostfail_pool *b = HostFailPoolAdd(actual, name, timeout);
    REQUIRE(clock_calls == calls && a && b);
    reference_fail_set_counter(a, step);
    b->counter = step;
    same_failure(a, b);
    same_failure(reference_fail_find(reference, name), HostFailPoolFind(*actual, name));
    ++fail_operations;
}
static void check_failures(void)
{
    void *reference = reference_fail_create();
    REQUIRE(reference);
    hostfail_index *actual = NULL;
    time_t a_previous = 0, b_previous = 0;
    // Force both effective and ineffective hash expansions with duplicate keys.
    for (step = 0; step < 1000; ++step) {
        char name[80];
        snprintf(name, sizeof(name), "failure-%u.example", step % 3 ? step % 257 : 0);
        fail_add_pair(reference, &actual, name, 1 + step);
        if (step % 17 == 0) same_fail_table(reference, actual);
    }
    same_fail_table(reference, actual);
    for (step = 0; step < 60000; ++step) {
        char name[128];
        unsigned key = random32() % 1024;
        snprintf(name, sizeof(name), "%s-%u.example", key & 1 ? "Case" : "case", key);
        if (step % 71 == 0) *name = 0;
        unsigned action = random32() % 8;
        if (action < 3) fail_add_pair(reference, &actual, name, (int)(random32() % 19) - 3);
        else if (action < 6) {
            void *a = reference_fail_find(reference, name);
            hostfail_pool *b = HostFailPoolFind(actual, name);
            same_failure(a, b);
            if (a) {
                if (action == 5) reference_fail_delete(reference, a), HostFailPoolDel(&actual, b);
                else reference_fail_increment(a), zapret_hostfail_increment(b), same_failure(a, b);
            }
            ++fail_operations;
        } else {
            bool limited = action == 7;
            clock_calls = 0;
            reference_fail_purge(reference, &a_previous, limited);
            unsigned calls = clock_calls;
            clock_calls = 0;
            if (limited) HostFailPoolPurgeRateLimited(&actual, &b_previous);
            else HostFailPoolPurge(&actual);
            REQUIRE(clock_calls == calls && a_previous == b_previous);
            ++fail_operations;
        }
        if (step % 101 == 0) ++fake_time;
        if (step % 997 == 0) --fake_time;
        if (step % 127 == 0) same_fail_table(reference, actual);
    }
    HostFailPoolDestroy(&actual); reference_fail_destroy(reference);
    same_fail_table(reference, actual);
    HostFailPoolDestroy(&actual); reference_fail_destroy(reference);
    REQUIRE(!actual);
    free(reference);
}

static void addresses(unsigned index, struct in_addr *a4, struct in6_addr *a6)
{
    a4->s_addr = htonl(0xc0000200 + index);
    memset(a6, 0, sizeof(*a6));
    ((unsigned char *)a6)[0] = 0x20; ((unsigned char *)a6)[1] = 1;
    ((unsigned char *)a6)[2] = 0x0d; ((unsigned char *)a6)[3] = 0xb8;
    memcpy((unsigned char *)a6 + 12, a4, 4);
}
static void set_hostname(ip_cache_item *a, ip_cache_item *b, unsigned value)
{
    char text[100];
    snprintf(text, sizeof(text), "name-%u.example", value);
    free(a->hostname); free(b->hostname);
    a->hostname = strdup(text); b->hostname = strdup(text);
    REQUIRE(a->hostname && b->hostname);
    a->hostname_is_ip = b->hostname_is_ip = value & 1;
}
static ip_cache_item *ip_pair(void *reference, ip_cache *actual, const struct in_addr *a4,
    const struct in6_addr *a6, const char *iface, bool touch, ip_cache_item **ref_out)
{
    clock_calls = 0;
    ip_cache_item *a = touch ? reference_ip_touch(reference, a4, a6, iface) : reference_ip_find(reference, a4, a6, iface);
    unsigned calls = clock_calls;
    clock_calls = 0;
    ip_cache_item *b = touch ? ipcacheTouch(actual, a4, a6, iface) : ipcacheFind(actual, a4, a6, iface);
    REQUIRE(clock_calls == calls);
    same_item(a, b);
    if (touch && a) {
        a->ttl = b->ttl = step & 255;
        if (step % 3 == 0) set_hostname(a, b, step);
        same_item(a, b);
        REQUIRE(reference_ip_find(reference, a4, a6, iface) == a);
        REQUIRE(ipcacheFind(actual, a4, a6, iface) == b);
    }
    ++ip_operations;
    if (ref_out) *ref_out = a;
    return b;
}
static void check_ip_cache(void)
{
    void *reference[2] = {reference_ip_create(), reference_ip_create()};
    REQUIRE(reference[0] && reference[1]);
    ip_cache actual[2] = {{0}, {0}};
    struct in_addr a4; struct in6_addr a6;
    char iface_a[200], iface_b[200], utf8_iface[200];
    memset(iface_a, 'x', sizeof(iface_a)-1); iface_a[sizeof(iface_a)-1] = 0;
    memcpy(iface_b, iface_a, sizeof(iface_a)); iface_b[IFNAMSIZ-1] = 'y';
    for (unsigned i = 0; i < sizeof(utf8_iface)-1; ++i) utf8_iface[i] = i & 1 ? '\xb0' : '\xd0';
    utf8_iface[sizeof(utf8_iface)-1] = 0;
    const char *ifaces[] = {NULL, "", "17.4", "Wi-Fi", "wi-fi", iface_a, iface_b, utf8_iface};
    ip_cache_item *saved_a = NULL, *saved_b = NULL;
    // Grow both indexes while keeping a mutable C payload and its hostname alive.
    for (step = 0; step < 4096; ++step) {
        addresses(step, &a4, &a6);
        ip_cache_item *a;
        ip_cache_item *b = ip_pair(reference[0], &actual[0], step & 1 ? NULL : &a4,
            step & 1 ? &a6 : NULL, ifaces[step % 8], true, &a);
        if (!step) saved_a = a, saved_b = b;
    }
    addresses(0, &a4, &a6);
    REQUIRE(reference_ip_find(reference[0], &a4, NULL, NULL) == saved_a);
    REQUIRE(ipcacheFind(&actual[0], &a4, NULL, NULL) == saved_b);
    same_ip_table(reference[0], &actual[0]);
    for (step = 0; step < 80000; ++step) {
        addresses(random32() % 512, &a4, &a6);
        unsigned which = random32() & 1, family = random32() % 4;
        const struct in_addr *p4 = family == 0 || family == 2 ? &a4 : NULL;
        const struct in6_addr *p6 = family == 1 || family == 2 ? &a6 : NULL;
        ip_pair(reference[which], &actual[which], p4, p6, ifaces[random32() % 8], random32() & 1, NULL);
        if (step % 29 == 0) {
            time_t lifetime = step % 13 == 0 ? 0 : step % 11 == 0 ? -1 : 10;
            clock_calls = 0; reference_ip_purge(reference[which], lifetime);
            unsigned calls = clock_calls;
            clock_calls = 0; ipcachePurgeRateLimited(&actual[which], lifetime);
            REQUIRE(clock_calls == calls);
            // Rate limiting is global, including calls on another cache and
            // zero lifetime. The second cache is called during the same second.
            reference_ip_purge(reference[which ^ 1], 1);
            ipcachePurgeRateLimited(&actual[which ^ 1], 1);
        }
        if (step % 71 == 0) ++fake_time;
        if (step % 997 == 0) fake_time -= 2;
        if (step % 521 == 0) same_ip_table(reference[which], &actual[which]);
    }
    fake_time = 0;
    reference_ip_purge(reference[0], 1); ipcachePurgeRateLimited(&actual[0], 1);
    for (unsigned which = 0; which < 2; ++which) {
        same_ip_table(reference[which], &actual[which]);
        reference_ip_destroy(reference[which]); ipcacheDestroy(&actual[which]);
        same_ip_table(reference[which], &actual[which]);
        reference_ip_destroy(reference[which]); ipcacheDestroy(&actual[which]);
        REQUIRE(!actual[which].ipcache4 && !actual[which].ipcache6);
        free(reference[which]);
    }
}
#undef main
int main(void)
{
    check_failures();
    check_ip_cache();
    printf("PASS %" PRIu64 " host failure operations, %" PRIu64 " IP cache operations, %" PRIu64
        " state snapshots, %" PRIu64 " ordered diagnostic dumps; clock calls match pinned C\n",
        fail_operations, ip_operations, snapshots, dumps);
    return 0;
}
