/* MIT. Compare the two selectors with the native list and filter APIs. */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "hostlist.h"
#include "ipset.h"

#undef main

struct params_s params;

static unsigned cases, boundary_cases;
static char trace[4096];
static size_t trace_len;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL profile selection case %u line %d: %s\n", cases, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

static int log_trace(const char *format, va_list args)
{
    if (!params.debug) return 0;
    int bytes = vsnprintf(trace + trace_len, sizeof(trace) - trace_len, format, args);
    CHECK(bytes >= 0 && (size_t)bytes < sizeof(trace) - trace_len);
    trace_len += bytes;
    return bytes;
}

#define TRACE_LOG(name) \
    int name(const char *format, ...) { \
        va_list args; \
        va_start(args, format); \
        int bytes = log_trace(format, args); \
        va_end(args); \
        return bytes; \
    }
TRACE_LOG(DLOG)
TRACE_LOG(DLOG_CONDUP)
TRACE_LOG(DLOG_ERR)
int DLOG_PERROR(const char *message) { return DLOG("%s\n", message); }

struct tm *zapret_localtime_r(const time_t *value, struct tm *output)
{
    return localtime_s(output, value) ? NULL : output;
}

#define proto_name reference_proto_name
#include "profile_protocol_names.inc"
#define dp_find reference_dp_find
#include "profile_selection_reference.inc"
#undef dp_find
#undef proto_name
#include "profile_selection_actual.inc"

typedef __typeof__(&dp_find) Find;

struct outcome {
    struct desync_profile *profile;
    bool done, result, excluded;
};

static struct outcome run(Find find, const struct zapret_profile_query *query,
    unsigned outputs, unsigned initial)
{
    struct outcome value = {NULL, initial & 1, initial & 2, initial & 4};
    trace_len = 0;
    trace[0] = 0;
    value.profile = find(&params.desync_profiles, query->protocol,
        query->ipv4, query->ipv6, query->reverse_ipv4, query->reverse_ipv6,
        query->port, query->icmp_type, query->icmp_code,
        query->hostname, query->no_subdomains, query->l7, NULL, 0,
        outputs & 1 ? &value.done : NULL, outputs & 2 ? &value.result : NULL,
        outputs & 4 ? &value.excluded : NULL);
    return value;
}

static struct outcome compare(const struct zapret_profile_query *query, unsigned outputs,
    unsigned initial)
{
    ++cases;
    struct outcome expected = run(reference_dp_find, query, outputs, initial);
    char expected_trace[sizeof(trace)];
    memcpy(expected_trace, trace, trace_len + 1);
    struct outcome actual = run(dp_find, query, outputs, initial);
    CHECK(expected.profile == actual.profile);
    CHECK(expected.done == actual.done && expected.result == actual.result &&
        expected.excluded == actual.excluded);
    CHECK(!strcmp(expected_trace, trace));
    return actual;
}

enum profile_id { WEB, AUTO, CONTROL, DEFAULT, BROKEN, PROFILE_COUNT };
static struct desync_profile_list profiles[PROFILE_COUNT];
static struct in_addr include4, exclude4, other4;
static struct in6_addr include6, exclude6, other6;

static void order(const enum profile_id *ids, size_t count)
{
    LIST_INIT(&params.desync_profiles);
    while (count) {
        struct desync_profile_list *node = &profiles[ids[--count]];
        LIST_INSERT_HEAD(&params.desync_profiles, node, next);
    }
}

static void port(struct port_filters_head *list, const char *spec)
{
    port_filter filter;
    CHECK(pf_parse(spec, &filter) && port_filter_add(list, &filter));
}

static void setup(void)
{
    for (unsigned i = 0; i < PROFILE_COUNT; ++i) {
        profiles[i].dp.n = i + 1;
        profiles[i].dp.filter_ipv4 = profiles[i].dp.filter_ipv6 = true;
    }
    CHECK(inet_pton(AF_INET, "192.0.2.10", &include4) == 1);
    CHECK(inet_pton(AF_INET, "192.0.2.11", &exclude4) == 1);
    CHECK(inet_pton(AF_INET, "192.0.2.12", &other4) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::a", &include6) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::b", &exclude6) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::c", &other6) == 1);

    struct desync_profile *web = &profiles[WEB].dp;
    web->name = "website";
    web->filter_l7 = (UINT64_C(1) << L7_TLS) | (UINT64_C(1) << L7_HTTP);
    port(&web->pf_tcp, "80-81");
    port(&web->pf_tcp, "443");
    port(&web->pf_udp, "0");
    struct zapret_list_file *list = RegisterHostlist(web, false, NULL);
    CHECK(list && HostlistPoolAddStr(&list->hostlist, "example.com", 0));
    CHECK(HostlistPoolAddStr(&list->hostlist, "strict.example", HOSTLIST_POOL_FLAG_STRICT_MATCH));
    list = RegisterHostlist(web, true, NULL);
    CHECK(list && HostlistPoolAddStr(&list->hostlist, "blocked.example.com", 0));
    list = RegisterIpset(web, false, NULL);
    CHECK(list && ipset4Add(&list->ipset.ips4, &include4, 32));
    CHECK(ipset6Add(&list->ipset.ips6, &include6, 128));
    list = RegisterIpset(web, true, NULL);
    CHECK(list && ipset4Add(&list->ipset.ips4, &exclude4, 32));
    CHECK(ipset6Add(&list->ipset.ips6, &exclude6, 128));

    struct desync_profile *automatic = &profiles[AUTO].dp;
    automatic->name = "automatic";
    automatic->filter_ipv6 = false;
    automatic->filter_l7 = UINT64_C(1) << L7_KNOWN;
    port(&automatic->pf_tcp, "0");
    port(&automatic->pf_udp, "~53");
    automatic->hostlist_auto = RegisterHostlist(automatic, false, NULL);
    CHECK(automatic->hostlist_auto && NonEmptyHostlist(&automatic->hostlist_auto->hostlist));
    list = RegisterHostlist(automatic, true, NULL);
    CHECK(list && HostlistPoolAddStr(&list->hostlist, "blocked.example.com", 0));
    CHECK(RegisterIpset(automatic, false, NULL)); // Empty IP list admits all.

    struct desync_profile *control = &profiles[CONTROL].dp;
    control->filter_ipv4 = false;
    port(&control->pf_tcp, "0");
    port(&control->pf_udp, "0");
    icmp_filter icf;
    CHECK(icf_parse("128:0", &icf) && icmp_filter_add(&control->icf, &icf));
    CHECK(icf_parse("3", &icf) && icmp_filter_add(&control->icf, &icf));
    ipp_filter ipf;
    CHECK(ipp_parse("47", &ipf) && ipp_filter_add(&control->ipf, &ipf));
    CHECK(RegisterHostlist(control, false, NULL)); // Present, with no loaded entries.

    const char *name = "invalid-hostlist.gz";
    const unsigned char corrupt[] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    FILE *file = fopen(name, "wb");
    CHECK(file && fwrite(corrupt, 1, sizeof(corrupt), file) == sizeof(corrupt));
    CHECK(!fclose(file));
    CHECK(RegisterHostlist(&profiles[BROKEN].dp, false, name));
}

#define ORDER(...) do { \
    const enum profile_id ids[] = {__VA_ARGS__}; \
    order(ids, sizeof(ids) / sizeof(ids[0])); \
} while (0)

static void expect(const struct zapret_profile_query *query, int id, unsigned flags)
{
    struct outcome outcome = compare(query, 7, 7);
    CHECK(outcome.profile == (id < 0 ? NULL : &profiles[id].dp));
    CHECK(outcome.done == !!(flags & 1) && outcome.result == !!(flags & 2) &&
        outcome.excluded == !!(flags & 4));
    ++boundary_cases;
}

static void boundaries(void)
{
    params.debug = true;
    struct zapret_profile_query q = {
        .protocol = IPPROTO_TCP, .l7 = L7_TLS, .port = 443,
        .ipv4 = &include4, .hostname = "www.example.com"
    };
    order(NULL, 0);
    expect(&q, -1, 6);
    ORDER(WEB, DEFAULT);
    expect(&q, WEB, 3);
    ORDER(DEFAULT, WEB);
    expect(&q, DEFAULT, 6);
    ORDER(WEB, DEFAULT);
    q.hostname = NULL;
    expect(&q, DEFAULT, 6);
    q.hostname = "sub.strict.example";
    expect(&q, DEFAULT, 0);
    q.hostname = "strict.example";
    expect(&q, WEB, 3);
    q.hostname = "blocked.example.com";
    expect(&q, DEFAULT, 4);
    ORDER(WEB);
    expect(&q, -1, 5);
    ORDER(WEB, DEFAULT);
    q.hostname = "www.example.com";
    q.no_subdomains = true;
    expect(&q, DEFAULT, 0);
    q.no_subdomains = false;
    q.reverse_ipv4 = &exclude4;
    expect(&q, DEFAULT, 6);
    q.ipv4 = &other4;
    q.reverse_ipv4 = &include4;
    expect(&q, WEB, 3);
    q.ipv4 = NULL;
    q.reverse_ipv4 = NULL;
    q.ipv6 = &other6;
    q.reverse_ipv6 = &include6;
    expect(&q, WEB, 3);
    q.ipv6 = &exclude6;
    expect(&q, DEFAULT, 6);
    q.ipv6 = &include6;
    q.port = 0;
    expect(&q, DEFAULT, 6);
    q.port = 80;
    expect(&q, WEB, 3);
    q.port = 81;
    expect(&q, WEB, 3);
    q.port = 82;
    expect(&q, DEFAULT, 6);

    ORDER(AUTO, DEFAULT);
    q = (struct zapret_profile_query){
        .protocol = IPPROTO_UDP, .l7 = L7_QUIC, .port = 443,
        .ipv4 = &include4, .hostname = "blocked.example.com"
    };
    expect(&q, AUTO, 6);
    q.hostname = NULL;
    expect(&q, DEFAULT, 6);
    q.hostname = "example.com";
    q.port = 53;
    expect(&q, DEFAULT, 6);

    ORDER(CONTROL, DEFAULT);
    q = (struct zapret_profile_query){
        .protocol = IPPROTO_ICMPV6, .ipv6 = &include6, .icmp_type = 128
    };
    expect(&q, CONTROL, 6);
    q.icmp_code = 1;
    expect(&q, DEFAULT, 6);
    q.icmp_type = 3;
    expect(&q, CONTROL, 6);
    q.protocol = 47;
    expect(&q, CONTROL, 6);
    q.protocol = 50;
    expect(&q, DEFAULT, 6);

    ORDER(BROKEN, DEFAULT);
    q.hostname = "example.com";
    expect(&q, DEFAULT, 6);
    params.debug = false;
}

static void combinations(void)
{
    static const enum profile_id orders[][4] = {
        {WEB, AUTO, CONTROL, DEFAULT}, {AUTO, WEB, CONTROL, DEFAULT},
        {CONTROL, AUTO, WEB, DEFAULT}, {DEFAULT, WEB, CONTROL, AUTO}
    };
    static const uint8_t protocols[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP,
        IPPROTO_ICMPV6, 47, 50};
    static const uint16_t ports[] = {0, 1, 53, 79, 80, 81, 82, 443, 65535};
    static const t_l7proto l7[] = {L7_UNKNOWN, L7_TLS, L7_HTTP, L7_QUIC};
    static const char *const hosts[] = {
        NULL, "", "example.com", "www.example.com", "strict.example", "sub.strict.example",
        "blocked.example.com", "unlisted.example"
    };
    for (unsigned i = 0; i < sizeof(orders) / sizeof(orders[0]); ++i) {
        order(orders[i], sizeof(orders[i]) / sizeof(orders[i][0]));
        for (unsigned j = 0; j < 16384; ++j) {
            // Coprime strides vary the transport filters and secondary addresses.
            struct zapret_profile_query q = {
                .protocol = protocols[j / 7 % 6],
                .port = ports[j / 11 % 9],
                .l7 = l7[j / 13 % 4],
                .icmp_type = j % 3 ? 128 : 3,
                .icmp_code = j / 17 % 2,
                .hostname = hosts[j / 19 % 8],
                .no_subdomains = j / 23 % 2,
                .ipv4 = j & 1 ? (j % 3 ? &include4 : &other4) : NULL,
                .ipv6 = j & 2 ? (j % 5 ? &include6 : &other6) : NULL,
                .reverse_ipv4 = j & 4 ? (j % 3 ? &exclude4 : &include4) : NULL,
                .reverse_ipv6 = j & 8 ? (j % 5 ? &exclude6 : &include6) : NULL,
            };
            compare(&q, j / 5 % 8, j / 3 % 8);
        }
    }
}

enum { BENCH_ROUNDS = 9, BENCH_SEARCHES = 131072 };

static __attribute__((noinline)) double time_searches(Find find,
    const struct zapret_profile_query queries[4], unsigned *result)
{
    LARGE_INTEGER frequency, start, end;
    CHECK(QueryPerformanceFrequency(&frequency));
    CHECK(QueryPerformanceCounter(&start));
    unsigned matches = 0;
    for (unsigned i = 0; i < BENCH_SEARCHES; ++i) {
        const struct zapret_profile_query *q = &queries[i % 4];
        const struct desync_profile *profile = find(&params.desync_profiles, q->protocol,
            q->ipv4, q->ipv6, q->reverse_ipv4, q->reverse_ipv6, q->port, q->icmp_type,
            q->icmp_code, q->hostname, q->no_subdomains, q->l7, NULL, 0, NULL, NULL, NULL);
        if (profile) matches += profile->n;
    }
    CHECK(QueryPerformanceCounter(&end));
    *result = matches;
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / BENCH_SEARCHES;
}

static int compare_time(const void *left, const void *right)
{
    double a = *(const double *)left, b = *(const double *)right;
    return (a > b) - (a < b);
}

static void benchmark(const char *name, const struct zapret_profile_query queries[4])
{
    double reference[BENCH_ROUNDS], actual[BENCH_ROUNDS];
    unsigned c_matches, rust_matches;
    for (unsigned i = 0; i < BENCH_ROUNDS; ++i) {
        if (i % 2 == 0) {
            reference[i] = time_searches(reference_dp_find, queries, &c_matches);
            actual[i] = time_searches(dp_find, queries, &rust_matches);
        } else {
            actual[i] = time_searches(dp_find, queries, &rust_matches);
            reference[i] = time_searches(reference_dp_find, queries, &c_matches);
        }
        CHECK(c_matches == rust_matches);
    }
    qsort(reference, BENCH_ROUNDS, sizeof(reference[0]), compare_time);
    qsort(actual, BENCH_ROUNDS, sizeof(actual[0]), compare_time);
    printf("BENCH profile_selection %s c_ns=%.2f rust_ns=%.2f rounds=%u searches_per_round=%u\n",
        name, reference[BENCH_ROUNDS / 2], actual[BENCH_ROUNDS / 2], BENCH_ROUNDS, BENCH_SEARCHES);
}

static void benchmarks(void)
{
    const struct zapret_profile_query headers[4] = {
        {.protocol = IPPROTO_TCP, .ipv4 = &include4, .l7 = L7_TLS, .port = 82},
        {.protocol = IPPROTO_UDP, .ipv4 = &include4, .l7 = L7_QUIC, .port = 53},
        {.protocol = IPPROTO_ICMPV6, .ipv6 = &include6, .icmp_type = 128, .icmp_code = 1},
        {.protocol = 50, .ipv6 = &include6}
    };
    ORDER(DEFAULT);
    benchmark("unfiltered", headers);
    ORDER(WEB, AUTO, CONTROL, DEFAULT);
    benchmark("header-fallback", headers);
    const struct zapret_profile_query with_lists[4] = {
        {.protocol = IPPROTO_TCP, .ipv4 = &include4, .l7 = L7_TLS, .port = 443,
            .hostname = "www.example.com"},
        {.protocol = IPPROTO_TCP, .ipv6 = &include6, .l7 = L7_TLS, .port = 443,
            .hostname = "blocked.example.com"},
        {.protocol = IPPROTO_TCP, .ipv4 = &other4, .reverse_ipv4 = &include4,
            .l7 = L7_HTTP, .port = 80, .hostname = "strict.example"},
        {.protocol = IPPROTO_TCP, .ipv6 = &exclude6, .l7 = L7_HTTP, .port = 81,
            .hostname = "example.com"}
    };
    ORDER(WEB, DEFAULT);
    benchmark("inline-lists", with_lists);
}

static void cleanup(void)
{
    for (unsigned i = 0; i < PROFILE_COUNT; ++i) {
        struct desync_profile *p = &profiles[i].dp;
        port_filters_destroy(&p->pf_tcp);
        port_filters_destroy(&p->pf_udp);
        icmp_filters_destroy(&p->icf);
        ipp_filters_destroy(&p->ipf);
        zapret_list_collection_destroy(&p->hl_collection);
        zapret_list_collection_destroy(&p->hl_collection_exclude);
        zapret_list_collection_destroy(&p->ips_collection);
        zapret_list_collection_destroy(&p->ips_collection_exclude);
    }
    zapret_list_files_destroy(&params.hostlists);
    zapret_list_files_destroy(&params.ipsets);
}

#include "profile_rediscovery_oracle.inc"
#include "play_prolog_oracle.inc"

int main(void)
{
    setup();
    boundaries();
    combinations();
    printf("PASS profile_selection cases=%u boundary_cases=%u\n", cases, boundary_cases);
    benchmarks();
    check_rediscovery();
    check_play_prolog();
    cleanup();
    return 0;
}
