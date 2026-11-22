/* MIT. Packet setup against pinned C with deterministic connection/cache operations. */
#include "play_prolog_helpers.inc"

static unsigned prolog_cases, prolog_boundaries;
static t_ctrack *prolog_track;
static bool prolog_found, prolog_reverse, prolog_cache_hit, prolog_cache_is_ip, prolog_alloc_fail;
static const char *prolog_cache_name = "example.com";
static char prolog_calls[32];
static size_t prolog_call_count;

static void prolog_call(char code)
{
    CHECK(prolog_call_count < sizeof(prolog_calls) - 1);
    prolog_calls[prolog_call_count++] = code;
    prolog_calls[prolog_call_count] = 0;
}

static void prolog_connection_purge(t_conntrack *table)
{
    CHECK(table == &params.conntrack);
    prolog_call('P');
}

static bool prolog_connection_find(t_conntrack *table, const struct dissect *packet,
    t_ctrack **track, bool *reverse)
{
    CHECK(table == &params.conntrack && packet && track && reverse);
    prolog_call('S');
    if (prolog_found) {
        *track = prolog_track;
        *reverse = prolog_reverse;
    }
    return prolog_found;
}

static bool prolog_connection_feed(t_conntrack *table, const struct dissect *packet,
    t_ctrack **track, bool *reverse)
{
    CHECK(table == &params.conntrack && packet && track && reverse);
    prolog_call('F');
    if (prolog_found) {
        *track = prolog_track;
        *reverse = prolog_reverse;
        ++prolog_track->lua_state;
    }
    return prolog_found;
}

static bool ipcache_get_hostname(const struct in_addr *ip, const struct in6_addr *ip6,
    char *host, size_t capacity, bool *is_ip)
{
    CHECK(!!ip != !!ip6 && capacity == 256 && host);
    prolog_call('H');
    bool found = params.cache_hostname && prolog_cache_hit;
    snprintf(host, capacity, "%s", found ? prolog_cache_name : "");
    if (found && is_ip) *is_ip = prolog_cache_is_ip;
    return found;
}

static char *prolog_duplicate(const char *host)
{
    prolog_call('D');
    return prolog_alloc_fail ? NULL : strdup(host);
}

static struct desync_profile *prolog_reference_find(struct desync_profile_list_head *head,
    uint8_t protocol, const struct in_addr *ip, const struct in6_addr *ip6,
    const struct in_addr *reverse_ip, const struct in6_addr *reverse_ip6,
    uint16_t port, uint8_t icmp_type, uint8_t icmp_code, const char *host, bool no_subdomains,
    t_l7proto l7, const char *ssid, uint32_t mark, bool *done, bool *result, bool *excluded)
{
    prolog_call('L');
    return reference_dp_find(head, protocol, ip, ip6, reverse_ip, reverse_ip6, port,
        icmp_type, icmp_code, host, no_subdomains, l7, ssid, mark, done, result, excluded);
}

static struct desync_profile *prolog_actual_find(struct desync_profile_list_head *head,
    uint8_t protocol, const struct in_addr *ip, const struct in6_addr *ip6,
    const struct in_addr *reverse_ip, const struct in6_addr *reverse_ip6,
    uint16_t port, uint8_t icmp_type, uint8_t icmp_code, const char *host, bool no_subdomains,
    t_l7proto l7, const char *ssid, uint32_t mark, bool *done, bool *result, bool *excluded)
{
    prolog_call('L');
    return dp_find(head, protocol, ip, ip6, reverse_ip, reverse_ip6, port,
        icmp_type, icmp_code, host, no_subdomains, l7, ssid, mark, done, result, excluded);
}

static void prolog_failures_purge(hostfail_index **pool, time_t *previous)
{
    CHECK(pool && previous);
    prolog_call('R');
    // A callback can update the shared purge clock.
    *previous = 170;
}

static void ipcache_update_ttl(t_ctrack *track, const struct in_addr *ip,
    const struct in6_addr *ip6, const char *interface)
{
    CHECK(!!ip != !!ip6);
    (void)track;
    (void)interface;
    prolog_call('U');
}

static void ipcache_get_ttl(t_ctrack *track, const struct in_addr *ip,
    const struct in6_addr *ip6, const char *interface)
{
    CHECK(!!ip != !!ip6);
    (void)interface;
    prolog_call('T');
    if (track && !params.server && !track->incoming_ttl) track->incoming_ttl = 91;
}

#define ConntrackPoolPurge prolog_connection_purge
#define ConntrackPoolDoubleSearch prolog_connection_find
#define ConntrackPoolFeed prolog_connection_feed
#define HostFailPoolPurgeRateLimited prolog_failures_purge
#define strdup prolog_duplicate
#define dp_find prolog_reference_find
#define setup_direction reference_setup_direction
#define play_prolog reference_play_prolog
#include "play_prolog_reference.inc"
#undef play_prolog
#undef setup_direction
#undef dp_find
#define dp_find prolog_actual_find
#include "play_prolog_windows.inc"
#undef dp_find
#undef strdup
#undef HostFailPoolPurgeRateLimited
#undef ConntrackPoolFeed
#undef ConntrackPoolDoubleSearch
#undef ConntrackPoolPurge

typedef bool (*PlayProlog)(struct play_state *, const struct dissect *,
    const t_ctrack_positions *, bool, const char *, const char *, uint32_t);

static bool compare_prolog(struct play_state *left, struct play_state *right,
    t_ctrack *lt, t_ctrack *rt, const struct dissect *packet,
    const t_ctrack_positions *positions, bool replay, const char *ifin, const char *ifout)
{
    ++prolog_cases;
    prolog_track = lt;
    trace[0] = 0;
    trace_len = prolog_call_count = 0;
    prolog_calls[0] = 0;
    bool expected = reference_play_prolog(left, packet, positions, replay, ifin, ifout, 0x8012ffff);
    char expected_trace[sizeof(trace)], expected_calls[sizeof(prolog_calls)];
    memcpy(expected_trace, trace, trace_len + 1);
    strcpy(expected_calls, prolog_calls);
    prolog_track = rt;
    trace[0] = 0;
    trace_len = prolog_call_count = 0;
    prolog_calls[0] = 0;
    bool actual = play_prolog(right, packet, positions, replay, ifin, ifout, 0x8012ffff);
    if (expected != actual || strcmp(expected_trace, trace) || strcmp(expected_calls, prolog_calls)) {
        fprintf(stderr, "prolog case %u expected=%u actual=%u C calls=%s Rust calls=%s\nC %s\nRust %s\n",
            prolog_cases, expected, actual, expected_calls, prolog_calls, expected_trace, trace);
        CHECK(false);
    }
    if (!!packet->ip == !!packet->ip6) {
        CHECK(!memcmp(left, right, sizeof(*left)));
    } else {
        CHECK(!!left->tpos == !!right->tpos);
        if (left->tpos) {
            CHECK(left->tpos == (positions ? positions : &lt->pos));
            CHECK(right->tpos == (positions ? positions : &rt->pos));
        }
        // Normalize only pointers into the two independently owned connections.
        struct play_state a, b;
        memcpy(&a, left, sizeof(a));
        memcpy(&b, right, sizeof(b));
        a.tpos = b.tpos = NULL;
        compare_discovery_records(&a, &b);
    }
    return actual;
}

struct prolog_packet {
    struct ip ip4;
    struct ip6_hdr ip6;
    struct tcphdr tcp;
    struct udphdr udp;
    struct dissect packet;
};

static void prolog_packet_init(struct prolog_packet *fixture, bool ipv6, unsigned transport)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->ip4.ip_src = other4;
    fixture->ip4.ip_dst = include4;
    fixture->ip4.ip_ttl = 77;
    fixture->ip6.ip6_src = other6;
    fixture->ip6.ip6_dst = include6;
    fixture->ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 188;
    fixture->tcp.th_sport = fixture->udp.uh_sport = htons(40000);
    fixture->tcp.th_dport = fixture->udp.uh_dport = htons(443);
    if (ipv6) fixture->packet.ip6 = &fixture->ip6;
    else fixture->packet.ip = &fixture->ip4;
    fixture->packet.tcp = transport == 0 ? &fixture->tcp : NULL;
    fixture->packet.udp = transport == 1 ? &fixture->udp : NULL;
    fixture->packet.proto = transport == 0 ? IPPROTO_TCP : transport == 1 ? IPPROTO_UDP : 47;
    fixture->packet.len_payload = transport == 2 ? 0 : 17;
}

static void prolog_initial_state(struct play_state *ps, t_ctrack *track)
{
    memset(ps, 0x5a, sizeof(*ps));
    memset(track, 0, sizeof(*track));
    track->l7proto = L7_TLS;
    track->lua_state = 81;
    track->lua_instance_cutoff = 94;
    track->pos.client.pcounter = 17;
    track->pos.server.pcounter = 3;
}

static void prolog_combinations(void)
{
    const char *interfaces[] = {NULL, "", "Wi-Fi", "adapter-\xd0\xb0"};
    ORDER(WEB, AUTO, CONTROL, DEFAULT);
    prolog_cache_is_ip = prolog_alloc_fail = false;
    for (unsigned i = 0; i < 32768; ++i) {
        struct prolog_packet fixture;
        struct play_state left, right;
        t_ctrack lt, rt;
        prolog_packet_init(&fixture, i & 32, i % 3);
        fixture.packet.len_payload = i % 5 ? 17 : 0;
        params.server = i & 2;
        params.ctrack_disable = i & 4;
        prolog_found = i & 8;
        prolog_reverse = i & 16;
        prolog_cache_hit = i & 512;
        params.cache_hostname = i & 2048;
        params.debug = i % 7 == 0;
        prolog_initial_state(&left, &lt);
        prolog_initial_state(&right, &rt);
        lt.dp = rt.dp = i & 64 ? &profiles[i / 64 % 4].dp : NULL;
        lt.dp_search_complete = rt.dp_search_complete = i & 128;
        lt.l7proto = rt.l7proto = i % 5 ? L7_TLS : L7_UNKNOWN;
        lt.incoming_ttl = rt.incoming_ttl = i & 4096 ? 33 : 0;
        if (i & 256) {
            lt.hostname = strdup("example.com");
            rt.hostname = strdup("example.com");
            CHECK(lt.hostname && rt.hostname);
            lt.hostname_is_ip = rt.hostname_is_ip = i & 8192;
        }
        compare_prolog(&left, &right, &lt, &rt, &fixture.packet,
            i & 1024 ? &discovery_positions : NULL, i & 1,
            interfaces[i / 73 % 4], interfaces[i / 127 % 4]);
        free(lt.hostname);
        free(rt.hostname);
    }
}

static void prolog_boundaries_check(void)
{
    ORDER(WEB, DEFAULT);
    params.server = params.ctrack_disable = false;
    params.cache_hostname = params.debug = true;
    prolog_found = prolog_cache_hit = true;
    prolog_reverse = prolog_cache_is_ip = false;
    struct prolog_packet fixture;
    struct play_state left, right;
    t_ctrack lt, rt;
    prolog_packet_init(&fixture, false, 0);

    for (unsigned invalid = 0; invalid < 2; ++invalid) {
        prolog_initial_state(&left, &lt);
        prolog_initial_state(&right, &rt);
        fixture.packet.ip = invalid ? &fixture.ip4 : NULL;
        fixture.packet.ip6 = invalid ? &fixture.ip6 : NULL;
        CHECK(!compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, false, "in", "out"));
        CHECK(!prolog_call_count && left.verdict == VERDICT_PASS);
        ++prolog_boundaries;
    }
    fixture.packet.ip = &fixture.ip4;
    fixture.packet.ip6 = NULL;

    prolog_initial_state(&left, &lt);
    prolog_initial_state(&right, &rt);
    prolog_cache_hit = false;
    CHECK(compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, false, NULL, "out"));
    CHECK(left.dp == &profiles[DEFAULT].dp && left.tpos == &lt.pos);
    CHECK(!strcmp(prolog_calls, "PFHLRT"));
    ++prolog_boundaries;
    // Repeating the call uses the cached profile and avoids another list search.
    CHECK(compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, false, NULL, "out"));
    CHECK(!strcmp(prolog_calls, "PFRT"));
    ++prolog_boundaries;

    prolog_initial_state(&left, &lt);
    prolog_initial_state(&right, &rt);
    prolog_found = false;
    CHECK(!compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, true, NULL, "out"));
    CHECK(!strcmp(prolog_calls, "S"));
    ++prolog_boundaries;
    prolog_found = prolog_reverse = true;
    CHECK(!compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, true, NULL, "out"));
    CHECK(!strcmp(prolog_calls, "S"));
    ++prolog_boundaries;

    // Regression: the C path caches the IP string without its accompanying flag.
    prolog_reverse = false;
    prolog_cache_hit = prolog_cache_is_ip = true;
    prolog_cache_name = "192.0.2.10";
    prolog_initial_state(&left, &lt);
    prolog_initial_state(&right, &rt);
    prolog_track = &lt;
    CHECK(reference_play_prolog(&left, &fixture.packet, NULL, false, NULL, "out", 0));
    CHECK(lt.hostname && !lt.hostname_is_ip);
    prolog_track = &rt;
    CHECK(play_prolog(&right, &fixture.packet, NULL, false, NULL, "out", 0));
    CHECK(rt.hostname && rt.hostname_is_ip && !strcmp(rt.hostname, "192.0.2.10"));
    ++prolog_boundaries;
    free(lt.hostname);
    free(rt.hostname);

    // Regression: a failed duplicate must leave discovery pending for a retry.
    prolog_cache_is_ip = false;
    prolog_cache_name = "example.com";
    prolog_alloc_fail = true;
    prolog_initial_state(&left, &lt);
    prolog_initial_state(&right, &rt);
    prolog_track = &lt;
    CHECK(reference_play_prolog(&left, &fixture.packet, NULL, false, NULL, "out", 0));
    CHECK(lt.dp && lt.dp_search_complete && !lt.hostname);
    prolog_track = &rt;
    CHECK(!play_prolog(&right, &fixture.packet, NULL, false, NULL, "out", 0));
    CHECK(!rt.dp && !rt.dp_search_complete && !rt.hostname);
    ++prolog_boundaries;
    prolog_alloc_fail = false;
    memcpy(&lt, &rt, sizeof(lt));
    CHECK(compare_prolog(&left, &right, &lt, &rt, &fixture.packet, NULL, false, NULL, "out"));
    CHECK(rt.dp == &profiles[WEB].dp && rt.dp_search_complete && rt.hostname);
    ++prolog_boundaries;
    free(lt.hostname);
    free(rt.hostname);
    params.debug = false;
}

static __attribute__((noinline)) double time_play_prolog(PlayProlog prolog,
    struct play_state *ps, t_ctrack *track, const struct dissect *packet, bool replay, bool find)
{
    LARGE_INTEGER frequency, first, last;
    CHECK(QueryPerformanceFrequency(&frequency));
    prolog_track = track;
    CHECK(QueryPerformanceCounter(&first));
    unsigned successes = 0;
    for (unsigned i = 0; i < BENCH_SEARCHES; ++i) {
        prolog_call_count = 0;
        if (find) {
            track->dp = NULL;
            track->dp_search_complete = false;
        }
        successes += prolog(ps, packet, NULL, replay, NULL, "out", 0);
    }
    CHECK(QueryPerformanceCounter(&last));
    CHECK(successes == BENCH_SEARCHES);
    return (double)(last.QuadPart - first.QuadPart) * 1e9 /
        frequency.QuadPart / BENCH_SEARCHES;
}

static void prolog_benchmark(const char *name, bool replay, bool find)
{
    struct prolog_packet fixture;
    struct play_state left, right;
    t_ctrack lt, rt;
    prolog_packet_init(&fixture, false, 0);
    prolog_initial_state(&left, &lt);
    prolog_initial_state(&right, &rt);
    lt.dp = rt.dp = &profiles[DEFAULT].dp;
    lt.dp_search_complete = rt.dp_search_complete = true;
    lt.hostname = strdup("example.com");
    rt.hostname = strdup("example.com");
    CHECK(lt.hostname && rt.hostname);
    params.server = params.ctrack_disable = params.cache_hostname = params.debug = false;
    prolog_found = true;
    prolog_reverse = prolog_alloc_fail = false;
    ORDER(WEB, DEFAULT);
    double reference[BENCH_ROUNDS], actual[BENCH_ROUNDS];
    for (unsigned i = 0; i < BENCH_ROUNDS; ++i) {
        if (i % 2 == 0) {
            reference[i] = time_play_prolog(reference_play_prolog, &left, &lt, &fixture.packet, replay, find);
            actual[i] = time_play_prolog(play_prolog, &right, &rt, &fixture.packet, replay, find);
        } else {
            actual[i] = time_play_prolog(play_prolog, &right, &rt, &fixture.packet, replay, find);
            reference[i] = time_play_prolog(reference_play_prolog, &left, &lt, &fixture.packet, replay, find);
        }
    }
    qsort(reference, BENCH_ROUNDS, sizeof(reference[0]), compare_time);
    qsort(actual, BENCH_ROUNDS, sizeof(actual[0]), compare_time);
    printf("BENCH play_prolog %s c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",
        name, reference[BENCH_ROUNDS / 2], actual[BENCH_ROUNDS / 2], BENCH_ROUNDS, BENCH_SEARCHES);
    free(lt.hostname);
    free(rt.hostname);
}

static void check_play_prolog(void)
{
    prolog_combinations();
    prolog_boundaries_check();
    printf("PASS play_prolog cases=%u boundary_cases=%u intentional_fixes=2\n",
        prolog_cases, prolog_boundaries);
    prolog_benchmark("cached-profile", false, false);
    prolog_benchmark("profile-search", false, true);
    prolog_benchmark("replay", true, false);
}
