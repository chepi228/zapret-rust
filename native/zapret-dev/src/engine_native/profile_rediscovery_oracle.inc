/* MIT. In-memory connection discovery, real profile selection and injected failures. */
static unsigned discovery_cases, discovery_boundaries, duplicate_calls, release_calls;
static unsigned cache_calls, udp_calls, last_actual_duplicates, last_reference_duplicates;
static bool fail_duplicate, fail_cache;
static char cached_hostname[256];
static bool cached_is_ip;

static char *discovery_strdup(const char *name)
{
    ++duplicate_calls;
    return fail_duplicate ? NULL : strdup(name);
}

static void discovery_free(void *name)
{
    if (name) ++release_calls;
    free(name);
}

static bool ipcache_put_hostname(const struct in_addr *ip, const struct in6_addr *ip6,
    const char *hostname, bool is_ip)
{
    if (!params.cache_hostname) return true;
    ++cache_calls;
    char address[INET6_ADDRSTRLEN];
    ntopa46(ip, ip6, address, sizeof(address));
    DLOG("fixture cache ip=%s hostname=%s is_ip=%u\n", address, hostname, is_ip);
    if (fail_cache) {
        DLOG_ERR("ipcache_put_hostname: out of memory\n");
        return false;
    }
    snprintf(cached_hostname, sizeof(cached_hostname), "%s", hostname);
    cached_is_ip = is_ip;
    return true;
}

static void process_udp_fail(t_ctrack *track, const t_ctrack_positions *positions,
    const struct sockaddr *client)
{
    CHECK(track && client && client->sa_family == AF_INET);
    CHECK(positions && positions->client.pcounter == 17 && positions->server.pcounter == 3);
    ++udp_calls;
    DLOG("fixture udp profile=%u done=%u result=%u excluded=%u automatic=%u\n",
        track->dp ? track->dp->n : 0, track->bCheckDone, track->bCheckResult,
        track->bCheckExcluded, track->hostname_ah_check);
    // Observe callback-side writes when checking that the Rust call preserves
    // fields outside its profile state.
    track->failure_detect_finalized = true;
}

#define strdup discovery_strdup
#define free discovery_free
#define dp_find reference_dp_find
#define dp_rediscovery reference_dp_rediscovery
#include "profile_rediscovery_reference.inc"
#undef dp_rediscovery
#undef dp_find
#include "profile_rediscovery_windows.inc"
#undef free
#undef strdup

typedef bool (*Rediscover)(struct play_state *);
static const t_ctrack_positions discovery_positions = {
    .client.pcounter = 17, .server.pcounter = 3
};

static void reset_discovery_observation(void)
{
    trace_len = 0;
    trace[0] = 0;
    duplicate_calls = release_calls = cache_calls = udp_calls = 0;
    strcpy(cached_hostname, "previous-cache.example");
    cached_is_ip = false;
}

static void compare_discovery_records(const struct play_state *left,
    const struct play_state *right)
{
    unsigned char a[sizeof(*left)], b[sizeof(*right)];
    memcpy(a, left, sizeof(a));
    memcpy(b, right, sizeof(b));
    // The records belong to two independent connections in the same fixture.
    memset(a + offsetof(struct play_state, ctrack), 0, sizeof(left->ctrack));
    memset(b + offsetof(struct play_state, ctrack), 0, sizeof(right->ctrack));
    memset(a + offsetof(struct play_state, ctrack_replay), 0, sizeof(left->ctrack_replay));
    memset(b + offsetof(struct play_state, ctrack_replay), 0, sizeof(right->ctrack_replay));
    CHECK(!memcmp(a, b, sizeof(a)));
    if (left->ctrack_replay) {
        const t_ctrack *lt = left->ctrack_replay, *rt = right->ctrack_replay;
        CHECK(rt && !!lt->hostname == !!rt->hostname);
        if (lt->hostname) CHECK(!strcmp(lt->hostname, rt->hostname));
        unsigned char la[sizeof(*lt)], ra[sizeof(*rt)];
        memcpy(la, lt, sizeof(la));
        memcpy(ra, rt, sizeof(ra));
        memset(la + offsetof(t_ctrack, hostname), 0, sizeof(lt->hostname));
        memset(ra + offsetof(t_ctrack, hostname), 0, sizeof(rt->hostname));
        CHECK(!memcmp(la, ra, sizeof(la)));
    }
}

static bool compare_discovery(struct play_state *left, struct play_state *right)
{
    ++discovery_cases;
    reset_discovery_observation();
    bool expected = reference_dp_rediscovery(left);
    last_reference_duplicates = duplicate_calls;
    unsigned expected_cache_calls = cache_calls, expected_udp_calls = udp_calls;
    bool expected_is_ip = cached_is_ip;
    char expected_trace[sizeof(trace)], expected_hostname[sizeof(cached_hostname)];
    memcpy(expected_trace, trace, trace_len + 1);
    strcpy(expected_hostname, cached_hostname);
    reset_discovery_observation();
    bool actual = dp_rediscovery(right);
    last_actual_duplicates = duplicate_calls;
    if (expected != actual || strcmp(expected_trace, trace)) {
        fprintf(stderr, "discovery scenario %u expected=%u actual=%u\nC %s\nRust %s\n",
            discovery_cases, expected, actual, expected_trace, trace);
        CHECK(false);
    }
    CHECK(expected_cache_calls == cache_calls && expected_udp_calls == udp_calls);
    CHECK(expected_is_ip == cached_is_ip && !strcmp(expected_hostname, cached_hostname));
    compare_discovery_records(left, right);
    return actual;
}

static void discovery_state(struct play_state *ps, t_ctrack *track,
    struct dissect *packet, unsigned tracked, const char *host)
{
    memset(ps, 0, sizeof(*ps));
    memset(track, 0, sizeof(*track));
    ps->dp = track->dp = &profiles[DEFAULT].dp;
    ps->dis = packet;
    ps->sdip4 = &include4;
    ps->sdport = 443;
    ps->l7proto = track->l7proto = L7_TLS;
    ps->l7payload = L7P_TLS_CLIENT_HELLO;
    ps->tpos = &discovery_positions;
    ((struct sockaddr_in *)&ps->src)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ps->src)->sin_port = htons(40000);
    ((struct sockaddr_in *)&ps->src)->sin_addr = other4;
    ((struct sockaddr_in *)&ps->dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ps->dst)->sin_port = htons(443);
    ((struct sockaddr_in *)&ps->dst)->sin_addr = include4;
    if (tracked) ps->ctrack_replay = track;
    if (tracked == 1) ps->ctrack = track;
    ps->bHaveHost = host != NULL;
    if (host) snprintf(ps->host, sizeof(ps->host), "%s", host);
    track->lua_state = 81;
    track->lua_instance_cutoff = 94;
    track->req_retrans_counter = 2;
    track->b_lua_in_cutoff = track->b_lua_out_cutoff = true;
}

static uint32_t discovery_random_state = 0x941720bf;
static uint32_t discovery_random(void)
{
    discovery_random_state ^= discovery_random_state << 13;
    discovery_random_state ^= discovery_random_state >> 17;
    discovery_random_state ^= discovery_random_state << 5;
    return discovery_random_state;
}

static void discovery_combinations(void)
{
    static const enum profile_id orders[][4] = {
        {WEB, AUTO, CONTROL, DEFAULT}, {AUTO, WEB, CONTROL, DEFAULT},
        {DEFAULT, WEB, CONTROL, AUTO}, {WEB, AUTO, CONTROL, DEFAULT}
    };
    static const char *const names[] = {
        NULL, "", "example.com", " www.example.com:443", "blocked.example.com",
        "strict.example", "sub.strict.example", "192.0.2.10:443",
        " [2001:db8::a]:8443", "\t2001:db8::a", "unknown.example", "x",
        "[bad-address]:443", "[missing-bracket", "\t", "192.0.2.999"
    };
    struct dissect packet = {0};
    for (unsigned i = 0; i < 16384; ++i) {
        uint32_t bits = discovery_random();
        unsigned tracked = i % 3;
        struct play_state left, right;
        t_ctrack lt, rt;
        packet.proto = i & 1 ? IPPROTO_TCP : IPPROTO_UDP;
        order(orders[i % 4], i % 7 == 0 ? 0 : i % 4 == 3 ? 3 : 4);
        discovery_state(&left, &lt, &packet, tracked, names[bits % 16]);
        lt.dp = left.dp = &profiles[i % 4].dp;
        left.l7proto = lt.l7proto = i % 5 ? L7_TLS : L7_UNKNOWN;
        lt.l7proto_discovered = bits & 1;
        lt.hostname_discovered = bits & 2;
        lt.hostname_is_ip = bits & 4;
        lt.hostname_ah_check = bits & 8;
        lt.bCheckDone = bits & 16;
        lt.bCheckResult = bits & 32;
        lt.bCheckExcluded = bits & 64;
        lt.b_lua_in_cutoff = bits & 128;
        lt.b_lua_out_cutoff = bits & 256;
        lt.req_retrans_counter = i % 256;
        left.bReverse = bits & 512;
        left.bReverseFixed = bits & 1024;
        left.fwmark = bits;
        left.sdip4 = i & 2 ? NULL : &include4;
        left.sdip6 = i & 2 ? &include6 : NULL;
        params.cache_hostname = bits & 2048;
        params.debug = i % 11 == 0;
        memcpy(&right, &left, sizeof(right));
        memcpy(&rt, &lt, sizeof(rt));
        if (tracked) {
            if (i % 4) {
                lt.hostname = strdup(i % 4 == 1 ? "example.com" : "previous.example");
                rt.hostname = strdup(lt.hostname);
                CHECK(lt.hostname && rt.hostname);
            }
            right.ctrack_replay = &rt;
            if (tracked == 1) right.ctrack = &rt;
        }
        for (unsigned turn = 0; turn < 3; ++turn) {
            compare_discovery(&left, &right);
            if (!left.dp) break; // play_prolog rejects this connection before the next call.
            if (turn == 0) {
                left.l7proto = right.l7proto = lt.l7proto = rt.l7proto = L7_HTTP;
                left.bHaveHost = right.bHaveHost = true;
                strcpy(left.host, i % 2 ? "example.com" : "blocked.example.com");
                strcpy(right.host, left.host);
            }
        }
        free(lt.hostname);
        free(rt.hostname);
    }
    params.debug = false;
}

static void discovery_failure(unsigned failure)
{
    ORDER(WEB, DEFAULT);
    params.cache_hostname = params.debug = true;
    struct dissect packet = {.proto = IPPROTO_TCP};
    struct play_state left, right;
    t_ctrack lt, rt;
    discovery_state(&left, &lt, &packet, 1, "example.com");
    discovery_state(&right, &rt, &packet, 1, "example.com");
    lt.hostname = strdup("previous.example");
    rt.hostname = strdup("previous.example");
    CHECK(lt.hostname && rt.hostname);
    char *previous = rt.hostname;
    fail_duplicate = failure == 0;
    fail_cache = failure == 1;
    reset_discovery_observation();
    CHECK(!reference_dp_rediscovery(&left));
    CHECK(lt.l7proto_discovered);
    CHECK(failure == 0 ? !lt.hostname : lt.hostname_discovered);
    reset_discovery_observation();
    CHECK(!dp_rediscovery(&right));
    CHECK(rt.hostname == previous && !strcmp(rt.hostname, "previous.example"));
    CHECK(!rt.hostname_discovered && !rt.l7proto_discovered);
    CHECK(!rt.dp_search_complete && right.dp == &profiles[DEFAULT].dp);
    CHECK(release_calls == (failure == 1 ? 1 : 0));
    ++discovery_boundaries;

    fail_duplicate = fail_cache = false;
    free(lt.hostname);
    discovery_state(&left, &lt, &packet, 1, "example.com");
    lt.hostname = strdup("previous.example");
    CHECK(lt.hostname);
    CHECK(compare_discovery(&left, &right));
    CHECK(rt.hostname_discovered && rt.l7proto_discovered && rt.dp == &profiles[WEB].dp);
    CHECK(!rt.b_lua_in_cutoff && !rt.b_lua_out_cutoff);
    CHECK(rt.bCheckDone && rt.bCheckResult && !rt.bCheckExcluded);
    ++discovery_boundaries;
    free(lt.hostname);
    free(rt.hostname);
}

static void discovery_boundaries_check(void)
{
    discovery_failure(0);
    discovery_failure(1);
    ORDER(WEB, DEFAULT);
    struct dissect packet = {.proto = IPPROTO_TCP};
    struct play_state left, right;
    t_ctrack lt, rt;
    discovery_state(&left, &lt, &packet, 1, "example.com");
    discovery_state(&right, &rt, &packet, 1, "example.com");
    lt.hostname = strdup("example.com");
    rt.hostname = strdup("example.com");
    CHECK(lt.hostname && rt.hostname);
    CHECK(compare_discovery(&left, &right));
    CHECK(last_reference_duplicates == 1 && last_actual_duplicates == 0);
    ++discovery_boundaries;
    free(lt.hostname);
    free(rt.hostname);

    discovery_state(&right, &rt, &packet, 1, "example.com");
    char *previous = rt.hostname = strdup("example.com");
    CHECK(previous);
    fail_duplicate = true;
    reset_discovery_observation();
    CHECK(dp_rediscovery(&right));
    CHECK(rt.hostname == previous && rt.hostname_discovered);
    CHECK(!duplicate_calls);
    fail_duplicate = false;
    ++discovery_boundaries;
    free(rt.hostname);

    packet.proto = IPPROTO_UDP;
    discovery_state(&left, &lt, &packet, 2, NULL);
    discovery_state(&right, &rt, &packet, 2, NULL);
    lt.l7proto_discovered = rt.l7proto_discovered = true;
    lt.bCheckDone = rt.bCheckDone = true;
    lt.bCheckResult = rt.bCheckResult = false;
    CHECK(!compare_discovery(&left, &right));
    CHECK(udp_calls == 1 && rt.failure_detect_finalized);
    CHECK(!cache_calls && !duplicate_calls);
    ++discovery_boundaries;

    packet.proto = IPPROTO_TCP;
    for (unsigned automatic = 0; automatic < 2; ++automatic) {
        discovery_state(&left, &lt, &packet, 1, "example.com");
        discovery_state(&right, &rt, &packet, 1, "example.com");
        lt.dp = left.dp = rt.dp = right.dp = &profiles[WEB].dp;
        lt.l7proto_discovered = rt.l7proto_discovered = true;
        lt.hostname_discovered = rt.hostname_discovered = true;
        lt.hostname_ah_check = rt.hostname_ah_check = automatic;
        CHECK(compare_discovery(&left, &right));
        CHECK(rt.req_retrans_counter == (automatic ? RETRANS_COUNTER_STOP : 2));
        CHECK(rt.b_lua_in_cutoff && rt.b_lua_out_cutoff); // Same profile retains cutoffs.
        ++discovery_boundaries;
    }
    for (unsigned excluded = 0; excluded < 2; ++excluded) {
        const char *host = excluded ? "blocked.example.com" : "unlisted.example";
        discovery_state(&left, &lt, &packet, 1, host);
        discovery_state(&right, &rt, &packet, 1, host);
        lt.dp = left.dp = rt.dp = right.dp = &profiles[AUTO].dp;
        lt.l7proto_discovered = rt.l7proto_discovered = true;
        lt.hostname_discovered = rt.hostname_discovered = true;
        lt.hostname_ah_check = rt.hostname_ah_check = true;
        CHECK(!compare_discovery(&left, &right));
        CHECK(rt.hostname_ah_check == !excluded && rt.bCheckExcluded == excluded);
        CHECK(rt.req_retrans_counter == 2);
        ++discovery_boundaries;
    }
    char maximum[256];
    memset(maximum, 'a', sizeof(maximum) - 1);
    maximum[sizeof(maximum) - 1] = 0;
    discovery_state(&left, &lt, &packet, 1, maximum);
    discovery_state(&right, &rt, &packet, 1, maximum);
    CHECK(compare_discovery(&left, &right));
    CHECK(rt.hostname && strlen(rt.hostname) == 255);
    ++discovery_boundaries;
    free(lt.hostname);
    free(rt.hostname);
}

static __attribute__((noinline)) double time_discovery(Rediscover rediscover,
    struct play_state *ps, bool repeat_hostname)
{
    LARGE_INTEGER frequency, first, last;
    CHECK(QueryPerformanceFrequency(&frequency));
    CHECK(QueryPerformanceCounter(&first));
    unsigned successes = 0;
    for (unsigned i = 0; i < BENCH_SEARCHES; ++i) {
        if (repeat_hostname) ps->ctrack_replay->hostname_discovered = false;
        successes += rediscover(ps);
    }
    CHECK(QueryPerformanceCounter(&last));
    CHECK(successes == BENCH_SEARCHES);
    return (double)(last.QuadPart - first.QuadPart) * 1e9 /
        frequency.QuadPart / BENCH_SEARCHES;
}

static void discovery_benchmark(const char *name, bool have_host, bool repeat_hostname)
{
    struct dissect packet = {.proto = IPPROTO_TCP};
    struct play_state left, right;
    t_ctrack lt, rt;
    discovery_state(&left, &lt, &packet, 1, have_host ? "example.com" : NULL);
    discovery_state(&right, &rt, &packet, 1, have_host ? "example.com" : NULL);
    lt.dp = left.dp = rt.dp = right.dp = &profiles[WEB].dp;
    lt.l7proto_discovered = rt.l7proto_discovered = true;
    lt.hostname_discovered = rt.hostname_discovered = true;
    lt.bCheckDone = rt.bCheckDone = true;
    lt.bCheckResult = rt.bCheckResult = true;
    lt.hostname = strdup("example.com");
    rt.hostname = strdup("example.com");
    CHECK(lt.hostname && rt.hostname);
    params.cache_hostname = params.debug = false;
    ORDER(WEB, DEFAULT);
    double reference[BENCH_ROUNDS], actual[BENCH_ROUNDS];
    for (unsigned i = 0; i < BENCH_ROUNDS; ++i) {
        if (i % 2 == 0) {
            reference[i] = time_discovery(reference_dp_rediscovery, &left, repeat_hostname);
            actual[i] = time_discovery(dp_rediscovery, &right, repeat_hostname);
        } else {
            actual[i] = time_discovery(dp_rediscovery, &right, repeat_hostname);
            reference[i] = time_discovery(reference_dp_rediscovery, &left, repeat_hostname);
        }
    }
    qsort(reference, BENCH_ROUNDS, sizeof(reference[0]), compare_time);
    qsort(actual, BENCH_ROUNDS, sizeof(actual[0]), compare_time);
    printf("BENCH profile_rediscovery %s c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",
        name, reference[BENCH_ROUNDS / 2], actual[BENCH_ROUNDS / 2], BENCH_ROUNDS, BENCH_SEARCHES);
    free(lt.hostname);
    free(rt.hostname);
}

static void check_rediscovery(void)
{
    discovery_combinations();
    discovery_boundaries_check();
    printf("PASS profile_rediscovery cases=%u boundary_cases=%u failure_retries=2\n",
        discovery_cases, discovery_boundaries);
    params.debug = false;
    discovery_benchmark("cached-profile", false, false);
    discovery_benchmark("known-host", true, false);
    discovery_benchmark("cached-host-discovery", true, true);
}
